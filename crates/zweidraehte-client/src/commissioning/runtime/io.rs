//! Service sizing and dispatch use the same concrete operands as preflight.
use super::data::changed_ranges;
use super::{ExecutionSession, mutating_request_may_have_reached_device};
use crate::bus::BusError;
use crate::bus::management::FunctionPropertyResult;
use crate::commissioning::error::Diagnostic;
use crate::commissioning::procedure::operands::{
    FUNCTION_PROPERTY_NOT_SUPPORTED_ERROR, MemoryAddress, MemoryService, PointerEncoding, PropertyAddress,
    validate_range,
};
use crate::commissioning::procedure::{
    FunctionPropertyOperation, LoadControlCause, LoadEffect, LoadRecord, OperationExtent, OperationTarget,
    PropertyDataTypeLookup, WritePolicy,
};
use crate::commissioning::runtime::TransferContext;
use zweidraehte_proto::messages::apdu::load_control::LoadState;
use zweidraehte_proto::pid;

#[derive(Clone, Copy)]
struct MemoryGeometry {
    service: MemoryService,
    address: u32,
    length: usize,
    capacity: usize,
}

impl MemoryGeometry {
    /// Chunks are subsets of a validated transfer, so they retain its service
    /// and negotiated capacity without re-resolving pointers or sizing again.
    fn range(self, range: std::ops::Range<usize>) -> Self {
        assert!(range.start <= range.end && range.end <= self.length, "chunk is within checked transfer");
        Self { address: self.address + range.start as u32, length: range.len(), ..self }
    }
}

#[derive(Clone, Copy)]
struct PropertyGeometry {
    address: PropertyAddress,
    start: u16,
    extent: OperationExtent,
    count: usize,
    width: usize,
    capacity: usize,
}

#[derive(Clone, Copy)]
enum PropertyOperation<'a> {
    Read,
    Write(&'a [u8]),
    ConfirmedWrite(&'a [u8]),
}

impl<'a> PropertyOperation<'a> {
    fn data(self) -> Option<&'a [u8]> {
        match self {
            Self::Read => None,
            Self::Write(bytes) | Self::ConfirmedWrite(bytes) => Some(bytes),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum MemoryVerification {
    Acknowledgement,
    DeviceResponse,
    ReadBack,
}

impl ExecutionSession<'_> {
    async fn memory_address(
        &mut self,
        address: &MemoryAddress,
        context: TransferContext<'_>,
    ) -> Result<u32, Diagnostic> {
        match address {
            MemoryAddress::Fixed(address) => Ok(*address),
            MemoryAddress::Pointer { space, read, offset, encoding } => {
                // Allocations and restarts can relocate these bytes. Resolve at
                // the actual transfer, never into a profile-wide pointer cache.
                let bytes = Box::pin(self.read(&read.target, read.extent, context)).await?;
                if bytes.is_empty() || bytes.len() > 4 {
                    return Err(Diagnostic::new("pointer requires one through four bytes"));
                }
                let base = match encoding {
                    PointerEncoding::Absolute => bytes.iter().fold(0u32, |value, byte| value << 8 | u32::from(*byte)),
                    PointerEncoding::PageOne if bytes.len() == 1 => 0x100 + u32::from(bytes[0]),
                    PointerEncoding::PageOne => return Err(Diagnostic::new("page-one pointer requires one byte")),
                };
                let address =
                    base.checked_add(*offset).ok_or_else(|| Diagnostic::new("pointer plus offset exceeds 32 bits"))?;
                self.images.remember_pointer(space.clone(), *read.clone(), base);
                Ok(address)
            }
        }
    }

    pub(super) async fn resolve_target(
        &mut self,
        target: &OperationTarget,
        context: TransferContext<'_>,
    ) -> Result<OperationTarget, Diagnostic> {
        Ok(match target {
            OperationTarget::Memory { service, address } => OperationTarget::Memory {
                service: *service,
                address: MemoryAddress::Fixed(self.memory_address(address, context).await?),
            },
            _ => target.clone(),
        })
    }

    pub(in crate::commissioning) async fn read(
        &mut self,
        target: &OperationTarget,
        extent: OperationExtent,
        context: TransferContext<'_>,
    ) -> Result<Vec<u8>, Diagnostic> {
        target.minimum_apdu(extent)?;
        let resolved = self.resolve_target(target, context).await?;
        let resolved = self.fit_property_target(resolved, extent).await?;
        let bytes = match &resolved {
            OperationTarget::Memory { service, address: MemoryAddress::Fixed(address) } => {
                self.memory_read(self.memory_geometry(*service, *address, extent.byte_length as usize)?).await
            }
            OperationTarget::Property { address, start_element } => {
                let geometry = self.property_geometry(*address, *start_element, extent, false)?;
                return self.read_property(geometry, context).await;
            }
            OperationTarget::Adc { channel } => {
                let value = self.connection_mut()?.adc_read(*channel, 1).await?;
                Ok(value.to_be_bytes().to_vec())
            }
            OperationTarget::Constant(value) => Ok(value.clone()),
            OperationTarget::ImageMemory(_) => {
                Err(Diagnostic::new("image-memory target was not bound during preparation"))
            }
            OperationTarget::Memory { .. } => unreachable!("memory address was resolved above"),
        }?;
        self.observe_target(&resolved, extent, &bytes, context)?;
        if resolved != *target {
            self.observe_target(target, extent, &bytes, context)?;
        }
        Ok(bytes)
    }

    pub(in crate::commissioning) async fn write(
        &mut self,
        target: &OperationTarget,
        data: &[u8],
        extent: OperationExtent,
        policy: WritePolicy,
        context: TransferContext<'_>,
    ) -> Result<(), Diagnostic> {
        target.minimum_apdu(extent)?;
        if data.len() != extent.byte_length as usize {
            return Err(Diagnostic::new("write length differs from prepared extent"));
        }
        // A failed pointer read is not a mutation. Invalidation follows the
        // successful resolution and uses the actual physical destination.
        let resolved = self.resolve_target(target, context).await?;
        let resolved = self.fit_property_target(resolved, extent).await?;
        match &resolved {
            OperationTarget::Memory { service, address: MemoryAddress::Fixed(address) } => {
                // Check the final range and chunk capacity before mode changes
                // or invalidation, including for direct pointer-backed writes.
                let geometry = self.memory_geometry(*service, *address, data.len())?;
                let extended = geometry.service == MemoryService::Extended;
                let auto = !extended && policy == WritePolicy::DeviceAutoVerify;
                self.connection_mut()?;
                if !extended {
                    self.set_memory_verify_mode(auto).await?;
                }
                self.images.invalidate_target(&resolved, extent);
                if policy == WritePolicy::Optimistic {
                    let current = self.memory_read(geometry).await?;
                    for range in changed_ranges(data.len(), 4, true, |index| data[index] == current[index]) {
                        self.memory_write(
                            geometry.range(range.clone()),
                            &data[range],
                            MemoryVerification::Acknowledgement,
                        )
                        .await?;
                    }
                    Ok(())
                } else {
                    let verification = if auto {
                        MemoryVerification::DeviceResponse
                    } else if !extended && policy == WritePolicy::ReadBack {
                        MemoryVerification::ReadBack
                    } else {
                        MemoryVerification::Acknowledgement
                    };
                    self.memory_write(geometry, data, verification).await
                }?;
                Ok(())
            }
            OperationTarget::Property { address, start_element } => {
                if policy == WritePolicy::DeviceAutoVerify {
                    return Err(Diagnostic::new("Verify Mode is unavailable for properties"));
                }
                let geometry = self.property_geometry(*address, *start_element, extent, true)?;
                if policy == WritePolicy::Optimistic && self.read_property(geometry, context).await? == data {
                    return Ok(());
                }
                self.property_transfer(geometry, PropertyOperation::Write(data), context).await?;
                if policy == WritePolicy::ReadBack && self.read_property(geometry, context).await? != data {
                    return Err(self.compare_error("property read-back differs"));
                }
                Ok(())
            }
            _ => Err(Diagnostic::new("operation target is read-only")),
        }?;
        self.observe_target(&resolved, extent, data, context)?;
        if resolved != *target {
            self.observe_target(target, extent, data, context)?;
        }
        Ok(())
    }

    pub(super) fn observe_target(
        &mut self,
        target: &OperationTarget,
        extent: OperationExtent,
        bytes: &[u8],
        context: TransferContext<'_>,
    ) -> Result<(), Diagnostic> {
        // Private payloads and their verification reads never enter ordinary
        // image knowledge or stamp snapshots, including on cleanup failure.
        if matches!(context, TransferContext::Private { .. }) {
            return Ok(());
        }
        if let Some(location) = super::image_state::ImageState::target_location(target, extent) {
            self.images.observe(location, bytes)?;
        }
        Ok(())
    }

    fn memory_geometry(
        &self,
        service: MemoryService,
        address: u32,
        length: usize,
    ) -> Result<MemoryGeometry, Diagnostic> {
        let length_u32 = u32::try_from(length).map_err(|_| Diagnostic::new("memory length exceeds 32 bits"))?;
        let service = service.at(address, length_u32);
        validate_range(address, length_u32, service.max_address())?;
        let capacity = self.payload_budget(service.overhead())?.min(service.max_count());
        if capacity == 0 && length != 0 {
            return Err(Diagnostic::new("APDU cannot carry a memory byte"));
        }
        Ok(MemoryGeometry { service, address, length, capacity })
    }

    async fn memory_read(&mut self, geometry: MemoryGeometry) -> Result<Vec<u8>, Diagnostic> {
        let MemoryGeometry { service, address, length, capacity } = geometry;
        let mut bytes = Vec::with_capacity(length);
        while bytes.len() < length {
            let count = (length - bytes.len()).min(capacity) as u8;
            let address = address + bytes.len() as u32;
            let connection = self.connection_mut()?;
            let result = match service {
                MemoryService::Classic => connection.memory_read(address as u16, count).await,
                MemoryService::Extended => connection.memory_extended_read(address, count).await,
                MemoryService::User => connection.user_memory_read(address, count).await,
                MemoryService::Filter => connection.filter_table_read(address, count).await,
                MemoryService::Router => connection.router_memory_read(address, count).await,
                MemoryService::Standard => unreachable!("deferred service resolves before dispatch"),
            };
            let chunk = result?;
            if chunk.len() != usize::from(count) {
                return Err(Diagnostic::new("memory response length differs from request"));
            }
            bytes.extend(chunk);
        }
        Ok(bytes)
    }

    async fn memory_write(
        &mut self,
        geometry: MemoryGeometry,
        data: &[u8],
        verification: MemoryVerification,
    ) -> Result<(), Diagnostic> {
        let MemoryGeometry { service, address, capacity, .. } = geometry;
        for (index, chunk) in data.chunks(capacity.max(1)).enumerate() {
            let address = address + (index * capacity) as u32;
            let connection = self.connection_mut()?;
            let result = match (service, verification == MemoryVerification::DeviceResponse) {
                (MemoryService::Classic, false) => connection.memory_write(address as u16, chunk).await,
                (MemoryService::Classic, true) => connection.memory_write_auto_verify(address as u16, chunk).await,
                (MemoryService::Extended, _) => connection.memory_extended_write(address, chunk).await,
                (MemoryService::User, false) => connection.user_memory_write(address, chunk).await,
                (MemoryService::User, true) => connection.user_memory_write_auto_verify(address, chunk).await,
                (MemoryService::Filter, false) => connection.filter_table_write(address, chunk).await,
                (MemoryService::Filter, true) => connection.filter_table_write_auto_verify(address, chunk).await,
                (MemoryService::Router, false) => connection.router_memory_write(address, chunk).await,
                (MemoryService::Router, true) => connection.router_memory_write_auto_verify(address, chunk).await,
                (MemoryService::Standard, _) => unreachable!("deferred service resolves before dispatch"),
            };
            result.map_err(|error| self.mutating_client_error(error))?;
            self.record_mutation();
            let chunk_geometry = geometry.range(index * capacity..index * capacity + chunk.len());
            if verification == MemoryVerification::ReadBack && self.memory_read(chunk_geometry).await? != chunk {
                return Err(self.compare_error(format!("memory read-back differs at {address:#010x}")));
            }
        }
        Ok(())
    }

    fn property_geometry(
        &self,
        address: PropertyAddress,
        start: u16,
        extent: OperationExtent,
        write: bool,
    ) -> Result<PropertyGeometry, Diagnostic> {
        let target = OperationTarget::Property { address, start_element: start };
        target.minimum_apdu(extent)?;
        // TODO: a type-addressed transfer fitted to its located index looks
        // up the index key here and misses a type-wide declaration; the
        // reference's choice of cache after that fallback is untraced.
        if let Some(descriptor) = self.property_descriptors.get(&super::DescriptorKey::from(address)) {
            if write && !descriptor.writable {
                return Err(Diagnostic::new("declared property is not writable"));
            }
            if start > 0
                && u32::from(start) + u32::from(extent.property_elements.expect("validated extent")) - 1
                    > u32::from(descriptor.maximum_elements)
            {
                return Err(Diagnostic::new("property range exceeds its declared maximum"));
            }
        }
        let count = usize::from(extent.property_elements.expect("validated property extent"));
        let width = extent.element_width()? as usize;
        let capacity = (self.payload_budget(address.overhead())? / width).min(address.max_count());
        if capacity == 0 {
            return Err(Diagnostic::new("APDU cannot carry one complete property element"));
        }
        Ok(PropertyGeometry { address, start, extent, count, width, capacity })
    }

    async fn read_property(
        &mut self,
        geometry: PropertyGeometry,
        context: TransferContext<'_>,
    ) -> Result<Vec<u8>, Diagnostic> {
        let mut bytes = self.property_transfer(geometry, PropertyOperation::Read, context).await?;
        let target = OperationTarget::Property { address: geometry.address, start_element: geometry.start };
        // ReadResource requests complete elements but returns only the
        // selected image prefix. Device knowledge retains the complete reply.
        let observed_extent = OperationExtent::property(
            bytes.len() as u32,
            geometry.extent.property_elements.expect("property read carries elements"),
        );
        self.observe_target(&target, observed_extent, &bytes, context)?;
        bytes.truncate(geometry.extent.byte_length as usize);
        Ok(bytes)
    }

    async fn property_transfer(
        &mut self,
        geometry: PropertyGeometry,
        operation: PropertyOperation<'_>,
        context: TransferContext<'_>,
    ) -> Result<Vec<u8>, Diagnostic> {
        let PropertyGeometry { address, start, extent, count, width, capacity } = geometry;
        let target = OperationTarget::Property { address, start_element: start };
        let data = operation.data();
        if let Some(data) = data {
            if data.len() != extent.byte_length as usize {
                return Err(Diagnostic::new("property payload differs from its declared extent"));
            }
        }
        self.connection_mut()?;
        // No local validation can reject the transfer after invalidation.
        if data.is_some() {
            self.images.invalidate_target(&target, extent);
        }
        let mut bytes = Vec::new();
        for offset in (0..count).step_by(capacity) {
            let chunk_count = capacity.min(count - offset) as u16;
            let chunk_start = start + offset as u16;
            let connection = self.connection_mut()?;
            if let Some(data) = data {
                let chunk = &data[offset * width..(offset + usize::from(chunk_count)) * width];
                let result = match address {
                    PropertyAddress::Indexed { object_index, property_id } => {
                        connection
                            .property_write(object_index, property_id.into(), chunk_start, chunk_count, chunk)
                            .await
                    }
                    PropertyAddress::Extended { object_type, object_instance, property_id }
                        if matches!(operation, PropertyOperation::ConfirmedWrite(_)) =>
                    {
                        connection
                            .property_ext_write(
                                object_type,
                                object_instance,
                                property_id,
                                chunk_start,
                                chunk_count,
                                chunk,
                            )
                            .await
                    }
                    PropertyAddress::Extended { object_type, object_instance, property_id } => {
                        connection
                            .property_ext_write_unconfirmed(
                                object_type,
                                object_instance,
                                property_id,
                                chunk_start,
                                chunk_count,
                                chunk,
                            )
                            .await
                    }
                };
                if result.is_ok() || result.as_ref().err().is_some_and(mutating_request_may_have_reached_device) {
                    self.effects.expose_group_keys(
                        context
                            .group_keys()
                            .get(offset..offset + usize::from(chunk_count))
                            .unwrap_or_default()
                            .iter()
                            .copied(),
                    );
                }
                result.map_err(|error| self.mutating_client_error(error))?;
                self.record_mutation();
            } else {
                let result = match address {
                    PropertyAddress::Indexed { object_index, property_id } => {
                        connection.property_read(object_index, property_id.into(), chunk_start, chunk_count).await
                    }
                    PropertyAddress::Extended { object_type, object_instance, property_id } => {
                        connection
                            .property_ext_read(object_type, object_instance, property_id, chunk_start, chunk_count)
                            .await
                    }
                };
                let chunk = result?;
                if chunk.len() != usize::from(chunk_count) * width {
                    return Err(Diagnostic::new("property response length differs from request"));
                }
                bytes.extend(chunk);
            }
        }
        Ok(bytes)
    }

    pub(super) async fn load_record(&mut self, record: &LoadRecord) -> Result<(), Diagnostic> {
        if usize::from(record.minimum_apdu()?) > self.payload_budget(0)? {
            return Err(Diagnostic::new("negotiated APDU cannot carry one atomic load record"));
        }
        if record.bytes.len() != record.write.extent.byte_length as usize {
            return Err(Diagnostic::new("load record bytes differ from the prepared extent"));
        }
        let target = self.resolve_target(&record.write.target, TransferContext::Public).await?;
        let target = self.fit_property_target(target, record.write.extent).await?;
        target.minimum_apdu(record.write.extent)?;
        let property_geometry = match target {
            OperationTarget::Property { address, start_element } => {
                Some(self.property_geometry(address, start_element, record.write.extent, true)?)
            }
            OperationTarget::Memory { service, .. } => {
                if service != MemoryService::Extended {
                    self.set_memory_verify_mode(false).await?;
                }
                None
            }
            _ => return Err(Diagnostic::new("load record target is read-only")),
        };
        self.connection_mut()?;
        // Load records are side-effecting commands, never differential writes.
        // Their status read belongs to the same authored error boundary.
        match &record.effect {
            crate::commissioning::procedure::LoadEffect::None => {}
            crate::commissioning::procedure::LoadEffect::Invalidate { location, length } => {
                self.images.invalidate_range(location, *length)
            }
            crate::commissioning::procedure::LoadEffect::InvalidateAll => self.images.forget_device(),
        }
        if let Some(geometry) = property_geometry {
            self.property_transfer(geometry, PropertyOperation::ConfirmedWrite(&record.bytes), TransferContext::Public)
                .await?;
        } else {
            self.write(
                &target,
                &record.bytes,
                record.write.extent,
                WritePolicy::NoVerification,
                TransferContext::Public,
            )
            .await?;
        }
        if let Some((read, expected)) = &record.poll {
            for attempt in 0..self.config.load_state_poll_attempts {
                let bytes = self.read(&read.target, read.extent, TransferContext::Public).await?;
                let raw = *bytes.first().ok_or_else(|| Diagnostic::new("load status is empty"))?;
                let state =
                    LoadState::try_from(raw).map_err(|_| Diagnostic::new(format!("unknown load state {raw:#04x}")))?;
                if state == *expected {
                    return Ok(());
                }
                if state == LoadState::Err {
                    return Err(self.semantic_error(
                        "load machine entered Error",
                        LoadControlCause::Symbolic("LoadStateError".into()),
                    ));
                }
                if attempt + 1 < self.config.load_state_poll_attempts {
                    tokio::time::sleep(self.config.load_state_poll_interval).await;
                }
            }
            return Err(self.semantic_error(
                format!("load machine did not reach {expected}"),
                LoadControlCause::Symbolic("LoadStateMismatch".into()),
            ));
        }
        Ok(())
    }

    /// A property element travels whole: a ten-octet load record in an
    /// extended property frame needs a 19-octet APDU, and an eight-octet
    /// element 17, more than a standard connection carries. The standard
    /// property service at the object's index is four octets shorter, so an
    /// element that does not fit the extended frame goes through the located
    /// index instead. Elements that fit keep the authored extended address.
    ///
    /// Witnesses: MV-0912 line couplers address their router load machine by
    /// object type, and MV-2920 couplers read their router object's eight-octet
    /// PID 27 by type; the reference programs both over 15-octet connections.
    async fn fit_property_target(
        &mut self,
        target: OperationTarget,
        extent: OperationExtent,
    ) -> Result<OperationTarget, Diagnostic> {
        let OperationTarget::Property {
            address: PropertyAddress::Extended { object_type, object_instance, property_id },
            start_element,
        } = target
        else {
            return Ok(target);
        };
        if usize::from(target.minimum_apdu(extent)?) <= self.payload_budget(0)? {
            return Ok(target);
        }

        let property_id = u8::try_from(property_id)
            .map_err(|_| Diagnostic::new("negotiated APDU cannot carry one property element"))?;
        let object_index = self.locate_object(u16::from(object_type), object_instance).await?;

        Ok(OperationTarget::Property { address: PropertyAddress::Indexed { object_index, property_id }, start_element })
    }

    /// Find the index of the `object_instance`-th (one-based) interface
    /// object of `object_type` by reading each object's type (PID 1) in index
    /// order. The first index without an object ends the list. Types already
    /// read stay known for the session: the object list does not change while
    /// the device is being programmed.
    ///
    /// TODO: masks that publish an interface-object list in the Device
    /// object could answer this with fewer reads; the per-index walk works on
    /// every device.
    pub(super) async fn locate_object(&mut self, object_type: u16, object_instance: u16) -> Result<u8, Diagnostic> {
        self.locate_object_with_lookup(object_type, object_instance, None).await
    }

    /// Identification precedes the whole procedure, including ordinary typed
    /// transfers before the first numeric comparison. Register these initial
    /// facts before executing any step, without reviving invalidated seeds.
    pub(super) fn seed_property_object_types(
        &mut self,
        procedure: &crate::commissioning::procedure::NormalizedProcedure,
    ) -> Result<(), Diagnostic> {
        use crate::commissioning::procedure::{DescribedPropertyAction, ProcedureOperation};
        let mut seeds = self.property_mask_object_types.clone();
        for step in &procedure.steps {
            if let ProcedureOperation::DescribedProperty(operation) = &step.operation
                && let DescribedPropertyAction::CompareRange { lookup: Some(lookup), .. } = &operation.action
            {
                for (index, seed) in &lookup.indexed {
                    if let Some(object_type) = seed.object_type
                        && let Some(previous) = seeds.insert(*index, object_type)
                        && previous != object_type
                    {
                        return Err(Diagnostic::new(format!("numeric lookup seeds disagree on object index {index}")));
                    }
                }
            }
        }
        self.property_mask_object_types = seeds;
        Ok(())
    }

    async fn locate_object_with_lookup(
        &mut self,
        object_type: u16,
        object_instance: u16,
        lookup: Option<&PropertyDataTypeLookup>,
    ) -> Result<u8, Diagnostic> {
        let mut remaining =
            object_instance.checked_sub(1).ok_or_else(|| Diagnostic::new("interface-object instance is one-based"))?;

        for index in 0..=u8::MAX {
            let known = match self.object_types.get(usize::from(index)) {
                Some(known) => *known,
                None => {
                    let seeded = self
                        .indexed_mask_seeds_active
                        .then(|| {
                            self.property_mask_object_types.get(&index).copied().or_else(|| {
                                lookup.and_then(|lookup| lookup.indexed.get(&index)).and_then(|seed| seed.object_type)
                            })
                        })
                        .flatten();
                    let known = if let Some(object_type) = seeded {
                        Some(object_type)
                    } else {
                        match self.connection_mut()?.property_read(index, pid::OBJECT_TYPE, 1, 1).await {
                            Ok(bytes) => {
                                let raw: [u8; 2] = bytes
                                    .as_slice()
                                    .try_into()
                                    .map_err(|_| Diagnostic::new("interface-object type is not two octets"))?;
                                Some(u16::from_be_bytes(raw))
                            }
                            Err(BusError::PropertyValueUnavailable { .. }) => None,
                            Err(error) => return Err(error.into()),
                        }
                    };
                    self.object_types.push(known);
                    known
                }
            };

            let Some(found) = known else {
                break;
            };
            if found == object_type {
                if remaining == 0 {
                    return Ok(index);
                }
                remaining -= 1;
            }
        }

        Err(Diagnostic::new(format!("device has no interface object of type {object_type} instance {object_instance}")))
    }

    /// Resolve a numeric control's type from the state available when it runs.
    /// Source declarations used for image allocation never populate this cache.
    pub(super) async fn numeric_property_type(
        &mut self,
        target: &OperationTarget,
        extended: bool,
        lookup: &PropertyDataTypeLookup,
    ) -> Result<u8, Diagnostic> {
        let OperationTarget::Property { address, .. } = target else {
            return Err(Diagnostic::new("numeric property lookup requires a property address"));
        };
        match *address {
            PropertyAddress::Indexed { object_index, property_id } => {
                self.numeric_indexed_property_type(object_index, property_id, lookup).await
            }
            PropertyAddress::Extended { object_type, object_instance, property_id } => {
                // Native type addressing asks well-known metadata before its
                // descriptor cache. Indexed lookup has a different priority.
                let object_type_number = u16::from(object_type);
                if let Some(pdt) = Self::well_known_property_type(lookup, Some(object_type_number)) {
                    return Ok(pdt);
                }
                if let Some(pdt) = self.declared_property_type(*address, lookup)? {
                    return Ok(pdt);
                }
                if let Some(pdt) = self.described_property_types_by_type.get(&(object_type_number, property_id)) {
                    return Ok(*pdt);
                }
                if self.initial_typed_descriptors_active
                    && let Some(pdt) = lookup.initial_descriptor
                {
                    return Ok(pdt);
                }
                if extended && self.bus.max_apdu().min(self.config.target_max_apdu) > 15 {
                    return self.described_property_type(target, extended).await;
                }
                let property_id = u8::try_from(property_id).map_err(|_| {
                    Diagnostic::new("a type-addressed property beyond PID 255 needs extended property services")
                })?;
                let object_index = self
                    .locate_object_with_lookup(object_type_number, object_instance, Some(lookup))
                    .await
                    .map_err(|mut error| {
                        error.load_control_cause = Some(LoadControlCause::ResourceNotFound);
                        error
                    })?;
                // Classic typed fallback is a complete indexed PDT lookup,
                // including any mask seed. Its result stays in indexed state.
                self.numeric_indexed_property_type(object_index, property_id, lookup).await
            }
        }
    }

    fn well_known_property_type(lookup: &PropertyDataTypeLookup, object_type: Option<u16>) -> Option<u8> {
        lookup.well_known.get(&object_type).or_else(|| lookup.well_known.get(&None)).copied().flatten()
    }

    fn declared_property_type(
        &self,
        address: PropertyAddress,
        lookup: &PropertyDataTypeLookup,
    ) -> Result<Option<u8>, Diagnostic> {
        self.property_descriptors
            .get(&address.into())
            .map(|descriptor| {
                lookup.declaration_types.get(&descriptor.property_data_type).copied().ok_or_else(|| {
                    Diagnostic::new(format!(
                        "declared property data type {:?} has no wire number",
                        descriptor.property_data_type
                    ))
                })
            })
            .transpose()
    }

    async fn numeric_indexed_property_type(
        &mut self,
        object_index: u8,
        property_id: u8,
        lookup: &PropertyDataTypeLookup,
    ) -> Result<u8, Diagnostic> {
        let seed = lookup.indexed.get(&object_index);
        if self.indexed_mask_seeds_active
            && let Some(pdt) = seed.and_then(|seed| seed.property_data_type)
        {
            return Ok(pdt);
        }
        let address = PropertyAddress::Indexed { object_index, property_id };
        if let Some(pdt) = self.declared_property_type(address, lookup)? {
            return Ok(pdt);
        }
        if let Some(pdt) = self.described_property_types.get(&(object_index, property_id)) {
            return Ok(*pdt);
        }
        if self.initial_indexed_descriptors_active
            && let Some(pdt) = seed.and_then(|seed| seed.descriptor)
        {
            return Ok(pdt);
        }
        let object_type = if property_id <= 50 {
            None
        } else if object_index == 0 {
            Some(0)
        } else {
            match self.object_types.get(usize::from(object_index)) {
                Some(object_type) => *object_type,
                None => self
                    .indexed_mask_seeds_active
                    .then(|| {
                        self.property_mask_object_types
                            .get(&object_index)
                            .copied()
                            .or_else(|| seed.and_then(|seed| seed.object_type))
                    })
                    .flatten(),
            }
        };
        if let Some(pdt) = Self::well_known_property_type(lookup, object_type) {
            return Ok(pdt);
        }
        self.described_indexed_property_type(object_index, property_id).await
    }

    /// The property data type the target describes for a property which no
    /// metadata types.
    ///
    /// An indexed property is described by object index and property ID once
    /// and kept for the session. A type-addressed one follows the reference's
    /// lookup by object type: a description already read by type; then, when
    /// the product admits extended property services (`extended`) and the
    /// connection carries more than 15 octets, an extended description read
    /// by type and instance, kept by type; otherwise the object is located
    /// and described by index. A negative response zeroes the type, element
    /// count and access levels; the property is then absent, which the
    /// reference reports as an unavailable resource.
    pub(super) async fn described_property_type(
        &mut self,
        target: &OperationTarget,
        extended: bool,
    ) -> Result<u8, Diagnostic> {
        let OperationTarget::Property { address, .. } = target else {
            return Err(Diagnostic::new("described property requires a property address"));
        };
        let (object_type, object_instance, property_id) = match *address {
            PropertyAddress::Indexed { object_index, property_id } => {
                return self.described_indexed_property_type(object_index, property_id).await;
            }
            PropertyAddress::Extended { object_type, object_instance, property_id } => {
                (object_type, object_instance, property_id)
            }
        };

        let key = (u16::from(object_type), property_id);
        if let Some(property_data_type) = self.described_property_types_by_type.get(&key) {
            return Ok(*property_data_type);
        }

        let connection_apdu = self.bus.max_apdu().min(self.config.target_max_apdu);
        if extended && connection_apdu > 15 {
            let description =
                self.connection_mut()?.property_ext_description_read(object_type, object_instance, property_id).await?;

            // TODO: The reference reports a missing extended description as
            // a device-management failure rather than an unavailable
            // resource; how a negative response maps onto that is not
            // established, so no error handler cause is attached.
            if description.pdt == 0
                && description.max_elements == 0
                && description.read_level == 0
                && description.write_level == 0
            {
                return Err(Diagnostic::new(format!(
                    "device does not describe property {property_id} on interface object type {} instance {object_instance}",
                    key.0
                )));
            }

            self.described_property_types_by_type.insert(key, description.pdt);
            return Ok(description.pdt);
        }

        // Classic property services carry a one-octet property identifier.
        let property_id = u8::try_from(property_id).map_err(|_| {
            Diagnostic::new("a type-addressed property beyond PID 255 needs extended property services")
        })?;
        let object_index = self.locate_object(key.0, object_instance).await.map_err(|mut error| {
            error.load_control_cause = Some(LoadControlCause::ResourceNotFound);
            error
        })?;
        self.described_indexed_property_type(object_index, property_id).await
    }

    async fn described_indexed_property_type(&mut self, object_index: u8, property_id: u8) -> Result<u8, Diagnostic> {
        if let Some(property_data_type) = self.described_property_types.get(&(object_index, property_id)) {
            return Ok(*property_data_type);
        }

        let description =
            self.connection_mut()?.property_description_read(object_index, u16::from(property_id), 0).await?;

        if description.pdt == 0
            && description.max_elements == 0
            && description.read_access == 0
            && description.write_access == 0
        {
            let mut error = Diagnostic::new(format!(
                "device does not describe property {property_id} on interface object {object_index}"
            ));
            error.load_control_cause = Some(LoadControlCause::ResourceNotFound);
            return Err(error);
        }

        self.described_property_types.insert((object_index, property_id), description.pdt);
        Ok(description.pdt)
    }

    /// Clear both indexed and type-addressed descriptor state, including
    /// executed declarations, when a control clears cached object types.
    pub(super) fn forget_described_property_types(&mut self) {
        self.forget_indexed_property_state();
        self.initial_typed_descriptors_active = false;
        self.property_descriptors.clear();
        self.described_property_types_by_type.clear();
    }

    /// Disconnect, including restart/reset closure, invalidates indexed state
    /// without discarding descriptors keyed only by object type.
    pub(super) fn forget_indexed_property_state(&mut self) {
        self.indexed_mask_seeds_active = false;
        self.initial_indexed_descriptors_active = false;
        self.object_types.clear();
        self.property_descriptors.retain(|key, _| matches!(key, super::DescriptorKey::ObjectType { .. }));
        self.described_property_types.clear();
    }

    pub(super) fn activate_indexed_mask_seeds(&mut self) {
        self.indexed_mask_seeds_active = true;
        // Identification replaces cached object types at the mask's indices.
        // Keep the immutable roster separate so Clear/Disconnect can disable
        // it, and only a real fresh connection can activate it again.
        for (index, object_type) in &self.property_mask_object_types {
            if let Some(cached) = self.object_types.get_mut(usize::from(*index)) {
                *cached = Some(*object_type);
            }
        }
    }

    pub(super) async fn function(&mut self, operation: &FunctionPropertyOperation) -> Result<(), Diagnostic> {
        let (address, data, command, effect) = match operation {
            FunctionPropertyOperation::Invoke { address, data, effect } => (*address, data.as_slice(), true, effect),
            FunctionPropertyOperation::ReadResult { address } => (*address, &[][..], false, &LoadEffect::None),
        };
        self.function_request(address, data, command, effect).await?;
        Ok(())
    }

    pub(crate) async fn function_request(
        &mut self,
        address: PropertyAddress,
        data: &[u8],
        command: bool,
        effect: &LoadEffect,
    ) -> Result<FunctionPropertyResult, Diagnostic> {
        let overhead = match address {
            PropertyAddress::Indexed { .. } => 3,
            PropertyAddress::Extended { .. } => 6,
        };
        if data.len() > self.payload_budget(overhead)? {
            return Err(Diagnostic::new("function payload exceeds negotiated APDU"));
        }
        self.connection_mut()?;
        match effect {
            LoadEffect::None => {}
            LoadEffect::Invalidate { location, length } => self.images.invalidate_range(location, *length),
            LoadEffect::InvalidateAll => self.images.forget_device(),
        }
        let connection = self.connection_mut()?;
        let result = match (address, command) {
            (PropertyAddress::Indexed { object_index, property_id }, true) => {
                connection.function_property_command(object_index, property_id.into(), data).await
            }
            (PropertyAddress::Indexed { object_index, property_id }, false) => {
                connection.function_property_state_read(object_index, property_id.into(), data).await
            }
            (PropertyAddress::Extended { object_type, object_instance, property_id }, true) => {
                connection.function_property_ext_command(object_type, object_instance, property_id, data).await
            }
            (PropertyAddress::Extended { object_type, object_instance, property_id }, false) => {
                connection.function_property_ext_state_read(object_type, object_instance, property_id, data).await
            }
        };
        let result = result
            .map_err(|error| if command { self.mutating_client_error(error) } else { Diagnostic::from(error) })?;
        if result.return_code != 0 {
            let mut error =
                Diagnostic::new("function property returned an error").with_device_return_code(result.return_code);
            if result.return_code == 2 {
                error = error.with_legacy_error_code(FUNCTION_PROPERTY_NOT_SUPPORTED_ERROR);
            }
            return Err(error);
        }
        if command {
            self.record_mutation();
        }
        Ok(result)
    }
}
