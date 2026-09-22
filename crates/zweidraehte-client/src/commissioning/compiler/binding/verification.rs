//! Bind final evidence reads while the selected profile and public image are available.

use crate::commissioning::catalog::profile::{ReadAccess, ResolvedProfile};
use crate::commissioning::error::CompileError;
use crate::commissioning::image::{ImageLocation, ImageSpace, SparseDeviceImage};
use crate::commissioning::procedure::OperationExtent;
use crate::commissioning::procedure::operands::{
    MemoryAddress, MemoryService, OperationTarget, ServiceRead, StandardMemoryService,
};

pub(super) fn bind(
    profile: &ResolvedProfile,
    service: StandardMemoryService,
    image: &SparseDeviceImage,
) -> Result<Vec<(ImageLocation, ServiceRead)>, CompileError> {
    let mut reads = Vec::new();
    for range in image.ranges() {
        let location = &range.location;
        let length = range.length;
        match &location.space {
            ImageSpace::StandardMemory
            | ImageSpace::UserMemory
            | ImageSpace::LineCouplerSlave
            | ImageSpace::LineCouplerFilter => {
                // These ranges come from public product memory, under the same
                // authorization as the authored memory controls. Secrets never
                // contribute ranges to this image.
                let service = match location.space {
                    ImageSpace::StandardMemory => service.for_range(location.offset, length),
                    ImageSpace::UserMemory => MemoryService::User,
                    ImageSpace::LineCouplerSlave => MemoryService::Router,
                    ImageSpace::LineCouplerFilter => MemoryService::Filter,
                    _ => unreachable!("memory space matched above"),
                };
                let target = OperationTarget::Memory { service, address: MemoryAddress::Fixed(location.offset) };
                let read = ServiceRead { target, extent: OperationExtent::bytes(length) };
                read.minimum_apdu()?;
                reads.push((location.clone(), read));
            }
            _ => {
                // A property or pointer image is not itself a readable service.
                // Bind only an exact, runtime-readable catalog declaration.
                for name in profile.resource_names() {
                    let Ok(Some(resource)) = profile.resource(name) else { continue };
                    if resource.length() != length
                        || resource.image_location().ok().flatten().as_ref() != Some(location)
                        || resource.access_rights()?.read != ReadAccess::Runtime
                    {
                        continue;
                    }
                    if let Ok(read) = resource.read(service) {
                        reads.push((location.clone(), read));
                        break;
                    }
                }
            }
        }
    }
    Ok(reads)
}
