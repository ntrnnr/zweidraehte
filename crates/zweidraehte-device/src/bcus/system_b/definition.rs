//! System B stack definition supertrait.
//!
//! [`SystemBStackDefinition`] extends [`StackDefinition`] with memory layout
//! helpers and table-size associated consts that are common to all System B
//! devices using [`SystemBMemoryMap`].

use crate::StackDefinition;
use crate::context::layer::LayerContext;
use crate::objects::tables::{
    HasAddressTable, HasApplication, HasAssociationTable, HasCommunicationObjectTable, HasLoadStateMachine,
    HasPeiApplication, HasRunStateMachine,
};
use crate::service::Augment;

use super::memory_map::{MemoryLayout, SystemBMemoryMap};
use super::objects::{DefaultSystemBInterfaceObjects, create_system_b_objects};

/// Supertrait for System B devices that use [`SystemBMemoryMap`].
///
/// Provides:
///
/// - [`ADT_SIZE`](Self::ADT_SIZE), [`AST_SIZE`](Self::AST_SIZE) and
///   [`COT_SIZE`](Self::COT_SIZE) associated consts derived from
///   [`DEVICE`](StackDefinition::DEVICE). Use with the [`Tp1StateFor`],
///   [`IpStateFor`] and [`SecureTp1StateFor`] aliases below so that
///   devices never have to restate table sizes by hand.
/// - [`memory_layout()`](Self::memory_layout) and
///   [`memory_map()`](Self::memory_map) as provided methods derived from
///   [`DEVICE`](StackDefinition::DEVICE) and `size_of::<P>()`.
///
/// Implement with an empty body to get the defaults:
///
/// ```rust,ignore
/// impl SystemBStackDefinition for MyDevice {}
/// ```
///
/// Override [`memory_layout()`](Self::memory_layout) if you need a
/// non-standard base address or custom layout calculation.
pub trait SystemBStackDefinition: StackDefinition<Mem = SystemBMemoryMap> {
    /// Address-table capacity, derived from
    /// [`DEVICE`](StackDefinition::DEVICE).
    const ADT_SIZE: usize = Self::DEVICE.address_table_size();

    /// Association-table capacity, derived from
    /// [`DEVICE`](StackDefinition::DEVICE).
    const AST_SIZE: usize = Self::DEVICE.association_table_size();

    /// Communication-object table capacity, derived from
    /// [`DEVICE`](StackDefinition::DEVICE).
    const COT_SIZE: usize = Self::DEVICE.comm_object_table_size();

    /// Compute the memory layout for this device's tables.
    ///
    /// Derives all table offsets and sizes from
    /// [`DEVICE`](StackDefinition::DEVICE) and `size_of::<P>()`.
    fn memory_layout() -> MemoryLayout {
        MemoryLayout::from_descriptor(
            SystemBMemoryMap::DEFAULT_BASE_ADDRESS,
            Self::DEVICE,
            core::mem::size_of::<Self::P>(),
        )
    }

    /// Compute the memory map for this device.
    ///
    /// Pass to [`zweidraehte_device::new()`](crate::new).
    fn memory_map() -> SystemBMemoryMap {
        SystemBMemoryMap::new(Self::memory_layout())
    }

    /// Build the standard System B interface-object container from
    /// [`DEVICE`](StackDefinition::DEVICE), [`memory_layout()`](Self::memory_layout),
    /// and the augment chain.
    ///
    /// Use as the body of
    /// [`StackDefinition::create_interface_objects`](crate::StackDefinition::create_interface_objects)
    /// when `Self::InterfaceObjects<'a>` is the standard
    /// [`SystemBInterfaceObjectsFor<'a, Self>`](super::SystemBInterfaceObjectsFor).
    /// Each device's `create_interface_objects` body collapses to:
    ///
    /// ```rust,ignore
    /// fn create_interface_objects<'a>(state, platform, layer_ctx, augments)
    ///     -> Self::InterfaceObjects<'a>
    /// where Self::State: 'a, Self::Platform: 'a
    /// {
    ///     Self::default_interface_objects(state, platform, layer_ctx, augments)
    /// }
    /// ```
    ///
    /// `Rust trait method defaults can't be inherited from a supertrait
    /// (i.e. `SystemBStackDefinition` can't provide the body for
    /// `StackDefinition::create_interface_objects` directly), so devices
    /// still write the trait-method shell. The body is one canonical
    /// call, with all the bounds and helper logic centralised here.
    ///
    /// `Into<Self::InterfaceObjects<'a>>` lets devices that pin
    /// `InterfaceObjects` to a wrapper type still use this helper if
    /// they provide a `From` impl for the wrapper.
    fn default_interface_objects<'a>(
        state: &'a Self::State,
        _platform: &'a Self::Platform,
        layer_ctx: &'a LayerContext<Self>,
        augments: &'a Self::Augments<'a>,
    ) -> Self::InterfaceObjects<'a>
    where
        Self::State: 'a,
        Self::Platform: 'a,
        Self::State: HasPeiApplication,
        <Self::State as HasAddressTable>::ADT: HasLoadStateMachine,
        <Self::State as HasAssociationTable>::AST: HasLoadStateMachine,
        <Self::State as HasCommunicationObjectTable>::COT: HasLoadStateMachine,
        <Self::State as HasApplication>::APP: HasLoadStateMachine + HasRunStateMachine,
        <Self::State as HasPeiApplication>::PEI: HasLoadStateMachine + HasRunStateMachine,
        Self::Augments<'a>: Augment<Self>,
        DefaultSystemBInterfaceObjects<'a, Self, Self::Augments<'a>>: Into<Self::InterfaceObjects<'a>>,
    {
        create_system_b_objects::<Self, _>(state, layer_ctx, &Self::memory_layout(), augments).into()
    }
}

// ============================================================================
// State type aliases
// ============================================================================
//
// These aliases project the table-size consts off `SystemBStackDefinition`
// into the shape expected by the underlying `SystemBDeviceState` aliases
// (`Tp1SystemBDeviceState`, `IpDeviceState`, `SecureTp1DeviceState`). They
// require `generic_const_exprs` (already enabled crate-wide) to push the
// associated const `D::ADT_SIZE` etc. into a type-level position.
//
// Users write:
//
// ```rust,ignore
// type State = Tp1StateFor<MyStack>;
// // instead of
// const ADT_SIZE: usize = DEVICE_DESCRIPTOR.address_table_size();
// const AST_SIZE: usize = DEVICE_DESCRIPTOR.association_table_size();
// const COT_SIZE: usize = DEVICE_DESCRIPTOR.comm_object_table_size();
// type State = Tp1SystemBDeviceState<ADT_SIZE, AST_SIZE, COT_SIZE, MyStack>;
// ```

/// TP1 System B state for `D`, with sizes drawn from `D::DEVICE`.
pub type Tp1StateFor<D>
where
    D: SystemBStackDefinition,
= super::extensions::Tp1SystemBDeviceState<
    { <D as SystemBStackDefinition>::ADT_SIZE },
    { <D as SystemBStackDefinition>::AST_SIZE },
    { <D as SystemBStackDefinition>::COT_SIZE },
    D,
>;

/// KNX-RF System B state for `D`, with sizes drawn from `D::DEVICE`. Pairs the
/// device with [`RfExtensionState`](super::extensions::RfExtensionState) (the RF
/// Medium Object + Domain Address store) for use with the KNX-RF link layer.
pub type RfStateFor<D>
where
    D: SystemBStackDefinition,
= super::extensions::RfSystemBDeviceState<
    { <D as SystemBStackDefinition>::ADT_SIZE },
    { <D as SystemBStackDefinition>::AST_SIZE },
    { <D as SystemBStackDefinition>::COT_SIZE },
    D,
>;

/// KNX/IP System B state for `D` using feature set `Proto`, with sizes
/// drawn from `D::DEVICE`.
#[cfg(feature = "knxip")]
pub type IpStateFor<D, Proto>
where
    D: SystemBStackDefinition,
= super::extensions::IpDeviceState<
    { <D as SystemBStackDefinition>::ADT_SIZE },
    { <D as SystemBStackDefinition>::AST_SIZE },
    { <D as SystemBStackDefinition>::COT_SIZE },
    D,
    Proto,
>;

/// KNX/IP System B state for tunnelling-capable `D` using feature set
/// `Proto`, with sizes drawn from `D::DEVICE`. Pairs `IpExtensionState`
/// with [`TunnellingExtension`](super::extensions::TunnellingExtension);
/// the resulting `ES` is
/// [`IpInterfaceExtension`](super::extensions::IpInterfaceExtension).
#[cfg(feature = "knxip")]
pub type IpInterfaceStateFor<D, Proto>
where
    D: SystemBStackDefinition,
= super::extensions::IpInterfaceDeviceState<
    { <D as SystemBStackDefinition>::ADT_SIZE },
    { <D as SystemBStackDefinition>::AST_SIZE },
    { <D as SystemBStackDefinition>::COT_SIZE },
    D,
    Proto,
>;

/// Secure TP1 System B state for `D` with sequence-number storage `SEQ`,
/// P2P Key Table capacity `P2P`, and SIAT capacity `SIAT`.
///
/// `P2P` and `SIAT` are independent per 03/03/07 §5.3: the SIAT holds
/// LastValidSeqNr for every non-tool secure sender — P2P partners *and*
/// pure group-secure senders — while the P2P Key Table only holds
/// entries for devices we have a secure P2P link with. A group-only
/// secure device typically has `P2P = 0` and `SIAT > 0`. Table sizes
/// ADT / AST / COT are drawn from `D::DEVICE`.
///
/// # The Data Secure table-size invariant lives here
///
/// All four secure `*StateFor` aliases delegate to [`SecureStateFor`], which
/// is the *one* place that maps the security table sizes to the device's other
/// tables: the group key table is keyed by GA index (`GRP = ADT_SIZE`) and the
/// GO security flags table has one entry per communication object
/// (`GO = COT_SIZE`). Adding a new secure medium is therefore a one-line alias
/// over `SecureStateFor` with the right inner extension — no need to restate
/// the invariant.
pub type SecureTp1StateFor<D, SEQ, const P2P: usize, const SIAT: usize>
where
    D: SystemBStackDefinition,
= SecureStateFor<D, super::extensions::Tp1ExtensionState, SEQ, P2P, SIAT>;

/// KNX-RF Data Secure System B state for `D`. The RF analogue of
/// [`SecureTp1StateFor`]; pairs [`RfExtensionState`](super::extensions::RfExtensionState)
/// with the Data Secure wrapper. See [`SecureTp1StateFor`] for the `P2P`/`SIAT`
/// sizing rationale (03/03/07 §5.3).
pub type SecureRfStateFor<D, SEQ, const P2P: usize, const SIAT: usize>
where
    D: SystemBStackDefinition,
= SecureStateFor<D, super::extensions::RfExtensionState, SEQ, P2P, SIAT>;

/// KNX-RF **retransmitter** Data Secure System B state for `D`. As
/// [`SecureRfStateFor`], but the RF medium extension is wrapped in
/// [`RfRetransmitterExtension`](super::extensions::RfRetransmitterExtension),
/// adding the PID 57 / PID 74 retransmitter surface. Pair it with
/// `type LLB = KnxRfLinkLayerBuilder<Radio, RetransmitEnabled>`.
pub type SecureRfRetransmitterStateFor<D, SEQ, const P2P: usize, const SIAT: usize>
where
    D: SystemBStackDefinition,
= SecureStateFor<D, super::extensions::RfRetransmitterExtension, SEQ, P2P, SIAT>;

/// KNX/IP Data Secure System B state for `D` using capability flags `CAPS`.
/// The KNX/IP analogue of [`SecureTp1StateFor`]; pairs
/// [`IpExtensionState`](super::extensions::IpExtensionState) with the Data
/// Secure wrapper. (Tunnelling-capable secure devices wrap
/// [`IpInterfaceExtension`](super::extensions::IpInterfaceExtension) and use
/// [`SecureStateFor`] directly with that inner type.)
#[cfg(feature = "knxip")]
pub type SecureIpStateFor<D, SEQ, const CAPS: u16, const P2P: usize, const SIAT: usize>
where
    D: SystemBStackDefinition,
= SecureStateFor<D, super::extensions::IpExtensionState<CAPS>, SEQ, P2P, SIAT>;

/// Generic Data Secure System B state for `D` wrapping an arbitrary inner
/// medium extension `Inner`.
///
/// This is the single home of the Data Secure table-size invariant
/// (`GRP = ADT_SIZE`, `GO = COT_SIZE`) and the ADT/AST/COT projection off
/// `D::DEVICE`. The medium-specific aliases ([`SecureTp1StateFor`],
/// [`SecureRfStateFor`], [`SecureRfRetransmitterStateFor`],
/// [`SecureIpStateFor`]) are thin wrappers that fix `Inner`; a future secure
/// medium only needs to add one such wrapper (or use this alias directly).
pub type SecureStateFor<D, Inner, SEQ, const P2P: usize, const SIAT: usize>
where
    D: SystemBStackDefinition,
    Inner: super::ExtensionState,
= super::SystemBDeviceState<
    { <D as SystemBStackDefinition>::ADT_SIZE },
    { <D as SystemBStackDefinition>::AST_SIZE },
    { <D as SystemBStackDefinition>::COT_SIZE },
    D,
    super::extensions::SecureExtensionState<
        Inner,
        SEQ,
        { <D as SystemBStackDefinition>::ADT_SIZE },
        P2P,
        SIAT,
        { <D as SystemBStackDefinition>::COT_SIZE },
    >,
>;

// ============================================================================
// Augment type alias
// ============================================================================

/// The augment type produced by `D`'s extension state.
///
/// Every device's augment chain begins with the augment its `type ES`
/// extension creates (the Security IO + medium object for secure devices, the
/// RF Medium Object for plain RF devices, etc.). Naming that type used to
/// require each device to hand-write the projection
///
/// ```rust,ignore
/// type SecAugment<'a> =
///     <<Self as StackDefinition>::ES as Extension<()>>::Augment<'a, Self>;
/// ```
///
/// This alias replaces that incantation. Devices write the augment field as
/// `sec: ExtensionAugmentFor<'a, Self>` in their
/// [`#[derive(ServiceRegistry)]`](crate::service::ServiceRegistry) augment
/// bundle. Unlike the hand-written version it threads
/// [`D::Platform`](StackDefinition::Platform) rather than hard-coding `()`, so
/// it is correct for IP-platform secure devices too.
pub type ExtensionAugmentFor<'a, D>
where
    D: StackDefinition,
= <<D as StackDefinition>::ES as super::Extension<<D as StackDefinition>::Platform>>::Augment<'a, D>;
