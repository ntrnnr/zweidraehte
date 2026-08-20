//! System 7 stack definition supertrait and the standard-stack macro.
//!
//! [`System7StackDefinition`] extends [`StackDefinition`] with the
//! System 7 table-size consts and the interface-object helper;
//! [`system_7_standard_stack!`](crate::system_7_standard_stack)
//! collapses the always-identical half of a device's `StackDefinition`
//! impl, mirroring `system_b_standard_stack!`.

use crate::StackDefinition;
use crate::context::layer::LayerContext;
use crate::objects::tables::{
    HasAddressTable, HasApplication, HasAssociationTable, HasLoadStateMachine, HasPeiApplication, HasRunStateMachine,
};
use crate::service::Augment;

use super::memory_map::System7MemoryMap;
use super::objects::{DefaultSystem7InterfaceObjects, create_system_7_objects};

/// The augment type produced by `D`'s extension state — same projection
/// as System B's alias of the same name, re-exported here so the
/// System 7 macro and devices stay within their family's namespace.
pub use crate::bcus::system_b::ExtensionAugmentFor;

/// The product-defined memory placements a System 7 device must know
/// about itself.
///
/// On System 7 the group object table has no device-side location
/// resource: the ETS master data locates `MV-0705`'s `GroupObjectTable`
/// with `AddressSpace="None"`, and ETS takes the address purely from
/// the product database's `ComObjectTable` segment binding. The device
/// firmware and the product database come from the same device
/// definition, so the address is a compile-time constant here — the
/// same shape as the address table's fixed 4000h, just
/// per-product. [`System7MemoryMap`] serves the group-object-table
/// window at this address unconditionally; the table's load lifecycle
/// rides on the Application Program's load state machine, which is why
/// no allocation record ever names the table itself.
pub trait System7ProductLayout {
    /// Where the product database places the group object table.
    const COT_ADDRESS: u16;
}

/// Supertrait for System 7 devices that use [`System7MemoryMap`].
///
/// Provides the System 7 table sizes derived from
/// [`DEVICE`](StackDefinition::DEVICE) (the byte formulas differ from
/// System B: System 7 tables carry 1-octet size fields and the address table
/// embeds the individual address) and the standard interface-object
/// helper. Implement with an empty body:
///
/// ```rust,ignore
/// impl System7StackDefinition for MyDevice {}
/// ```
pub trait System7StackDefinition: StackDefinition<Mem = System7MemoryMap> + System7ProductLayout {
    /// RT8-coded address table byte size: 1-octet length + 2-octet IA +
    /// 2 octets per group address.
    const ADT_SIZE: usize = 3 + Self::DEVICE.max_address_table_entries as usize * 2;

    /// System 7 association table byte size: 1-octet count + 2 octets
    /// per entry (TSAP u8 + ASAP u8).
    const AST_SIZE: usize = 1 + Self::DEVICE.max_association_table_entries as usize * 2;

    /// Group object table byte size in the System 7 memory format ETS's
    /// System 7 formatter writes: 3-octet header (count + RAM-flags
    /// pointer) plus one 4-octet entry per ASAP `0..=max`. The table is
    /// indexed directly by ASAP, so the highest ASAP is
    /// `FIRST_ASAP + max_com_objects - 1` and the entry span covers
    /// `FIRST_ASAP + max_com_objects` slots. Products have
    /// `FIRST_ASAP = 0`; the formula must agree with the
    /// `system7_stack_config!` COT layout (a mismatch fails to compile
    /// as an array-size conflict in `Tp1StateFor7`).
    const COT_SIZE: usize = 3 + (Self::FIRST_ASAP as usize + Self::DEVICE.max_com_objects as usize) * 4;

    /// Number of address-table entries (group addresses).
    const ADT_ENTRIES: usize = Self::DEVICE.max_address_table_entries as usize;

    /// Number of communication objects.
    const COT_ENTRIES: usize = Self::DEVICE.max_com_objects as usize;

    /// The (stateless) memory map. Pass to
    /// [`zweidraehte_device::new()`](crate::new).
    fn memory_map() -> System7MemoryMap {
        System7MemoryMap::new()
    }

    /// Build the standard System 7 interface-object container; the
    /// canonical body of `StackDefinition::create_interface_objects`
    /// (which Rust cannot inherit from a supertrait — see the System B
    /// twin for the rationale).
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
        <Self::State as HasApplication>::APP: HasLoadStateMachine + HasRunStateMachine,
        <Self::State as HasPeiApplication>::PEI: HasLoadStateMachine + HasRunStateMachine,
        Self::Augments<'a>: Augment<Self>,
        DefaultSystem7InterfaceObjects<'a, Self, Self::Augments<'a>>: Into<Self::InterfaceObjects<'a>>,
    {
        create_system_7_objects::<Self, _>(state, layer_ctx, augments).into()
    }
}

/// TP1 System 7 state for `D`, with sizes drawn from `D::DEVICE`.
pub type Tp1StateFor7<D>
where
    D: System7StackDefinition,
= super::System7DeviceState<
    { <D as System7StackDefinition>::ADT_SIZE },
    { <D as System7StackDefinition>::AST_SIZE },
    { <D as System7StackDefinition>::COT_SIZE },
    D,
    super::extensions::Tp1ExtensionState,
>;

/// System 7 state with KNX Data Secure, wrapping the medium extension
/// `Inner`.
///
/// The System 7 twin of
/// [`SecureStateFor`](crate::bcus::system_b::SecureStateFor), and the
/// single place the Data Secure table-capacity invariant is stated for
/// this family: `GRP = ADT_ENTRIES` — one group key slot per address
/// table entry — and `GO = COT_ENTRIES` — one security-flag byte per
/// communication object, the positional table of 03/05/01 §6.3.15.
///
/// `P2P` sizes the Point-to-point Key Table, which is `C` rather than
/// `M` (06 Profiles v02.02.01 §9.1.2.6.4 footnote c: only mandatory when
/// P2P communication uses a key other than the Tool Key or FDSK), so a
/// group-only device passes 0. The Security Individual Address Table is
/// not a parameter here at all — its capacity is the `N` of the
/// [`SiatStore`](crate::storage::views::SiatStore) behind the device's
/// sequence store.
pub type SecureStateFor7<D, Inner, const P2P: usize>
where
    D: System7StackDefinition,
    Inner: crate::extension::ExtensionState,
= super::System7DeviceState<
    { <D as System7StackDefinition>::ADT_SIZE },
    { <D as System7StackDefinition>::AST_SIZE },
    { <D as System7StackDefinition>::COT_SIZE },
    D,
    crate::security::SecureExtensionState<
        Inner,
        { <D as System7StackDefinition>::ADT_ENTRIES },
        P2P,
        { <D as System7StackDefinition>::COT_ENTRIES },
    >,
>;

/// TP1 System 7 state with KNX Data Secure — the secure twin of
/// [`Tp1StateFor7`].
pub type SecureTp1StateFor7<D, const P2P: usize> = SecureStateFor7<D, super::extensions::Tp1ExtensionState, P2P>;

// ============================================================================
// system_7_standard_stack! — collapse the always-identical StackDefinition shell
// ============================================================================

/// Generate the boilerplate half of a System 7 device's
/// [`StackDefinition`](crate::StackDefinition) impl.
///
/// The System 7 twin of
/// [`system_b_standard_stack!`](crate::system_b_standard_stack): same
/// slots, same semantics, but pinning the family types
/// (`System7MemoryMap`, `System7StateInit`, `System7InterfaceObjectsFor`,
/// `System7DeviceModel`). Security remains an explicit composition choice:
/// secure devices supply the secure extension, resources, services, and
/// builder through the existing slots.
#[macro_export]
macro_rules! system_7_standard_stack {
    (
        stack: $stack:ty,
        device: $device:expr,
        cot_address: $cot_address:expr,
        params: $params:ty,
        com_objects: $com_objects:ty,
        link_layer_builder: $llb:ty,
        platform: $platform:ty,
        extension_state: $es:ty,
        state: $state:ty,
        al_extensions: $al_extensions:ty,
        layer_builder: $layer_builder:ty
        $(, resources: $resources:ty)?
        $(, augments: {
            bundle: $aug_bundle:ident,
            create: |$aug_state:ident, $aug_platform:ident, $aug_lctx:ident| $aug_body:expr $(,)?
        })?
        $(, extra { $($extra:item)* })?
        $(,)?
    ) => {
        impl $crate::bcus::system_7::System7ProductLayout for $stack {
            const COT_ADDRESS: u16 = $cot_address;
        }

        impl $crate::bcus::system_7::System7StackDefinition for $stack {}

        impl $crate::StackDefinition for $stack {
            // ---- device-specific bill of materials -------------------------
            const DEVICE: &'static $crate::__macro_support::device::DeviceDescriptor = $device;
            // Profiles v02.02.01 §4.1.2 mandates Style 3 for the
            // System 7 profile containing mask 0705h.
            const TL_STYLE: $crate::layers::transport::TlStyle =
                $crate::layers::transport::TlStyle::Style3;
            // System 7 numbers communication objects from 0; unlike RT7,
            // its group object table can represent ASAP 0.
            const FIRST_ASAP: u16 = 0;

            type P = $params;
            type CO = $com_objects;
            type LLB = $llb;
            type Platform = $platform;
            type ES = $es;
            type State = $state;
            type AlExtensions = $al_extensions;
            type LayerBuilder = $layer_builder;

            // ---- always-identical shell ------------------------------------
            type Mem = $crate::bcus::system_7::System7MemoryMap;
            type StateInit = $crate::bcus::system_7::System7StateInit<
                Self::Identity,
                <$state as $crate::storage::HasDeviceConfig>::Config
                $(, $resources)?
            >;

            fn create_state(init: Self::StateInit) -> Self::State {
                <$state>::from_init(init)
            }

            type InterfaceObjects<'a> = $crate::bcus::system_7::System7InterfaceObjectsFor<'a, Self>;

            fn create_interface_objects<'a>(
                state: &'a Self::State,
                platform: &'a Self::Platform,
                layer_ctx: &'a $crate::context::layer::LayerContext<Self>,
                augments: &'a Self::Augments<'a>,
            ) -> Self::InterfaceObjects<'a>
            where
                Self::State: 'a,
                Self::Platform: 'a,
            {
                <Self as $crate::bcus::system_7::System7StackDefinition>::default_interface_objects(
                    state, platform, layer_ctx, augments,
                )
            }

            type DeviceModel<'a> = $crate::bcus::system_7::System7DeviceModel<'a, Self>;

            fn create_device_model<'a>(
                state: &'a Self::State,
                layer_context: &'a $crate::context::layer::LayerContext<Self>,
                interface_objects: &'a Self::InterfaceObjects<'static>,
            ) -> Self::DeviceModel<'a>
            where
                Self::State: 'a,
            {
                $crate::bcus::system_7::System7DeviceModel::new(state, layer_context, interface_objects)
            }

            $crate::system_7_standard_stack!(@augments $es $(, {
                bundle: $aug_bundle,
                create: |$aug_state, $aug_platform, $aug_lctx| $aug_body
            })?);

            $($($extra)*)?
        }
    };

    // ---- internal: default single-extension augment chain ----------------
    (@augments $es:ty) => {
        type Augments<'a> = $crate::bcus::system_7::ExtensionAugmentFor<'a, Self>;

        fn create_augments<'a>(
            state: &'a Self::State,
            platform: &'a Self::Platform,
            _layer_ctx: &'a $crate::context::layer::LayerContext<Self>,
        ) -> Self::Augments<'a>
        where
            Self::State: 'a,
            Self::Platform: 'a,
        {
            let es = <Self::State as $crate::HasExtensionState>::extension_state(state);
            <$es as $crate::extension::Extension<Self::Platform>>::create_augment::<Self>(es, platform)
        }
    };

    // ---- internal: caller-supplied augment bundle -------------------------
    (@augments $es:ty, {
        bundle: $aug_bundle:ident,
        create: |$aug_state:ident, $aug_platform:ident, $aug_lctx:ident| $aug_body:expr
    }) => {
        type Augments<'a> = $aug_bundle<'a>;

        fn create_augments<'a>(
            state: &'a Self::State,
            platform: &'a Self::Platform,
            layer_ctx: &'a $crate::context::layer::LayerContext<Self>,
        ) -> Self::Augments<'a>
        where
            Self::State: 'a,
            Self::Platform: 'a,
        {
            let $aug_state = state;
            let $aug_platform = platform;
            let $aug_lctx = layer_ctx;
            $aug_body
        }
    };
}
