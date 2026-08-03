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

    /// Number of address-table entries (group addresses), derived from
    /// [`DEVICE`](StackDefinition::DEVICE).
    ///
    /// This is an **entry count**, unlike [`ADT_SIZE`](Self::ADT_SIZE)
    /// which is the table's byte length. Use it for per-entry
    /// capacities such as the Data Secure group key table (`GRP`).
    const ADT_ENTRIES: usize = Self::DEVICE.max_address_table_entries as usize;

    /// Number of communication objects, derived from
    /// [`DEVICE`](StackDefinition::DEVICE).
    ///
    /// This is an **entry count**, unlike [`COT_SIZE`](Self::COT_SIZE)
    /// which is the table's byte length. Use it for per-entry
    /// capacities such as the Data Secure GO security flags table
    /// (`GO`).
    const COT_ENTRIES: usize = Self::DEVICE.max_com_objects as usize;

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
pub type SecureTp1StateFor<D, const P2P: usize>
where
    D: SystemBStackDefinition,
= SecureStateFor<D, super::extensions::Tp1ExtensionState, P2P>;

/// KNX-RF Data Secure System B state for `D`. The RF analogue of
/// [`SecureTp1StateFor`]; pairs [`RfExtensionState`](super::extensions::RfExtensionState)
/// with the Data Secure wrapper. See [`SecureTp1StateFor`] for the `P2P`/`SIAT`
/// sizing rationale (03/03/07 §5.3).
pub type SecureRfStateFor<D, const P2P: usize>
where
    D: SystemBStackDefinition,
= SecureStateFor<D, super::extensions::RfExtensionState, P2P>;

/// KNX-RF **retransmitter** Data Secure System B state for `D`. As
/// [`SecureRfStateFor`], but the RF medium extension is wrapped in
/// [`RfRetransmitterExtension`](super::extensions::RfRetransmitterExtension),
/// adding the PID 57 / PID 74 retransmitter surface. Pair it with
/// `type LLB = KnxRfLinkLayerBuilder<Radio, RetransmitEnabled>`.
pub type SecureRfRetransmitterStateFor<D, const P2P: usize>
where
    D: SystemBStackDefinition,
= SecureStateFor<D, super::extensions::RfRetransmitterExtension, P2P>;

/// KNX/IP Data Secure System B state for `D` using capability flags `CAPS`.
/// KNX/IP **Secure-interface** Data Secure System B state for `D` — the state
/// shape for a device that combines KNX IP Secure (secure routing / secure
/// tunnelling, PIDs 91–97 + tunnelling-user table) **and** KNX Data Secure
/// (encrypted group telegrams).
///
/// It wraps the IP **Secure** interface extension
/// [`IpSecureInterfaceExtensionFor`](super::extensions::IpSecureInterfaceExtensionFor)
/// (itself `IpInterfaceExtension` + the IP Secure secrets) as the `Inner` of
/// the Data Secure wrapper, realising the composition documented on
/// [`IpSecureInterfaceExtension`](super::extensions::IpSecureInterfaceExtension):
/// `SecureExtensionState<IpSecureInterfaceExtension<...>, SEQ, ...>`.
///
/// `F` is the KNX/IP [`FeatureSet`](crate::layers::linklayers::knxip::features::FeatureSet)
/// (it fixes the tunnelling capacity and KNXnet/IP device capabilities);
/// `MAX_PW` / `MAX_TU` size the IP Secure password-hash and tunnelling-user
/// tables; `P2P` sizes the Data Secure P2P key table. The Security Individual
/// Address Table is sized by the `N` of the [`SiatStore`](crate::storage::views::SiatStore)
/// chosen for `SEQ`, not a const here (see [`SecureTp1StateFor`] for the
/// 03/03/07 §5.3 rationale). Pair it with
/// `type LayerBuilder = SecureIpDeviceBuilder` and
/// `resources: SecureResources<IpSecureInterfaceExtensionFor<F, MAX_PW, MAX_TU>>`.
#[cfg(feature = "ip-secure")]
pub type SecureIpInterfaceStateFor<D, F, const P2P: usize, const MAX_PW: usize, const MAX_TU: usize>
where
    D: SystemBStackDefinition,
    F: crate::layers::linklayers::knxip::features::FeatureSet,
= SecureStateFor<D, super::extensions::IpSecureInterfaceExtensionFor<F, MAX_PW, MAX_TU>, P2P>;

/// Generic Data Secure System B state for `D` wrapping an arbitrary inner
/// medium extension `Inner`.
///
/// This is the single home of the Data Secure table-size invariant
/// (`GRP = ADT_ENTRIES`: one group key slot per address table entry,
/// `GO = COT_ENTRIES`: one flag byte per communication object) and the
/// ADT/AST/COT projection off `D::DEVICE`. The medium-specific aliases
/// ([`SecureTp1StateFor`], [`SecureRfStateFor`],
/// [`SecureRfRetransmitterStateFor`], [`SecureIpInterfaceStateFor`]) are thin
/// wrappers that fix `Inner`; a future secure medium only needs to add
/// one such wrapper (or use this alias directly).
pub type SecureStateFor<D, Inner, const P2P: usize>
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
        { <D as SystemBStackDefinition>::ADT_ENTRIES },
        P2P,
        { <D as SystemBStackDefinition>::COT_ENTRIES },
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
pub type ExtensionAugmentFor<'a, D> =
    <<D as StackDefinition>::ES as super::Extension<<D as StackDefinition>::Platform>>::Augment<'a, D>;

// ============================================================================
// system_b_standard_stack! — collapse the always-identical StackDefinition shell
// ============================================================================

/// Generate the boilerplate half of a System B device's
/// [`StackDefinition`](crate::StackDefinition) impl.
///
/// Every standard System B device (`SystemBStackDefinition` +
/// `SystemBMemoryMap` + the `ExtensionAugmentFor` augment chain) repeats the
/// same shell: the `StateInit`/`Mem` types, the one-line `create_state`, the
/// `InterfaceObjects`/`Augments` GATs, and the two `create_*` method bodies
/// (which Rust can't inherit from the `SystemBStackDefinition` supertrait —
/// see [`SystemBStackDefinition::default_interface_objects`]). Only the
/// device-specific bill of materials varies. This macro takes that BOM and
/// emits the full `impl StackDefinition` (plus the empty
/// `impl SystemBStackDefinition`), so a device's stack wiring collapses to one
/// invocation.
///
/// It is **opt-in**: a device with a custom augment bundle or a non-standard
/// `InterfaceObjects` wrapper should keep writing the impl by hand. Defaulted
/// `StackDefinition` items not listed below (`Identity`, `Rng`, `Mutex`,
/// `MAX_APDU_LENGTH`, …) take their trait defaults; override them in the
/// optional `extra { … }` block, whose items are spliced into the generated
/// `impl StackDefinition` verbatim. Only items that the macro does **not**
/// already generate may appear in `extra { … }` — duplicates cause a Rust
/// compile error. The macro always generates `Augments`, `create_augments`,
/// `InterfaceObjects`, `create_interface_objects`, `Mem`, `StateInit`, and
/// `create_state`.
///
/// # Optional slots
///
/// - `resources: <type>` — third parameter of the generated
///   `SystemBStateInit` (e.g. `SecureResources<Tp1ExtensionState, MySeq>`
///   for Data Secure devices). Defaults to `()` when absent.
/// - `augments: { bundle: <ident>, create: |state, platform, layer_ctx| <expr> }`
///   — use a custom (usually `#[derive(ServiceRegistry)]`) augment bundle
///   instead of the single-extension default. `bundle` is the bundle's
///   type *name* (it must be generic over exactly one lifetime; the macro
///   applies `<'a>` itself — a lifetime inside a captured type would not
///   resolve across macro hygiene). The three closure-style idents bind
///   `&'a Self::State`, `&'a Self::Platform`, and
///   `&'a LayerContext<Self>` for use in the body expression; name an
///   ident `_layer_ctx` (etc.) if unused. The extension's own augment is
///   typically built in the body via
///   `state.extension_state().create_augment::<Self>(platform)`.
///
/// Both slots, when present, must appear after `layer_builder` and before
/// `extra { … }`, in the order `resources`, then `augments`.
///
/// # Limitations: items that require hand-writing `StackDefinition`
///
/// - **Non-standard `InterfaceObjects` wrapper** — the macro pins
///   `InterfaceObjects<'a>` to `SystemBInterfaceObjectsFor<'a, Self>`.
/// - **Custom `Mem`, `State` newtype init, or `StateInit` shape** — the
///   macro pins `Mem = SystemBMemoryMap`, `StateInit = SystemBStateInit`
///   and `create_state = from_init`. The conformance DUTs (custom memory
///   map + state newtype) are the canonical hand-written examples.
///
/// ```rust,ignore
/// system_b_standard_stack! {
///     stack: DemoStack,
///     device: &DEVICE_DESCRIPTOR,
///     tl_style: TlStyle::Style3,
///     params: DemoParams,
///     com_objects: comm_objs::DemoComObjects,
///     link_layer_builder: KnxNetIpBuilder<DemoStack>,
///     platform: LinuxIpPlatform,
///     extension_state: IpExtensionFor<KnxIpDeviceTcp>,
///     state: DemoState,
///     al_extensions: (SystemBAlServices, DomainAddressService),
///     layer_builder: PlainIpDeviceBuilder,
///     augments: {
///         bundle: DemoAugments,
///         create: |state, platform, _layer_ctx| DemoAugments {
///             ip: state.extension_state().create_augment::<Self>(platform),
///             easter: EasterEggAugment,
///         },
///     },
/// }
/// ```
#[macro_export]
macro_rules! system_b_standard_stack {
    (
        stack: $stack:ty,
        device: $device:expr,
        tl_style: $tl_style:expr,
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
        impl $crate::bcus::system_b::SystemBStackDefinition for $stack {}

        impl $crate::StackDefinition for $stack {
            // ---- device-specific bill of materials -------------------------
            const DEVICE: &'static $crate::ets::DeviceDescriptor = $device;
            const TL_STYLE: $crate::layers::transport::TlStyle = $tl_style;
            // System B numbers communication objects from 1 — the
            // RealizationType-7 CO table cannot express ASAP 0.
            const FIRST_ASAP: u16 = 1;

            type P = $params;
            type CO = $com_objects;
            type LLB = $llb;
            type Platform = $platform;
            type ES = $es;
            type State = $state;
            type AlExtensions = $al_extensions;
            type LayerBuilder = $layer_builder;

            // ---- always-identical shell ------------------------------------
            type Mem = $crate::bcus::system_b::SystemBMemoryMap;
            // The config type is always derivable as `<State as HasDeviceConfig>::Config`,
            // so we project it here rather than requiring callers to spell it out.
            // The optional `resources:` slot becomes the third parameter
            // (construction-time resources, `()` when absent).
            type StateInit = $crate::bcus::system_b::SystemBStateInit<
                Self::Identity,
                <$state as $crate::storage::HasDeviceConfig>::Config
                $(, $resources)?
            >;

            fn create_state(init: Self::StateInit) -> Self::State {
                <$state>::from_init(init)
            }

            type InterfaceObjects<'a> = $crate::bcus::system_b::SystemBInterfaceObjectsFor<'a, Self>;

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
                <Self as $crate::bcus::system_b::SystemBStackDefinition>::default_interface_objects(
                    state, platform, layer_ctx, augments,
                )
            }

            // The System B device model and its constructor. `StackDefinition`
            // is BCU-agnostic (no default), so both are named here.
            type DeviceModel<'a> = $crate::bcus::system_b::SystemBDeviceModel<'a, Self>;

            fn create_device_model<'a>(
                state: &'a Self::State,
                layer_context: &'a $crate::context::layer::LayerContext<Self>,
                interface_objects: &'a Self::InterfaceObjects<'static>,
            ) -> Self::DeviceModel<'a>
            where
                Self::State: 'a,
            {
                $crate::bcus::system_b::SystemBDeviceModel::new(state, layer_context, interface_objects)
            }

            $crate::system_b_standard_stack!(@augments $es $(, {
                bundle: $aug_bundle,
                create: |$aug_state, $aug_platform, $aug_lctx| $aug_body
            })?);

            $($($extra)*)?
        }
    };

    // ---- internal: default single-extension augment chain ----------------
    (@augments $es:ty) => {
        type Augments<'a> = $crate::bcus::system_b::ExtensionAugmentFor<'a, Self>;

        fn create_augments<'a>(
            state: &'a Self::State,
            platform: &'a Self::Platform,
            _layer_ctx: &'a $crate::context::layer::LayerContext<Self>,
        ) -> Self::Augments<'a>
        where
            Self::State: 'a,
            Self::Platform: 'a,
        {
            // `extension_state()` comes from `HasExtensionState`; spell the
            // trait explicitly so the macro doesn't depend on it being
            // imported at the call site.
            let es = <Self::State as $crate::HasExtensionState>::extension_state(state);
            <$es as $crate::bcus::system_b::Extension<Self::Platform>>::create_augment::<Self>(es, platform)
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
