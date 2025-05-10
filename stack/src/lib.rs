#![feature(slice_as_array)]
#![feature(const_trait_impl)]
#![feature(adt_const_params)]
#![feature(generic_const_exprs)]
#![feature(generic_arg_infer)]
#![feature(type_alias_impl_trait)]
#![feature(never_type)]

#[macro_use]
mod macros;

pub mod address;
pub mod bcus;
pub mod dpt;
pub mod error;
pub mod layers;
pub mod messages;
pub mod objects;
pub mod util;

use address::IndividualAddress;
use const_default::ConstDefault;
use ector::ActorContext;
use layers::{network::NetworkLayer, transport::TransportLayer};
use messages::buffers::{Buffer, BufferManager};
use objects::{
    comm::ComObjects,
    tables::{MemoryBackedTable, app::Application},
};

static NL_CTX: ActorContext<NetworkLayer<Buffer<'static>>> = ActorContext::new();
static TL_CTX: ActorContext<TransportLayer<Buffer<'static>>> = ActorContext::new();

// FIXME: Introduce traits for ADT, AST, COT
pub struct StackResources<
    const NUM_BUFS: usize,
    ADT: MemoryBackedTable,
    AST: MemoryBackedTable,
    COT: MemoryBackedTable,
    P: ConstDefault,
    R: ComObjects,
> {
    pub buffer_manager: BufferManager<NUM_BUFS>,
    pub ind_addr: IndividualAddress,
    pub adt: ADT,
    pub ast: AST,
    pub cot: COT,
    pub app: Application<P>,
    pub ram: R,
}

impl<
    const NUM_BUFS: usize,
    ADT: MemoryBackedTable,
    AST: MemoryBackedTable,
    COT: MemoryBackedTable,
    P: ConstDefault,
    R: ComObjects,
> StackResources<NUM_BUFS, ADT, AST, COT, P, R>
{
    pub fn bootstrap(self) -> (ProtocolStack<NUM_BUFS, ADT, AST, COT, P, R>, StackRunner) {
        let _allocator = self.buffer_manager.dyn_buffer_manager();

        let nl_addr = NL_CTX.dyn_address();
        let tl_addr = TL_CTX.dyn_address();

        let network_layer = NetworkLayer::<Buffer<'static>>::new(self.ind_addr, 6, tl_addr);
        let transport_layer = TransportLayer::<Buffer<'static>>::new();

        (
            ProtocolStack { resources: self },
            StackRunner {
                network_layer,
                transport_layer,
            },
        )
    }
}

pub struct StackRunner {
    network_layer: NetworkLayer<Buffer<'static>>,
    transport_layer: TransportLayer<Buffer<'static>>,
}

impl StackRunner {
    /// Run the KNX stack.
    ///
    /// You must call this in a background task, to process KNX messages.
    pub async fn run(self) -> ! {
        let nl_task = NL_CTX.mount(self.network_layer);
        let tl_task = TL_CTX.mount(self.transport_layer);

        let tasks = embassy_futures::join::join(nl_task, tl_task);
        tasks.await;
        unreachable!();
    }
}

pub struct ProtocolStack<
    const NUM_BUFS: usize,
    ADT: MemoryBackedTable,
    AST: MemoryBackedTable,
    COT: MemoryBackedTable,
    P: ConstDefault,
    R: ComObjects,
> {
    pub resources: StackResources<NUM_BUFS, ADT, AST, COT, P, R>,
}
