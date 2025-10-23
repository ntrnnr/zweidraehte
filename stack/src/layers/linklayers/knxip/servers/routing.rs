use super::{DynBufferManager, EndpointType, KNXnetIPServiceType, ServerError, ServerInterest};

#[derive(Debug, Clone, Copy)]
pub struct RoutingServer {
    interests: [ServerInterest; 2],
    // FIXME: Add what we need to send device info etc.
}

impl RoutingServer {
    pub fn new(local_hpai: EndpointType) -> Self {
        RoutingServer {
            interests: [
                ServerInterest::new(KNXnetIPServiceType::RoutingIndication, local_hpai),
                ServerInterest::new(KNXnetIPServiceType::RoutingBusy, local_hpai),
            ],
        }
    }
}

impl super::KnxServer for RoutingServer {
    const N_INTERESTS: usize = 2;

    /// Returns the list of service codes and endpoints this server is interested in
    fn interests(&self) -> &[ServerInterest; Self::N_INTERESTS] {
        &self.interests
    }

    async fn handle_message(
        &self,
        service_code: KNXnetIPServiceType,
        _data: &[u8],
        _response_handle: &super::ResponseHandle<'_>,
        _buffer_manager: &DynBufferManager<'static>,
    ) -> Result<(), ServerError> {
        trace!("Routing server handling service code {:?}", service_code);
        // TODO: Implement routing protocol handling
        Ok(())
    }
}
