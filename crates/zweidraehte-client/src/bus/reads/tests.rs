use super::*;
use crate::IndividualAddress;
use crate::bus::driver::{BusCommand, ConnectionId};
use crate::bus::frames;
use tokio::sync::mpsc;
use zweidraehte_proto::messages::apdu::memory::{MemoryAccess, MemoryResponse};
use zweidraehte_proto::messages::apdu::property::{PropertyValueHeader, PropertyValueResponse};
use zweidraehte_proto::messages::knx::{ApciCode, KnxMessageBuffer, Tpci};

#[tokio::test]
async fn ranged_reads_respect_both_peers_and_secure_overhead() {
    let address = IndividualAddress::new(1, 1, 10);
    // Expected chunk lengths are independent wire examples, including the
    // service's 6-bit count cap and a secure target smaller than its interface.
    for (interface, target, secure, chunks) in [
        (64, 15, false, vec![12, 12, 6]),
        (15, 64, false, vec![12, 12, 6]),
        (64, 30, true, vec![14, 14, 2]),
        (254, 254, false, vec![63, 7]),
    ] {
        let (tx, mut rx) = mpsc::channel(1);
        let mut connection = DeviceConnection::new(address, tx, secure, None, ConnectionId::TEST);
        let length = chunks.iter().sum::<u8>() as usize;
        let peer = async {
            let mut offset = 0;
            for count in chunks {
                let BusCommand::TlRequest { frame, tx, .. } = rx.recv().await.expect("memory request") else {
                    panic!("connected read");
                };
                let request = KnxMessageBuffer::from_buffer(frame);
                let read = MemoryAccess::parse_read(request.buf()).expect("memory request parses");
                assert_eq!(request.get_apci_code(), ApciCode::MemoryRead);
                assert_eq!((read.address, read.count), (0x100 + offset, count));
                let data = (offset..offset + u16::from(count)).map(|value| value as u8).collect::<Vec<_>>();
                let response = frames::build_individual_frame(
                    address,
                    IndividualAddress::new(1, 1, 1),
                    Tpci::DataConnected(0),
                    ApciCode::MemoryReadResponse,
                    MemoryResponse::msg_len(data.len()),
                    |buf| MemoryResponse::write(buf, count, 0x100 + offset, &data),
                );
                tx.send(Ok(response)).expect("read receiver");
                offset += u16::from(count);
            }
        };
        let (result, ()) = tokio::join!(connection.read_memory_range(0x100, length, interface, target), peer);
        assert_eq!(result.expect("complete range"), (0..length as u8).collect::<Vec<_>>());
    }
}

#[tokio::test]
async fn invalid_range_and_insufficient_secure_budget_send_nothing() {
    let (tx, mut rx) = mpsc::channel(1);
    let mut connection = DeviceConnection::new(IndividualAddress::new(1, 1, 10), tx, true, None, ConnectionId::TEST);
    for (address, length, target) in [(0xfffe, 3, 64), (0, usize::MAX, 64), (0, 1, 15), (0, 1, 16)] {
        assert!(connection.read_memory_range(address, length, 64, target).await.is_err());
        assert!(rx.try_recv().is_err());
    }
    assert!(connection.read_memory_range(0xffff, 0, 0, 0).await.expect("empty range").is_empty());
}

#[tokio::test]
async fn target_apdu_probe_uses_standard_capacity_on_bad_or_missing_values() {
    for (reply, expected) in [(Some(vec![0, 30]), 30), (Some(vec![0, 14]), 15), (Some(vec![1]), 15), (None, 15)] {
        let (tx, mut rx) = mpsc::channel(1);
        let address = IndividualAddress::new(1, 1, 10);
        let mut connection = DeviceConnection::new(address, tx, false, None, ConnectionId::TEST);
        let peer = async {
            let BusCommand::TlRequest { frame, tx, .. } = rx.recv().await.expect("APDU probe") else {
                panic!("property read");
            };
            let request = KnxMessageBuffer::from_buffer(frame);
            let header = PropertyValueHeader::parse(request.buf()).expect("property header");
            assert_eq!((header.object_idx, header.prop_id), (0, pid::device::MAX_APDU_LENGTH));
            let response = reply.map_or(Err(BusError::Timeout), |bytes| {
                Ok(frames::build_individual_frame(
                    address,
                    IndividualAddress::new(1, 1, 1),
                    Tpci::DataConnected(0),
                    ApciCode::PropertyValueResponse,
                    PropertyValueResponse::msg_len(bytes.len()),
                    |buf| PropertyValueResponse::write(buf, 0, pid::device::MAX_APDU_LENGTH, 1, 1, &bytes),
                ))
            });
            tx.send(response).expect("probe receiver");
        };
        let (limit, ()) = tokio::join!(connection.read_max_apdu(64), peer);
        assert_eq!(limit, expected);
    }
}
