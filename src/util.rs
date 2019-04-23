use std::net::{IpAddr, Ipv4Addr};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use pnet::packet::icmp::echo_request::{EchoRequestPacket, MutableEchoRequestPacket};
use pnet::packet::icmp::IcmpTypes;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::Packet;
use pnet::transport::{
    self, icmp_packet_iter, TransportChannelType, TransportProtocol::Ipv4, TransportReceiver,
    TransportSender,
};
use pnet::util::checksum;


#[test]
fn test_is_ipaddr_already_in_use() {
    assert_eq!(
        true,
        is_ipaddr_already_in_use(&"192.168.111.1".parse().unwrap()).unwrap()
    );
}

pub fn create_default_icmp_buffer() -> [u8; 8] {
    let mut buffer = [0u8; 8];
    let mut icmp_packet = MutableEchoRequestPacket::new(&mut buffer).unwrap();
    icmp_packet.set_icmp_type(IcmpTypes::EchoRequest);
    let checksum = checksum(icmp_packet.to_immutable().packet(), 16);
    icmp_packet.set_checksum(checksum);
    return buffer;
}


// IPアドレスが既に使用されているか調べる。
// TODO: tr, tsはArcを使えば生成は1回だけで良い？
pub fn is_ipaddr_already_in_use(target_ip: &Ipv4Addr) -> Result<bool, failure::Error> {
    let icmp_buf = create_default_icmp_buffer();
    let icmp_packet = EchoRequestPacket::new(&icmp_buf).unwrap();

    let (mut transport_sender, mut transport_receiver) = transport::transport_channel(
        1024,
        TransportChannelType::Layer4(Ipv4(IpNextHeaderProtocols::Icmp)),
    )
    .unwrap();
    if transport_sender
        .send_to(icmp_packet, IpAddr::V4(target_ip.clone()))
        .is_err()
    {
        return Err(failure::err_msg("Failed to send icmp echo."));
    }

    let (sender, receiver) = mpsc::channel();

    thread::spawn(move || {
        match icmp_packet_iter(&mut transport_receiver).next() {
            Ok((packet, _)) => {
                match packet.get_icmp_type() {
                    IcmpTypes::EchoReply => {
                        if sender.send(true).is_err() {
                            // タイムアウトしているとき
                            return;
                        };
                    }
                    _ => {
                        if sender.send(false).is_err() {
                            return;
                        }
                    }
                }
            }
            _ => error!("Failed to receive icmp echo reply."),
        }
    });

    if let Ok(is_used) = receiver.recv_timeout(Duration::from_millis(30)) {
        return Ok(is_used);
    } else {
        // タイムアウトした時。アドレスは使われていない
        debug!("not received reply within timeout");
        return Ok(false);
    }
}

pub fn u8_to_ipv4addr(buf: &[u8]) -> Result<Ipv4Addr, failure::Error> {
    if buf.len() == 4 {
        return Ok(Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]));
    } else {
        return Err(failure::err_msg("Could not get ip addr."));
    }
}
