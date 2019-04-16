use std::net::{IpAddr, Ipv4Addr};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;
use std::{env, io, net, ptr, str};

use pnet::packet::icmp::echo_request::{EchoRequestPacket, MutableEchoRequestPacket};
use pnet::packet::icmp::IcmpTypes;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::{Packet, PrimitiveValues};
use pnet::transport::{
    self, icmp_packet_iter, TransportChannelType, TransportProtocol::Ipv4, TransportReceiver,
    TransportSender,
};
use pnet::util::checksum;

use failure;

#[macro_use]
extern crate log;

use env_logger;
use log::{debug, error, info, warn};

/*
TODO
バイト列からDHCPパケットの生成
DHCPパケットを作成してフィールドを埋める
任意のDHCPメッセージを送信
ブロードキャストされたDHCPリクエストに対して返信
*/

const HTYPE_ETHER: u8 = 1;
const HLEN_MACADDR: u8 = 6;

const DHCP_MINIMUM_SIZE: usize = 237;
const OPTION_MESSAGE_TYPE_CODE: u8 = 53;

const DHCP_SIZE: usize = 400;
const OPTION_IP_ADDRESS_LEASE_TIME: u8 = 51;
const OPTION_SERVER_IDENTIFIER: u8 = 54;
const OPTION_END: u8 = 255;

const WIDTH: usize = 20;

const DHCPDISCOVER: u8 = 1;
const DHCPOFFER: u8 = 2;
const DHCPREQUEST: u8 = 3;
const DHCPDECLINE: u8 = 4;
const DHCPACK: u8 = 5;
const DHCPNAK: u8 = 6;
const DHCPRELEASE: u8 = 7;

const BOOTREQUEST: u8 = 1;
const BOOTREPLY: u8 = 2;

mod dhcp;
use dhcp::DhcpPacket;

#[test]
fn test_is_ip_use() {
    // assert_eq!(
    //     true,
    //     is_ipaddr_already_in_use(
    //         "en0".to_string(),
    //         "192.168.11.22".parse().unwrap(),
    //         "192.168.11.1".parse().unwrap()
    //     )
    // );
}

// IPアドレスが既に使用されているか調べる。
fn is_ipaddr_already_in_use(
    icmp_packet: EchoRequestPacket,
    target_ip: Ipv4Addr,
    ts: &mut TransportSender,
    tr: &mut TransportReceiver,
) -> Result<bool, failure::Error> {
    match ts.send_to(icmp_packet, IpAddr::V4(target_ip)) {
        Ok(_) => {
            debug!("OK");
        }
        Err(e) => {
            warn!("{:?}", e);
            return Err(failure::err_msg("Failed to send icmp echo."));
        }
    }

    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        match icmp_packet_iter(tr).next() {
            Ok((packet, _)) => {
                match packet.get_icmp_type() {
                    IcmpTypes::EchoReply => {
                        if sender.send(true).is_err() {
                            // タイムアウトしているとき
                            return;
                        };
                    },
                    _ => {
                        if sender.send(false).is_err() {
                            return;
                        }
                    }
                }
            },
            _ => error!("Failed to receive icmp echo reply.")
        }
    });

    if let Ok(is_used) = receiver.recv_timeout(Duration::from_secs(1)) {
        return Ok(is_used);
    } else {
        // タイムアウトした時。アドレスは使われていない
        debug!("not received reply within timeout");
        return Ok(false);
    }
}

fn create_default_icmp_buffer() -> [u8; 8] {
    let mut buffer = [0u8; 8];
    let mut icmp_packet = MutableEchoRequestPacket::new(&mut buffer).unwrap();
    icmp_packet.set_icmp_type(IcmpTypes::EchoRequest);
    let checksum = checksum(icmp_packet.to_immutable().packet(), 16);
    icmp_packet.set_checksum(checksum);
    return buffer;
}

fn main() {
    env::set_var("RUST_LOG", "debug");
    env_logger::init();

    let server_socket = net::UdpSocket::bind("0.0.0.0:67").expect("Failed to bind socket");
    server_socket.set_broadcast(true).unwrap();
    loop {
        let mut recv_buf = [0u8; 1024];
        let client_socket = server_socket
            .try_clone()
            .expect("Failed to create client socket");
        match server_socket.recv_from(&mut recv_buf) {
            Ok((size, src)) => {
                println!("incoming data from {}/size: {}", src, size);
                thread::spawn(move || {
                    if let Some(dhcp_packet) = DhcpPacket::new(&mut recv_buf[..size]) {
                        if dhcp_packet.get_op() == BOOTREQUEST {
                            dhcp_handler(&dhcp_packet, &client_socket);
                        }
                    }
                });
                // srcにsend_toして正しく送信できるのか・・・？
                // server_socket.send_to(&buf[..size], src).expect("Failed to send response");
            }
            Err(e) => {
                eprintln!("could not recieve a datagram: {}", e);
            }
        }
    }
}

// こうすると、icmpパケットの中身までも1つのパケットで生成できるが、EchoRequestがずっと行き続けるのでよくない
// fn create_echo_request_packet() -> EchoRequestPacket<'static> {
//     let buffer = vec![0u8; 8];
//     let mut icmp_packet = MutableEchoRequestPacket::owned(buffer).unwrap();
//     icmp_packet.set_icmp_type(IcmpTypes::EchoRequest);
//     let checksum = checksum(icmp_packet.to_immutable().packet(), 16);
//     icmp_packet.set_checksum(checksum);
//     return icmp_packet.consume_to_immutable();
// }

// 利用可能なIPアドレスを探す。
// 以前リースされたものがあればそれを返し、なければアドレスプールから利用可能なIPアドレスを返却する。
fn select_lease_ip(
    sender: &mut TransportSender,
    receiver: &mut TransportReceiver,
) -> Result<Ipv4Addr, failure::Error> {
    //TODO: MACアドレスでDB問い合わせ
    //TODO: アドレスプールからIP取得
    let addr_pool: [Ipv4Addr; 4] = [
        "192.168.111.1".parse().unwrap(),
        "192.168.111.89".parse().unwrap(),
        "192.168.111.90".parse().unwrap(),
        "192.168.111.91".parse().unwrap(),
    ]; //ダミー
    for target_ip in &addr_pool {
        let icmp_buf = create_default_icmp_buffer();
        let icmp_packet = EchoRequestPacket::new(&icmp_buf).unwrap();
        match is_ipaddr_already_in_use(icmp_packet, target_ip.clone(), sender, receiver) {
            Ok(used) => {
                if used {
                    continue;
                } else {
                    return Ok(target_ip.clone());
                }
            }
            Err(msg) => {
                warn!("{}", msg);
            }
        }
    }
    return Err(failure::err_msg("Could not decide available ip address."));
}

fn dhcp_handler(packet: &DhcpPacket, soc: &net::UdpSocket) {
    // dhcpのヘッダ読み取り
    if let Some(message) = packet.get_option(OPTION_MESSAGE_TYPE_CODE) {
        let message_type = message[0];
        let mut packet_buffer = [0u8; DHCP_SIZE];
        let dest: net::SocketAddr = "255.255.255.255:68".parse().unwrap(); //TODO: ブロードキャストをユニキャストに
        let target_ip = "192.168.111.88".parse().unwrap(); //TODO: アドレスプールから選ぶ
        let (mut sender, mut receiver) = transport::transport_channel(
            1024,
            TransportChannelType::Layer4(Ipv4(IpNextHeaderProtocols::Icmp)),
        )
        .unwrap();

        match message_type {
            DHCPDISCOVER => {
                println!("dhcp discover");
                // DBアクセス。以前リースしたやつがあればそれを再び渡す
                // IPアドレスの決定
                let ip_to_be_leased = match select_lease_ip(&mut sender, &mut receiver) {
                    Ok(ip) => ip,
                    Err(msg) => {
                        error!("{}", msg);
                        return;
                    }
                };
                if let Ok(dhcp_packet) =
                    make_dhcp_packet(&packet, DHCPOFFER, &mut packet_buffer, ip_to_be_leased)
                {
                    soc.send_to(dhcp_packet.get_buffer(), dest)
                        .expect("failed to send");
                    println!("send dhcp offer");
                }
                return;
            }

            DHCPREQUEST => {
                println!("dhcp request");
                // TODO: DBに使用ずみをコミット
                if let Ok(dhcp_packet) =
                    make_dhcp_packet(&packet, DHCPACK, &mut packet_buffer, target_ip)
                {
                    soc.send_to(dhcp_packet.get_buffer(), dest)
                        .expect("failed to send");
                }
                return;
            }

            DHCPRELEASE => {
                println!("dhcp release");
                return;
            }

            _ => {
                warn!("message_type: {}", message_type);
                return;
            }
        }
    } else {
        error!("option not found");
        return;
    }
}

fn make_dhcp_packet<'a>(
    incoming_packet: &DhcpPacket,
    message_type: u8,
    buffer: &'a mut [u8],
    target_ip: Ipv4Addr,
) -> Result<DhcpPacket<'a>, io::Error> {
    let mut dhcp_packet = DhcpPacket::new(buffer).unwrap();
    dhcp_packet.set_op(BOOTREPLY);
    dhcp_packet.set_htype(HTYPE_ETHER);
    dhcp_packet.set_hlen(HLEN_MACADDR);
    dhcp_packet.set_xid(incoming_packet.get_xid());
    if incoming_packet.get_giaddr() != Ipv4Addr::new(0, 0, 0, 0) {
        dhcp_packet.set_flags(incoming_packet.get_flags());
    }
    dhcp_packet.set_yiaddr(&target_ip);
    let client_macaddr = incoming_packet.get_chaddr();
    dhcp_packet.set_chaddr(&client_macaddr);

    let mut cursor = dhcp::OPTIONS;
    dhcp_packet.set_magic_cookie(&mut cursor);
    dhcp_packet.set_option(
        &mut cursor,
        OPTION_MESSAGE_TYPE_CODE,
        1,
        Some(&mut vec![message_type]),
    );
    dhcp_packet.set_option(
        &mut cursor,
        OPTION_IP_ADDRESS_LEASE_TIME,
        4,
        Some(&mut vec![0, 0, 1, 0]),
    ); //TODO: リースタイム変更
    dhcp_packet.set_option(
        &mut cursor,
        OPTION_SERVER_IDENTIFIER,
        4,
        Some(&mut vec![127, 0, 0, 1]),
    );
    dhcp_packet.set_option(&mut cursor, OPTION_END, 0, None);
    Ok(dhcp_packet)
}
