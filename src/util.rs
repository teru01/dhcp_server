use std::collections::HashMap;
use std::net::{AddrParseError, IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;
use std::{fs, io};

use byteorder::{BigEndian, WriteBytesExt};
use pnet::packet::icmp::echo_request::{EchoRequestPacket, MutableEchoRequestPacket};
use pnet::packet::icmp::IcmpTypes;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::Packet;
use pnet::transport::{self, icmp_packet_iter, TransportChannelType, TransportProtocol::Ipv4};
use pnet::util::checksum;

#[test]
fn test_is_ipaddr_already_in_use() {
    assert_eq!(
        true,
        is_ipaddr_already_in_use(&"192.168.111.1".parse().unwrap()).unwrap()
    );
}

/**
 * ICMP echoリクエストのバッファを作成する。
 */
pub fn create_default_icmp_buffer() -> [u8; 8] {
    let mut buffer = [0u8; 8];
    let mut icmp_packet = MutableEchoRequestPacket::new(&mut buffer).unwrap();
    icmp_packet.set_icmp_type(IcmpTypes::EchoRequest);
    let checksum = checksum(icmp_packet.to_immutable().packet(), 16);
    icmp_packet.set_checksum(checksum);
    return buffer;
}

/**
 * IPアドレスがすでに使用されているか調べる。
 */
pub fn is_ipaddr_already_in_use(target_ip: &Ipv4Addr) -> Result<bool, failure::Error> {
    let icmp_buf = create_default_icmp_buffer();
    let icmp_packet = EchoRequestPacket::new(&icmp_buf).unwrap();

    let (mut transport_sender, mut transport_receiver) = transport::transport_channel(
        1024,
        TransportChannelType::Layer4(Ipv4(IpNextHeaderProtocols::Icmp)),
    )?;
    transport_sender.send_to(icmp_packet, IpAddr::V4(*target_ip))?;

    let (sender, receiver) = mpsc::channel();

    // ICMP echoリクエストのリプライに対してタイムアウトを設定するため、スレッドを起動する。
    thread::spawn(move || {
        let mut iter = icmp_packet_iter(&mut transport_receiver);
        let (packet, _) = iter.next().unwrap();
        if packet.get_icmp_type() == IcmpTypes::EchoReply {
            sender.send(true);
        }
    });

    // recvは相手のチャネルがドロップされると失敗する。
    if receiver.recv_timeout(Duration::from_millis(30)).is_ok() {
        Ok(true)
    } else {
        // タイムアウトした時。アドレスは使われていない
        debug!("not received reply within timeout");
        Ok(false)
    }
}

pub fn u8_to_ipv4addr(buf: &[u8]) -> Option<Ipv4Addr> {
    if buf.len() == 4 {
        return Some(Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]));
    } else {
        return None;
    }
}

// 環境情報を読んでハッシュマップを返す
pub fn load_env() -> HashMap<String, String> {
    let contents = fs::read_to_string(".env").expect("Failed to read env file");
    let lines: Vec<_> = contents.split('\n').collect();
    let mut map = HashMap::new();
    for line in lines {
        let elm: Vec<_> = line.split('=').map(str::trim).collect();
        if elm.len() == 2 {
            map.insert(elm[0].to_string(), elm[1].to_string());
        }
    }
    return map;
}

pub fn obtain_static_addresses(
    env: &HashMap<String, String>,
) -> Result<HashMap<String, Ipv4Addr>, AddrParseError> {
    let network_addr: Ipv4Addr = env
        .get("NETWORK_ADDR")
        .expect("Missing network_addr")
        .parse()?;

    let subnet_mask = env
        .get("SUBNET_MASK")
        .expect("Missing subnet_mask")
        .parse()?;

    let dhcp_server_address = env
        .get("SERVER_IDENTIFIER")
        .expect("Missing server_identifier")
        .parse()?;

    let default_gateway = env
        .get("DEFAULT_GATEWAY")
        .expect("Missing default_gateway")
        .parse()?;

    let dns_addr = env.get("DNS_SERVER").expect("Missing dns_server").parse()?;

    let mut map = HashMap::new();
    map.insert("network_addr".to_string(), network_addr);
    map.insert("subnet_mask".to_string(), subnet_mask);
    map.insert("dhcp_server_addr".to_string(), dhcp_server_address);
    map.insert("default_gateway".to_string(), default_gateway);
    map.insert("dns_addr".to_string(), dns_addr);
    return Ok(map);
}

pub fn make_vec_from_u32(i: u32) -> Result<Vec<u8>, io::Error> {
    let mut v = Vec::new();
    v.write_u32::<BigEndian>(i)?;
    return Ok(v);
}

pub fn send_dhcp_broadcast_response(soc: &UdpSocket, data: &[u8]) -> Result<(), failure::Error> {
    let destination: SocketAddr = "255.255.255.255:68".parse()?;
    soc.send_to(data, destination)?;
    return Ok(());
}
