use pnet::transport::{self, TransportProtocol::Ipv4};
use pnet::packet::ip;
use pnet::datalink;
use std::net;
use std::str;


struct DhcpPacket {
    op:      u8,
    htype:   u8,
    hlen:    u8,
    hops:    u8,
    xid:     u32,
    secs:    u16,
    flags:   u16,
    ciaddr:  net::Ipv4Addr,
    yiaddr:  net::Ipv4Addr,
    siaddr:  net::Ipv4Addr,
    giaddr:  net::Ipv4Addr,
    chaddr:  datalink::MacAddr,
    sname:   [u8; 64],
    file:    [u8; 128],
    options: []// optionがどの用途に使われるのか?
}

impl DhcpPacket {
    fn new(buffer: &[u8]) -> Option<DhcpPacket>{

        // DhcpPacketを構成して返す
    }
}

fn main() {
    let server_socket = net::UdpSocket::bind("127.0.0.1:12345")
                           .expect("Failed to bind socket");
    loop {
        let mut buf = [0u8; 1024];
        match server_socket.recv_from(&mut buf) {
            Ok((size, src)) => {
                if let dhcp_packet = DhcpPacket::new(&buf[..size]) {
                    dhcp_handler(&dhcp_packet);
                }

                // srcにsend_toして正しく送信できるのか・・・？
                // server_socket.send_to(&buf[..size], src).expect("Failed to send response");
            },
            Err(e) => {
                eprintln!("could not recieve a datagram: {}", e);
            }
        }
    }
}

fn dhcp_handler(packet: &DhcpPacket) {
    // dhcpのヘッダ読み取り
    // DHCPoffer送信

    // or DHCPACK送信
    // or リリース

}

// 
// 受信したバイト列をDHCP構造体にする
// 
