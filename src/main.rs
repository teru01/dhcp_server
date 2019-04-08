use pnet::transport::{self, TransportProtocol::Ipv4};
use pnet::packet::ip;
use pnet::datalink;
use std::net;
use std::str;
use byteorder::{ByteOrder, NetworkEndian, LittleEndian};
/*
TODO
バイト列からDHCPパケットの生成
DHCPパケットを作成してフィールドを埋める
任意のDHCPメッセージを送信
ブロードキャストされたDHCPリクエストに対して返信
*/


enum MessageType {
    BOOTREQUEST = 1,
    BOOTREPLY = 2
}

enum Htype {
    ETHER = 1,
}


const DHCP_MINIMUM_SIZE: usize = 548;
const MESSAGE_TYPE_CODE: u8 = 53;

// 全体で548oc以上
struct DhcpPacket {
    op:      u8, /* 0: Message type */
    htype:   u8, /* 1: Hardware addr type */
    hlen:    u8, /* 2: Hardware addr length */
    hops:    u8, /* 3: agent hops from client */
    xid:     u32, /* 4: Transaction ID */
    secs:    u16, /* 8: seconds elapsed since client started to trying to boot */
    flags:   u16, /* 10: flags */
    ciaddr:  u32, /* 12: client ip addr if already in use */
    yiaddr:  u32, /* 16: client ip addr */
    siaddr:  u32, /* 20: ip addr of next server to use in bootstrap */
    giaddr:  u32, /* 24: ip addr of relay agent */
    chaddr:  u128, /* 28: client hardware address */
    sname:   [u8; 64], /* 44: optional server host name */
    file:    [u8; 128], /* 108: boot file name */
    options: [u8; 312] /* 236: optionがどの用途に使われるのか? minで312 */
}

// fn create_ip(n: u32) -> [u8; 4]{
//     let buf = [0u8; 4];
//     for i in 0..4 {
//         buf[i] = n >> (8 * (3 - i)) as u8 & 0xff;
//     }
//     buf
// }

impl DhcpPacket {
    fn new(buf: &[u8]) -> Option<DhcpPacket>{
        let packet = DhcpPacket {
            op:     buf[0],
            htype:  buf[1],
            hlen:   buf[2],
            hops:   buf[3],
            xid:    NetworkEndian::read_u32(&buf[4..8]),
            secs:   NetworkEndian::read_u16(&buf[8..10]), /* 8: seconds elapsed since client started to trying to boot */
            flags:  NetworkEndian::read_u16(&buf[10..12]), /* 10: flags */
            ciaddr: NetworkEndian::read_u32(&buf[12..16]), /* 12: client ip addr if already in use */
            yiaddr: NetworkEndian::read_u32(&buf[16..20]), /* 16: client ip addr */
            siaddr: NetworkEndian::read_u32(&buf[20..24]), /* 20: ip addr of next server to use in bootstrap */
            giaddr: NetworkEndian::read_u32(&buf[24..28]), /* 24: ip addr of relay agent */
            chaddr: NetworkEndian::read_u128(&buf[28..44]), /* 28: client hardware address */
            sname:   [0u8; 64], /* 44: optional server host name */
            file:    [0u8; 128], /* 108: boot file name */
            options: [0u8; 312]
        };
        Some(packet)
    }


    fn set_op(&mut self, op: u8) {
        self.op = op;
    }

    //optionはcode, length, bufferの順に並んでいる
    fn get_option(&self, option_code: u8) -> Option<Vec<u8>> {
        let mut index = 4; // 最初の4バイトはクッキー
        while index < 255 {
            if self.options[index] == option_code {
                let len = self.options[index+1];
                let buf_index = index + 2;
                let v = self.options[buf_index..buf_index+len as usize].to_vec();
                return Some(v);
            } else if self.options[index] == 0 {
                index += 1;
            } else {
                let len = self.options[index+1];
                index += 1 + len as usize;
            }
        }
        None
    }

}

fn main() {
    let server_socket = net::UdpSocket::bind("127.0.0.1:12345")
                           .expect("Failed to bind socket");
    loop {
        let mut buf = [0u8; 1024];
        match server_socket.recv_from(&mut buf) {
            Ok((size, src)) => {
                println!("incoming connection from {}", src);
                if size >= DHCP_MINIMUM_SIZE {
                    if let Some(dhcp_packet) = DhcpPacket::new(&buf[..size]) {
                        dhcp_handler(&dhcp_packet);
                    }
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

const DHCPDISCOVER: u8 = 1;
const DHCPREQUEST: u8 = 3;
const DHCPRELEASE: u8 = 7;

fn dhcp_handler(packet: &DhcpPacket) {
    // dhcpのヘッダ読み取り
    if let Some(message) = packet.get_option(MESSAGE_TYPE_CODE) {
        let message_type = message[0];
        match message_type {
            DHCPDISCOVER => {
                println!("dhcp discover");
                // make_dhcp_packet();
            },

            DHCPREQUEST => {
                println!("dhcp request");

            },

            DHCPRELEASE => {
                println!("dhcp release");
            }

            _ => {

            }
        }
    }
    // DHCPoffer送信

    // or DHCPACK送信
    // or リリース
}

fn make_dhcp_packet() {
    let buffer = [0u8; DHCP_MINIMUM_SIZE];
    let mut dhcp_packet = DhcpPacket::new(&buffer);

}
