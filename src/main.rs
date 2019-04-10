use pnet::transport::{self, TransportProtocol::Ipv4};
use pnet::packet;
use pnet::datalink;
use std::{ net, io, str, ptr };
use std::net::Ipv4Addr;
use std::thread;
use pnet::datalink::Channel::Ethernet;

use pnet::datalink::{Channel, MacAddr, NetworkInterface, ParseMacAddrErr};

use pnet::packet::arp::{ArpHardwareTypes, ArpOperations};
use pnet::packet::arp::{ArpPacket, MutableArpPacket};
use pnet::packet::ethernet::{ EtherTypes, EthernetPacket };
use pnet::packet::ethernet::MutableEthernetPacket;
use pnet::packet::{MutablePacket, Packet};

use std::sync::mpsc;
use std::time::Duration;

/*
TODO
バイト列からDHCPパケットの生成
DHCPパケットを作成してフィールドを埋める
任意のDHCPメッセージを送信
ブロードキャストされたDHCPリクエストに対して返信
*/

const HTYPE_ETHER: u8 = 1;
const HLEN_MACADDR: u8 = 6;

const DHCP_MINIMUM_SIZE: usize = 548;
const OPTION_MESSAGE_TYPE_CODE: u8 = 53;

const DHCP_SIZE:usize = 400;
const OPTION_IP_ADDRESS_LEASE_TIME: u8 = 51;
const OPTION_SERVER_IDENTIFIER: u8 = 54;
const OPTION_END: u8 = 255;

const WIDTH: usize = 20;

const DHCPDISCOVER: u8 = 1;
const DHCPOFFER   : u8 = 2;
const DHCPREQUEST : u8 = 3;
const DHCPDECLINE : u8 = 4;
const DHCPACK     : u8 = 5;
const DHCPNAK     : u8 = 6;
const DHCPRELEASE : u8 = 7;

const BOOTREQUEST: u8 = 1;
const BOOTREPLY: u8 = 2;

const OP:      usize = 0;
const HTYPE:   usize = 1;
const HLEN:    usize = 2;
const HOPS:    usize = 3;
const XID:     usize = 4;
const SECS:    usize = 8;
const FLAGS:   usize = 10;
const CIADDR:  usize = 12;
const YIADDR:  usize = 16;
const SIADDR:  usize = 20;
const GIADDR:  usize = 24;
const CHADDR:  usize = 28;
const SNAME:   usize = 44;
const FILE:    usize = 108;
const OPTIONS: usize = 236;

struct DhcpPacket<'a> {
    buffer: &'a mut [u8],
}

impl<'a> DhcpPacket<'a> {
    fn new(buf: &mut [u8]) -> Option<DhcpPacket>{
        let packet = DhcpPacket {
            buffer: buf
        };
        Some(packet)
    }

    fn get_op(&self) -> u8 {
        self.buffer[OP]
    }

    fn get_options(&self) -> &[u8] {
        &self.buffer[OPTIONS..]
    }

    fn get_xid(&self) -> &[u8] {
        &self.buffer[XID..SECS]
    }

    fn get_flags(&self) -> &[u8] {
        &self.buffer[FLAGS..CIADDR]
    }

    fn get_giaddr(&self) -> Ipv4Addr {
        let b = &self.buffer[GIADDR..CHADDR];
        Ipv4Addr::new(b[0], b[1], b[2], b[3])
    }

    fn get_chaddr(&self) -> &[u8] {
        &self.buffer[CHADDR..SNAME]
    }

    fn set_op(&mut self, op: u8) {
        self.buffer[OP] = op;
    }

    fn set_htype(&mut self, htype: u8) {
        self.buffer[HTYPE] = htype;
    }

    fn set_hlen(&mut self, hlen: u8) {
        self.buffer[HLEN] = hlen;
    }

    fn set_xid(&mut self, xid: &[u8]) {
        unsafe {
            ptr::copy_nonoverlapping(xid.as_ptr(), self.buffer[XID..SECS].as_mut_ptr(), SECS - XID);
        }
    }

    fn set_flags(&mut self, flags: &[u8]) {
        unsafe {
            ptr::copy_nonoverlapping(flags.as_ptr(), self.buffer[FLAGS..CIADDR].as_mut_ptr(), CIADDR - FLAGS);
        }
    }

    fn set_yiaddr(&mut self, yiaddr: &Ipv4Addr) {
        unsafe {
            ptr::copy_nonoverlapping(yiaddr.octets().as_ptr(), self.buffer[YIADDR..SIADDR].as_mut_ptr(), SIADDR - YIADDR);
        }
    }

    fn set_chaddr(&mut self, chaddr: &[u8]) {
        unsafe {
            ptr::copy_nonoverlapping(chaddr.as_ptr(), self.buffer[CHADDR..SNAME].as_mut_ptr(), SNAME - CHADDR);
        }
    }

    fn set_option(&mut self, cursor: &mut usize, message_type: u8, len: usize, contents: Option<&[u8]>){
        self.buffer[*cursor] = message_type;
        if message_type == OPTION_END {
            return;
        }
        self.buffer[*cursor + 1] = len as u8;

        if let Some(contents) = contents {
            unsafe {
                ptr::copy_nonoverlapping(contents.as_ptr(), self.buffer[*cursor+2..].as_mut_ptr(), len);
            }
        }
        *cursor += 2 + len; //message_type + len + buffer;
    }

    fn set_magic_cookie(&mut self, cursor: &mut usize) {
        unsafe {
            ptr::copy_nonoverlapping([0x63, 0x82, 0x53, 0x63].as_ptr(), self.buffer[*cursor..].as_mut_ptr(), 4);
        }
        *cursor += 4;
    }

    // fn get_htype(&self) -> u8 {
    //     self.buffer[1]
    // }

    // fn get_hlen(&self) -> u8 {
    //     self.buffer[2]
    // }

    // fn get_hops(&self) -> u8 {
    //     self.buffer[3]
    // }

    //optionはcode, length, bufferの順に並んでいる
    fn get_option(&self, option_code: u8) -> Option<Vec<u8>> {
        let mut index: usize = 4; // 最初の4バイトはクッキー
        let options = self.get_options();
        while index < OPTION_END as usize {
            if options[index] == option_code {
                let len = options[index+1];
                let buf_index = index + 2;
                let v = options[buf_index..buf_index+len as usize].to_vec();
                return Some(v);
            } else if options[index] == 0 {
                index += 1;
            } else {
                let len = options[index+1];
                index += 1 + len as usize;
            }
        }
        None
    }
}

#[test]
fn test_is_ip_use() {
    assert_eq!(true, is_ipaddr_already_in_use("en0".to_string(), "192.168.11.22".parse().unwrap(), "192.168.11.1".parse().unwrap()));
}

// TODO: IPが使用中かどうかいちいちチャンネル立ち上げて確認するのは効率悪い
fn is_ipaddr_already_in_use(interface_name: String, dhcp_server_addr: Ipv4Addr, target_ip: Ipv4Addr) -> bool {
    let interfaces = datalink::interfaces();
    let interface = interfaces.into_iter()
                              .filter(|iface| iface.name == interface_name)
                              .next()
                              .expect("Failed to get interface");

    let (mut tx, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unhandled channel type"),
        Err(e) => {
            panic!("Failed to create datalink channel {}", e)
        }
    };

    let mut ethernet_buffer = [0u8; 42];
    let mut ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();

    ethernet_packet.set_destination(MacAddr::broadcast());
    ethernet_packet.set_source(interface.mac_address());
    ethernet_packet.set_ethertype(EtherTypes::Arp);

    let mut arp_buffer = [0u8; 28];
    let mut arp_packet = MutableArpPacket::new(&mut arp_buffer).unwrap();

    arp_packet.set_hardware_type(ArpHardwareTypes::Ethernet);
    arp_packet.set_protocol_type(EtherTypes::Ipv4);
    arp_packet.set_hw_addr_len(6);
    arp_packet.set_proto_addr_len(4);
    arp_packet.set_operation(ArpOperations::Request);
    arp_packet.set_sender_hw_addr(interface.mac_address());
    arp_packet.set_sender_proto_addr(dhcp_server_addr);
    arp_packet.set_target_hw_addr(MacAddr::zero());
    arp_packet.set_target_proto_addr(target_ip);

    ethernet_packet.set_payload(arp_packet.packet_mut());

    tx.send_to(ethernet_packet.packet(), None).unwrap();
    println!("sent ARP query");

    //受信処理：rx.next でパケットが届くまで待機、s秒後に再開
    // rx.try_clone()
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        loop {
            match rx.next() {
                Ok(frame) => {
                    let frame = EthernetPacket::new(frame).unwrap();
                    if frame.get_ethertype() == EtherTypes::Arp {
                        let arp_packet = ArpPacket::new(frame.payload()).unwrap();
                        if arp_packet.get_operation() == ArpOperations::Reply {
                            // アドレスは使用されている。
                            // タイムアウト後にARPを受信するか、DHCP受信スレッドが終了すればこのスレッドは終了する。
                            if sender.send(true).is_err() {
                                break;
                            }
                        }
                    }
                },
                _ => {}
            }
        }
    });

    if let Ok(_) = receiver.recv_timeout(Duration::from_secs(1)) {
        return true;
    }
    return false;
}


fn main() {
    let server_socket = net::UdpSocket::bind("0.0.0.0:67")
                           .expect("Failed to bind socket");
    server_socket.set_broadcast(true).unwrap();
    loop {
        let mut buf = [0u8; 1024];
        let client_socket = server_socket.try_clone().expect("Failed to create client socket");
        match server_socket.recv_from(&mut buf) {
            Ok((size, src)) => {
                println!("incoming data from {}/size: {}", src, size);
                thread::spawn(move || {
                    if let Some(dhcp_packet) = DhcpPacket::new(&mut buf[..size]) {
                        // dump_dhcp_info(&dhcp_packet);
                        dhcp_handler(&dhcp_packet, &client_socket);
                    }
                });
                // srcにsend_toして正しく送信できるのか・・・？
                // server_socket.send_to(&buf[..size], src).expect("Failed to send response");
            },
            Err(e) => {
                eprintln!("could not recieve a datagram: {}", e);
            }
        }
    }
}

fn dump_dhcp_info(packet: &DhcpPacket) {
    // println!("op: {}", packet.op);
    // println!("htype: {}", packet.htype);
    // println!("hlen: {}", packet.hlen);
    // println!("hops: {}", packet.hops);
    // println!("xid: {}", packet.xid);
    // println!("secs: {}", packet.secs);
    // println!("flags: {}", packet.flags);
    // print_ip(packet.ciaddr);
    // print_ip(packet.yiaddr);
    // print_ip(packet.siaddr);
    // print_ip(packet.giaddr);
    // print_ip(packet.chaddr);
}

fn dhcp_handler(packet: &DhcpPacket, soc: &net::UdpSocket) {
    if packet.get_op() != BOOTREQUEST {
        return;
    }
    // dhcpのヘッダ読み取り
    if let Some(message) = packet.get_option(OPTION_MESSAGE_TYPE_CODE) {
        let message_type = message[0];
        let mut packet_buffer = [0u8; DHCP_SIZE];
        let dest: net::SocketAddr = "255.255.255.255:68".parse().unwrap();
        let target_ip = "192.168.111.88".parse().unwrap();
        match message_type {
            DHCPDISCOVER => {
                println!("dhcp discover");
                if is_ipaddr_already_in_use("en0".to_string(), "192.168.111.222".parse().unwrap(), target_ip) {
                    panic!("ip already in use");
                }
                if let Ok(dhcp_packet) = make_dhcp_packet(&packet, DHCPOFFER, &mut packet_buffer, target_ip) {
                    // let payload = dhcp_packet.buffer;
                    // dump_payload(payload);
                    // let payload = bincode::serialize(&dhcp_packet).unwrap();
                    soc.send_to(dhcp_packet.buffer, dest).expect("failed to send");
                    println!("send dhcp offer");
                }
            },

            DHCPREQUEST => {
                println!("dhcp request");
                if let Ok(dhcp_packet) = make_dhcp_packet(&packet, DHCPACK, &mut packet_buffer, target_ip) {
                    soc.send_to(dhcp_packet.buffer, dest).expect("failed to send");
                }
            },

            DHCPRELEASE => {
                println!("dhcp release");
            }

            _ => {
                println!("else: {}", message_type);
            }
        }
    } else {
        println!("not found");
    }
}

fn make_dhcp_packet<'a>(incoming_packet: &DhcpPacket, message_type: u8, buffer: &'a mut [u8], target_ip: Ipv4Addr) -> Result<DhcpPacket<'a>, io::Error>{
    let mut dhcp_packet = DhcpPacket::new(buffer).unwrap();
    dhcp_packet.set_op(BOOTREPLY);
    dhcp_packet.set_htype(HTYPE_ETHER);
    dhcp_packet.set_hlen(HLEN_MACADDR);
    dhcp_packet.set_xid(incoming_packet.get_xid());
    if incoming_packet.get_giaddr() != Ipv4Addr::new(0, 0, 0, 0) {
        dhcp_packet.set_flags(incoming_packet.get_flags());
    }
    dhcp_packet.set_yiaddr(&target_ip); //TODO: IPプールを用意
    dhcp_packet.set_chaddr(incoming_packet.get_chaddr());

    let mut cursor = OPTIONS;
    dhcp_packet.set_magic_cookie(&mut cursor);
    dhcp_packet.set_option(&mut cursor, OPTION_MESSAGE_TYPE_CODE, 1, Some(&mut vec![message_type]));
    dhcp_packet.set_option(&mut cursor, OPTION_IP_ADDRESS_LEASE_TIME, 4, Some(&mut vec![0,0,1,0])); //TODO: リースタイム変更
    dhcp_packet.set_option(&mut cursor, OPTION_SERVER_IDENTIFIER, 4, Some(&mut vec![127, 0, 0, 1]));
    dhcp_packet.set_option(&mut cursor, OPTION_END, 0, None);
    Ok(dhcp_packet)
}

