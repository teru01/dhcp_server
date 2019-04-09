use pnet::transport::{self, TransportProtocol::Ipv4};
use pnet::packet::ip;
use pnet::datalink;
use std::{ net, io, str, ptr };
use byteorder::{ByteOrder, NetworkEndian, LittleEndian};
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
    // op:      u8, /* 0: Message type */
    // htype:   u8, /* 1: Hardware addr type */
    // hlen:    u8, /* 2: Hardware addr length MACアドレスなら6で固定 */
    // hops:    u8, /* 3: agent hops from client */
    // xid:     u32, /* 4: Transaction ID */
    // secs:    u16, /* 8: seconds elapsed since client started to trying to boot */
    // flags:   u16, /* 10: flags */
    // ciaddr:  net::Ipv4Addr, /* 12: client ip addr 以前使っている値があるとき、それを通達する。リース延長のときなど */
    // yiaddr:  net::Ipv4Addr, /* 16: client ip addr */
    // siaddr:  net::Ipv4Addr, /* 20: ip addr of next server to use in bootstrap */
    // giaddr:  net::Ipv4Addr, /* 24: ip addr of relay agent */
    // chaddr:  [u8; 16], /* 28: client hardware address */
    // sname:   Vec<u8>, /* 44: optional server host name */
    // file:    Vec<u8>, /* 108: boot file name */
    // options: Vec<u8> /* 236: optionがどの用途に使われるのか? minで312 */
}

fn create_ip(buf: &[u8]) -> net::Ipv4Addr {
    net::Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3])
}

fn create_macaddr(buf: &[u8]) -> [u8; 16] {
    let mut ch = [0u8; 16];
    for i in 0..6 {
        ch[i] = buf[i];
    }
    ch
}

impl<'a> DhcpPacket<'a> {
    fn new(buf: &mut [u8]) -> Option<DhcpPacket>{
        let packet = DhcpPacket {
            buffer: buf
            // op:      buf[0],
            // htype:   buf[1],
            // hlen:    buf[2],
            // hops:    buf[3],
            // xid:     NetworkEndian::read_u32(&buf[4..8]),
            // secs:    NetworkEndian::read_u16(&buf[8..10]), /* 8: seconds elapsed since client started to trying to boot */
            // flags:   NetworkEndian::read_u16(&buf[10..12]), /* 10: flags */
            // ciaddr:  create_ip(&buf[12..16]), /* 12: client ip addr if already in use */
            // yiaddr:  create_ip(&buf[16..20]), /* 16: client ip addr */
            // siaddr:  create_ip(&buf[20..24]), /* 20: ip addr of next server to use in bootstrap */
            // giaddr:  create_ip(&buf[24..28]), /* 24: ip addr of relay agent */
            // chaddr:  create_macaddr(&buf[28..44]), /* 28: client hardware address */
            // sname:   buf[44..108].to_vec(), /* 44: optional server host name */
            // file:    buf[108..236].to_vec(), /* 108: boot file name */
            // options: buf[236..].to_vec()
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

    fn get_giaddr(&self) -> net::Ipv4Addr {
        let b = &self.buffer[GIADDR..CHADDR];
        net::Ipv4Addr::new(b[0], b[1], b[2], b[3])
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

    fn set_yiaddr(&mut self, yiaddr: &net::Ipv4Addr) {
        unsafe {
            ptr::copy_nonoverlapping(yiaddr.octets().as_ptr(), self.buffer[YIADDR..SIADDR].as_mut_ptr(), SIADDR - YIADDR);
        }
    }

    fn set_chaddr(&mut self, chaddr: &[u8]) {
        unsafe {
            ptr::copy_nonoverlapping(chaddr.as_ptr(), self.buffer[CHADDR..SNAME].as_mut_ptr(), SNAME - CHADDR);
        }
    }

    fn set_option(&mut self, cursor: &mut usize, message_type: u8, len: usize, contents: &[u8]){
        self.buffer[*cursor] = message_type;
        self.buffer[*cursor + 1] = len as u8;
        unsafe {
            ptr::copy_nonoverlapping(contents.as_ptr(), self.buffer[*cursor+2..].as_mut_ptr(), len);
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
        let mut index = 4; // 最初の4バイトはクッキー
        let options = self.get_options();
        while index < 255 {
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

fn main() {
    let server_socket = net::UdpSocket::bind("0.0.0.0:67")
                           .expect("Failed to bind socket");
    server_socket.set_broadcast(true).unwrap();
    loop {
        let mut buf = [0u8; 1024];
        match server_socket.recv_from(&mut buf) {
            Ok((size, src)) => {
                println!("incoming data from {}/size: {}", src, size);
                if let Some(dhcp_packet) = DhcpPacket::new(&mut buf[..size]) {
                    // dump_dhcp_info(&dhcp_packet);
                    dhcp_handler(&dhcp_packet, &server_socket, &src);
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

fn print_ip(n: u32) {
    let mut ip = [0u8; 4];
    for i in 0..4 {
        ip[i] = (n >> 8*(3-i) & 0xff) as u8;
    }
    println!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]);
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

unsafe fn any_as_u8_slice<T: Sized>(p: &T) -> &[u8] {
    ::std::slice::from_raw_parts((p as *const T) as *const u8, ::std::mem::size_of::<T>())
}

fn dhcp_handler(packet: &DhcpPacket, soc: &net::UdpSocket, dest: &net::SocketAddr) {
    if packet.get_op() != BOOTREQUEST {
        return;
    }
    // dhcpのヘッダ読み取り
    if let Some(message) = packet.get_option(OPTION_MESSAGE_TYPE_CODE) {
        let message_type = message[0];
        let mut packet_buffer = [0u8; DHCP_SIZE];
        match message_type {
            DHCPDISCOVER => {
                println!("dhcp discover");
                if let Ok(dhcp_packet) = make_dhcp_packet(&packet, DHCPOFFER, &mut packet_buffer) {
                    // let payload = dhcp_packet.buffer;
                    // dump_payload(payload);
                    // let payload = bincode::serialize(&dhcp_packet).unwrap();
                    soc.send_to(dhcp_packet.buffer, *dest).expect("failed to send");
                }
            },

            DHCPREQUEST => {
                println!("dhcp request");
                if let Ok(dhcp_packet) = make_dhcp_packet(&packet, DHCPACK, &mut packet_buffer) {
                    soc.send_to(dhcp_packet.buffer, *dest).expect("failed to send");
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
    // DHCPoffer送信

    // or DHCPACK送信
    // or リリース
}

const DHCP_SIZE:usize = 400;
const OPTION_IP_ADDRESS_LEASE_TIME: u8 = 51;
const OPTION_SERVER_IDENTIFIER: u8 = 54;

const WIDTH: usize = 20;

fn dump_payload(payload: &[u8]) {
    let len = payload.len();
    for i in 0..len {
        print!("{:<02X} ", payload[i]);
        if i%WIDTH == WIDTH-1 || i == len-1 {
            for _j in 0..WIDTH-1-(i % (WIDTH)) {
                print!("   ");
            }
            print!("| ");
            for j in i-i%WIDTH..i+1 {
                if payload[j].is_ascii_alphabetic() {
                    print!("{}", payload[j] as char);
                } else {
                    print!(".");
                }
            }
            print!("\n");
        }
    }

}

fn make_dhcp_packet<'a>(incoming_packet: &DhcpPacket, message_type: u8, buffer: &'a mut [u8]) -> Result<DhcpPacket<'a>, io::Error>{
    let mut dhcp_packet = DhcpPacket::new(buffer).unwrap();
    dhcp_packet.set_op(BOOTREPLY);
    dhcp_packet.set_htype(HTYPE_ETHER);
    dhcp_packet.set_hlen(HLEN_MACADDR);
    dhcp_packet.set_xid(incoming_packet.get_xid());
    if incoming_packet.get_giaddr() != net::Ipv4Addr::new(0, 0, 0, 0) {
        dhcp_packet.set_flags(incoming_packet.get_flags());
    }
    dhcp_packet.set_yiaddr(&"192.168.11.88".parse().unwrap()); //TODO: IPプールを用意
    dhcp_packet.set_chaddr(incoming_packet.get_chaddr());

    let mut cursor = OPTIONS;
    dhcp_packet.set_magic_cookie(&mut cursor);
    dhcp_packet.set_option(&mut cursor, OPTION_MESSAGE_TYPE_CODE, 1, &mut vec![message_type]);
    dhcp_packet.set_option(&mut cursor, OPTION_IP_ADDRESS_LEASE_TIME, 4, &mut vec![0,0,1,0]); //TODO: リースタイム変更
    dhcp_packet.set_option(&mut cursor, OPTION_SERVER_IDENTIFIER, 4, &mut vec![127, 0, 0, 1]);

    Ok(dhcp_packet)
}

