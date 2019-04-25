use std::ptr;
use std::net::Ipv4Addr;

use pnet::datalink::MacAddr;
use pnet::packet::PrimitiveValues;

const OP: usize = 0;
const HTYPE: usize = 1;
const HLEN: usize = 2;
const HOPS: usize = 3;
const XID: usize = 4;
const SECS: usize = 8;
const FLAGS: usize = 10;
const CIADDR: usize = 12;
const YIADDR: usize = 16;
const SIADDR: usize = 20;
const GIADDR: usize = 24;
const CHADDR: usize = 28;
const SNAME: usize = 44;
const FILE: usize = 108;
pub const OPTIONS: usize = 236;

const DHCP_MINIMUM_SIZE: usize = 237;
const OPTION_END: u8 = 255;

pub struct DhcpPacket<'a> {
    buffer: &'a mut [u8],
}

impl<'a> DhcpPacket<'a> {
    pub fn new(buf: &mut [u8]) -> Option<DhcpPacket> {
        if buf.len() > DHCP_MINIMUM_SIZE {
            let packet = DhcpPacket { buffer: buf };
            return Some(packet);
        }
        None
    }

    pub fn get_buffer(&self) -> &[u8] {
        self.buffer
    }

    pub fn get_op(&self) -> u8 {
        self.buffer[OP]
    }

    pub fn get_options(&self) -> &[u8] {
        &self.buffer[OPTIONS..]
    }

    pub fn get_xid(&self) -> &[u8] {
        &self.buffer[XID..SECS]
    }

    pub fn get_flags(&self) -> &[u8] {
        &self.buffer[FLAGS..CIADDR]
    }

    pub fn get_giaddr(&self) -> Ipv4Addr {
        let b = &self.buffer[GIADDR..CHADDR];
        Ipv4Addr::new(b[0], b[1], b[2], b[3])
    }

    pub fn get_chaddr(&self) -> MacAddr {
        let b = &self.buffer[CHADDR..SNAME];
        MacAddr::new(b[0], b[1], b[2], b[3], b[4], b[5])
    }

    pub fn get_ciaddr(&self) -> Ipv4Addr {
        let b = &self.buffer[CIADDR..YIADDR];
        Ipv4Addr::new(b[0], b[1], b[2], b[3])
    }

    pub fn set_op(&mut self, op: u8) {
        self.buffer[OP] = op;
    }

    pub fn set_htype(&mut self, htype: u8) {
        self.buffer[HTYPE] = htype;
    }

    pub fn set_hlen(&mut self, hlen: u8) {
        self.buffer[HLEN] = hlen;
    }

    pub fn set_xid(&mut self, xid: &[u8]) {
        unsafe {
            ptr::copy_nonoverlapping(
                xid.as_ptr(),
                self.buffer[XID..SECS].as_mut_ptr(),
                SECS - XID,
            );
        }
    }

    pub fn set_flags(&mut self, flags: &[u8]) {
        unsafe {
            ptr::copy_nonoverlapping(
                flags.as_ptr(),
                self.buffer[FLAGS..CIADDR].as_mut_ptr(),
                CIADDR - FLAGS,
            );
        }
    }

    pub fn set_yiaddr(&mut self, yiaddr: &Ipv4Addr) {
        unsafe {
            ptr::copy_nonoverlapping(
                yiaddr.octets().as_ptr(),
                self.buffer[YIADDR..SIADDR].as_mut_ptr(),
                SIADDR - YIADDR,
            );
        }
    }

    pub fn set_chaddr(&mut self, chaddr: &MacAddr) {
        let t = chaddr.to_primitive_values();
        let macaddr_value = [t.0, t.1, t.2, t.3, t.4, t.5];
        unsafe {
            ptr::copy_nonoverlapping(
                macaddr_value.as_ptr(),
                self.buffer[CHADDR..SNAME].as_mut_ptr(),
                SNAME - CHADDR,
            );
        }
    }

    pub fn set_option(
        &mut self,
        cursor: &mut usize,
        message_type: u8,
        len: usize,
        contents: Option<&[u8]>,
    ) {
        self.buffer[*cursor] = message_type;
        if message_type == OPTION_END {
            return;
        }
        self.buffer[*cursor + 1] = len as u8;

        if let Some(contents) = contents {
            unsafe {
                ptr::copy_nonoverlapping(
                    contents.as_ptr(),
                    self.buffer[*cursor + 2..].as_mut_ptr(),
                    len,
                );
            }
        }
        *cursor += 2 + len; //message_type + len + buffer;
    }

    pub fn set_magic_cookie(&mut self, cursor: &mut usize) {
        unsafe {
            ptr::copy_nonoverlapping(
                [0x63, 0x82, 0x53, 0x63].as_ptr(),
                self.buffer[*cursor..].as_mut_ptr(),
                4,
            );
        }
        *cursor += 4;
    }

    //optionはcode, length, bufferの順に並んでいる
    pub fn get_option(&self, option_code: u8) -> Option<Vec<u8>> {
        let mut index: usize = 4; // 最初の4バイトはクッキー
        let options = self.get_options();
        while options[index] != OPTION_END {
            if options[index] == option_code {
                let len = options[index + 1];
                let buf_index = index + 2;
                let v = options[buf_index..buf_index + len as usize].to_vec();
                return Some(v);
            } else if options[index] == 0 {
                index += 1;
            } else {
                index += 1; // on the 'len' field
                let len = options[index];
                index += 1; // on the first byte of value.
                index += len as usize;
            }
        }
        None
    }
}
