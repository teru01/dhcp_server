use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::{Mutex, RwLock};

use ipnetwork::Ipv4Network;
use pnet::packet::PrimitiveValues;
use pnet::util::MacAddr;
use rusqlite::Connection;

const OP: usize = 0;
const HTYPE: usize = 1;
const HLEN: usize = 2;
// const HOPS: usize = 3;
const XID: usize = 4;
const SECS: usize = 8;
const FLAGS: usize = 10;
const CIADDR: usize = 12;
const YIADDR: usize = 16;
const SIADDR: usize = 20;
const GIADDR: usize = 24;
const CHADDR: usize = 28;
const SNAME: usize = 44;
// const FILE: usize = 108;
pub const OPTIONS: usize = 236;

const DHCP_MINIMUM_SIZE: usize = 237;
const OPTION_END: u8 = 255;

use super::database;
use super::util;

pub struct DhcpPacket {
    buffer: Box<[u8]>,
}

impl DhcpPacket {
    pub fn new(buf: Box<[u8]>) -> Option<DhcpPacket> {
        if buf.len() > DHCP_MINIMUM_SIZE {
            let packet = DhcpPacket { buffer: buf };
            return Some(packet);
        }
        None
    }

    pub fn get_buffer(&self) -> &[u8] {
        self.buffer.as_ref()
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
        self.buffer[XID..SECS].copy_from_slice(xid);
    }

    pub fn set_yiaddr(&mut self, yiaddr: Ipv4Addr) {
        self.buffer[YIADDR..SIADDR].copy_from_slice(&yiaddr.octets());
    }

    pub fn set_flags(&mut self, flags: &[u8]) {
        self.buffer[FLAGS..CIADDR].copy_from_slice(flags);
    }

    pub fn set_giaddr(&mut self, giaddr: Ipv4Addr) {
        self.buffer[GIADDR..CHADDR].copy_from_slice(&giaddr.octets());
    }

    pub fn set_chaddr(&mut self, chaddr: MacAddr) {
        let t = chaddr.to_primitive_values();
        let macaddr_value = [t.0, t.1, t.2, t.3, t.4, t.5];
        // ここだけCHADDR..SNAMEでないのは、chaddrフィールドが16オクテット確保されているため。
        // 今回はMACアドレスしかこのフィールドに入らないので、MACアドレスのサイズである6オクテット確保している。
        self.buffer[CHADDR..CHADDR + 6].copy_from_slice(&macaddr_value);
    }

    pub fn set_option(
        &mut self,
        cursor: &mut usize,
        code: u8,
        len: usize,
        contents: Option<&[u8]>,
    ) {
        // オプションにはコード番号、サイズ、値を順番に入れる
        self.buffer[*cursor] = code;
        if code == OPTION_END {
            // 値は存在しないため
            return;
        }
        *cursor += 1;
        self.buffer[*cursor] = len as u8;
        *cursor += 1;
        if let Some(contents) = contents {
            self.buffer[*cursor..*cursor + contents.len()].copy_from_slice(contents);
        }
        *cursor += len;
    }

    pub fn set_magic_cookie(&mut self, cursor: &mut usize) {
        self.buffer[*cursor..*cursor + 4].copy_from_slice(&[0x63, 0x82, 0x53, 0x63]);
        *cursor += 4;
    }

    pub fn get_option(&self, option_code: u8) -> Option<Vec<u8>> {
        // 最初の4バイトはクッキーなので飛ばす
        let mut index: usize = 4;
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
                index += 1;
                let len = options[index];
                index += 1;
                index += len as usize;
            }
        }
        None
    }
}


/**
 * DHCPサーバの情報を保持する。
 * 複数のスレッドで共有されるため、フィールドにmutアクセスする際はロックを取得する必要がある。
 * 読み出しだけならフィールドにロックは必要ない。
 */
pub struct DhcpServer {
    address_pool: RwLock<Vec<Ipv4Addr>>,   // 利用可能なアドレス。
    pub db_connection: Mutex<Connection>, // ConnectionはSyncを実装しないのでRwLockではだめ。
    pub server_address: Ipv4Addr,
    pub default_gateway: Ipv4Addr,
    pub subnet_mask: Ipv4Addr,
    pub dns_server: Ipv4Addr,
    pub lease_time: Vec<u8>,
}

impl DhcpServer {
    pub fn new() -> Result<DhcpServer, failure::Error> {
        let env = util::load_env();

        // DNSやゲートウェイなどのアドレス
        let static_addresses = util::obtain_static_addresses(&env)?;

        let con = Connection::open("dhcp.db")?;

        let addr_pool = Self::init_address_pool(&con, &static_addresses)?;
        info!(
            "There are {} addresses in the address pool",
            addr_pool.len()
        );

        let lease_v = util::make_vec_from_u32(
            env.get("LEASE_TIME")
                .expect("Missing lease_time")
                .parse()
                .unwrap(),
        )?;

        Ok(DhcpServer {
            address_pool: RwLock::new(addr_pool),
            db_connection: Mutex::new(con),
            server_address: static_addresses["dhcp_server_addr"],
            default_gateway: static_addresses["default_gateway"],
            subnet_mask: static_addresses["subnet_mask"],
            dns_server: static_addresses["dns_addr"],
            lease_time: lease_v,
        })
    }

    // 新たなホストに割り当て可能なアドレスプールを初期化
    fn init_address_pool(
        con: &Connection,
        static_addresses: &HashMap<String, Ipv4Addr>
    ) -> Result<Vec<Ipv4Addr>, failure::Error> {
        let network_addr = static_addresses.get("network_addr").unwrap();
        let prefix = ipnetwork::ipv4_mask_to_prefix(*static_addresses.get("subnet_mask").unwrap())?;
        let network_addr_with_prefix = Ipv4Network::new(*network_addr, prefix)?;
        let default_gateway = static_addresses.get("default_gateway").unwrap();
        let dhcp_server_addr = static_addresses.get("dhcp_server_addr").unwrap();
        let dns_server_addr = static_addresses.get("dns_addr").unwrap();
        let broadcast = network_addr_with_prefix.broadcast();

        // すでに使用されていて、リリースもされていないアドレス
        let mut used_ip_addrs = database::select_addresses(con, Some(0))?;

        used_ip_addrs.push(*network_addr);
        used_ip_addrs.push(*default_gateway);
        used_ip_addrs.push(*dhcp_server_addr);
        used_ip_addrs.push(*dns_server_addr);
        used_ip_addrs.push(broadcast);

        // ネットワークの全てのアドレスから静的に割り振られているアドレスを除いたものを
        // アドレスプールとする。
        let mut addr_pool: Vec<Ipv4Addr> = network_addr_with_prefix
            .iter()
            .filter(|addr| !used_ip_addrs.contains(addr))
            .collect();
        addr_pool.reverse();

        Ok(addr_pool)
    }

    pub fn pick_available_ip(&self) -> Option<Ipv4Addr> {
        let mut lock = self.address_pool.write().unwrap();
        lock.pop()
    }

    // pub fn get_available_ip(&self) -> Option<Ipv4Addr> {
    //     let mut lock = self.address_pool.write().unwrap();
    //     // ここで返したものを後にpop()で削除するかもしれないので、最後の値を返す。
    //     lock[lock.len() - 1]
    // }

    pub fn pick_specified_ip(&self, requested_ip: Ipv4Addr) -> Option<Ipv4Addr> {
        let mut lock = self.address_pool.write().unwrap();
        for i in 0..lock.len() {
            if lock[i] == requested_ip {
                return Some(lock.remove(i));
            }
        }
        None
    }

    // ベクタの先頭にアドレスを返す。
    // ベクタの後方からリースされていくため、返されたアドレスは当分他のホストにリースされない
    pub fn release_address(&self, released_ip: Ipv4Addr) {
        let mut lock = self.address_pool.write().unwrap();
        lock.insert(0, released_ip);
    }
}
