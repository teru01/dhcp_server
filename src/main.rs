use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::mpsc;
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::Duration;
use std::{env, fs, io, net, ptr, str};

use pnet::packet::icmp::echo_request::{EchoRequestPacket, MutableEchoRequestPacket};
use pnet::packet::icmp::IcmpTypes;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::{Packet, PrimitiveValues};
use pnet::transport::{
    self, icmp_packet_iter, TransportChannelType, TransportProtocol::Ipv4, TransportReceiver,
    TransportSender,
};
// use pnet::datalink::MacAddr;
use pnet::util::checksum;
use pnet::util::MacAddr;

use ipnetwork::Ipv4Network;

use failure;

use byteorder::{BigEndian, ByteOrder};

#[macro_use]
extern crate log;

use env_logger;
use log::{debug, error, info, warn};

extern crate rusqlite;

use rusqlite::NO_PARAMS;
use rusqlite::{Connection, RowIndex, Rows};

/*
TODO
バイト列からDHCPパケットの生成
DHCPパケットを作成してフィールドを埋める
任意のDHCPメッセージを送信
ブロードキャストされたDHCPリクエストに対して返信
*/

const HTYPE_ETHER: u8 = 1;
const HLEN_MACADDR: u8 = 6;

const DHCP_SIZE: usize = 400;

enum Code {
    MessageType = 53,
    IPAddressLeaseTime = 51,
    ServerIdentifier = 54,
    RequestedIpAddress = 50,
    End = 255,
}

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
fn test_is_ipaddr_already_in_use() {
    assert_eq!(
        true,
        is_ipaddr_already_in_use(&"192.168.111.1".parse().unwrap()).unwrap()
    );
}

fn create_default_icmp_buffer() -> [u8; 8] {
    let mut buffer = [0u8; 8];
    let mut icmp_packet = MutableEchoRequestPacket::new(&mut buffer).unwrap();
    icmp_packet.set_icmp_type(IcmpTypes::EchoRequest);
    let checksum = checksum(icmp_packet.to_immutable().packet(), 16);
    icmp_packet.set_checksum(checksum);
    return buffer;
}

// IPアドレスが既に使用されているか調べる。
// TODO: tr, tsはArcを使えば生成は1回だけで良い？
fn is_ipaddr_already_in_use(target_ip: &Ipv4Addr) -> Result<bool, failure::Error> {
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

type LeaseEntry = HashMap<MacAddr, Ipv4Addr>;

struct DhcpServer {
    used_ipaddr_table: RwLock<LeaseEntry>, //MACアドレスとリースIPのマップ
    address_pool: RwLock<Vec<Ipv4Addr>>,   //利用可能なアドレス。降順に並ぶ。
    transaction_list: RwLock<Vec<u32>>,    //トランザクションIDのベクタ
    server_address: Ipv4Addr,
    default_gateway: Ipv4Addr,
}

#[test]
fn test_init_address_pool() {
    let mut used_ip = LeaseEntry::new();
    used_ip.insert(
        "f4:0f:24:27:aa:00".parse().unwrap(),
        "192.168.111.3".parse().unwrap(),
    );
    used_ip.insert(
        "f4:0f:24:27:ee:00".parse().unwrap(),
        "192.168.111.23".parse().unwrap(),
    );
    used_ip.insert(
        "f4:0f:24:27:db:00".parse().unwrap(),
        "192.168.111.10".parse().unwrap(),
    );
    let mut env = HashMap::new();
    env.insert("NETWORK_ADDR".to_string(), "192.168.111.0/24".to_string());
    env.insert("DEFAULT_GATEWAY".to_string(), "192.168.111.1".to_string());
    env.insert("SERVER_IDENTIFIER".to_string(), "192.168.111.2".to_string());
    let v = match DhcpServer::init_address_pool(&used_ip, &env) {
        Ok(v) => v,
        Err(e) => {
            println!("{:?}", e);
            return;
        }
    };
    assert_eq!(v.len(), 249);
}

impl DhcpServer {
    fn new() -> Result<DhcpServer, failure::Error> {
        // envから設定情報の読み込み
        // アドレスプールの設定、使用中マップの
        let env = Self::load_env();

        let used_ipaddr_table = Self::init_used_ipaddr_table()?;
        info!("There are {} leased entries", used_ipaddr_table.len());

        let addr_pool = Self::init_address_pool(&used_ipaddr_table, &env)?;
        info!(
            "There are {} addresses in the address pool",
            addr_pool.len()
        );

        return Ok(DhcpServer {
            used_ipaddr_table: RwLock::new(used_ipaddr_table),
            address_pool: RwLock::new(addr_pool),
            transaction_list: RwLock::new(Vec::new()),
            server_address: env
                .get("SERVER_IDENTIFIER")
                .expect("Missing server_identifier")
                .parse()?,
            default_gateway: env
                .get("DEFAULT_GATEWAY")
                .expect("Missing default_gateway")
                .parse()?,
        });
    }

    // 新たなホストに割り当て可能なアドレスプールを初期化
    // ネットワーク中のアドレスからデフォルトゲートウェイ、DHCPサーバ自身、
    // ブロードキャストアドレス、ネットワークアドレス、すでに割り当て済みのIPアドレスを除く
    fn init_address_pool(
        used_ipaddr_table: &LeaseEntry,
        env: &HashMap<String, String>,
    ) -> Result<Vec<Ipv4Addr>, failure::Error> {
        let network_addr_with_prefix: Ipv4Network = env
            .get("NETWORK_ADDR")
            .expect("Missing NETWORK_ADDR")
            .parse()?;

        let default_gateway = env
            .get("DEFAULT_GATEWAY")
            .expect("Missing DEFAULT_GATEWAY")
            .parse()?;

        let dhcp_server_addr = env
            .get("SERVER_IDENTIFIER")
            .expect("Missing SERVER_IDENTIFIER")
            .parse()?;

        let network_addr = network_addr_with_prefix.network();
        let broadcast = network_addr_with_prefix.broadcast();

        let mut used_ip_addrs: Vec<&Ipv4Addr> = used_ipaddr_table.values().collect();

        used_ip_addrs.push(&default_gateway);
        used_ip_addrs.push(&dhcp_server_addr);
        used_ip_addrs.push(&network_addr);
        used_ip_addrs.push(&broadcast);

        let addr_pool: Vec<_> = network_addr_with_prefix
            .iter() //0〜255までイテレートする
            .filter(|addr| !used_ip_addrs.contains(&addr))
            .collect();

        return Ok(addr_pool);
    }

    // DBから使用中のIP情報を取得する
    fn init_used_ipaddr_table() -> Result<LeaseEntry, failure::Error> {
        let mut used_ip_map = LeaseEntry::new();

        let con = Connection::open("dhcp.db")?;
        let mut statement = con.prepare("SELECT (macaddr, ipaddr) FROM `lease_entry`")?;
        let mut entries: Rows = statement.query(NO_PARAMS)?;
        while let Some(entry) = entries.next()? {
            let mac_addr: MacAddr = match entry.get(0) {
                Ok(mac) => {
                    let mac_string: String = mac;
                    mac_string.parse().unwrap()
                }
                Err(_) => continue,
            };

            let ip_addr = match entry.get(1) {
                Ok(ip) => {
                    let ip_string: String = ip;
                    ip_string.parse().unwrap()
                }
                Err(_) => continue,
            };

            used_ip_map.insert(mac_addr, ip_addr);
        }
        Ok(used_ip_map)
    }

    // 環境情報を読んでハッシュマップを返す
    fn load_env() -> HashMap<String, String> {
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

    fn insert_entry(&self, key: MacAddr, value: Ipv4Addr) {
        // 利用中IPアドレスのテーブルにinsertする。insertしたら即ロックを解放する。
        let mut table_lock = self.used_ipaddr_table.write().unwrap();
        table_lock.insert(key, value);
    }

    fn get_entry(&self, key: MacAddr) -> Option<Ipv4Addr> {
        let mut table_lock = self.used_ipaddr_table.read().unwrap();
        match table_lock.get(&key) {
            Some(ip) => return Some(ip.clone()),
            None => return None,
        };
    }

    // ロックを取得し、アドレスプールの最後を引き抜いて返す
    fn pick_available_ip(&self) -> Option<Ipv4Addr> {
        let mut lock = self.address_pool.write().unwrap();
        return lock.pop();
    }

    // ロックを取得し、アドレスプールから指定のアドレスを検索し、それを引き抜いて返す
    fn pick_specified_ip(&self, requested_ip: &Ipv4Addr) -> Option<Ipv4Addr> {
        let mut lock = self.address_pool.write().unwrap();
        // 線形探索。2分探索もあり
        for i in 0..lock.len() {
            if &lock[i] == requested_ip {
                let ip_to_be_leased = lock[i].clone();
                lock.remove(i);
                return Some(ip_to_be_leased);
            }
        }
        None
    }

    // fn remove_specified_ip(&self, )

    fn add_transaction_id(&self, id: u32) {}
}

fn main() {
    env::set_var("RUST_LOG", "debug");
    env_logger::init();

    let server_socket = net::UdpSocket::bind("0.0.0.0:67").expect("Failed to bind socket");
    server_socket.set_broadcast(true).unwrap();

    let dhcp_server = Arc::new(match DhcpServer::new() {
        Ok(dhcp) => dhcp,
        Err(e) => {
            panic!("Failed to start dhcp server. {:?}", e);
        }
    });

    loop {
        let mut recv_buf = [0u8; 1024];
        match server_socket.recv_from(&mut recv_buf) {
            Ok((size, src)) => {
                info!("Incoming data from {}, size: {}", src, size);
                let client_socket = server_socket
                    .try_clone()
                    .expect("Failed to create client socket");
                let cloned_dhcp_server = dhcp_server.clone();

                thread::spawn(move || {
                    if let Some(dhcp_packet) = DhcpPacket::new(&mut recv_buf[..size]) {
                        if dhcp_packet.get_op() == BOOTREQUEST {
                            dhcp_handler(&dhcp_packet, &client_socket, cloned_dhcp_server);
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

fn u8_to_ipv4addr(buf: &[u8]) -> Result<Ipv4Addr, failure::Error> {
    if buf.len() == 4 {
        return Ok(Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]));
    } else {
        return Err(failure::err_msg("Could not get ip addr."));
    }
}

// オプションからリクエストされたIPアドレスがあり、利用可能ならばそれを返す。
fn obtain_available_ip_from_requested_option(
    dhcp_server: Arc<DhcpServer>,
    received_packet: &DhcpPacket,
) -> Result<Ipv4Addr, failure::Error> {
    if let Some(ip) = received_packet.get_option(Code::RequestedIpAddress as u8) {
        let requested_ip = u8_to_ipv4addr(&ip)?;
        // アドレスプールからの検索
        if let Some(ip_from_pool) = dhcp_server.pick_specified_ip(&requested_ip) {
            let used = is_ipaddr_already_in_use(&ip_from_pool)?;
            if !used {
                return Ok(requested_ip);
            }
        }
    }
    // 本当はエラーじゃないのでエラーにするのは如何なものか。
    return Err(failure::err_msg("not specify requested ip address"));
}

// 利用可能なIPアドレスを探す。
// 要求されたものがあればそれを返し、
// 以前リースされたものがあればそれを返し、
// アドレスプールから利用可能なIPアドレスを返却する。
fn select_lease_ip(
    dhcp_server: Arc<DhcpServer>,
    received_packet: &DhcpPacket,
) -> Result<Ipv4Addr, failure::Error> {
    // Requested Ip Addrオプションからの取得
    if let Ok(ip_to_be_leased) =
        obtain_available_ip_from_requested_option(dhcp_server.clone(), &received_packet)
    {
        dhcp_server.insert_entry(received_packet.get_chaddr(), ip_to_be_leased);
        return Ok(ip_to_be_leased);
    }

    // usedからの取得
    if let Some(ip_from_used) = dhcp_server.get_entry(received_packet.get_chaddr()) {
        if let Ok(in_use) = is_ipaddr_already_in_use(&ip_from_used) {
            if !in_use {
                return Ok(ip_from_used);
            }
        }
    }

    // アドレスプールからの取得
    while let Some(ip_addr) = dhcp_server.pick_available_ip() {
        match is_ipaddr_already_in_use(&ip_addr) {
            Ok(used) => {
                if !used {
                    return Ok(ip_addr.clone());
                }
            }
            Err(msg) => {
                warn!("{}", msg);
            }
        }
    }
    return Err(failure::err_msg("Could not obtain available ip address."));
}

fn dhcp_handler(packet: &DhcpPacket, soc: &net::UdpSocket, dhcp_server: Arc<DhcpServer>) {
    // dhcpのヘッダ読み取り
    if let Some(message) = packet.get_option(Code::MessageType as u8) {
        let message_type = message[0];
        let mut packet_buffer = [0u8; DHCP_SIZE];
        let dest: net::SocketAddr = "255.255.255.255:68".parse().unwrap(); //TODO: ブロードキャストをユニキャストに
        let transaction_id = BigEndian::read_u32(packet.get_xid());

        match message_type {
            DHCPDISCOVER => {
                // DISCOVERを受け取った時。
                // OFFERを返却する。
                // この際、クライアントのrequested ip address、chaddrで照合した以前リースしたIP、アドレスプールから選んだ値の優先順にIPを選んで返す
                // chaddrと返したIPのマップ、トランザクションIDを記録しておく
                debug!("dhcp discover");

                // DBアクセス。以前リースしたやつがあればそれを再び渡す
                // IPアドレスの決定
                let ip_to_be_leased = match select_lease_ip(dhcp_server.clone(), &packet) {
                    Ok(ip) => ip,
                    Err(msg) => {
                        // 付与できるIPがない場合。エラーを報告する。
                        // TODO: DHCPNAKをクライアントに送信する。
                        error!("{}", msg);
                        return;
                    }
                };

                {
                    // 利用中IPアドレスのテーブルにinsertする。insertしたら即ロックを解放する。
                    let mut table_lock = dhcp_server.used_ipaddr_table.write().unwrap();
                    table_lock.insert(packet.get_chaddr(), ip_to_be_leased);
                }

                if let Ok(dhcp_packet) =
                    make_dhcp_packet(&packet, DHCPOFFER, &mut packet_buffer, &ip_to_be_leased)
                {
                    soc.send_to(dhcp_packet.get_buffer(), dest)
                        .expect("failed to send");
                    println!("send dhcp offer");
                }
                return;
            }

            DHCPREQUEST => {
                // クライアントからのリクエストを受け取る。
                // トランザクションIDがあるか確認

                // OFFERに対する返答（server_identifierがあるとき）自分と異なるなら破棄、別のDHCPが選ばれたから
                // リース期間などで変更されてるかもしれないので確認
                // 問題なければACKを返して、DBにマップをコミット
                // 問題あればNAKを返して、マップからエントリーを削除
                // リース延長、更新（server_idがない時)
                //ciaddrでレコード検索して、一致するものがあれば返す。なければNACK
                debug!("dhcp request");
                // TODO: DBに使用ずみをコミット
                let ip_to_be_leased = {
                    match dhcp_server.get_entry(packet.get_chaddr()) {
                        Some(ip) => ip.clone(),
                        None => return,
                    }
                };

                if let Ok(dhcp_packet) =
                    make_dhcp_packet(&packet, DHCPACK, &mut packet_buffer, &ip_to_be_leased)
                {
                    soc.send_to(dhcp_packet.get_buffer(), dest)
                        .expect("Failed to send");
                }
                return;
            }

            DHCPRELEASE => {
                // IPを利用可能としてアドレスプールに戻す
                // マップからエントリの削除。アドレスプールへの追加
                debug!("dhcp release");
                return;
            }

            DHCPDECLINE => {
                // クライアントがARPした際に衝突していたらこれが届く。
                // 利用不可能なIPとしてマークする。=> アドレスプールからの削除
                debug!("dhcp decline");
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
    target_ip: &Ipv4Addr,
) -> Result<DhcpPacket<'a>, io::Error> {
    let mut dhcp_packet = DhcpPacket::new(buffer).unwrap();
    dhcp_packet.set_op(BOOTREPLY);
    dhcp_packet.set_htype(HTYPE_ETHER);
    dhcp_packet.set_hlen(HLEN_MACADDR);
    dhcp_packet.set_xid(incoming_packet.get_xid());
    if incoming_packet.get_giaddr() != Ipv4Addr::new(0, 0, 0, 0) {
        dhcp_packet.set_flags(incoming_packet.get_flags());
    }
    dhcp_packet.set_yiaddr(target_ip);
    let client_macaddr = incoming_packet.get_chaddr();
    dhcp_packet.set_chaddr(&client_macaddr);

    let mut cursor = dhcp::OPTIONS;
    dhcp_packet.set_magic_cookie(&mut cursor);
    dhcp_packet.set_option(
        &mut cursor,
        Code::MessageType as u8,
        1,
        Some(&mut vec![message_type]),
    );
    dhcp_packet.set_option(
        &mut cursor,
        Code::IPAddressLeaseTime as u8,
        4,
        Some(&mut vec![0, 0, 1, 0]),
    ); //TODO: リースタイム変更
    dhcp_packet.set_option(
        &mut cursor,
        Code::ServerIdentifier as u8,
        4,
        Some(&mut vec![127, 0, 0, 1]),
    ); // TODO: DHCPサーバのIP
    dhcp_packet.set_option(&mut cursor, Code::End as u8, 0, None);
    Ok(dhcp_packet)
}
