use std::net::Ipv4Addr;
use std::sync::Arc;
use std::thread;
use std::{env, io, net};

use failure;

use byteorder::{BigEndian, ByteOrder};

#[macro_use]
extern crate log;

use env_logger;
use log::{debug, error, info, warn};

const HTYPE_ETHER: u8 = 1;
const HLEN_MACADDR: u8 = 6;

const DHCP_SIZE: usize = 400;

enum Code {
    MessageType = 53,
    IPAddressLeaseTime = 51,
    ServerIdentifier = 54,
    RequestedIpAddress = 50,
    SubnetMask = 1,
    Router = 3,
    DNS = 6,
    End = 255,
}

const DHCPDISCOVER: u8 = 1;
const DHCPOFFER: u8 = 2;
const DHCPREQUEST: u8 = 3;
const DHCPACK: u8 = 5;
const DHCPNAK: u8 = 6;
const DHCPRELEASE: u8 = 7;

const BOOTREQUEST: u8 = 1;
const BOOTREPLY: u8 = 2;

mod dhcp;
use dhcp::DhcpPacket;
use dhcp::DhcpServer;

mod database;
mod util;

fn main() {
    // ログの設定
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
                    if let Some(dhcp_packet) = DhcpPacket::new(Box::new(recv_buf)) {
                        if dhcp_packet.get_op() != BOOTREQUEST {
                            // クライアントからのリクエストでなければ無視
                            return;
                        }
                        if let Err(e) =
                            dhcp_handler(&dhcp_packet, &client_socket, cloned_dhcp_server)
                        {
                            error!("{}", e);
                        }
                    }
                });
            }
            Err(e) => {
                error!("Could not recieve a datagram: {}", e);
            }
        }
    }
}

/**
 * DHCPリクエストを解析してレスポンスを返す。
 */
fn dhcp_handler(
    packet: &DhcpPacket,
    soc: &net::UdpSocket,
    dhcp_server: Arc<DhcpServer>,
) -> Result<(), failure::Error> {
    // DHCPのヘッダ読み取り
    let message = match packet.get_option(Code::MessageType as u8) {
        Some(m) => m,
        None => {
            return Err(failure::err_msg("specified option was not found"));
        }
    };
    let message_type = message[0];
    let dest: net::SocketAddr = "255.255.255.255:68".parse().unwrap();
    let transaction_id = BigEndian::read_u32(packet.get_xid());
    let client_macaddr = packet.get_chaddr();

    match message_type {
        DHCPDISCOVER => {
            //DISCOVERを受信した時。利用できるアドレスを選択してOFFERを返却する。

            info!("{:x}: received DHCPDISCOVER", transaction_id);

            // IPアドレスの決定
            let ip_to_be_leased = select_lease_ip(dhcp_server.clone(), &packet)?;

            // リーステーブルにエントリを追加する。
            dhcp_server.insert_entry(client_macaddr, ip_to_be_leased);

            // 決定したリースIPでDHCPパケットの作成
            let dhcp_packet = make_dhcp_packet(&packet, &dhcp_server, DHCPOFFER, &ip_to_be_leased)?;
            soc.send_to(dhcp_packet.get_buffer(), dest)?;

            info!("{:x}: sent DHCPOFFER", transaction_id);
            return Ok(());
        }

        DHCPREQUEST => {
            // REQUESTを受け取った時
            // ACKを返してリース情報をコミットする。
            match packet.get_option(Code::ServerIdentifier as u8) {
                Some(server_id) => {
                    // レスポンスのオプションにserver_identifierが含まれる場合。
                    // サーバが返したOFFERに対する返答を処理する。

                    info!("{:x}: received DHCPREQUEST with server_id", transaction_id);
                    let server_ip = util::u8_to_ipv4addr(&server_id)?;

                    if server_ip != dhcp_server.server_address {
                        // クライアントが別のDHCPサーバを選択した場合。

                        info!("Client has chosen another dhcp server.");
                        // リーステーブルとアドレスプールを元に戻す。
                        if let Some(ip) = dhcp_server.pick_entry(client_macaddr) {
                            dhcp_server.push_address(ip);
                        }

                        debug!("deleted from lease_entries");
                        return Ok(());
                    }

                    let ip_to_be_leased = dhcp_server.get_entry(client_macaddr).unwrap();

                    // コネクションのロックを取得してクリティカルセクションの開始。
                    let mut con = dhcp_server.db_connection.lock().unwrap();
                    let tx = con.transaction()?;
                    // macaddrがすでに存在する場合がある。（起動後DBに保存されていたもの、または途中で要求するIPを変更する場合）
                    let count = database::count_records_by_mac_addr(&tx, &client_macaddr)?;
                    match count {
                        // レコードがないならinsert
                        0 => database::insert_entry(&tx, &client_macaddr, &ip_to_be_leased)?,
                        // レコードがあるならupdate
                        _ => database::update_entry(&tx, &client_macaddr, &ip_to_be_leased)?,
                    }

                    let dhcp_packet =
                        make_dhcp_packet(&packet, &dhcp_server, DHCPACK, &ip_to_be_leased)?;
                    soc.send_to(dhcp_packet.get_buffer(), dest)?;
                    info!("{:x}: sent DHCPACK", transaction_id);

                    // トランザクションの終了
                    tx.commit()?;
                    // ロックを解放してクリティカルセクションの終了
                    drop(con);

                    debug!("{:x}: leased address: {}", transaction_id, ip_to_be_leased);
                    match count {
                        0 => debug!("{:x}: inserted into DB", transaction_id),
                        _ => debug!("{:x}: updated DB", transaction_id),
                    }
                    return Ok(());
                }
                None => {
                    // レスポンスのオプションにserver_identifierが含まれない場合。
                    // IPリース延長要求などを処理する。

                    info!(
                        "{:x}: received DHCPREQUEST without server_id",
                        transaction_id
                    );

                    let ip_to_be_leased = dhcp_server.get_entry(client_macaddr).unwrap();
                    let prev_ip = packet.get_ciaddr();
                    if prev_ip != ip_to_be_leased {
                        // 以前リースした値とクライアントのciaddrが一致しない場合はNAKを返す。
                        let dhcp_packet =
                            make_dhcp_packet(&packet, &dhcp_server, DHCPNAK, &prev_ip)?;
                        soc.send_to(dhcp_packet.get_buffer(), dest)?;
                        info!("{:x}: sent DHCPNAK", transaction_id);
                        return Ok(());
                    }

                    // ACKを返す。
                    let dhcp_packet =
                        make_dhcp_packet(&packet, &dhcp_server, DHCPACK, &ip_to_be_leased)?;
                    soc.send_to(dhcp_packet.get_buffer(), dest)?;
                    info!("{:x}: sent DHCPACK", transaction_id);
                    return Ok(());
                },
            }
        }

        DHCPRELEASE => {
            // RELEASEを受信した時。
            // DBからリース記録、リーステーブルからエントリを削除し、
            // リースしていたIPアドレスをアドレスプールに戻す。
            info!("{:x}: received DHCPRELEASE", transaction_id);

            // コネクションのロックを取得してクリティカルセクションの開始。
            let mut con = dhcp_server.db_connection.lock().unwrap();
            let tx = con.transaction()?;
            database::delete_entry(&tx, &client_macaddr)?;
            tx.commit()?;
            // コネクションのロックを解放してクリティカルセクションの終了。
            drop(con);

            debug!("{:x}: deleted from DB", transaction_id);
            // リーステーブルからIPアドレスを取り出しアドレスプールに戻す。
            if let Some(ip) = dhcp_server.pick_entry(client_macaddr) {
                dhcp_server.push_address(ip);
            }
            return Ok(());
        }

        _ => {
            // 未実装のメッセージを受信した場合。

            let msg = format!("{:x}: received unimplemented message, message_type:{}",
                transaction_id, message_type);
            return Err(failure::err_msg(msg));
        }
    }
}

// オプションからリクエストされたIPアドレスがあり、利用可能ならばそれを返す。
fn obtain_available_ip_from_requested_option(
    dhcp_server: Arc<DhcpServer>,
    received_packet: &DhcpPacket,
) -> Result<Ipv4Addr, failure::Error> {
    if let Some(ip) = received_packet.get_option(Code::RequestedIpAddress as u8) {
        let requested_ip = util::u8_to_ipv4addr(&ip)?;
        // アドレスプールからの検索
        if let Some(ip_from_pool) = dhcp_server.pick_specified_ip(&requested_ip) {
            let used = util::is_ipaddr_already_in_use(&ip_from_pool)?;
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
        if let Ok(in_use) = util::is_ipaddr_already_in_use(&ip_from_used) {
            if !in_use {
                return Ok(ip_from_used);
            }
        }
    }

    // アドレスプールからの取得
    while let Some(ip_addr) = dhcp_server.pick_available_ip() {
        match util::is_ipaddr_already_in_use(&ip_addr) {
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

fn make_dhcp_packet(
    incoming_packet: &DhcpPacket,
    dhcp_server: &DhcpServer,
    message_type: u8,
    ip_to_be_leased: &Ipv4Addr,
) -> Result<DhcpPacket, io::Error> {
    let buffer = Box::new([0u8; DHCP_SIZE]);
    let mut dhcp_packet = DhcpPacket::new(buffer).unwrap();
    dhcp_packet.set_op(BOOTREPLY);
    dhcp_packet.set_htype(HTYPE_ETHER);
    dhcp_packet.set_hlen(HLEN_MACADDR);
    dhcp_packet.set_xid(incoming_packet.get_xid());
    if incoming_packet.get_giaddr() != Ipv4Addr::new(0, 0, 0, 0) {
        dhcp_packet.set_flags(incoming_packet.get_flags());
    }
    dhcp_packet.set_yiaddr(ip_to_be_leased);
    let client_macaddr = incoming_packet.get_chaddr();
    dhcp_packet.set_chaddr(&client_macaddr);

    let mut cursor = dhcp::OPTIONS;
    dhcp_packet.set_magic_cookie(&mut cursor);
    dhcp_packet.set_option(
        &mut cursor,
        Code::MessageType as u8,
        1,
        Some(&vec![message_type]),
    );
    dhcp_packet.set_option(
        &mut cursor,
        Code::IPAddressLeaseTime as u8,
        4,
        Some(&dhcp_server.lease_time),
    );
    dhcp_packet.set_option(
        &mut cursor,
        Code::ServerIdentifier as u8,
        4,
        Some(&dhcp_server.server_address.octets()),
    );
    dhcp_packet.set_option(
        &mut cursor,
        Code::SubnetMask as u8,
        4,
        Some(&dhcp_server.subnet_mask.octets()),
    );
    dhcp_packet.set_option(
        &mut cursor,
        Code::Router as u8,
        4,
        Some(&dhcp_server.default_gateway.octets()),
    );
    dhcp_packet.set_option(
        &mut cursor,
        Code::DNS as u8,
        4,
        Some(&dhcp_server.dns_server.octets()), // TODO DNS
    );

    dhcp_packet.set_option(&mut cursor, Code::End as u8, 0, None);
    Ok(dhcp_packet)
}
