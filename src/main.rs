use byteorder::{BigEndian, ByteOrder};
use env_logger;
use failure;
use log::{debug, error, info, warn};
use pnet::util::MacAddr;
use std::net::{Ipv4Addr, UdpSocket};
use std::sync::Arc;
use std::thread;
use std::{env, io};
#[macro_use]
extern crate log;
use dhcp::DhcpPacket;
use dhcp::DhcpServer;

mod database;
mod dhcp;
mod util;

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

fn main() {
    env::set_var("RUST_LOG", "debug");
    env_logger::init();

    let server_socket = UdpSocket::bind("0.0.0.0:67").expect("Failed to bind socket");
    server_socket.set_broadcast(true).unwrap();

    // ヒープ上にDhcpServer構造体を確保し、複数のスレッドから共有するためArcを利用している。
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
                info!("received data from {}, size: {}", src, size);
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
    soc: &UdpSocket,
    dhcp_server: Arc<DhcpServer>,
) -> Result<(), failure::Error> {
    // DHCPのヘッダ読み取り
    let message = packet
        .get_option(Code::MessageType as u8)
        .ok_or_else(|| failure::err_msg("specified option was not found"))?;
    let message_type = message[0];
    let transaction_id = BigEndian::read_u32(packet.get_xid());
    let client_macaddr = packet.get_chaddr();

    match message_type {
        DHCPDISCOVER => {
            dhcp_discover_message_handler(
                transaction_id,
                dhcp_server,
                &packet,
                client_macaddr,
                soc,
            )
        }

        DHCPREQUEST => match packet.get_option(Code::ServerIdentifier as u8) {
            Some(server_id) => {
                dhcp_request_message_handler_responded_to_offer(
                    transaction_id,
                    dhcp_server,
                    &packet,
                    client_macaddr,
                    soc,
                    server_id,
                )
            }
            None => {
                dhcp_request_message_handler_to_extend_lease(
                    transaction_id,
                    dhcp_server,
                    &packet,
                    client_macaddr,
                    soc,
                )
            }
        },

        DHCPRELEASE => {
            dhcp_release_message_handler(transaction_id, dhcp_server, &packet, client_macaddr)
        }

        _ => {
            // 未実装のメッセージを受信した場合。
            let msg = format!(
                "{:x}: received unimplemented message, message_type:{}",
                transaction_id, message_type
            );
            Err(failure::err_msg(msg))
        }
    }
}

/**
 * DISCOVERメッセージを受信した時のハンドラ。
 * 利用できるアドレスを選択してOFFERを返却する。
 */
fn dhcp_discover_message_handler(
    xid: u32,
    dhcp_server: Arc<DhcpServer>,
    received_packet: &DhcpPacket,
    client_macaddr: MacAddr,
    soc: &UdpSocket,
) -> Result<(), failure::Error> {
    info!("{:x}: received DHCPDISCOVER", xid);

    // IPアドレスの決定
    let ip_to_be_leased = select_lease_ip(&dhcp_server, &received_packet)?;

    // 決定したリースIPでDHCPパケットの作成
    let dhcp_packet =
        make_dhcp_packet(&received_packet, &dhcp_server, DHCPOFFER, ip_to_be_leased)?;
    util::send_dhcp_broadcast_response(soc, dhcp_packet.get_buffer())?;

    info!("{:x}: sent DHCPOFFER", xid);
    Ok(())
}

/**
* REQUESTメッセージのオプションにserver_identifierが含まれる場合のハンドラ
* サーバが返したOFFERに対する返答を処理する。
*/
fn dhcp_request_message_handler_responded_to_offer(
    xid: u32,
    dhcp_server: Arc<DhcpServer>,
    received_packet: &DhcpPacket,
    client_macaddr: MacAddr,
    soc: &UdpSocket,
    server_id: Vec<u8>,
) -> Result<(), failure::Error> {
    info!("{:x}: received DHCPREQUEST with server_id", xid);

    let server_ip =
        util::u8_to_ipv4addr(&server_id).ok_or_else(|| failure::err_msg("Failed to convert ip addr."))?;

    if server_ip != dhcp_server.server_address {
        // クライアントが別のDHCPサーバを選択した場合。
        info!("Client has chosen another dhcp server.");
        return Ok(());
    }

    // OFFERに対する応答の場合、必ず'requested IP address'にリース予定のIPアドレスが含まれる（RFC2131 P30)
    let ip_bin = received_packet.get_option(Code::RequestedIpAddress as u8).unwrap();
    let ip_to_be_leased = util::u8_to_ipv4addr(&ip_bin).ok_or_else(|| failure::err_msg("Failed to convert ip addr."))?;

    let mut con = dhcp_server.db_connection.lock().unwrap();
    let tx = con.transaction()?;
    // macaddrがすでに存在する場合がある。（起動後DBに保存されていたもの、または途中で要求するIPを変更する場合）
    let count = database::count_records_by_mac_addr(&tx, client_macaddr)?;
    match count {
        // レコードがないならinsert
        0 => database::insert_entry(&tx, client_macaddr, ip_to_be_leased)?,
        // レコードがあるならupdate
        _ => database::update_entry(&tx, client_macaddr, ip_to_be_leased)?,
    }

    let dhcp_packet = make_dhcp_packet(&received_packet, &dhcp_server, DHCPACK, ip_to_be_leased)?;
    util::send_dhcp_broadcast_response(soc, dhcp_packet.get_buffer())?;
    info!("{:x}: sent DHCPACK", xid);

    tx.commit()?;
    drop(con);

    debug!("{:x}: leased address: {}", xid, ip_to_be_leased);
    match count {
        0 => debug!("{:x}: inserted into DB", xid),
        _ => debug!("{:x}: updated DB", xid),
    }
    Ok(())
}

/**
 * REQUESTメッセージのオプションにserver_identifierが含まれない場合のハンドラ
 * IPリース延長要求、以前割り当てられていたIPの確認などを処理する。
 */
fn dhcp_request_message_handler_to_extend_lease(
    xid: u32,
    dhcp_server: Arc<DhcpServer>,
    received_packet: &DhcpPacket,
    client_macaddr: MacAddr,
    soc: &UdpSocket,
) -> Result<(), failure::Error> {
    info!("{:x}: received DHCPREQUEST without server_id", xid);

    let client_ip = if let Some(requested_ip) = received_packet.get_option(Code::RequestedIpAddress as u8) {
        // クライアントがINIT-REBOOT状態にあるとき
        // レコードがないなら何もしない
        let mut con = dhcp_server.db_connection.lock().unwrap();
        let tx = con.transaction()?;
        match database::select_entry(&tx, client_macaddr) {
            Ok(ip) => ip,
            Err(e) => {
                error!("{}", e);
                return Ok(());
            }
        }
    } else {
        received_packet.get_ciaddr()
    };

    // ACKを返す。
    let dhcp_packet = make_dhcp_packet(&received_packet, &dhcp_server, DHCPACK, client_ip)?;
    util::send_dhcp_broadcast_response(soc, dhcp_packet.get_buffer())?;
    info!("{:x}: sent DHCPACK", xid);
    Ok(())
}

/**
 * RELEASEメッセージを受け取った時のハンドラ
 * DBからリース記録、リーステーブルからエントリを削除し、
 * リースしていたIPアドレスをアドレスプールに戻す。
 */
fn dhcp_release_message_handler(
    xid: u32,
    dhcp_server: Arc<DhcpServer>,
    received_packet: &DhcpPacket,
    client_macaddr: MacAddr,
) -> Result<(), failure::Error> {
    info!("{:x}: received DHCPRELEASE", xid);

    let mut con = dhcp_server.db_connection.lock().unwrap();
    let tx = con.transaction()?;
    database::delete_entry(&tx, client_macaddr)?;
    tx.commit()?;
    drop(con);

    debug!("{:x}: deleted from DB", xid);
    // リーステーブルからIPアドレスを取り出しアドレスプールに戻す。
    dhcp_server.release_address(received_packet.get_ciaddr());
    Ok(())
}

/**
 * オプションにRequested Ip Addressがあり、利用可能ならばそれを返す。
 */
fn obtain_available_ip_from_requested_option(
    dhcp_server: &Arc<DhcpServer>,
    received_packet: &DhcpPacket,
) -> Option<Ipv4Addr> {
    let ip = received_packet.get_option(Code::RequestedIpAddress as u8)?;
    let requested_ip = util::u8_to_ipv4addr(&ip)?;
    // アドレスプールからの検索
    let ip_from_pool = dhcp_server.pick_specified_ip(requested_ip)?;

    // すでに使われているかチェック
    if let Ok(used) = util::is_ipaddr_already_in_use(ip_from_pool) {
        if !used {
            // 使われていなければそれを返す
            return Some(requested_ip);
        }
    }
    None
}

/**
 * 利用可能なIPアドレスを選ぶ。
 * クライアントから要求されたアドレス、以前そのクライアントにリースされたアドレス、
 * アドレスプールの優先順位で利用可能なIPアドレスを返却する。
 */
fn select_lease_ip(
    dhcp_server: &Arc<DhcpServer>,
    received_packet: &DhcpPacket,
) -> Result<Ipv4Addr, failure::Error> {
    let mut con = dhcp_server.db_connection.lock().unwrap();
    let tx = con.transaction()?;

    // DBから以前リースしたIPアドレスがあればそれを返す。
    if let Ok(ip_from_used) = database::select_entry(&tx, received_packet.get_chaddr()) {
        if let Ok(in_use) = util::is_ipaddr_already_in_use(ip_from_used) {
            if !in_use {
                return Ok(ip_from_used);
            }
        }
    }
    tx.commit()?;
    drop(con);

    // Requested Ip Addrオプションがあり、利用可能ならばそのIPアドレスを返却。
    if let Some(ip_to_be_leased) =
        obtain_available_ip_from_requested_option(dhcp_server, &received_packet)
    {
        return Ok(ip_to_be_leased);
    }

    // アドレスプールからの取得
    while let Some(ip_addr) = dhcp_server.pick_available_ip() {
        match util::is_ipaddr_already_in_use(ip_addr) {
            Ok(used) => {
                if !used {
                    return Ok(ip_addr);
                }
            }
            Err(msg) => {
                warn!("{}", msg);
            }
        }
    }
    // 利用できるIPアドレスが取得できなかった場合
    Err(failure::err_msg("Could not obtain available ip address."))
}

/**
 * DHCPのパケットを作成して返す。
 */
fn make_dhcp_packet(
    received_packet: &DhcpPacket,
    dhcp_server: &Arc<DhcpServer>,
    message_type: u8,
    ip_to_be_leased: Ipv4Addr,
) -> Result<DhcpPacket, io::Error> {
    // パケットの本体となるバッファ。ヒープに確保する。
    let buffer = Box::new([0u8; DHCP_SIZE]);
    let mut dhcp_packet = DhcpPacket::new(buffer).unwrap();

    // 各種フィールドの設定
    dhcp_packet.set_op(BOOTREPLY);
    dhcp_packet.set_htype(HTYPE_ETHER);
    dhcp_packet.set_hlen(HLEN_MACADDR);
    dhcp_packet.set_xid(received_packet.get_xid());
    if received_packet.get_giaddr() != Ipv4Addr::new(0, 0, 0, 0) {
        dhcp_packet.set_flags(received_packet.get_flags());
    }
    dhcp_packet.set_yiaddr(ip_to_be_leased);
    dhcp_packet.set_chaddr(received_packet.get_chaddr());

    // 各種オプションの設定
    let mut cursor = dhcp::OPTIONS;
    dhcp_packet.set_magic_cookie(&mut cursor);
    dhcp_packet.set_option(
        &mut cursor,
        Code::MessageType as u8,
        1,
        Some(&[message_type]),
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
        Some(&dhcp_server.dns_server.octets()),
    );

    dhcp_packet.set_option(&mut cursor, Code::End as u8, 0, None);
    Ok(dhcp_packet)
}
