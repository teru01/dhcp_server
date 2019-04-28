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

mod util;

mod database;

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
                        if dhcp_packet.get_op() != BOOTREQUEST {
                            return;
                        }
                        match dhcp_handler(&dhcp_packet, &client_socket, cloned_dhcp_server) {
                            Ok(_) => {}
                            Err(e) => {
                                error!("{}", e);
                            }
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

fn dhcp_handler(
    packet: &DhcpPacket,
    soc: &net::UdpSocket,
    dhcp_server: Arc<DhcpServer>,
) -> Result<(), failure::Error> {
    // dhcpのヘッダ読み取り
    if let Some(message) = packet.get_option(Code::MessageType as u8) {
        let message_type = message[0];
        let mut packet_buffer = [0u8; DHCP_SIZE];
        let dest: net::SocketAddr = "255.255.255.255:68".parse().unwrap();
        let transaction_id = BigEndian::read_u32(packet.get_xid());
        let client_macaddr = packet.get_chaddr();

        match message_type {
            DHCPDISCOVER => {
                // DISCOVERを受け取った時。
                // OFFERを返却する。
                // この際、クライアントのrequested ip address、chaddrで照合した以前リースしたIP、アドレスプールから選んだ値の優先順にIPを選んで返す
                // chaddrと返したIPのマップ、トランザクションIDを記録しておく
                info!("{}: received DHCPDISCOVER", transaction_id);

                // DBアクセス。以前リースしたやつがあればそれを再び渡す
                // IPアドレスの決定
                let ip_to_be_leased = match select_lease_ip(dhcp_server.clone(), &packet) {
                    Ok(ip) => ip,
                    Err(e) => {
                        // 利用できるIPが見つからないので強制終了。
                        panic!("{}", e);
                    }
                };

                // NoneならACKではinsert, SomeならACKではupdate（すでにDBにエントリがある）
                dhcp_server.insert_entry(client_macaddr, ip_to_be_leased);

                let dhcp_packet = make_dhcp_packet(
                    &packet,
                    &dhcp_server,
                    DHCPOFFER,
                    &mut packet_buffer,
                    &ip_to_be_leased,
                )?;
                soc.send_to(dhcp_packet.get_buffer(), dest)?;

                info!("{}: sent DHCPOFFER", transaction_id);
                return Ok(());
            }

            DHCPREQUEST => {
                // クライアントからのリクエストを受け取る。
                match packet.get_option(Code::ServerIdentifier as u8) {
                    // OFFERに対する返答
                    Some(server_id) => {
                        info!("{}: received DHCPREQUEST with server_id", transaction_id);
                        let server_ip = util::u8_to_ipv4addr(&server_id)?;

                        if server_ip != dhcp_server.server_address {
                            // クライアントは別のDHCPサーバを選択。
                            info!("Client has chosen another dhcp server.");

                            // 使用中テーブルとアドレスプールを戻す。
                            if let Some(ip) = dhcp_server.pick_entry(client_macaddr) {
                                dhcp_server.push_address(ip);
                            }

                            debug!("deleted from lease_entry");
                            return Ok(());
                        }
                        if let Some(ip_to_be_leased) = dhcp_server.get_entry(client_macaddr) {
                            let mut con = dhcp_server.db_connection.lock().unwrap();
                            let tx = con.transaction()?;
                            // macaddrがすでに存在する場合がある。（起動後DBに保存されていたもの、または途中でrequest_ipを変更する
                            let count = database::count_records_by_mac_addr(&tx, &client_macaddr)?;
                            match count {
                                // レコードがないならinsert
                                0 => {
                                    database::insert_entry(&tx, &client_macaddr, &ip_to_be_leased)?
                                }
                                // レコードがあるならupdate
                                _ => {
                                    database::update_entry(&tx, &client_macaddr, &ip_to_be_leased)?
                                }
                            }
                            // ACKを返して、DBにマップをコミット
                            let dhcp_packet = make_dhcp_packet(
                                &packet,
                                &dhcp_server,
                                DHCPACK,
                                &mut packet_buffer,
                                &ip_to_be_leased,
                            )?;
                            soc.send_to(dhcp_packet.get_buffer(), dest)?;
                            info!("{}: sent DHCPACK", transaction_id);

                            // パケット送信で失敗すればこれは実行されずにロールバックされる。=> DBの整合性は保たれる
                            tx.commit()?;
                            // ガードの破棄
                            drop(con);

                            debug!("{}: leased address: {}", transaction_id, ip_to_be_leased);
                            if count == 0 {
                                debug!("{}: inserted into DB", transaction_id);
                            } else {
                                debug!("{}: updated DB", transaction_id);
                            }
                        }
                        return Ok(());
                    }
                    // リース延長 or IP更新(= dhcp informらしいので未対応にする)？
                    None => {
                        info!("{}: received DHCPREQUEST without server_id", transaction_id);
                        // ACKを返す。
                        if let Some(ip_to_be_leased) = dhcp_server.get_entry(client_macaddr) {
                            let prev_ip = packet.get_ciaddr();
                            if prev_ip != ip_to_be_leased {
                                // NAKを返す
                                let dhcp_packet = make_dhcp_packet(
                                    &packet,
                                    &dhcp_server,
                                    DHCPNAK,
                                    &mut packet_buffer,
                                    &prev_ip,
                                )?;
                                soc.send_to(dhcp_packet.get_buffer(), dest)?;
                                info!("{}: sent DHCPNAK", transaction_id);
                                return Ok(());
                            }
                            // ACKを返す。
                            let dhcp_packet = make_dhcp_packet(
                                &packet,
                                &dhcp_server,
                                DHCPACK,
                                &mut packet_buffer,
                                &ip_to_be_leased,
                            )?;
                            soc.send_to(dhcp_packet.get_buffer(), dest)?;
                            info!("{}: sent DHCPACK", transaction_id);
                        }
                    }
                }
                return Ok(());
            }

            DHCPRELEASE => {
                // IPを利用可能としてアドレスプールに戻す
                // マップからエントリの削除。アドレスプールへの追加
                info!("{}: received DHCPRELEASE", transaction_id);
                let mut con = dhcp_server.db_connection.lock().unwrap();
                let tx = con.transaction()?;
                database::delete_entry(&tx, &client_macaddr)?;
                tx.commit()?;
                drop(con);

                debug!("{}: deleted from DB", transaction_id);
                // 使用中テーブルとアドレスプールを戻す。
                if let Some(ip) = dhcp_server.pick_entry(client_macaddr) {
                    dhcp_server.push_address(ip);
                }
                return Ok(());
            }

            _ => {
                warn!(
                    "{}: received unimplemented message, message_type:{}",
                    transaction_id, message_type
                );
                return Ok(());
            }
        }
    } else {
        error!("option not found");
        return Ok(());
    }
}

fn make_dhcp_packet<'a>(
    incoming_packet: &DhcpPacket,
    dhcp_server: &DhcpServer,
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
