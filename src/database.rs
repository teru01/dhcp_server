use pnet::util::MacAddr;
use rusqlite::{params, Connection, Transaction, Rows, NO_PARAMS};
use std::net::Ipv4Addr;


// /**
//  * 全てのリースの一覧を返す
//  */
// pub fn get_all_entries(con: &Connection) -> Result<LeaseEntry, rusqlite::Error> {
//     let mut mac_ip_map = LeaseEntry::new();

//     let mut statement = con.prepare("SELECT mac_addr, ip_addr FROM lease_entries")?;
//     let mut entries = statement.query(NO_PARAMS)?;
//     while let Some(entry) = entries.next()? {
//         let mac_addr: MacAddr = match entry.get(0) {
//             Ok(mac) => {
//                 let mac_string: String = mac;
//                 mac_string.parse().unwrap()
//             }
//             Err(_) => continue,
//         };

//         let ip_addr = match entry.get(1) {
//             Ok(ip) => {
//                 let ip_string: String = ip;
//                 ip_string.parse().unwrap()
//             }
//             Err(_) => continue,
//         };

//         mac_ip_map.insert(mac_addr, ip_addr);
//     }
//     Ok(mac_ip_map)
// }

fn get_addresses_from_row(mut ip_addrs: Rows) -> Result<Vec<Ipv4Addr>, failure::Error> {
    let mut leased_addrs: Vec<Ipv4Addr> = Vec::new();
    while let Some(entry) = ip_addrs.next()? {
        let ip_addr = match entry.get(0) {
            Ok(ip) => {
                let ip_string: String = ip;
                ip_string.parse().unwrap()
            }
            Err(_) => continue,
        };
        leased_addrs.push(ip_addr);
    }
    Ok(leased_addrs)
}

pub fn select_addresses(con: &Connection, deleted: Option<u8>) -> Result<Vec<Ipv4Addr>, failure::Error> {
    if let Some(deleted) = deleted {
        let mut statement = con.prepare("SELECT ip_addr FROM lease_entries WHERE deleted = ?")?;
        let ip_addrs = statement.query(params![deleted.to_string()])?;
        get_addresses_from_row(ip_addrs)
    } else {
        let mut statement = con.prepare("SELECT ip_addr FROM lease_entries")?;
        let ip_addrs = statement.query(NO_PARAMS)?;
        get_addresses_from_row(ip_addrs)
    }
}

/**
 * 指定のMACアドレスを持つレコードの件数を返す
 */
pub fn count_records_by_mac_addr(
    tx: &Transaction,
    mac_addr: MacAddr,
) -> Result<u8, rusqlite::Error> {
    let mut stmnt = tx.prepare("SELECT COUNT (*) FROM lease_entries WHERE mac_addr = ?")?;
    let mut count_result = stmnt.query(params![mac_addr.to_string()])?;

    let count: u8 = match count_result.next()? {
        Some(row) => row.get(0)?,
        None => {
            // 1行も結果がなかった場合（countの結果なので基本的に起こりえない）
            return Err(rusqlite::Error::QueryReturnedNoRows);
        }
    };
    Ok(count)
}

/**
 * リースエントリの追加
 */
pub fn insert_entry(
    tx: &Transaction,
    mac_addr: MacAddr,
    ip_addr: Ipv4Addr,
) -> Result<(), rusqlite::Error> {
    tx.execute(
        "INSERT INTO lease_entries (mac_addr, ip_addr) VALUES (?1, ?2)",
        params![mac_addr.to_string(), ip_addr.to_string()],
    )?;
    Ok(())
}

/**
 * 指定のMACアドレスをもつエントリ（論理削除されているものも含めて）のIPアドレスを返す。
 */
pub fn select_entry(tx: &Transaction, mac_addr: MacAddr) -> Result<Ipv4Addr, failure::Error> {
    let mut stmnt = tx.prepare("SELECT ip_addr FROM lease_entries WHERE mac_addr = ?1")?;
    let mut row = stmnt.query(params![mac_addr.to_string()])?;
    if let Some(entry) = row.next()? {
        let ip = entry.get(0)?;
        let ip_string: String = ip;
        Ok(ip_string.parse().unwrap())
    } else {
        Err(failure::err_msg("specified MAC addr was not found."))
    }
}

/**
 * リースエントリの更新
 */
pub fn update_entry(
    tx: &Transaction,
    mac_addr: MacAddr,
    ip_addr: Ipv4Addr,
) -> Result<(), rusqlite::Error> {
    tx.execute(
        "UPDATE lease_entries SET ip_addr = ?2 WHERE mac_addr = ?1",
        params![mac_addr.to_string(), ip_addr.to_string()],
    )?;
    Ok(())
}

/**
 * リースエントリの論理削除
 */
pub fn delete_entry(tx: &Transaction, mac_addr: MacAddr) -> Result<(), rusqlite::Error> {
    tx.execute(
        "UPDATE lease_entries SET deleted = ?1 WHERE mac_addr = ?2",
        params![1.to_string(), mac_addr.to_string()]
    )?;
    Ok(())
}
