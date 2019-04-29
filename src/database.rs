use pnet::util::MacAddr;
use rusqlite::{params, Connection, Transaction, NO_PARAMS};
use std::collections::HashMap;
use std::net::Ipv4Addr;

type LeaseEntry = HashMap<MacAddr, Ipv4Addr>;

/**
 * 全てのリースの一覧を返す
 */
pub fn get_all_entries(con: &Connection) -> Result<LeaseEntry, rusqlite::Error> {
    let mut mac_ip_map = LeaseEntry::new();

    let mut statement = con.prepare("SELECT mac_addr, ip_addr FROM lease_entries")?;
    let mut entries = statement.query(NO_PARAMS)?;
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

        mac_ip_map.insert(mac_addr, ip_addr);
    }
    Ok(mac_ip_map)
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
 * リースエントリの削除
 */
pub fn delete_entry(tx: &Transaction, mac_addr: MacAddr) -> Result<(), rusqlite::Error> {
    tx.execute(
        "DELETE FROM lease_entries WHERE mac_addr = ?",
        params![mac_addr.to_string(),],
    )?;
    Ok(())
}
