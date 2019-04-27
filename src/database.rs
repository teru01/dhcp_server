use rusqlite::{Connection, NO_PARAMS, params, Transaction};
use std::net::Ipv4Addr;
use pnet::util::MacAddr;
use std::collections::HashMap;


type LeaseEntry = HashMap<MacAddr, Ipv4Addr>;

pub fn get_all_entries(con: &Connection) -> Result<LeaseEntry, rusqlite::Error> {
    let mut mac_ip_map = LeaseEntry::new();

    let mut statement = con.prepare("SELECT mac_addr, ip_addr FROM lease_entry")?;
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
    return Ok(mac_ip_map);
}

pub fn count_records_by_mac_addr(tx: &Transaction, mac_addr: &MacAddr) -> Result<u8, rusqlite::Error> {
    let mut stmnt = tx
        .prepare("SELECT COUNT (*) FROM lease_entry WHERE mac_addr = ?")?;
    let mut count_result =
        stmnt.query(params![mac_addr.to_string()])?;

    let count: u8 = match count_result.next()? {
        Some(row) => row.get(0)?,
        None => {
            // 1行も結果がなかった場合（countの結果なので基本的に起こりえない）
            return Err(rusqlite::Error::QueryReturnedNoRows);
        }
    };
    return Ok(count);
}
