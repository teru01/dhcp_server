use rusqlite::{Connection, NO_PARAMS};
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
