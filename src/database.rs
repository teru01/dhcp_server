use pnet::util::MacAddr;
use rusqlite::{params, Connection, Rows, Transaction, NO_PARAMS};
use std::net::Ipv4Addr;

/**
 * 結果のレコードからIPアドレスのカラムを取り出し、そのベクタを返す。
 */
fn get_addresses_from_row(mut ip_addrs: Rows) -> Result<Vec<Ipv4Addr>, failure::Error> {
    let mut leased_addrs: Vec<Ipv4Addr> = Vec::new();
    while let Some(entry) = ip_addrs.next()? {
        let ip_addr = match entry.get(0) {
            Ok(ip) => {
                let ip_string: String = ip;
                ip_string.parse()?
            }
            Err(_) => continue,
        };
        leased_addrs.push(ip_addr);
    }
    Ok(leased_addrs)
}

/**
 * 利用されているIPアドレスを返す。
 * deletedが渡された場合は`deleted`カラムをその条件で絞り込む
 */
pub fn select_addresses(
    con: &Connection,
    deleted: Option<u8>,
) -> Result<Vec<Ipv4Addr>, failure::Error> {
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
) -> Result<u8, failure::Error> {
    let mut stmnt = tx.prepare("SELECT COUNT (*) FROM lease_entries WHERE mac_addr = ?")?;
    let mut count_result = stmnt.query(params![mac_addr.to_string()])?;

    let count: u8 = match count_result.next()? {
        Some(row) => row.get(0)?,
        None => {
            // 1行も結果がなかった場合（countの結果なので基本的に起こりえない）
            return Err(failure::err_msg("No query returned."));
        }
    };
    Ok(count)
}

/**
 * バインディングの追加
 */
pub fn insert_entry(
    tx: &Transaction,
    mac_addr: MacAddr,
    ip_addr: Ipv4Addr,
) -> Result<(), failure::Error> {
    tx.execute(
        "INSERT INTO lease_entries (mac_addr, ip_addr) VALUES (?1, ?2)",
        params![mac_addr.to_string(), ip_addr.to_string()],
    )?;
    Ok(())
}

/**
 * 指定のMACアドレスをもつエントリ（論理削除されているものも含めて）のIPアドレスを返す。
 */
pub fn select_entry(
    con: &Connection,
    mac_addr: MacAddr,
) -> Result<Option<Ipv4Addr>, failure::Error> {
    let mut stmnt = con.prepare("SELECT ip_addr FROM lease_entries WHERE mac_addr = ?1")?;
    let mut row = stmnt.query(params![mac_addr.to_string()])?;
    if let Some(entry) = row.next()? {
        let ip = entry.get(0)?;
        let ip_string: String = ip;
        Ok(Some(ip_string.parse()?))
    } else {
        info!("specified MAC addr was not found.");
        Ok(None)
    }
}

/**
 * バインディングの更新
 */
pub fn update_entry(
    tx: &Transaction,
    mac_addr: MacAddr,
    ip_addr: Ipv4Addr,
    deleted: u8,
) -> Result<(), failure::Error> {
    tx.execute(
        "UPDATE lease_entries SET ip_addr = ?2, deleted = ?3 WHERE mac_addr = ?1",
        params![
            mac_addr.to_string(),
            ip_addr.to_string(),
            deleted.to_string()
        ],
    )?;
    Ok(())
}

/**
 * バインディングの論理削除
 */
pub fn delete_entry(tx: &Transaction, mac_addr: MacAddr) -> Result<(), failure::Error> {
    tx.execute(
        "UPDATE lease_entries SET deleted = ?1 WHERE mac_addr = ?2",
        params![1.to_string(), mac_addr.to_string()],
    )?;
    Ok(())
}
