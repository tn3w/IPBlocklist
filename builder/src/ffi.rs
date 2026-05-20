use crate::db::Db;
use std::ffi::CStr;
use std::os::raw::c_char;
use std::path::Path;

pub const IPINTEL_ALLOW: u8 = 0;
pub const IPINTEL_CHALLENGE: u8 = 1;
pub const IPINTEL_BLOCK: u8 = 2;

#[no_mangle]
pub extern "C" fn ipintel_open(path: *const c_char) -> *mut Db {
    if path.is_null() { return std::ptr::null_mut(); }
    let cstr = unsafe { CStr::from_ptr(path) };
    let s = match cstr.to_str() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };
    match Db::open(Path::new(s)) {
        Ok(db) => Box::into_raw(Box::new(db)),
        Err(_) => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn ipintel_close(db: *mut Db) {
    if !db.is_null() {
        drop(Box::from_raw(db));
    }
}

#[no_mangle]
pub unsafe extern "C" fn ipintel_v4_count(db: *const Db) -> u64 {
    if db.is_null() { return 0; }
    (*db).v4_count() as u64
}

#[no_mangle]
pub unsafe extern "C" fn ipintel_v6_count(db: *const Db) -> u64 {
    if db.is_null() { return 0; }
    (*db).v6_count() as u64
}

#[no_mangle]
pub unsafe extern "C" fn ipintel_lookup_v4_flags(
    db: *const Db, ip_host: u32,
) -> u32 {
    if db.is_null() { return 0; }
    (*db).lookup_v4_flags(ip_host)
}

#[no_mangle]
pub unsafe extern "C" fn ipintel_lookup_v4_score(
    db: *const Db, ip_host: u32,
) -> u8 {
    if db.is_null() { return 0; }
    (*db).lookup_v4_score(ip_host)
}

#[no_mangle]
pub unsafe extern "C" fn ipintel_lookup_v6_flags(
    db: *const Db, ip16: *const u8,
) -> u32 {
    if db.is_null() || ip16.is_null() { return 0; }
    let bytes = std::slice::from_raw_parts(ip16, 16);
    let mut arr = [0u8; 16];
    arr.copy_from_slice(bytes);
    (*db).lookup_v6_flags(u128::from_be_bytes(arr))
}

#[no_mangle]
pub unsafe extern "C" fn ipintel_lookup_v6_score(
    db: *const Db, ip16: *const u8,
) -> u8 {
    if db.is_null() || ip16.is_null() { return 0; }
    let bytes = std::slice::from_raw_parts(ip16, 16);
    let mut arr = [0u8; 16];
    arr.copy_from_slice(bytes);
    (*db).lookup_v6_score(u128::from_be_bytes(arr))
}

fn action_from_score(score: u8, block_thr: u8, challenge_thr: u8) -> u8 {
    if score >= block_thr { IPINTEL_BLOCK }
    else if score >= challenge_thr { IPINTEL_CHALLENGE }
    else { IPINTEL_ALLOW }
}

#[no_mangle]
pub unsafe extern "C" fn ipintel_lookup_v4_action(
    db: *const Db, ip_host: u32, block_thr: u8, challenge_thr: u8,
) -> u8 {
    if db.is_null() { return IPINTEL_ALLOW; }
    action_from_score((*db).lookup_v4_score(ip_host), block_thr, challenge_thr)
}

#[no_mangle]
pub unsafe extern "C" fn ipintel_lookup_v6_action(
    db: *const Db, ip16: *const u8, block_thr: u8, challenge_thr: u8,
) -> u8 {
    if db.is_null() || ip16.is_null() { return IPINTEL_ALLOW; }
    let bytes = std::slice::from_raw_parts(ip16, 16);
    let mut arr = [0u8; 16];
    arr.copy_from_slice(bytes);
    let score = (*db).lookup_v6_score(u128::from_be_bytes(arr));
    action_from_score(score, block_thr, challenge_thr)
}
