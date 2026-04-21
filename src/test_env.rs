use once_cell::sync::Lazy;
use std::sync::{Mutex, MutexGuard};

pub static ENV_LOCK: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

pub fn lock() -> MutexGuard<'static, ()> {
    ENV_LOCK.lock().unwrap()
}

