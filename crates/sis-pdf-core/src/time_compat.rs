#[cfg(not(target_arch = "wasm32"))]
pub use std::time::Instant;
#[cfg(not(target_arch = "wasm32"))]
pub use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(target_arch = "wasm32")]
pub use web_time::Instant;
#[cfg(target_arch = "wasm32")]
pub use web_time::{SystemTime, UNIX_EPOCH};

pub use std::time::Duration;
