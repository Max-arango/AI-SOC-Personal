//! Sentinel AI event definitions generated from Protocol Buffers.
//!
//! The generated modules live in `OUT_DIR` and are included here.

pub mod sentinel {
    pub mod events {
        pub mod v1 {
            include!(concat!(env!("OUT_DIR"), "/sentinel.events.v1.rs"));
        }
    }
    pub mod api {
        pub mod v1 {
            include!(concat!(env!("OUT_DIR"), "/sentinel.api.v1.rs"));
        }
    }
    pub mod plugin {
        pub mod v1 {
            include!(concat!(env!("OUT_DIR"), "/sentinel.plugin.v1.rs"));
        }
    }
}

/// Re-export the generated `events.v1` types at the crate root for ergonomic
/// imports such as `sentinel_events::Event`.
pub use sentinel::events::v1::*;

