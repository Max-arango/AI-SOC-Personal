//! USB Collector — Monitors USB device insertion and removal.
//!
//! Linux: polls `/sys/bus/usb/devices/` for new/removed entries.
//! Emits `sentinel.usb.connect` and `sentinel.usb.disconnect` events
//! with vendor ID, product ID, and serial number when available.

use std::collections::HashSet;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use sentinel_core::traits::EventBus;
use sentinel_events::usb_event::Action;
use sentinel_events::{Event, UsbEvent};
use tracing::{debug, info};

const POLL_INTERVAL: Duration = Duration::from_secs(5);

struct UsbDevice {
    vendor_id: String,
    product_id: String,
    serial: String,
    product_name: String,
}

fn read_sysfs_attr(dev_path: &Path, attr: &str) -> String {
    std::fs::read_to_string(dev_path.join(attr))
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

fn scan_usb_devices() -> Vec<UsbDevice> {
    let mut devices = Vec::new();
    let sys_usb = Path::new("/sys/bus/usb/devices");
    if !sys_usb.exists() {
        return devices;
    }

    let rd = match std::fs::read_dir(sys_usb) {
        Ok(r) => r,
        Err(_) => return devices,
    };

    for entry in rd.flatten() {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().to_string();

        if name.contains('-') || name.contains(':') {
            continue;
        }

        let vendor_id = read_sysfs_attr(&path, "idVendor");
        let product_id = read_sysfs_attr(&path, "idProduct");
        let serial = read_sysfs_attr(&path, "serial");
        let product_name = read_sysfs_attr(&path, "product");

        if !vendor_id.is_empty() {
            devices.push(UsbDevice {
                vendor_id,
                product_id,
                serial,
                product_name,
            });
        }
    }

    devices
}

fn device_key(d: &UsbDevice) -> String {
    format!("{}:{}:{}", d.vendor_id, d.product_id, d.serial)
}

fn device_to_event(d: &UsbDevice, action: Action) -> Event {
    Event {
        id: sentinel_core::Ulid::new().to_string(),
        r#type: match action {
            Action::DeviceConnect => "sentinel.usb.connect",
            Action::DeviceDisconnect => "sentinel.usb.disconnect",
            _ => "sentinel.usb.event",
        }
        .into(),
        source: "usb".into(),
        timestamp: sentinel_core::now_proto_ts(),
        ingest_timestamp: sentinel_core::now_proto_ts(),
        severity: sentinel_events::Severity::Notice as i32,
        risk_score: if action == Action::DeviceConnect { 15 } else { 5 },
        host_id: String::new(),
        schema_version: 1,
        payload: Some(sentinel_events::event::Payload::UsbEvent(UsbEvent {
            action: action as i32,
            device_id: device_key(d),
            vendor_id: d.vendor_id.clone(),
            product_id: d.product_id.clone(),
            serial_number: d.serial.clone(),
            manufacturer: String::new(),
            product: d.product_name.clone(),
            ..Default::default()
        })),
        tags: vec!["usb".into(), "removable_media".into()],
        ..Default::default()
    }
}

pub async fn start_usb_monitor(bus: Arc<dyn EventBus>, registry: Arc<sentinel_core::CollectorRegistry>) {
    tokio::spawn(async move {
        registry.register(sentinel_core::CollectorStatus::new("usb", "Usb Monitor", "Usb collector"));
        let reg = registry.clone();
        let mut known: HashSet<String> = HashSet::new();
        let mut tick = tokio::time::interval(POLL_INTERVAL);
        tick.tick().await;

        info!(
            "USB collector started ({}s polling)",
            POLL_INTERVAL.as_secs()
        );

        loop {
            tick.tick().await;
            let devices = scan_usb_devices();
            let current_keys: HashSet<String> =
                devices.iter().map(|d| device_key(d)).collect();

            for d in &devices {
                let key = device_key(d);
                if !known.contains(&key) {
                    let event = Arc::new(device_to_event(d, Action::DeviceConnect));
                    debug!(
                        "USB inserted: {}:{} ({})",
                        d.vendor_id, d.product_id, d.product_name
                    );
                    let _ = bus.publish(event).await;
                reg.increment_events("usb", 1);
                }
            }

            for key in known.difference(&current_keys) {
                let parts: Vec<&str> = key.split(':').collect();
                let d = UsbDevice {
                    vendor_id: parts.first().unwrap_or(&"?").to_string(),
                    product_id: parts.get(1).unwrap_or(&"?").to_string(),
                    serial: parts.get(2).unwrap_or(&"").to_string(),
                    product_name: String::new(),
                };
                let event = Arc::new(device_to_event(&d, Action::DeviceDisconnect));
                debug!("USB removed: {}", key);
                let _ = bus.publish(event).await;
                reg.increment_events("usb", 1);
            }

            known = current_keys;
        }
    });
}

#[cfg(not(target_os = "linux"))]
pub async fn start_usb_monitor(_bus: Arc<dyn EventBus>) {
    tracing::info!("USB collector: not supported on this platform");
}
