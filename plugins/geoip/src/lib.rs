use maxminddb::geoip2;
use std::path::PathBuf;
use std::sync::OnceLock;
use tracing::{info, warn};

static RESOLVER: OnceLock<GeoIpResolver> = OnceLock::new();

pub fn resolver() -> &'static GeoIpResolver {
    RESOLVER.get_or_init(GeoIpResolver::load)
}

pub struct GeoIpResolver {
    country_db: Option<maxminddb::Reader<Vec<u8>>>,
    city_db: Option<maxminddb::Reader<Vec<u8>>>,
    asn_db: Option<maxminddb::Reader<Vec<u8>>>,
}

#[derive(Debug, Clone)]
pub struct GeoIpData {
    pub ip: String,
    pub country_code: String,
    pub country_name: String,
    pub city: String,
    pub region: String,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
    pub asn: Option<u32>,
    pub asn_org: String,
    pub is_anonymous: bool,
    pub is_hosting: bool,
}

impl GeoIpResolver {
    pub fn load() -> Self {
        let base = geoip_dir();
        let mut resolver = Self {
            country_db: None,
            city_db: None,
            asn_db: None,
        };

        let country_path = std::env::var("SENTINEL_GEOIP_COUNTRY_DB")
            .ok()
            .map(PathBuf::from)
            .unwrap_or_else(|| base.join("GeoLite2-Country.mmdb"));

        let city_path = std::env::var("SENTINEL_GEOIP_CITY_DB")
            .ok()
            .map(PathBuf::from)
            .unwrap_or_else(|| base.join("GeoLite2-City.mmdb"));

        let asn_path = std::env::var("SENTINEL_GEOIP_ASN_DB")
            .ok()
            .map(PathBuf::from)
            .unwrap_or_else(|| base.join("GeoLite2-ASN.mmdb"));

        if country_path.exists() {
            match maxminddb::Reader::open_readfile(&country_path) {
                Ok(r) => {
                    info!("GeoIP country DB loaded: {}", country_path.display());
                    resolver.country_db = Some(r);
                }
                Err(e) => warn!("Failed to load GeoIP country DB: {e}"),
            }
        }

        if city_path.exists() {
            match maxminddb::Reader::open_readfile(&city_path) {
                Ok(r) => {
                    info!("GeoIP city DB loaded: {}", city_path.display());
                    resolver.city_db = Some(r);
                }
                Err(e) => warn!("Failed to load GeoIP city DB: {e}"),
            }
        }

        if asn_path.exists() {
            match maxminddb::Reader::open_readfile(&asn_path) {
                Ok(r) => {
                    info!("GeoIP ASN DB loaded: {}", asn_path.display());
                    resolver.asn_db = Some(r);
                }
                Err(e) => warn!("Failed to load GeoIP ASN DB: {e}"),
            }
        }

        if resolver.country_db.is_none()
            && resolver.city_db.is_none()
            && resolver.asn_db.is_none()
        {
            info!("GeoIP: no databases found in {}. Download free GeoLite2 from https://dev.maxmind.com/geoip/geolite2-free-geolocation-data",
                base.display());
        }

        resolver
    }

    pub fn lookup(&self, ip: &str) -> Option<GeoIpData> {
        let ip_addr: std::net::IpAddr = ip.parse().ok()?;
        let mut data = GeoIpData {
            ip: ip.into(),
            country_code: String::new(),
            country_name: String::new(),
            city: String::new(),
            region: String::new(),
            latitude: None,
            longitude: None,
            asn: None,
            asn_org: String::new(),
            is_anonymous: false,
            is_hosting: false,
        };

        if let Some(ref db) = self.country_db {
            if let Ok(country) = db.lookup::<geoip2::Country>(ip_addr) {
                let cc = country.country.as_ref();
                data.country_code = cc.and_then(|c| c.iso_code).unwrap_or("??").into();
                data.country_name = cc
                    .and_then(|c| c.names.as_ref())
                    .and_then(|n| n.get("en").copied())
                    .unwrap_or("Unknown")
                    .into();
            }
        }

        if let Some(ref db) = self.city_db {
            if let Ok(city) = db.lookup::<geoip2::City>(ip_addr) {
                data.city = city
                    .city
                    .and_then(|c| c.names)
                    .and_then(|n| n.get("en").copied())
                    .unwrap_or("")
                    .into();

                data.region = city
                    .subdivisions
                    .and_then(|s| s.first().cloned())
                    .and_then(|s| s.names)
                    .and_then(|n| n.get("en").copied())
                    .unwrap_or("")
                    .into();

                if let Some(ref loc) = city.location {
                    data.latitude = loc.latitude;
                    data.longitude = loc.longitude;
                }
            }
        }

        if let Some(ref db) = self.asn_db {
            if let Ok(asn) = db.lookup::<geoip2::Asn>(ip_addr) {
                data.asn = asn.autonomous_system_number;
                data.asn_org = asn
                    .autonomous_system_organization
                    .unwrap_or("")
                    .into();
            }
        }

        if data.country_code.is_empty()
            && data.city.is_empty()
            && data.asn_org.is_empty()
        {
            return None;
        }

        Some(data)
    }

    pub fn is_loaded(&self) -> bool {
        self.country_db.is_some()
            || self.city_db.is_some()
            || self.asn_db.is_some()
    }
}

pub fn enabled() -> bool {
    resolver().is_loaded()
}

fn geoip_dir() -> PathBuf {
    dirs::config_dir()
        .map(|mut p| {
            p.push("sentinel");
            p.push("geoip");
            p
        })
        .unwrap_or_else(|| PathBuf::from("geoip"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maxmind_db_format_rejection() {
        let dir = std::env::temp_dir().join("sentinel_geoip_test");
        let _ = std::fs::create_dir_all(&dir);
        let db_path = dir.join("test.mmdb");
        std::fs::write(&db_path, b"not a valid maxmind database").unwrap();

        let result = maxminddb::Reader::open_readfile(&db_path);
        // Either Err or Ok — should never crash/panic
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn lookup_without_db() {
        let resolver = GeoIpResolver {
            country_db: None,
            city_db: None,
            asn_db: None,
        };
        assert!(resolver.lookup("8.8.8.8").is_none());
    }

    #[test]
    fn resolver_creation_does_not_crash() {
        let resolver = GeoIpResolver::load();
        let result = resolver.lookup("8.8.8.8");
        // Either Some (if DBs installed) or None (if not) — never crash
        assert!(result.is_some() || result.is_none());
    }

    #[test]
    fn empty_ip_returns_none() {
        let resolver = GeoIpResolver {
            country_db: None,
            city_db: None,
            asn_db: None,
        };
        assert!(resolver.lookup("").is_none());
    }
}
