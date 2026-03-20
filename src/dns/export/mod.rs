pub mod bind;

use crate::dns::{DnsRecord, DnsZone};

#[derive(Debug, Clone)]
pub struct SoaConfig {
    pub mname: String,
    pub rname: String,
    pub refresh: u32,
    pub retry: u32,
    pub expire: u32,
    pub minimum: u32,
}

pub trait ZoneExporter {
    fn export_zone(
        &self,
        zone: &DnsZone,
        records: &[DnsRecord],
        soa: &SoaConfig,
    ) -> Result<String, String>;
}
