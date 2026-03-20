use chrono::Utc;

use crate::dns::{DnsRecord, DnsZone, RecordType};

use super::{SoaConfig, ZoneExporter};

pub struct BindExporter;

impl ZoneExporter for BindExporter {
    fn export_zone(
        &self,
        zone: &DnsZone,
        records: &[DnsRecord],
        soa: &SoaConfig,
    ) -> Result<String, String> {
        let mut out = String::new();

        // $TTL
        out.push_str(&format!("$TTL {}\n", zone.ttl_default));

        // SOA record — serial derived from current timestamp
        let serial = Utc::now().format("%Y%m%d%H").to_string();
        out.push_str(&format!(
            "@ IN SOA {} {} (\n    {} ; serial\n    {} ; refresh\n    {} ; retry\n    {} ; expire\n    {} ; minimum\n)\n",
            soa.mname, soa.rname, serial, soa.refresh, soa.retry, soa.expire, soa.minimum,
        ));

        // Records
        for r in records {
            let ttl_str = r
                .ttl
                .map(|t| t.to_string())
                .unwrap_or_else(|| zone.ttl_default.to_string());

            match r.record_type {
                RecordType::Mx => {
                    let pri = r.priority.unwrap_or(10);
                    out.push_str(&format!(
                        "{}\t{}\tIN\t{}\t{} {}\n",
                        r.name, ttl_str, r.record_type, pri, r.value
                    ));
                }
                _ => {
                    out.push_str(&format!(
                        "{}\t{}\tIN\t{}\t{}\n",
                        r.name, ttl_str, r.record_type, r.value
                    ));
                }
            }
        }

        Ok(out)
    }
}
