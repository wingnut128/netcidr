use std::net::IpAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use uuid::Uuid;

use crate::dns::arpa::ptr_components;
use crate::dns::export::{SoaConfig, ZoneExporter};
use crate::dns::repository::DnsRepository;
use crate::dns::{DnsRecord, DnsZone, RecordType, ZoneType};

pub struct DnsService {
    repo: Arc<dyn DnsRepository>,
    soa: SoaConfig,
}

impl DnsService {
    pub fn new(repo: Arc<dyn DnsRepository>, soa: SoaConfig) -> Self {
        Self { repo, soa }
    }

    /// Bind an IP allocation to an FQDN, optionally auto-generating a PTR record.
    ///
    /// - Creates the forward A/AAAA record in the appropriate zone (zone must exist)
    /// - If `auto_ptr` is true, creates or reuses the reverse zone and inserts PTR
    /// - All writes happen in a logical unit — caller should wrap in a DB transaction
    ///   if the repository backend supports it
    pub async fn bind_allocation(
        &self,
        allocation_id: Uuid,
        ip: IpAddr,
        fqdn: &str,
        forward_zone: &str,
        auto_ptr: bool,
    ) -> Result<()> {
        // 1. Resolve forward zone
        let zone = self
            .repo
            .get_zone_by_name(forward_zone)
            .await?
            .with_context(|| format!("forward zone '{}' not found", forward_zone))?;

        // 2. Derive relative label from FQDN + zone name
        let label = fqdn
            .strip_suffix(&format!(".{}", forward_zone))
            .unwrap_or(fqdn)
            .to_string();

        // 3. Insert forward A or AAAA record
        let record_type = match ip {
            IpAddr::V4(_) => RecordType::A,
            IpAddr::V6(_) => RecordType::Aaaa,
        };
        let forward_record = DnsRecord {
            id: Uuid::new_v4(),
            zone_id: zone.id,
            name: label,
            record_type,
            value: ip.to_string(),
            ttl: None,
            priority: None,
            allocation_id: Some(allocation_id),
            auto_generated: true,
        };
        self.repo.create_record(&forward_record).await?;
        self.repo.touch_zone(zone.id).await?;

        // 4. Auto-PTR
        if auto_ptr {
            self.ensure_ptr(allocation_id, ip, fqdn).await?;
        }

        Ok(())
    }

    /// Ensure a PTR record exists for the given IP pointing to `fqdn`.
    /// Creates the reverse zone if it doesn't exist.
    async fn ensure_ptr(&self, allocation_id: Uuid, ip: IpAddr, fqdn: &str) -> Result<()> {
        let (label, zone_name) = ptr_components(ip);

        // Get or create reverse zone
        let zone = match self.repo.get_zone_by_name(&zone_name).await? {
            Some(z) => z,
            None => {
                let z = DnsZone {
                    id: Uuid::new_v4(),
                    name: zone_name.clone(),
                    zone_type: match ip {
                        IpAddr::V4(_) => ZoneType::ReverseV4,
                        IpAddr::V6(_) => ZoneType::ReverseV6,
                    },
                    prefix: None,
                    ttl_default: 300,
                    updated_at: chrono::Utc::now(),
                };
                self.repo.create_zone(&z).await?;
                z
            }
        };

        // PTR value must be FQDN with trailing dot
        let ptr_value = if fqdn.ends_with('.') {
            fqdn.to_string()
        } else {
            format!("{}.", fqdn)
        };

        let ptr_record = DnsRecord {
            id: Uuid::new_v4(),
            zone_id: zone.id,
            name: label,
            record_type: RecordType::Ptr,
            value: ptr_value,
            ttl: None,
            priority: None,
            allocation_id: Some(allocation_id),
            auto_generated: true,
        };
        self.repo.create_record(&ptr_record).await?;
        self.repo.touch_zone(zone.id).await?;

        Ok(())
    }

    /// Remove all auto-generated DNS records for an allocation (called on deallocation).
    /// Manually curated records (auto_generated = false) are left untouched.
    pub async fn unbind_allocation(&self, allocation_id: Uuid) -> Result<u64> {
        self.repo
            .delete_auto_records_for_allocation(allocation_id)
            .await
    }

    /// Export a single zone to a string using the provided exporter.
    pub async fn export_zone<E: ZoneExporter>(
        &self,
        zone_name: &str,
        exporter: &E,
    ) -> Result<String> {
        let zone = self
            .repo
            .get_zone_by_name(zone_name)
            .await?
            .with_context(|| format!("zone '{}' not found", zone_name))?;
        let records = self.repo.list_records_for_zone(zone.id).await?;
        exporter
            .export_zone(&zone, &records, &self.soa)
            .map_err(|e| anyhow::anyhow!("export failed: {}", e))
    }

    /// Export all zones to a vec of (zone_name, zone_file_content) pairs.
    pub async fn export_all<E: ZoneExporter>(&self, exporter: &E) -> Result<Vec<(String, String)>> {
        let zones = self.repo.list_zones().await?;
        let mut results = Vec::with_capacity(zones.len());
        for zone in &zones {
            let records = self.repo.list_records_for_zone(zone.id).await?;
            let content = exporter
                .export_zone(zone, &records, &self.soa)
                .map_err(|e| anyhow::anyhow!("export failed for zone '{}': {}", zone.name, e))?;
            results.push((zone.name.clone(), content));
        }
        Ok(results)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::export::bind::BindExporter;
    use std::collections::HashMap;
    use std::sync::Mutex;

    /// In-memory mock of DnsRepository for unit tests.
    struct MockDnsRepo {
        zones: Mutex<Vec<DnsZone>>,
        records: Mutex<Vec<DnsRecord>>,
        touched: Mutex<Vec<Uuid>>,
    }

    impl MockDnsRepo {
        fn new() -> Self {
            Self {
                zones: Mutex::new(Vec::new()),
                records: Mutex::new(Vec::new()),
                touched: Mutex::new(Vec::new()),
            }
        }

        fn with_zone(self, zone: DnsZone) -> Self {
            self.zones.lock().unwrap().push(zone);
            self
        }

        fn records(&self) -> Vec<DnsRecord> {
            self.records.lock().unwrap().clone()
        }

        fn zones(&self) -> Vec<DnsZone> {
            self.zones.lock().unwrap().clone()
        }

        fn records_by_type(&self) -> HashMap<String, Vec<DnsRecord>> {
            let mut map: HashMap<String, Vec<DnsRecord>> = HashMap::new();
            for r in self.records.lock().unwrap().iter() {
                map.entry(r.record_type.to_string())
                    .or_default()
                    .push(r.clone());
            }
            map
        }
    }

    #[async_trait::async_trait]
    impl DnsRepository for MockDnsRepo {
        async fn get_zone_by_name(&self, name: &str) -> Result<Option<DnsZone>> {
            Ok(self
                .zones
                .lock()
                .unwrap()
                .iter()
                .find(|z| z.name == name)
                .cloned())
        }

        async fn create_zone(&self, zone: &DnsZone) -> Result<()> {
            self.zones.lock().unwrap().push(zone.clone());
            Ok(())
        }

        async fn list_zones(&self) -> Result<Vec<DnsZone>> {
            Ok(self.zones.lock().unwrap().clone())
        }

        async fn touch_zone(&self, zone_id: Uuid) -> Result<()> {
            self.touched.lock().unwrap().push(zone_id);
            Ok(())
        }

        async fn create_record(&self, record: &DnsRecord) -> Result<()> {
            self.records.lock().unwrap().push(record.clone());
            Ok(())
        }

        async fn list_records_for_zone(&self, zone_id: Uuid) -> Result<Vec<DnsRecord>> {
            Ok(self
                .records
                .lock()
                .unwrap()
                .iter()
                .filter(|r| r.zone_id == zone_id)
                .cloned()
                .collect())
        }

        async fn delete_auto_records_for_allocation(&self, allocation_id: Uuid) -> Result<u64> {
            let mut records = self.records.lock().unwrap();
            let before = records.len();
            records.retain(|r| !(r.auto_generated && r.allocation_id == Some(allocation_id)));
            Ok((before - records.len()) as u64)
        }
    }

    fn test_soa() -> SoaConfig {
        SoaConfig {
            mname: "ns1.example.com.".to_string(),
            rname: "admin.example.com.".to_string(),
            refresh: 3600,
            retry: 900,
            expire: 604800,
            minimum: 300,
        }
    }

    fn forward_zone() -> DnsZone {
        DnsZone {
            id: Uuid::new_v4(),
            name: "example.com".to_string(),
            zone_type: ZoneType::Forward,
            prefix: None,
            ttl_default: 300,
            updated_at: chrono::Utc::now(),
        }
    }

    // ── Test 1: IPv4 bind with auto-PTR ─────────────────────────────

    #[tokio::test]
    async fn test_bind_v4_with_ptr() {
        let zone = forward_zone();
        let repo = Arc::new(MockDnsRepo::new().with_zone(zone));
        let svc = DnsService::new(repo.clone(), test_soa());
        let alloc_id = Uuid::new_v4();
        let ip: IpAddr = "192.168.1.10".parse().unwrap();

        svc.bind_allocation(alloc_id, ip, "web01.example.com", "example.com", true)
            .await
            .unwrap();

        let by_type = repo.records_by_type();

        // Forward A record
        let a_records = &by_type["A"];
        assert_eq!(a_records.len(), 1);
        assert_eq!(a_records[0].name, "web01");
        assert_eq!(a_records[0].value, "192.168.1.10");
        assert_eq!(a_records[0].allocation_id, Some(alloc_id));

        // Reverse PTR record
        let ptr_records = &by_type["PTR"];
        assert_eq!(ptr_records.len(), 1);
        assert_eq!(ptr_records[0].name, "10");
        assert_eq!(ptr_records[0].value, "web01.example.com.");

        // Reverse zone was auto-created
        let zones = repo.zones();
        let rev = zones
            .iter()
            .find(|z| z.name.ends_with("in-addr.arpa"))
            .unwrap();
        assert_eq!(rev.name, "1.168.192.in-addr.arpa");
        assert_eq!(rev.zone_type, ZoneType::ReverseV4);
    }

    // ── Test 2: IPv6 bind with auto-PTR ─────────────────────────────

    #[tokio::test]
    async fn test_bind_v6_with_ptr() {
        let zone = forward_zone();
        let repo = Arc::new(MockDnsRepo::new().with_zone(zone));
        let svc = DnsService::new(repo.clone(), test_soa());
        let alloc_id = Uuid::new_v4();
        let ip: IpAddr = "2001:db8::1".parse().unwrap();

        svc.bind_allocation(alloc_id, ip, "web01.example.com", "example.com", true)
            .await
            .unwrap();

        let by_type = repo.records_by_type();

        // Forward AAAA record
        let aaaa_records = &by_type["AAAA"];
        assert_eq!(aaaa_records.len(), 1);
        assert_eq!(aaaa_records[0].name, "web01");
        assert_eq!(aaaa_records[0].value, "2001:db8::1");

        // PTR record exists
        let ptr_records = &by_type["PTR"];
        assert_eq!(ptr_records.len(), 1);
        assert_eq!(ptr_records[0].value, "web01.example.com.");

        // Reverse zone is ReverseV6
        let zones = repo.zones();
        let rev = zones.iter().find(|z| z.name.ends_with("ip6.arpa")).unwrap();
        assert_eq!(rev.zone_type, ZoneType::ReverseV6);
    }

    // ── Test 3: Bind without auto-PTR ───────────────────────────────

    #[tokio::test]
    async fn test_bind_without_auto_ptr() {
        let zone = forward_zone();
        let repo = Arc::new(MockDnsRepo::new().with_zone(zone));
        let svc = DnsService::new(repo.clone(), test_soa());
        let alloc_id = Uuid::new_v4();
        let ip: IpAddr = "10.0.0.1".parse().unwrap();

        svc.bind_allocation(alloc_id, ip, "db01.example.com", "example.com", false)
            .await
            .unwrap();

        let records = repo.records();
        // Only the forward A record — no PTR
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].record_type, RecordType::A);
        assert_eq!(records[0].name, "db01");

        // No reverse zone created
        let zones = repo.zones();
        assert_eq!(zones.len(), 1); // only the original forward zone
    }

    // ── Test 4: Unbind removes only auto-generated records ──────────

    #[tokio::test]
    async fn test_unbind_removes_auto_records() {
        let zone = forward_zone();
        let zone_id = zone.id;
        let repo = Arc::new(MockDnsRepo::new().with_zone(zone));
        let svc = DnsService::new(repo.clone(), test_soa());
        let alloc_id = Uuid::new_v4();
        let ip: IpAddr = "192.168.1.20".parse().unwrap();

        // Bind with PTR (creates 2 auto records)
        svc.bind_allocation(alloc_id, ip, "app01.example.com", "example.com", true)
            .await
            .unwrap();

        // Manually insert a non-auto record for the same allocation
        let manual = DnsRecord {
            id: Uuid::new_v4(),
            zone_id,
            name: "app01-cname".to_string(),
            record_type: RecordType::Cname,
            value: "app01.example.com.".to_string(),
            ttl: None,
            priority: None,
            allocation_id: Some(alloc_id),
            auto_generated: false,
        };
        repo.create_record(&manual).await.unwrap();

        assert_eq!(repo.records().len(), 3); // A + PTR + CNAME

        let deleted = svc.unbind_allocation(alloc_id).await.unwrap();
        assert_eq!(deleted, 2); // only auto-generated removed

        let remaining = repo.records();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].record_type, RecordType::Cname);
        assert!(!remaining[0].auto_generated);
    }

    // ── Test 5: Export single zone ──────────────────────────────────

    #[tokio::test]
    async fn test_export_zone() {
        let zone = forward_zone();
        let repo = Arc::new(MockDnsRepo::new().with_zone(zone));
        let svc = DnsService::new(repo.clone(), test_soa());
        let alloc_id = Uuid::new_v4();
        let ip: IpAddr = "192.168.1.10".parse().unwrap();

        svc.bind_allocation(alloc_id, ip, "web01.example.com", "example.com", false)
            .await
            .unwrap();

        let exporter = BindExporter;
        let output = svc.export_zone("example.com", &exporter).await.unwrap();

        assert!(output.starts_with("$TTL 300\n"));
        assert!(output.contains("IN SOA ns1.example.com. admin.example.com."));
        assert!(output.contains("web01\t300\tIN\tA\t192.168.1.10"));
    }

    // ── Test 6: Export all zones ────────────────────────────────────

    #[tokio::test]
    async fn test_export_all() {
        let zone = forward_zone();
        let repo = Arc::new(MockDnsRepo::new().with_zone(zone));
        let svc = DnsService::new(repo.clone(), test_soa());
        let alloc_id = Uuid::new_v4();
        let ip: IpAddr = "192.168.1.10".parse().unwrap();

        // This creates the forward record + a reverse zone with PTR
        svc.bind_allocation(alloc_id, ip, "web01.example.com", "example.com", true)
            .await
            .unwrap();

        let exporter = BindExporter;
        let results = svc.export_all(&exporter).await.unwrap();

        assert_eq!(results.len(), 2); // forward + reverse zones

        let names: Vec<&str> = results.iter().map(|(n, _)| n.as_str()).collect();
        assert!(names.contains(&"example.com"));
        assert!(names.contains(&"1.168.192.in-addr.arpa"));

        // Each export contains valid BIND preamble
        for (_, content) in &results {
            assert!(content.starts_with("$TTL"));
            assert!(content.contains("IN SOA"));
        }
    }
}
