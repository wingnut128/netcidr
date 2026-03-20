use anyhow::Result;
use async_trait::async_trait;
use uuid::Uuid;

use super::{DnsRecord, DnsZone};

#[async_trait]
pub trait DnsRepository: Send + Sync {
    async fn get_zone_by_name(&self, name: &str) -> Result<Option<DnsZone>>;
    async fn create_zone(&self, zone: &DnsZone) -> Result<()>;
    async fn list_zones(&self) -> Result<Vec<DnsZone>>;
    async fn touch_zone(&self, zone_id: Uuid) -> Result<()>;
    async fn create_record(&self, record: &DnsRecord) -> Result<()>;
    async fn list_records_for_zone(&self, zone_id: Uuid) -> Result<Vec<DnsRecord>>;
    async fn delete_auto_records_for_allocation(&self, allocation_id: Uuid) -> Result<u64>;
}
