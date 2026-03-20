pub mod arpa;
pub mod export;
pub mod repository;
pub mod service;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ZoneType {
    Forward,
    ReverseV4,
    ReverseV6,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RecordType {
    A,
    Aaaa,
    Ptr,
    Cname,
    Mx,
    Txt,
    Ns,
    Srv,
}

impl std::fmt::Display for RecordType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RecordType::A => write!(f, "A"),
            RecordType::Aaaa => write!(f, "AAAA"),
            RecordType::Ptr => write!(f, "PTR"),
            RecordType::Cname => write!(f, "CNAME"),
            RecordType::Mx => write!(f, "MX"),
            RecordType::Txt => write!(f, "TXT"),
            RecordType::Ns => write!(f, "NS"),
            RecordType::Srv => write!(f, "SRV"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsZone {
    pub id: Uuid,
    pub name: String,
    pub zone_type: ZoneType,
    pub prefix: Option<String>,
    pub ttl_default: u32,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsRecord {
    pub id: Uuid,
    pub zone_id: Uuid,
    pub name: String,
    pub record_type: RecordType,
    pub value: String,
    pub ttl: Option<u32>,
    pub priority: Option<u16>,
    pub allocation_id: Option<Uuid>,
    pub auto_generated: bool,
}
