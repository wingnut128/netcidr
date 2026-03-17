use crate::error::{IpCalcError, Result};
use crate::ipam::models::*;
use crate::output::{CsvOutput, TextOutput};
use std::fmt::Write;

// ---------------------------------------------------------------------------
// TextOutput implementations
// ---------------------------------------------------------------------------

impl TextOutput for Supernet {
    fn to_text(&self) -> String {
        let mut out = String::new();
        writeln!(out, "Supernet").unwrap();
        writeln!(out, "========").unwrap();
        writeln!(out, "ID:                {}", self.id).unwrap();
        writeln!(out, "CIDR:              {}", self.cidr).unwrap();
        writeln!(out, "Network Address:   {}", self.network_address).unwrap();
        writeln!(out, "Broadcast Address: {}", self.broadcast_address).unwrap();
        writeln!(out, "Prefix Length:     /{}", self.prefix_length).unwrap();
        writeln!(out, "Total Hosts:       {}", self.total_hosts).unwrap();
        writeln!(out, "IP Version:        IPv{}", self.ip_version).unwrap();
        if let Some(ref name) = self.name {
            writeln!(out, "Name:              {}", name).unwrap();
        }
        if let Some(ref desc) = self.description {
            writeln!(out, "Description:       {}", desc).unwrap();
        }
        writeln!(out, "Created:           {}", self.created_at).unwrap();
        out
    }
}

impl TextOutput for SupernetList {
    fn to_text(&self) -> String {
        let mut out = String::new();
        writeln!(out, "Supernets ({} total)", self.count).unwrap();
        writeln!(out, "===================").unwrap();
        for (i, sn) in self.supernets.iter().enumerate() {
            let name = sn.name.as_deref().unwrap_or("-");
            writeln!(
                out,
                "  {}. {} [{}] (IPv{}, {} hosts)",
                i + 1,
                sn.cidr,
                name,
                sn.ip_version,
                sn.total_hosts
            )
            .unwrap();
        }
        out
    }
}

impl TextOutput for Allocation {
    fn to_text(&self) -> String {
        let mut out = String::new();
        writeln!(out, "Allocation").unwrap();
        writeln!(out, "==========").unwrap();
        writeln!(out, "ID:                {}", self.id).unwrap();
        writeln!(out, "Supernet ID:       {}", self.supernet_id).unwrap();
        writeln!(out, "CIDR:              {}", self.cidr).unwrap();
        writeln!(out, "Network Address:   {}", self.network_address).unwrap();
        writeln!(out, "Broadcast Address: {}", self.broadcast_address).unwrap();
        writeln!(out, "Prefix Length:     /{}", self.prefix_length).unwrap();
        writeln!(out, "Total Hosts:       {}", self.total_hosts).unwrap();
        writeln!(out, "Status:            {}", self.status).unwrap();
        if let Some(ref v) = self.resource_id {
            writeln!(out, "Resource ID:       {}", v).unwrap();
        }
        if let Some(ref v) = self.resource_type {
            writeln!(out, "Resource Type:     {}", v).unwrap();
        }
        if let Some(ref v) = self.name {
            writeln!(out, "Name:              {}", v).unwrap();
        }
        if let Some(ref v) = self.description {
            writeln!(out, "Description:       {}", v).unwrap();
        }
        if let Some(ref v) = self.environment {
            writeln!(out, "Environment:       {}", v).unwrap();
        }
        if let Some(ref v) = self.owner {
            writeln!(out, "Owner:             {}", v).unwrap();
        }
        if !self.tags.is_empty() {
            writeln!(out, "Tags:").unwrap();
            for tag in &self.tags {
                writeln!(out, "  {}={}", tag.key, tag.value).unwrap();
            }
        }
        writeln!(out, "Created:           {}", self.created_at).unwrap();
        writeln!(out, "Updated:           {}", self.updated_at).unwrap();
        if let Some(ref v) = self.released_at {
            writeln!(out, "Released:          {}", v).unwrap();
        }
        out
    }
}

impl TextOutput for AllocationList {
    fn to_text(&self) -> String {
        let mut out = String::new();
        writeln!(out, "Allocations ({} total)", self.count).unwrap();
        writeln!(out, "======================").unwrap();
        for (i, a) in self.allocations.iter().enumerate() {
            let name = a.name.as_deref().unwrap_or("-");
            writeln!(
                out,
                "  {}. {} [{}] status={} resource={}",
                i + 1,
                a.cidr,
                name,
                a.status,
                a.resource_id.as_deref().unwrap_or("-"),
            )
            .unwrap();
        }
        out
    }
}

impl TextOutput for UtilizationReport {
    fn to_text(&self) -> String {
        let mut out = String::new();
        writeln!(out, "Utilization Report").unwrap();
        writeln!(out, "==================").unwrap();
        writeln!(out, "Supernet:          {}", self.supernet_cidr).unwrap();
        writeln!(out, "Total Addresses:   {}", self.total_addresses).unwrap();
        writeln!(out, "Allocated:         {}", self.allocated_addresses).unwrap();
        writeln!(out, "Free:              {}", self.free_addresses).unwrap();
        writeln!(out, "Utilization:       {:.2}%", self.utilization_percent).unwrap();
        writeln!(out, "Allocation Count:  {}", self.allocation_count).unwrap();
        writeln!(out).unwrap();
        writeln!(out, "By Status").unwrap();
        writeln!(out, "---------").unwrap();
        writeln!(
            out,
            "  Active:          {} addresses ({} allocations)",
            self.by_status.active_addresses, self.by_status.active_count
        )
        .unwrap();
        writeln!(
            out,
            "  Reserved:        {} addresses ({} allocations)",
            self.by_status.reserved_addresses, self.by_status.reserved_count
        )
        .unwrap();
        writeln!(
            out,
            "  Released:        {} addresses ({} allocations)",
            self.by_status.released_addresses, self.by_status.released_count
        )
        .unwrap();
        out
    }
}

impl TextOutput for FreeBlocksReport {
    fn to_text(&self) -> String {
        let mut out = String::new();
        writeln!(out, "Free Blocks").unwrap();
        writeln!(out, "===========").unwrap();
        writeln!(out, "Supernet:    {}", self.supernet_cidr).unwrap();
        writeln!(out, "Total Free:  {} addresses", self.total_free).unwrap();
        writeln!(out).unwrap();
        for (i, block) in self.blocks.iter().enumerate() {
            writeln!(
                out,
                "  {}. {} ({} addresses)",
                i + 1,
                block.cidr,
                block.size
            )
            .unwrap();
        }
        out
    }
}

impl TextOutput for AuditList {
    fn to_text(&self) -> String {
        let mut out = String::new();
        writeln!(out, "Audit Log ({} entries)", self.count).unwrap();
        writeln!(out, "========================").unwrap();
        for entry in &self.entries {
            writeln!(
                out,
                "  [{}] {} {}/{} {}",
                entry.timestamp,
                entry.action,
                entry.entity_type,
                entry.entity_id,
                entry.details.as_deref().unwrap_or(""),
            )
            .unwrap();
        }
        out
    }
}

// ---------------------------------------------------------------------------
// CsvOutput implementations
// ---------------------------------------------------------------------------

fn csv_err(e: impl std::fmt::Display) -> IpCalcError {
    IpCalcError::Csv(e.to_string())
}

fn finish_csv(wtr: csv::Writer<Vec<u8>>) -> Result<String> {
    let bytes = wtr.into_inner().map_err(csv_err)?;
    String::from_utf8(bytes).map_err(csv_err)
}

impl CsvOutput for Supernet {
    fn to_csv(&self) -> Result<String> {
        let mut wtr = csv::Writer::from_writer(Vec::new());
        wtr.write_record([
            "id",
            "cidr",
            "network_address",
            "broadcast_address",
            "prefix_length",
            "total_hosts",
            "name",
            "description",
            "ip_version",
            "created_at",
        ])
        .map_err(csv_err)?;
        wtr.write_record([
            &self.id,
            &self.cidr,
            &self.network_address,
            &self.broadcast_address,
            &self.prefix_length.to_string(),
            &self.total_hosts.to_string(),
            self.name.as_deref().unwrap_or(""),
            self.description.as_deref().unwrap_or(""),
            &self.ip_version.to_string(),
            &self.created_at,
        ])
        .map_err(csv_err)?;
        finish_csv(wtr)
    }
}

impl CsvOutput for SupernetList {
    fn to_csv(&self) -> Result<String> {
        let mut wtr = csv::Writer::from_writer(Vec::new());
        wtr.write_record([
            "id",
            "cidr",
            "network_address",
            "broadcast_address",
            "prefix_length",
            "total_hosts",
            "name",
            "description",
            "ip_version",
            "created_at",
        ])
        .map_err(csv_err)?;
        for sn in &self.supernets {
            wtr.write_record([
                &sn.id,
                &sn.cidr,
                &sn.network_address,
                &sn.broadcast_address,
                &sn.prefix_length.to_string(),
                &sn.total_hosts.to_string(),
                sn.name.as_deref().unwrap_or(""),
                sn.description.as_deref().unwrap_or(""),
                &sn.ip_version.to_string(),
                &sn.created_at,
            ])
            .map_err(csv_err)?;
        }
        finish_csv(wtr)
    }
}

impl CsvOutput for Allocation {
    fn to_csv(&self) -> Result<String> {
        let mut wtr = csv::Writer::from_writer(Vec::new());
        wtr.write_record(allocation_csv_header()).map_err(csv_err)?;
        write_allocation_csv_row(&mut wtr, self)?;
        finish_csv(wtr)
    }
}

impl CsvOutput for AllocationList {
    fn to_csv(&self) -> Result<String> {
        let mut wtr = csv::Writer::from_writer(Vec::new());
        wtr.write_record(allocation_csv_header()).map_err(csv_err)?;
        for a in &self.allocations {
            write_allocation_csv_row(&mut wtr, a)?;
        }
        finish_csv(wtr)
    }
}

impl CsvOutput for UtilizationReport {
    fn to_csv(&self) -> Result<String> {
        let mut wtr = csv::Writer::from_writer(Vec::new());
        wtr.write_record([
            "supernet_id",
            "supernet_cidr",
            "total_addresses",
            "allocated_addresses",
            "free_addresses",
            "utilization_percent",
            "allocation_count",
            "active_addresses",
            "active_count",
            "reserved_addresses",
            "reserved_count",
            "released_addresses",
            "released_count",
        ])
        .map_err(csv_err)?;
        wtr.write_record([
            &self.supernet_id,
            &self.supernet_cidr,
            &self.total_addresses.to_string(),
            &self.allocated_addresses.to_string(),
            &self.free_addresses.to_string(),
            &format!("{:.2}", self.utilization_percent),
            &self.allocation_count.to_string(),
            &self.by_status.active_addresses.to_string(),
            &self.by_status.active_count.to_string(),
            &self.by_status.reserved_addresses.to_string(),
            &self.by_status.reserved_count.to_string(),
            &self.by_status.released_addresses.to_string(),
            &self.by_status.released_count.to_string(),
        ])
        .map_err(csv_err)?;
        finish_csv(wtr)
    }
}

impl CsvOutput for FreeBlocksReport {
    fn to_csv(&self) -> Result<String> {
        let mut wtr = csv::Writer::from_writer(Vec::new());
        wtr.write_record(["cidr", "size"]).map_err(csv_err)?;
        for block in &self.blocks {
            wtr.write_record([&block.cidr, &block.size.to_string()])
                .map_err(csv_err)?;
        }
        finish_csv(wtr)
    }
}

impl CsvOutput for AuditList {
    fn to_csv(&self) -> Result<String> {
        let mut wtr = csv::Writer::from_writer(Vec::new());
        wtr.write_record([
            "id",
            "timestamp",
            "action",
            "entity_type",
            "entity_id",
            "details",
        ])
        .map_err(csv_err)?;
        for e in &self.entries {
            wtr.write_record([
                &e.id,
                &e.timestamp,
                &e.action,
                &e.entity_type,
                &e.entity_id,
                e.details.as_deref().unwrap_or(""),
            ])
            .map_err(csv_err)?;
        }
        finish_csv(wtr)
    }
}

fn allocation_csv_header() -> &'static [&'static str] {
    &[
        "id",
        "supernet_id",
        "cidr",
        "network_address",
        "broadcast_address",
        "prefix_length",
        "total_hosts",
        "status",
        "resource_id",
        "resource_type",
        "name",
        "description",
        "environment",
        "owner",
        "created_at",
        "updated_at",
        "released_at",
    ]
}

fn write_allocation_csv_row(wtr: &mut csv::Writer<Vec<u8>>, a: &Allocation) -> Result<()> {
    wtr.write_record([
        &a.id,
        &a.supernet_id,
        &a.cidr,
        &a.network_address,
        &a.broadcast_address,
        &a.prefix_length.to_string(),
        &a.total_hosts.to_string(),
        &a.status.to_string(),
        a.resource_id.as_deref().unwrap_or(""),
        a.resource_type.as_deref().unwrap_or(""),
        a.name.as_deref().unwrap_or(""),
        a.description.as_deref().unwrap_or(""),
        a.environment.as_deref().unwrap_or(""),
        a.owner.as_deref().unwrap_or(""),
        &a.created_at,
        &a.updated_at,
        a.released_at.as_deref().unwrap_or(""),
    ])
    .map_err(csv_err)
}
