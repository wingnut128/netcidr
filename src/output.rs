use crate::batch::{BatchEntryResult, BatchResult, SubnetResult};
use crate::contains::ContainsResult;
use crate::error::{NetcidrError, Result};
use crate::from_range::{Ipv4FromRangeResult, Ipv6FromRangeResult};
use crate::ipv4::Ipv4Subnet;
use crate::ipv6::Ipv6Subnet;
use crate::subnet_generator::{
    Ipv4SplitTree, Ipv4SplitTreeNode, Ipv4SubnetList, Ipv4VlsmList, Ipv6SplitTree,
    Ipv6SplitTreeNode, Ipv6SubnetList, Ipv6VlsmList, SplitSummary,
};
use crate::summarize::{Ipv4SummaryResult, Ipv6SummaryResult};
use serde::Serialize;
use std::fmt::Write as FmtWrite;
use std::fs::File;
use std::io::Write;
use std::path::Path;

#[derive(Debug, Clone, Copy, Default)]
pub enum OutputFormat {
    #[default]
    Json,
    Text,
    Csv,
    Yaml,
}

impl std::str::FromStr for OutputFormat {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "json" => Ok(Self::Json),
            "text" | "plain" | "txt" => Ok(Self::Text),
            "csv" => Ok(Self::Csv),
            "yaml" | "yml" => Ok(Self::Yaml),
            _ => Err(format!("Unknown output format: {}", s)),
        }
    }
}

fn csv_err(e: impl std::fmt::Display) -> NetcidrError {
    NetcidrError::Csv(e.to_string())
}

/// Neutralize a CSV cell that could be interpreted as a formula by spreadsheet
/// software. Cells beginning with `=`, `+`, `-`, `@`, tab, or carriage return
/// are prefixed with a single quote per the OWASP guidance — preserves the
/// visible value but prevents Excel/Sheets/LibreOffice from auto-evaluating it.
fn sanitize_csv_cell(cell: &str) -> String {
    match cell.chars().next() {
        Some('=' | '+' | '-' | '@' | '\t' | '\r') => {
            let mut s = String::with_capacity(cell.len() + 1);
            s.push('\'');
            s.push_str(cell);
            s
        }
        _ => cell.to_string(),
    }
}

/// Write a CSV record with every cell run through [`sanitize_csv_cell`] first.
fn write_safe_record<I, S>(wtr: &mut csv::Writer<Vec<u8>>, cells: I) -> Result<()>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let safe: Vec<String> = cells
        .into_iter()
        .map(|c| sanitize_csv_cell(c.as_ref()))
        .collect();
    wtr.write_record(&safe).map_err(csv_err)
}

pub struct OutputWriter {
    format: OutputFormat,
    file_path: Option<String>,
}

impl OutputWriter {
    pub fn new(format: OutputFormat, file_path: Option<String>) -> Self {
        Self { format, file_path }
    }

    pub fn write<T: Serialize + TextOutput + CsvOutput>(&self, data: &T) -> Result<String> {
        let output = match self.format {
            OutputFormat::Json => serde_json::to_string_pretty(data)?,
            OutputFormat::Text => data.to_text(),
            OutputFormat::Csv => data.to_csv()?,
            OutputFormat::Yaml => {
                serde_saphyr::to_string(data).map_err(|e| NetcidrError::Yaml(e.to_string()))?
            }
        };

        if let Some(ref path) = self.file_path {
            let mut file = File::create(Path::new(path))?;
            file.write_all(output.as_bytes())?;
        }

        Ok(output)
    }
}

// ---------------------------------------------------------------------------
// TextOutput trait + implementations
// ---------------------------------------------------------------------------

pub trait TextOutput {
    fn to_text(&self) -> String;
}

impl TextOutput for Ipv4Subnet {
    fn to_text(&self) -> String {
        let mut out = String::new();
        writeln!(out, "IPv4 Subnet Calculator").unwrap();
        writeln!(out, "======================").unwrap();
        writeln!(out, "Input:             {}", self.input).unwrap();
        writeln!(out, "Network Address:   {}", self.network).unwrap();
        writeln!(out, "Broadcast Address: {}", self.broadcast).unwrap();
        writeln!(out, "Subnet Mask:       {}", self.mask).unwrap();
        writeln!(out, "Wildcard Mask:     {}", self.wildcard).unwrap();
        writeln!(out, "Prefix Length:     /{}", self.prefix_length).unwrap();
        writeln!(out, "First Host:        {}", self.first_host).unwrap();
        writeln!(out, "Last Host:         {}", self.last_host).unwrap();
        writeln!(out, "Total Hosts:       {}", self.total_hosts).unwrap();
        writeln!(out, "Usable Hosts:      {}", self.usable_hosts).unwrap();
        writeln!(out, "Network Class:     {}", self.network_class).unwrap();
        writeln!(
            out,
            "Private Address:   {}",
            if self.is_private { "Yes" } else { "No" }
        )
        .unwrap();
        writeln!(out, "Address Type:      {}", self.address_type).unwrap();
        out
    }
}

impl TextOutput for Ipv6Subnet {
    fn to_text(&self) -> String {
        let mut out = String::new();
        writeln!(out, "IPv6 Subnet Calculator").unwrap();
        writeln!(out, "======================").unwrap();
        writeln!(out, "Input:               {}", self.input).unwrap();
        writeln!(out, "Network Address:     {}", self.network).unwrap();
        writeln!(out, "Network (Full):      {}", self.network_address_full).unwrap();
        writeln!(out, "Last Address:        {}", self.last).unwrap();
        writeln!(out, "Last Address (Full): {}", self.last_address_full).unwrap();
        writeln!(out, "Prefix Length:       /{}", self.prefix_length).unwrap();
        writeln!(out, "Total Addresses:     {}", self.total_addresses).unwrap();
        writeln!(out, "Hextets:             {}", self.hextets.join(":")).unwrap();
        writeln!(out, "Address Type:        {}", self.address_type).unwrap();
        out
    }
}

impl TextOutput for ContainsResult {
    fn to_text(&self) -> String {
        let mut out = String::new();
        writeln!(out, "Address Containment Check").unwrap();
        writeln!(out, "=========================").unwrap();
        writeln!(out, "Subnet:            {}", self.cidr).unwrap();
        writeln!(out, "Address:           {}", self.address).unwrap();
        writeln!(
            out,
            "Contained:         {}",
            if self.contained { "Yes" } else { "No" }
        )
        .unwrap();
        writeln!(out, "Network Address:   {}", self.network_address).unwrap();
        writeln!(out, "Broadcast Address: {}", self.broadcast_address).unwrap();
        out
    }
}

impl TextOutput for Ipv4SubnetList {
    fn to_text(&self) -> String {
        let mut out = String::new();
        writeln!(out, "IPv4 Subnet Generator").unwrap();
        writeln!(out, "=====================").unwrap();
        writeln!(out, "CidrBlock: {}", self.cidr_block.input).unwrap();
        writeln!(out, "New Prefix: /{}", self.new_prefix).unwrap();
        writeln!(out, "Generated {} subnets:\n", self.requested_count).unwrap();

        for (i, subnet) in self.subnets.iter().enumerate() {
            writeln!(
                out,
                "  {}. {}/{} (Hosts: {}-{})",
                i + 1,
                subnet.network,
                subnet.prefix_length,
                subnet.first_host,
                subnet.last_host
            )
            .unwrap();
        }
        out
    }
}

impl TextOutput for Ipv6SubnetList {
    fn to_text(&self) -> String {
        let mut out = String::new();
        writeln!(out, "IPv6 Subnet Generator").unwrap();
        writeln!(out, "=====================").unwrap();
        writeln!(out, "CidrBlock: {}", self.cidr_block.input).unwrap();
        writeln!(out, "New Prefix: /{}", self.new_prefix).unwrap();
        writeln!(out, "Generated {} subnets:\n", self.requested_count).unwrap();

        for (i, subnet) in self.subnets.iter().enumerate() {
            writeln!(
                out,
                "  {}. {}/{}",
                i + 1,
                subnet.network,
                subnet.prefix_length
            )
            .unwrap();
        }
        out
    }
}

impl TextOutput for Ipv4VlsmList {
    fn to_text(&self) -> String {
        let mut out = String::new();
        writeln!(out, "IPv4 VLSM Allocation").unwrap();
        writeln!(out, "====================").unwrap();
        writeln!(out, "Supernet:   {}", self.cidr_block.input).unwrap();
        writeln!(out, "Requested:  {} sub-allocations", self.requested_count).unwrap();
        writeln!(out, "Allocated:  {} addresses", self.allocated_addresses).unwrap();
        writeln!(out, "Remaining:  {} addresses\n", self.remaining_addresses).unwrap();

        for (i, subnet) in self.subnets.iter().enumerate() {
            writeln!(
                out,
                "  {}. {}/{} (Hosts: {}-{}, {} total)",
                i + 1,
                subnet.network,
                subnet.prefix_length,
                subnet.first_host,
                subnet.last_host,
                subnet.total_hosts
            )
            .unwrap();
        }
        out
    }
}

impl TextOutput for Ipv6VlsmList {
    fn to_text(&self) -> String {
        let mut out = String::new();
        writeln!(out, "IPv6 VLSM Allocation").unwrap();
        writeln!(out, "====================").unwrap();
        writeln!(out, "Supernet:   {}", self.cidr_block.input).unwrap();
        writeln!(out, "Requested:  {} sub-allocations", self.requested_count).unwrap();
        writeln!(out, "Allocated:  {} addresses", self.allocated_addresses).unwrap();
        writeln!(out, "Remaining:  {} addresses\n", self.remaining_addresses).unwrap();

        for (i, subnet) in self.subnets.iter().enumerate() {
            writeln!(
                out,
                "  {}. {}/{} ({} addresses)",
                i + 1,
                subnet.network,
                subnet.prefix_length,
                subnet.total_addresses
            )
            .unwrap();
        }
        out
    }
}

/// Render the children of an IPv4 tree node as an ASCII tree, recursively.
/// `prefix` is the indentation carried down from ancestor levels.
fn render_ipv4_tree_children(out: &mut String, node: &Ipv4SplitTreeNode, prefix: &str) {
    let n = node.children.len();
    for (i, child) in node.children.iter().enumerate() {
        let last = i == n - 1;
        let connector = if last { "└── " } else { "├── " };
        writeln!(
            out,
            "{prefix}{connector}{}/{}",
            child.subnet.network, child.subnet.prefix_length
        )
        .unwrap();
        let child_prefix = format!("{prefix}{}", if last { "    " } else { "│   " });
        render_ipv4_tree_children(out, child, &child_prefix);
    }
}

fn render_ipv6_tree_children(out: &mut String, node: &Ipv6SplitTreeNode, prefix: &str) {
    let n = node.children.len();
    for (i, child) in node.children.iter().enumerate() {
        let last = i == n - 1;
        let connector = if last { "└── " } else { "├── " };
        writeln!(
            out,
            "{prefix}{connector}{}/{}",
            child.subnet.network, child.subnet.prefix_length
        )
        .unwrap();
        let child_prefix = format!("{prefix}{}", if last { "    " } else { "│   " });
        render_ipv6_tree_children(out, child, &child_prefix);
    }
}

fn steps_label(steps: &[u8]) -> String {
    steps
        .iter()
        .map(|s| format!("/{s}"))
        .collect::<Vec<_>>()
        .join(", ")
}

impl TextOutput for Ipv4SplitTree {
    fn to_text(&self) -> String {
        let mut out = String::new();
        writeln!(out, "IPv4 Hierarchical Split").unwrap();
        writeln!(out, "=======================").unwrap();
        writeln!(
            out,
            "Supernet: {}/{}",
            self.root.subnet.network, self.root.subnet.prefix_length
        )
        .unwrap();
        writeln!(out, "Steps:    {}", steps_label(&self.steps)).unwrap();
        writeln!(out, "Total:    {} subnets\n", self.total_subnets).unwrap();

        writeln!(
            out,
            "{}/{}",
            self.root.subnet.network, self.root.subnet.prefix_length
        )
        .unwrap();
        render_ipv4_tree_children(&mut out, &self.root, "");
        out
    }
}

impl TextOutput for Ipv6SplitTree {
    fn to_text(&self) -> String {
        let mut out = String::new();
        writeln!(out, "IPv6 Hierarchical Split").unwrap();
        writeln!(out, "=======================").unwrap();
        writeln!(
            out,
            "Supernet: {}/{}",
            self.root.subnet.network, self.root.subnet.prefix_length
        )
        .unwrap();
        writeln!(out, "Steps:    {}", steps_label(&self.steps)).unwrap();
        writeln!(out, "Total:    {} subnets\n", self.total_subnets).unwrap();

        writeln!(
            out,
            "{}/{}",
            self.root.subnet.network, self.root.subnet.prefix_length
        )
        .unwrap();
        render_ipv6_tree_children(&mut out, &self.root, "");
        out
    }
}

impl TextOutput for SplitSummary {
    fn to_text(&self) -> String {
        let mut out = String::new();
        writeln!(out, "Subnet Split Summary").unwrap();
        writeln!(out, "====================").unwrap();
        writeln!(out, "CidrBlock:           {}", self.cidr_block).unwrap();
        writeln!(out, "New Prefix:         /{}", self.new_prefix).unwrap();
        writeln!(out, "Available Subnets:  {}", self.available_subnets).unwrap();
        out
    }
}

macro_rules! impl_summary_text_output {
    ($ty:ty) => {
        impl TextOutput for $ty {
            fn to_text(&self) -> String {
                let mut out = String::new();
                writeln!(out, "CIDR Summarization").unwrap();
                writeln!(out, "==================").unwrap();
                writeln!(out, "Input CIDRs:   {}", self.input_count).unwrap();
                writeln!(out, "Output CIDRs:  {}", self.output_count).unwrap();
                writeln!(out).unwrap();
                for (i, cidr) in self.cidrs.iter().enumerate() {
                    writeln!(out, "  {}. {}/{}", i + 1, cidr.network, cidr.prefix_length).unwrap();
                }
                out
            }
        }
    };
}

impl_summary_text_output!(Ipv4SummaryResult);
impl_summary_text_output!(Ipv6SummaryResult);

macro_rules! impl_from_range_text_output {
    ($ty:ty) => {
        impl TextOutput for $ty {
            fn to_text(&self) -> String {
                let mut out = String::new();
                writeln!(out, "IP Range to CIDR").unwrap();
                writeln!(out, "=================").unwrap();
                writeln!(out, "Start Address: {}", self.start_address).unwrap();
                writeln!(out, "End Address:   {}", self.end_address).unwrap();
                writeln!(out, "CIDR Count:    {}", self.cidr_count).unwrap();
                writeln!(out).unwrap();
                for (i, cidr) in self.cidrs.iter().enumerate() {
                    writeln!(out, "  {}. {}/{}", i + 1, cidr.network, cidr.prefix_length).unwrap();
                }
                out
            }
        }
    };
}

impl_from_range_text_output!(Ipv4FromRangeResult);
impl_from_range_text_output!(Ipv6FromRangeResult);

impl TextOutput for BatchResult {
    fn to_text(&self) -> String {
        let mut out = String::new();
        writeln!(out, "Batch CIDR Processing").unwrap();
        writeln!(out, "=====================").unwrap();
        writeln!(out, "Total CIDRs: {}", self.count).unwrap();
        writeln!(out).unwrap();

        let total = self.count;
        for (i, entry) in self.results.iter().enumerate() {
            writeln!(out, "--- [{}/{}] {} ---", i + 1, total, entry.cidr).unwrap();
            match &entry.result {
                BatchEntryResult::Ok { subnet } => match subnet.as_ref() {
                    SubnetResult::V4(s) => out.push_str(&s.to_text()),
                    SubnetResult::V6(s) => out.push_str(&s.to_text()),
                },
                BatchEntryResult::Err { error } => {
                    writeln!(out, "Error: {}", error).unwrap();
                    writeln!(out).unwrap();
                }
            }
        }
        out
    }
}

// ---------------------------------------------------------------------------
// CsvOutput trait + implementations
// ---------------------------------------------------------------------------

pub trait CsvOutput {
    fn to_csv(&self) -> Result<String>;
}

fn ipv4_csv_header() -> &'static [&'static str] {
    &[
        "input",
        "network_address",
        "broadcast_address",
        "subnet_mask",
        "wildcard_mask",
        "prefix_length",
        "first_host",
        "last_host",
        "total_hosts",
        "usable_hosts",
        "network_class",
        "is_private",
        "address_type",
    ]
}

fn write_ipv4_csv_record(wtr: &mut csv::Writer<Vec<u8>>, s: &Ipv4Subnet) -> Result<()> {
    write_safe_record(
        wtr,
        [
            s.input.as_str(),
            &s.network.to_string(),
            &s.broadcast.to_string(),
            &s.mask.to_string(),
            &s.wildcard.to_string(),
            &s.prefix_length.to_string(),
            &s.first_host.to_string(),
            &s.last_host.to_string(),
            &s.total_hosts.to_string(),
            &s.usable_hosts.to_string(),
            &s.network_class,
            &s.is_private.to_string(),
            &s.address_type,
        ],
    )
}

fn ipv6_csv_header() -> &'static [&'static str] {
    &[
        "input",
        "network_address",
        "network_address_full",
        "last_address",
        "last_address_full",
        "prefix_length",
        "total_addresses",
        "hextets",
        "address_type",
    ]
}

fn write_ipv6_csv_record(wtr: &mut csv::Writer<Vec<u8>>, s: &Ipv6Subnet) -> Result<()> {
    write_safe_record(
        wtr,
        [
            s.input.as_str(),
            &s.network.to_string(),
            &s.network_address_full,
            &s.last.to_string(),
            &s.last_address_full,
            &s.prefix_length.to_string(),
            &s.total_addresses,
            &s.hextets.join(":"),
            &s.address_type,
        ],
    )
}

fn finish_csv(wtr: csv::Writer<Vec<u8>>) -> Result<String> {
    let bytes = wtr.into_inner().map_err(csv_err)?;
    String::from_utf8(bytes).map_err(csv_err)
}

impl CsvOutput for Ipv4Subnet {
    fn to_csv(&self) -> Result<String> {
        let mut wtr = csv::Writer::from_writer(Vec::new());
        wtr.write_record(ipv4_csv_header()).map_err(csv_err)?;
        write_ipv4_csv_record(&mut wtr, self)?;
        finish_csv(wtr)
    }
}

impl CsvOutput for Ipv6Subnet {
    fn to_csv(&self) -> Result<String> {
        let mut wtr = csv::Writer::from_writer(Vec::new());
        wtr.write_record(ipv6_csv_header()).map_err(csv_err)?;
        write_ipv6_csv_record(&mut wtr, self)?;
        finish_csv(wtr)
    }
}

impl CsvOutput for ContainsResult {
    fn to_csv(&self) -> Result<String> {
        let mut wtr = csv::Writer::from_writer(Vec::new());
        wtr.write_record([
            "cidr",
            "address",
            "contained",
            "network_address",
            "broadcast_address",
        ])
        .map_err(csv_err)?;
        write_safe_record(
            &mut wtr,
            [
                self.cidr.as_str(),
                &self.address,
                &self.contained.to_string(),
                &self.network_address,
                &self.broadcast_address,
            ],
        )?;
        finish_csv(wtr)
    }
}

impl CsvOutput for SplitSummary {
    fn to_csv(&self) -> Result<String> {
        let mut wtr = csv::Writer::from_writer(Vec::new());
        wtr.write_record(["cidr_block", "new_prefix", "available_subnets"])
            .map_err(csv_err)?;
        write_safe_record(
            &mut wtr,
            [
                self.cidr_block.as_str(),
                &self.new_prefix.to_string(),
                &self.available_subnets,
            ],
        )?;
        finish_csv(wtr)
    }
}

impl CsvOutput for Ipv4SubnetList {
    fn to_csv(&self) -> Result<String> {
        let mut out = String::new();
        writeln!(out, "# cidr_block: {}", self.cidr_block.input).unwrap();
        writeln!(out, "# new_prefix: {}", self.new_prefix).unwrap();
        writeln!(out, "# count: {}", self.requested_count).unwrap();

        let mut wtr = csv::Writer::from_writer(Vec::new());
        wtr.write_record(ipv4_csv_header()).map_err(csv_err)?;
        for subnet in &self.subnets {
            write_ipv4_csv_record(&mut wtr, subnet)?;
        }
        out.push_str(&finish_csv(wtr)?);
        Ok(out)
    }
}

impl CsvOutput for Ipv6SubnetList {
    fn to_csv(&self) -> Result<String> {
        let mut out = String::new();
        writeln!(out, "# cidr_block: {}", self.cidr_block.input).unwrap();
        writeln!(out, "# new_prefix: {}", self.new_prefix).unwrap();
        writeln!(out, "# count: {}", self.requested_count).unwrap();

        let mut wtr = csv::Writer::from_writer(Vec::new());
        wtr.write_record(ipv6_csv_header()).map_err(csv_err)?;
        for subnet in &self.subnets {
            write_ipv6_csv_record(&mut wtr, subnet)?;
        }
        out.push_str(&finish_csv(wtr)?);
        Ok(out)
    }
}

impl CsvOutput for Ipv4VlsmList {
    fn to_csv(&self) -> Result<String> {
        let mut out = String::new();
        writeln!(out, "# supernet: {}", self.cidr_block.input).unwrap();
        writeln!(out, "# requested_count: {}", self.requested_count).unwrap();
        writeln!(out, "# allocated_addresses: {}", self.allocated_addresses).unwrap();
        writeln!(out, "# remaining_addresses: {}", self.remaining_addresses).unwrap();

        let mut wtr = csv::Writer::from_writer(Vec::new());
        wtr.write_record(ipv4_csv_header()).map_err(csv_err)?;
        for subnet in &self.subnets {
            write_ipv4_csv_record(&mut wtr, subnet)?;
        }
        out.push_str(&finish_csv(wtr)?);
        Ok(out)
    }
}

impl CsvOutput for Ipv6VlsmList {
    fn to_csv(&self) -> Result<String> {
        let mut out = String::new();
        writeln!(out, "# supernet: {}", self.cidr_block.input).unwrap();
        writeln!(out, "# requested_count: {}", self.requested_count).unwrap();
        writeln!(out, "# allocated_addresses: {}", self.allocated_addresses).unwrap();
        writeln!(out, "# remaining_addresses: {}", self.remaining_addresses).unwrap();

        let mut wtr = csv::Writer::from_writer(Vec::new());
        wtr.write_record(ipv6_csv_header()).map_err(csv_err)?;
        for subnet in &self.subnets {
            write_ipv6_csv_record(&mut wtr, subnet)?;
        }
        out.push_str(&finish_csv(wtr)?);
        Ok(out)
    }
}

/// CSV header for a flattened IPv4 split tree: a `depth` column followed by
/// the standard IPv4 subnet columns.
fn ipv4_tree_csv_header() -> Vec<&'static str> {
    let mut h = vec!["depth"];
    h.extend_from_slice(ipv4_csv_header());
    h
}

fn ipv6_tree_csv_header() -> Vec<&'static str> {
    let mut h = vec!["depth"];
    h.extend_from_slice(ipv6_csv_header());
    h
}

fn write_ipv4_tree_csv(
    wtr: &mut csv::Writer<Vec<u8>>,
    node: &Ipv4SplitTreeNode,
    depth: usize,
) -> Result<()> {
    let s = &node.subnet;
    write_safe_record(
        wtr,
        [
            depth.to_string(),
            s.input.clone(),
            s.network.to_string(),
            s.broadcast.to_string(),
            s.mask.to_string(),
            s.wildcard.to_string(),
            s.prefix_length.to_string(),
            s.first_host.to_string(),
            s.last_host.to_string(),
            s.total_hosts.to_string(),
            s.usable_hosts.to_string(),
            s.network_class.clone(),
            s.is_private.to_string(),
            s.address_type.clone(),
        ],
    )?;
    for child in &node.children {
        write_ipv4_tree_csv(wtr, child, depth + 1)?;
    }
    Ok(())
}

fn write_ipv6_tree_csv(
    wtr: &mut csv::Writer<Vec<u8>>,
    node: &Ipv6SplitTreeNode,
    depth: usize,
) -> Result<()> {
    let s = &node.subnet;
    write_safe_record(
        wtr,
        [
            depth.to_string(),
            s.input.clone(),
            s.network.to_string(),
            s.network_address_full.clone(),
            s.last.to_string(),
            s.last_address_full.clone(),
            s.prefix_length.to_string(),
            s.total_addresses.clone(),
            s.hextets.join(":"),
            s.address_type.clone(),
        ],
    )?;
    for child in &node.children {
        write_ipv6_tree_csv(wtr, child, depth + 1)?;
    }
    Ok(())
}

impl CsvOutput for Ipv4SplitTree {
    fn to_csv(&self) -> Result<String> {
        let mut out = String::new();
        writeln!(out, "# supernet: {}", self.root.subnet.input).unwrap();
        writeln!(out, "# steps: {}", steps_label(&self.steps)).unwrap();
        writeln!(out, "# total_subnets: {}", self.total_subnets).unwrap();

        let mut wtr = csv::Writer::from_writer(Vec::new());
        wtr.write_record(ipv4_tree_csv_header()).map_err(csv_err)?;
        write_ipv4_tree_csv(&mut wtr, &self.root, 0)?;
        out.push_str(&finish_csv(wtr)?);
        Ok(out)
    }
}

impl CsvOutput for Ipv6SplitTree {
    fn to_csv(&self) -> Result<String> {
        let mut out = String::new();
        writeln!(out, "# supernet: {}", self.root.subnet.input).unwrap();
        writeln!(out, "# steps: {}", steps_label(&self.steps)).unwrap();
        writeln!(out, "# total_subnets: {}", self.total_subnets).unwrap();

        let mut wtr = csv::Writer::from_writer(Vec::new());
        wtr.write_record(ipv6_tree_csv_header()).map_err(csv_err)?;
        write_ipv6_tree_csv(&mut wtr, &self.root, 0)?;
        out.push_str(&finish_csv(wtr)?);
        Ok(out)
    }
}

impl CsvOutput for Ipv4SummaryResult {
    fn to_csv(&self) -> Result<String> {
        let mut out = String::new();
        writeln!(out, "# input_count: {}", self.input_count).unwrap();
        writeln!(out, "# output_count: {}", self.output_count).unwrap();

        let mut wtr = csv::Writer::from_writer(Vec::new());
        wtr.write_record(ipv4_csv_header()).map_err(csv_err)?;
        for subnet in &self.cidrs {
            write_ipv4_csv_record(&mut wtr, subnet)?;
        }
        out.push_str(&finish_csv(wtr)?);
        Ok(out)
    }
}

impl CsvOutput for Ipv6SummaryResult {
    fn to_csv(&self) -> Result<String> {
        let mut out = String::new();
        writeln!(out, "# input_count: {}", self.input_count).unwrap();
        writeln!(out, "# output_count: {}", self.output_count).unwrap();

        let mut wtr = csv::Writer::from_writer(Vec::new());
        wtr.write_record(ipv6_csv_header()).map_err(csv_err)?;
        for subnet in &self.cidrs {
            write_ipv6_csv_record(&mut wtr, subnet)?;
        }
        out.push_str(&finish_csv(wtr)?);
        Ok(out)
    }
}

impl CsvOutput for Ipv4FromRangeResult {
    fn to_csv(&self) -> Result<String> {
        let mut out = String::new();
        writeln!(out, "# start_address: {}", self.start_address).unwrap();
        writeln!(out, "# end_address: {}", self.end_address).unwrap();
        writeln!(out, "# cidr_count: {}", self.cidr_count).unwrap();

        let mut wtr = csv::Writer::from_writer(Vec::new());
        wtr.write_record(ipv4_csv_header()).map_err(csv_err)?;
        for subnet in &self.cidrs {
            write_ipv4_csv_record(&mut wtr, subnet)?;
        }
        out.push_str(&finish_csv(wtr)?);
        Ok(out)
    }
}

impl CsvOutput for Ipv6FromRangeResult {
    fn to_csv(&self) -> Result<String> {
        let mut out = String::new();
        writeln!(out, "# start_address: {}", self.start_address).unwrap();
        writeln!(out, "# end_address: {}", self.end_address).unwrap();
        writeln!(out, "# cidr_count: {}", self.cidr_count).unwrap();

        let mut wtr = csv::Writer::from_writer(Vec::new());
        wtr.write_record(ipv6_csv_header()).map_err(csv_err)?;
        for subnet in &self.cidrs {
            write_ipv6_csv_record(&mut wtr, subnet)?;
        }
        out.push_str(&finish_csv(wtr)?);
        Ok(out)
    }
}

impl CsvOutput for BatchResult {
    fn to_csv(&self) -> Result<String> {
        let mut out = String::new();
        writeln!(out, "# count: {}", self.count).unwrap();

        let mut wtr = csv::Writer::from_writer(Vec::new());
        // Unified header covering both IPv4/IPv6 fields + error column
        wtr.write_record([
            "cidr",
            "network_address",
            "broadcast_address",
            "subnet_mask",
            "wildcard_mask",
            "prefix_length",
            "first_host",
            "last_host",
            "total_hosts",
            "usable_hosts",
            "network_class",
            "is_private",
            "network_address_full",
            "last_address",
            "last_address_full",
            "total_addresses",
            "hextets",
            "address_type",
            "error",
        ])
        .map_err(csv_err)?;

        for entry in &self.results {
            match &entry.result {
                BatchEntryResult::Ok { subnet } => match subnet.as_ref() {
                    SubnetResult::V4(s) => {
                        write_safe_record(
                            &mut wtr,
                            [
                                entry.cidr.as_str(),
                                &s.network.to_string(),
                                &s.broadcast.to_string(),
                                &s.mask.to_string(),
                                &s.wildcard.to_string(),
                                &s.prefix_length.to_string(),
                                &s.first_host.to_string(),
                                &s.last_host.to_string(),
                                &s.total_hosts.to_string(),
                                &s.usable_hosts.to_string(),
                                &s.network_class,
                                &s.is_private.to_string(),
                                "",
                                "",
                                "",
                                "",
                                "",
                                &s.address_type,
                                "",
                            ],
                        )?;
                    }
                    SubnetResult::V6(s) => {
                        write_safe_record(
                            &mut wtr,
                            [
                                entry.cidr.as_str(),
                                &s.network.to_string(),
                                "",
                                "",
                                "",
                                &s.prefix_length.to_string(),
                                "",
                                "",
                                "",
                                "",
                                "",
                                "",
                                &s.network_address_full,
                                &s.last.to_string(),
                                &s.last_address_full,
                                &s.total_addresses,
                                &s.hextets.join(":"),
                                &s.address_type,
                                "",
                            ],
                        )?;
                    }
                },
                BatchEntryResult::Err { error } => {
                    write_safe_record(
                        &mut wtr,
                        [
                            entry.cidr.as_str(),
                            "",
                            "",
                            "",
                            "",
                            "",
                            "",
                            "",
                            "",
                            "",
                            "",
                            "",
                            "",
                            "",
                            "",
                            "",
                            "",
                            "",
                            error.as_str(),
                        ],
                    )?;
                }
            }
        }

        out.push_str(&finish_csv(wtr)?);
        Ok(out)
    }
}

#[cfg(test)]
mod sanitize_tests {
    use super::sanitize_csv_cell;

    #[test]
    fn empty_cell_unchanged() {
        assert_eq!(sanitize_csv_cell(""), "");
    }

    #[test]
    fn safe_cells_unchanged() {
        assert_eq!(sanitize_csv_cell("192.168.1.0"), "192.168.1.0");
        assert_eq!(sanitize_csv_cell("hello"), "hello");
        assert_eq!(sanitize_csv_cell("/24"), "/24");
        assert_eq!(sanitize_csv_cell(" =attack"), " =attack");
    }

    #[test]
    fn formula_chars_get_quote_prefix() {
        assert_eq!(sanitize_csv_cell("=1+1"), "'=1+1");
        assert_eq!(sanitize_csv_cell("+SUM(A1)"), "'+SUM(A1)");
        assert_eq!(sanitize_csv_cell("-2+5"), "'-2+5");
        assert_eq!(sanitize_csv_cell("@SUM(A1)"), "'@SUM(A1)");
        assert_eq!(sanitize_csv_cell("\tinjection"), "'\tinjection");
        assert_eq!(sanitize_csv_cell("\rinjection"), "'\rinjection");
    }
}
