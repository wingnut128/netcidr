// TypeScript types mirroring Rust models in src/ipam/models.rs

export interface CidrBlock {
  id: string;
  cidr: string;
  network_address: string;
  broadcast_address: string;
  prefix_length: number;
  total_hosts: number;
  name?: string;
  description?: string;
  ip_version: number;
  created_at: string;
  updated_at: string;
}

export interface CidrBlockList {
  cidr_blocks: CidrBlock[];
  count: number;
}

export type AllocationStatus = "active" | "reserved" | "released";

export interface Allocation {
  id: string;
  cidr_block_id: string;
  cidr: string;
  network_address: string;
  broadcast_address: string;
  prefix_length: number;
  total_hosts: number;
  status: AllocationStatus;
  resource_id?: string;
  resource_type?: string;
  name?: string;
  description?: string;
  environment?: string;
  owner?: string;
  parent_allocation_id?: string;
  tags: Tag[];
  created_at: string;
  updated_at: string;
  released_at?: string;
  expires_at?: string;
}

export interface AllocationList {
  allocations: Allocation[];
  count: number;
}

export interface Tag {
  key: string;
  value: string;
}

export interface AuditEntry {
  id: string;
  entity_type: string;
  entity_id: string;
  action: string;
  details?: string;
  timestamp: string;
  caller_email?: string | null;
  pat_id?: string | null;
}

export interface AuditList {
  entries: AuditEntry[];
  count: number;
}

export interface StatusBreakdown {
  active_addresses: number;
  active_count: number;
  reserved_addresses: number;
  reserved_count: number;
  released_addresses: number;
  released_count: number;
}

export interface UtilizationReport {
  cidr_block_id: string;
  cidr_block_cidr: string;
  total_addresses: number;
  allocated_addresses: number;
  free_addresses: number;
  utilization_percent: number;
  allocation_count: number;
  by_status: StatusBreakdown;
}

export interface FreeBlock {
  cidr: string;
  size: number;
}

export interface FreeBlocksReport {
  cidr_block_id: string;
  cidr_block_cidr: string;
  blocks: FreeBlock[];
  total_free: number;
}

// Calculator types — mirrors src/ipv4.rs Ipv4Subnet

export interface Ipv4Subnet {
  input: string;
  network_address: string;
  broadcast_address: string;
  subnet_mask: string;
  wildcard_mask: string;
  prefix_length: number;
  first_host: string;
  last_host: string;
  total_hosts: number;
  usable_hosts: number;
  network_class: string;
  is_private: boolean;
  address_type: string;
}

// Mirrors src/ipv6.rs Ipv6Subnet

export interface Ipv6Subnet {
  input: string;
  network_address: string;
  network_address_full: string;
  last_address: string;
  last_address_full: string;
  prefix_length: number;
  total_addresses: string;
  hextets: string[];
  address_type: string;
}

export type CalcResult = Ipv4Subnet | Ipv6Subnet;

// Split result types

export interface SplitResult {
  cidr_block: Ipv4Subnet | Ipv6Subnet;
  subnets: (Ipv4Subnet | Ipv6Subnet)[];
  new_prefix: number;
}

// Contains result type

export interface ContainsResult {
  cidr: string;
  address: string;
  contained: boolean;
  network_address: string;
  broadcast_address?: string;
}

// Summarize result types

export interface SummarizeResult {
  input_count: number;
  output_count: number;
  cidrs: (Ipv4Subnet | Ipv6Subnet)[];
}

// From-range result types

export interface FromRangeResult {
  start_address: string;
  end_address: string;
  cidr_count: number;
  cidrs: (Ipv4Subnet | Ipv6Subnet)[];
}

export interface FeaturesResponse {
  ipam: boolean;
  swagger: boolean;
}
