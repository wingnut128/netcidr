// TypeScript types mirroring Rust models in src/ipam/models.rs

export interface Supernet {
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

export interface SupernetList {
  supernets: Supernet[];
  count: number;
}

export type AllocationStatus = "active" | "reserved" | "released";

export interface Allocation {
  id: string;
  supernet_id: string;
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
  supernet_id: string;
  supernet_cidr: string;
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
  supernet_id: string;
  supernet_cidr: string;
  blocks: FreeBlock[];
  total_free: number;
}

// Calculator types

export interface Ipv4Subnet {
  cidr: string;
  ip_address: string;
  network_address: string;
  broadcast_address: string;
  subnet_mask: string;
  wildcard_mask: string;
  prefix_length: number;
  total_hosts: number;
  usable_hosts: number;
  first_usable: string;
  last_usable: string;
  network_class: string;
  is_private: boolean;
  binary_mask: string;
  hex_mask: string;
}

export interface Ipv6Subnet {
  cidr: string;
  ip_address: string;
  network_address: string;
  prefix_length: number;
  total_addresses: string;
  first_address: string;
  last_address: string;
  address_type: string;
  scope: string;
  hextets: string[];
}

export interface FeaturesResponse {
  ipam: boolean;
  swagger: boolean;
}
