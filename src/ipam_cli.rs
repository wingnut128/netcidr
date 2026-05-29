use netcidr::cli::{
    AllocationCommands, CidrBlockCommands, HostnameCommands, IpamCommands, TagCommands,
};
use netcidr::error::Result;
use netcidr::ipam::config::IpamConfig;
use netcidr::ipam::models::*;
use netcidr::ipam::operations::IpamOps;
use netcidr::output::{CsvOutput, OutputWriter, TextOutput};
use netcidr::tenant::Tenant;
use netcidr::validation;
use serde::Serialize;

use crate::print_stdout;

// CLI uses local SQLite, single-tenant by definition. Pass `Tenant::LOCAL`.

fn output_result<T: Serialize + TextOutput + CsvOutput>(
    writer: &OutputWriter,
    output_file: &Option<String>,
    data: &T,
) {
    let output = writer.write(data).expect("Failed to write output");
    if output_file.is_none() {
        print_stdout(&output);
    }
}

async fn create_ops(db: Option<&str>) -> Result<IpamOps> {
    let config = IpamConfig::default();
    let store = netcidr::ipam::create_store(&config, db, None).await?;
    Ok(IpamOps::new(store))
}

fn parse_status(s: &Option<String>) -> Result<Option<AllocationStatus>> {
    match s {
        Some(v) => Ok(Some(validation::sanitize_status(v)?)),
        None => Ok(None),
    }
}

fn parse_tags(tags: &[String]) -> Result<Vec<Tag>> {
    let mut result = Vec::with_capacity(tags.len());
    for tag in tags {
        let (key, value) = tag.split_once('=').ok_or_else(|| {
            netcidr::error::NetcidrError::InvalidInput(format!(
                "tag '{}' must be in key=value format",
                tag
            ))
        })?;
        result.push(Tag {
            key: key.to_string(),
            value: value.to_string(),
        });
    }
    Ok(result)
}

pub async fn handle_ipam_command(
    writer: &OutputWriter,
    output_file: &Option<String>,
    db: Option<&str>,
    command: IpamCommands,
) -> Result<()> {
    let ops = create_ops(db).await?;

    match command {
        IpamCommands::CidrBlock { command } => match command {
            CidrBlockCommands::Create {
                cidr,
                name,
                description,
            } => {
                let sn = ops
                    .create_cidr_block(
                        Tenant::LOCAL,
                        &CreateCidrBlock {
                            cidr,
                            name,
                            description,
                        },
                    )
                    .await?;
                output_result(writer, output_file, &sn);
            }
            CidrBlockCommands::List => {
                let list = ops.list_cidr_blocks(Tenant::LOCAL).await?;
                let result = CidrBlockList {
                    count: list.len(),
                    cidr_blocks: list,
                };
                output_result(writer, output_file, &result);
            }
            CidrBlockCommands::Get { id } => {
                let sn = ops.get_cidr_block(Tenant::LOCAL, &id).await?;
                output_result(writer, output_file, &sn);
            }
            CidrBlockCommands::Delete { id } => {
                ops.delete_cidr_block(Tenant::LOCAL, &id).await?;
                eprintln!("CIDR block {} deleted", id);
            }
        },

        IpamCommands::Allocate {
            cidr_block_id,
            cidr,
            name,
            description,
            resource_id,
            resource_type,
            environment,
            owner,
            status,
            parent_id,
            ttl,
        } => {
            let status = parse_status(&status)?;
            let alloc = ops
                .allocate_specific(
                    Tenant::LOCAL,
                    &CreateAllocation {
                        cidr_block_id,
                        cidr,
                        status,
                        resource_id,
                        resource_type,
                        name,
                        description,
                        environment,
                        owner,
                        parent_allocation_id: parent_id,
                        tags: None,
                        ttl_seconds: ttl,
                    },
                )
                .await?;
            output_result(writer, output_file, &alloc);
        }

        IpamCommands::AutoAllocate {
            cidr_block_id,
            prefix,
            count,
            name,
            description,
            resource_id,
            resource_type,
            environment,
            owner,
            status,
            parent_id,
            ttl,
        } => {
            let status = parse_status(&status)?;
            let allocs = ops
                .allocate_auto(
                    Tenant::LOCAL,
                    &AutoAllocateRequest {
                        cidr_block_id,
                        prefix_length: prefix,
                        count: Some(count),
                        status,
                        resource_id,
                        resource_type,
                        name,
                        description,
                        environment,
                        owner,
                        parent_allocation_id: parent_id,
                        tags: None,
                        ttl_seconds: ttl,
                    },
                )
                .await?;
            let result = AllocationList {
                count: allocs.len(),
                allocations: allocs,
            };
            output_result(writer, output_file, &result);
        }

        IpamCommands::Allocation { command } => match command {
            AllocationCommands::Get { id } => {
                let alloc = ops.get_allocation(Tenant::LOCAL, &id).await?;
                output_result(writer, output_file, &alloc);
            }
            AllocationCommands::List {
                cidr_block_id,
                status,
                resource_id,
                resource_type,
                environment,
                owner,
            } => {
                let status = parse_status(&status)?;
                let allocs = ops
                    .list_allocations(
                        Tenant::LOCAL,
                        &AllocationFilter {
                            cidr_block_id,
                            status,
                            resource_id,
                            resource_type,
                            environment,
                            owner,
                        },
                    )
                    .await?;
                let result = AllocationList {
                    count: allocs.len(),
                    allocations: allocs,
                };
                output_result(writer, output_file, &result);
            }
            AllocationCommands::Update {
                id,
                name,
                description,
                resource_id,
                resource_type,
                environment,
                owner,
                status,
            } => {
                let status = parse_status(&status)?;
                let alloc = ops
                    .update_allocation(
                        Tenant::LOCAL,
                        &id,
                        &UpdateAllocation {
                            name,
                            description,
                            resource_id,
                            resource_type,
                            environment,
                            owner,
                            status,
                        },
                    )
                    .await?;
                output_result(writer, output_file, &alloc);
            }
        },

        IpamCommands::Release { id } => {
            let alloc = ops.release_allocation(Tenant::LOCAL, &id).await?;
            output_result(writer, output_file, &alloc);
        }

        IpamCommands::Utilization { cidr_block_id } => {
            let report = ops.utilization(Tenant::LOCAL, &cidr_block_id).await?;
            output_result(writer, output_file, &report);
        }

        IpamCommands::FreeBlocks {
            cidr_block_id,
            prefix,
        } => {
            let report = ops
                .free_blocks(Tenant::LOCAL, &cidr_block_id, prefix)
                .await?;
            output_result(writer, output_file, &report);
        }

        IpamCommands::FindIp { address } => {
            let allocs = ops.find_by_ip(Tenant::LOCAL, &address).await?;
            let result = AllocationList {
                count: allocs.len(),
                allocations: allocs,
            };
            output_result(writer, output_file, &result);
        }

        IpamCommands::FindResource { resource_id } => {
            let allocs = ops.find_by_resource(Tenant::LOCAL, &resource_id).await?;
            let result = AllocationList {
                count: allocs.len(),
                allocations: allocs,
            };
            output_result(writer, output_file, &result);
        }

        IpamCommands::Audit {
            entity_type,
            entity_id,
            action,
            limit,
        } => {
            let entries = ops
                .query_audit(
                    Tenant::LOCAL,
                    &AuditFilter {
                        entity_type,
                        entity_id,
                        action,
                        limit: Some(limit),
                    },
                )
                .await?;
            let result = AuditList {
                count: entries.len(),
                entries,
            };
            output_result(writer, output_file, &result);
        }

        IpamCommands::Dump { tenant } => {
            let dump = ops.dump(&tenant).await?;
            let json = serde_json::to_string_pretty(&dump).expect("Failed to serialize dump");
            if output_file.is_none() {
                print_stdout(&json);
            }
        }

        IpamCommands::Load { file, tenant } => {
            let json = match file {
                Some(path) => std::fs::read_to_string(&path).map_err(|e| {
                    netcidr::error::NetcidrError::InvalidInput(format!(
                        "failed to read {}: {}",
                        path, e
                    ))
                })?,
                None => {
                    use std::io::Read;
                    let mut buf = String::new();
                    std::io::stdin().read_to_string(&mut buf).map_err(|e| {
                        netcidr::error::NetcidrError::InvalidInput(format!(
                            "failed to read stdin: {}",
                            e
                        ))
                    })?;
                    buf
                }
            };

            let dump: netcidr::ipam::models::IpamDump =
                serde_json::from_str(&json).map_err(|e| {
                    netcidr::error::NetcidrError::InvalidInput(format!("invalid JSON: {}", e))
                })?;

            let (sn_count, alloc_count) = ops.load(&tenant, &dump).await?;
            eprintln!(
                "Imported {} CIDR blocks and {} allocations",
                sn_count, alloc_count
            );
        }

        IpamCommands::Tags { command } => match command {
            TagCommands::Get { allocation_id } => {
                let alloc = ops.get_allocation(Tenant::LOCAL, &allocation_id).await?;
                output_result(writer, output_file, &alloc);
            }
            TagCommands::Set {
                allocation_id,
                tags,
            } => {
                let parsed_tags = parse_tags(&tags)?;
                ops.set_tags(Tenant::LOCAL, &allocation_id, &parsed_tags)
                    .await?;
                let alloc = ops.get_allocation(Tenant::LOCAL, &allocation_id).await?;
                output_result(writer, output_file, &alloc);
            }
        },

        IpamCommands::Hostname { command } => match command {
            HostnameCommands::Set {
                ip,
                hostname,
                allocation_id,
                notes,
            } => {
                let pointer = ops
                    .set_hostname_pointer(
                        Tenant::LOCAL,
                        &CreateHostnamePointer {
                            ip_address: ip,
                            hostname,
                            allocation_id,
                            notes,
                        },
                    )
                    .await?;
                output_result(writer, output_file, &pointer);
            }
            HostnameCommands::Get { ip } => {
                let pointers = ops.get_hostname_pointers_for_ip(Tenant::LOCAL, &ip).await?;
                let result = HostnamePointerList {
                    count: pointers.len(),
                    pointers,
                };
                output_result(writer, output_file, &result);
            }
            HostnameCommands::List {
                ip,
                hostname,
                allocation_id,
            } => {
                let pointers = ops
                    .list_hostname_pointers(
                        Tenant::LOCAL,
                        &HostnamePointerFilter {
                            ip_address: ip,
                            hostname,
                            allocation_id,
                        },
                    )
                    .await?;
                let result = HostnamePointerList {
                    count: pointers.len(),
                    pointers,
                };
                output_result(writer, output_file, &result);
            }
            HostnameCommands::History { target } => {
                // Auto-detect: a parseable IP filters by IP, else by hostname.
                let filter = if target.parse::<std::net::IpAddr>().is_ok() {
                    HostnameHistoryFilter {
                        ip_address: Some(target),
                        hostname: None,
                    }
                } else {
                    HostnameHistoryFilter {
                        ip_address: None,
                        hostname: Some(target),
                    }
                };
                let entries = ops.list_hostname_history(Tenant::LOCAL, &filter).await?;
                let result = HostnamePointerHistoryList {
                    count: entries.len(),
                    entries,
                };
                output_result(writer, output_file, &result);
            }
            HostnameCommands::Delete { ip, hostname } => {
                ops.delete_hostname_pointer(Tenant::LOCAL, &ip, &hostname)
                    .await?;
                if output_file.is_none() {
                    print_stdout(&format!("Deleted hostname pointer {ip} -> {hostname}"));
                }
            }
        },
    }

    Ok(())
}
