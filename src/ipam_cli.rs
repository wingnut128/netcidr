use ipcalc::cli::{AllocationCommands, IpamCommands, SupernetCommands, TagCommands};
use ipcalc::error::Result;
use ipcalc::ipam::config::IpamConfig;
use ipcalc::ipam::models::*;
use ipcalc::ipam::operations::IpamOps;
use ipcalc::output::{CsvOutput, OutputWriter, TextOutput};
use ipcalc::validation;
use serde::Serialize;

use crate::print_stdout;

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
    let store = ipcalc::ipam::create_store(&config, db, None).await?;
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
            ipcalc::error::IpCalcError::InvalidInput(format!(
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
        IpamCommands::Supernet { command } => match command {
            SupernetCommands::Create {
                cidr,
                name,
                description,
            } => {
                let sn = ops
                    .create_supernet(&CreateSupernet {
                        cidr,
                        name,
                        description,
                    })
                    .await?;
                output_result(writer, output_file, &sn);
            }
            SupernetCommands::List => {
                let list = ops.list_supernets().await?;
                let result = SupernetList {
                    count: list.len(),
                    supernets: list,
                };
                output_result(writer, output_file, &result);
            }
            SupernetCommands::Get { id } => {
                let sn = ops.get_supernet(&id).await?;
                output_result(writer, output_file, &sn);
            }
            SupernetCommands::Delete { id } => {
                ops.delete_supernet(&id).await?;
                eprintln!("Supernet {} deleted", id);
            }
        },

        IpamCommands::Allocate {
            supernet_id,
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
                .allocate_specific(&CreateAllocation {
                    supernet_id,
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
                })
                .await?;
            output_result(writer, output_file, &alloc);
        }

        IpamCommands::AutoAllocate {
            supernet_id,
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
                .allocate_auto(&AutoAllocateRequest {
                    supernet_id,
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
                })
                .await?;
            let result = AllocationList {
                count: allocs.len(),
                allocations: allocs,
            };
            output_result(writer, output_file, &result);
        }

        IpamCommands::Allocation { command } => match command {
            AllocationCommands::Get { id } => {
                let alloc = ops.get_allocation(&id).await?;
                output_result(writer, output_file, &alloc);
            }
            AllocationCommands::List {
                supernet_id,
                status,
                resource_id,
                resource_type,
                environment,
                owner,
            } => {
                let status = parse_status(&status)?;
                let allocs = ops
                    .list_allocations(&AllocationFilter {
                        supernet_id,
                        status,
                        resource_id,
                        resource_type,
                        environment,
                        owner,
                    })
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
            let alloc = ops.release_allocation(&id).await?;
            output_result(writer, output_file, &alloc);
        }

        IpamCommands::Utilization { supernet_id } => {
            let report = ops.utilization(&supernet_id).await?;
            output_result(writer, output_file, &report);
        }

        IpamCommands::FreeBlocks {
            supernet_id,
            prefix,
        } => {
            let report = ops.free_blocks(&supernet_id, prefix).await?;
            output_result(writer, output_file, &report);
        }

        IpamCommands::FindIp { address } => {
            let allocs = ops.find_by_ip(&address).await?;
            let result = AllocationList {
                count: allocs.len(),
                allocations: allocs,
            };
            output_result(writer, output_file, &result);
        }

        IpamCommands::FindResource { resource_id } => {
            let allocs = ops.find_by_resource(&resource_id).await?;
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
                .query_audit(&AuditFilter {
                    entity_type,
                    entity_id,
                    action,
                    limit: Some(limit),
                })
                .await?;
            let result = AuditList {
                count: entries.len(),
                entries,
            };
            output_result(writer, output_file, &result);
        }

        IpamCommands::Dump => {
            let dump = ops.dump().await?;
            let json = serde_json::to_string_pretty(&dump).expect("Failed to serialize dump");
            if output_file.is_none() {
                print_stdout(&json);
            }
        }

        IpamCommands::Load { file } => {
            let json = match file {
                Some(path) => std::fs::read_to_string(&path).map_err(|e| {
                    ipcalc::error::IpCalcError::InvalidInput(format!(
                        "failed to read {}: {}",
                        path, e
                    ))
                })?,
                None => {
                    use std::io::Read;
                    let mut buf = String::new();
                    std::io::stdin().read_to_string(&mut buf).map_err(|e| {
                        ipcalc::error::IpCalcError::InvalidInput(format!(
                            "failed to read stdin: {}",
                            e
                        ))
                    })?;
                    buf
                }
            };

            let dump: ipcalc::ipam::models::IpamDump =
                serde_json::from_str(&json).map_err(|e| {
                    ipcalc::error::IpCalcError::InvalidInput(format!("invalid JSON: {}", e))
                })?;

            let (sn_count, alloc_count) = ops.load(&dump).await?;
            eprintln!(
                "Imported {} supernets and {} allocations",
                sn_count, alloc_count
            );
        }

        IpamCommands::Tags { command } => match command {
            TagCommands::Get { allocation_id } => {
                let alloc = ops.get_allocation(&allocation_id).await?;
                output_result(writer, output_file, &alloc);
            }
            TagCommands::Set {
                allocation_id,
                tags,
            } => {
                let parsed_tags = parse_tags(&tags)?;
                ops.set_tags(&allocation_id, &parsed_tags).await?;
                let alloc = ops.get_allocation(&allocation_id).await?;
                output_result(writer, output_file, &alloc);
            }
        },
    }

    Ok(())
}
