//! The expiry sweep, run on a schedule: release allocations past their TTL
//! in every tenant, and delete expired idempotency records and personal
//! access tokens (see [`IpamOps::sweep_expired`]).
//!
//! `netcidr serve` runs it with [`spawn`]. The Lambda binary has no
//! long-lived process, so a scheduled invocation calls [`sweep_and_log`]
//! instead.

use std::sync::Arc;
use std::time::Duration;

use tracing::{debug, info, warn};

use crate::error::Result;
use crate::ipam::models::SweepReport;
use crate::ipam::operations::IpamOps;

/// Run one sweep and log what it did: `info` when it changed something,
/// `warn` on failure, `debug` when there was nothing to do.
pub async fn sweep_and_log(ops: &IpamOps) -> Result<SweepReport> {
    let result = ops.sweep_expired().await;
    match &result {
        Ok(report) if report.is_empty() => debug!("expiry sweep: nothing due"),
        Ok(report) => info!(
            allocations_released = report.allocations_released,
            blocks_failed = report.blocks_failed,
            idempotency_keys_deleted = report.idempotency_keys_deleted,
            pats_deleted = report.pats_deleted,
            "expiry sweep"
        ),
        Err(e) => warn!(error = %e, "expiry sweep failed"),
    }
    result
}

/// Sweep now and then every `every` until the runtime shuts down. A slow
/// sweep delays the next one rather than overlapping it.
pub fn spawn(ops: Arc<IpamOps>, every: Duration) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(every);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            // Failures are logged; the next tick tries again.
            let _ = sweep_and_log(&ops).await;
        }
    })
}

#[cfg(test)]
mod tests {
    use chrono::{DateTime, TimeZone, Utc};

    use super::*;
    use crate::ipam::models::{AuditFilter, CreateAllocation, CreateCidrBlock};
    use crate::ipam::mutation::{Clock, UuidIds};
    use crate::ipam::sqlite::SqliteStore;
    use crate::ipam::store::IpamStore;

    struct At(DateTime<Utc>);
    impl Clock for At {
        fn now(&self) -> DateTime<Utc> {
            self.0
        }
    }

    async fn ops_at(now: DateTime<Utc>, store: Arc<dyn IpamStore>) -> IpamOps {
        IpamOps::with_clock_and_ids(store, Arc::new(At(now)), Arc::new(UuidIds))
    }

    #[tokio::test]
    async fn the_spawned_task_sweeps_without_being_asked() {
        let t0 = Utc.with_ymd_and_hms(2026, 10, 1, 12, 0, 0).unwrap();
        let store = SqliteStore::in_memory().unwrap();
        store.initialize().await.unwrap();
        store.migrate().await.unwrap();
        let store: Arc<dyn IpamStore> = Arc::new(store);

        let before = ops_at(t0, Arc::clone(&store)).await;
        let block = before
            .create_cidr_block(
                "t",
                &CreateCidrBlock {
                    cidr: "10.0.0.0/8".to_string(),
                    name: None,
                    description: None,
                },
            )
            .await
            .unwrap();
        before
            .allocate_specific(
                "t",
                &CreateAllocation {
                    cidr_block_id: block.id,
                    cidr: "10.0.1.0/24".to_string(),
                    status: None,
                    resource_id: None,
                    resource_type: None,
                    name: None,
                    description: None,
                    environment: None,
                    owner: None,
                    parent_allocation_id: None,
                    tags: None,
                    ttl_seconds: Some(60),
                },
            )
            .await
            .unwrap();

        let later = Arc::new(ops_at(t0 + chrono::Duration::hours(1), Arc::clone(&store)).await);
        let task = spawn(Arc::clone(&later), Duration::from_millis(20));
        let expire = AuditFilter {
            action: Some("expire".to_string()),
            ..Default::default()
        };
        let mut swept = false;
        for _ in 0..100 {
            if !later.query_audit("t", &expire).await.unwrap().is_empty() {
                swept = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        task.abort();
        assert!(swept, "the background sweep never released the allocation");
    }
}
