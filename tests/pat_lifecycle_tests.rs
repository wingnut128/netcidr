use std::sync::Arc;

use netcidr::ipam::sqlite::SqliteStore;
use netcidr::ipam::store::IpamStore;
use netcidr::pat::PatPepper;
use netcidr::pat_lifecycle::{CreatePatRequest, PatLifecycle, PatOwner, VerifyPatError};

const OWNER_EMAIL: &str = "owner@example.com";
const OWNER_SUB: &str = "oidc-sub-123";

async fn lifecycle() -> (PatLifecycle, Arc<PatPepper>) {
    let store = SqliteStore::in_memory().unwrap();
    store.initialize().await.unwrap();
    store.migrate().await.unwrap();
    let store: Arc<dyn IpamStore> = Arc::new(store);
    let pepper = Arc::new(PatPepper::from_bytes(&[0xA5u8; 32]).unwrap());
    (PatLifecycle::new(store, Arc::clone(&pepper)), pepper)
}

fn owner() -> PatOwner {
    PatOwner {
        tenant_id: OWNER_EMAIL.to_string(),
        subject: OWNER_SUB.to_string(),
        email: OWNER_EMAIL.to_string(),
    }
}

#[tokio::test]
async fn lifecycle_mints_lists_and_verifies_for_owner() {
    let (lifecycle, _pepper) = lifecycle().await;

    let minted = lifecycle
        .mint_for_owner(
            &owner(),
            CreatePatRequest {
                name: "ci-runner".to_string(),
                expires_in_days: Some(30),
            },
        )
        .await
        .unwrap();

    assert!(minted.plaintext.starts_with("ncdr_pat_"));
    assert_eq!(minted.summary.name, "ci-runner");
    assert_eq!(minted.summary.prefix.len(), 12);

    let listed = lifecycle.list_for_owner(&owner()).await.unwrap();
    assert_eq!(listed, vec![minted.summary.clone()]);

    let verified = lifecycle
        .verify_bearer_token(&minted.plaintext, &[])
        .await
        .unwrap();
    assert_eq!(verified.pat_id, minted.summary.id);
    assert_eq!(verified.owner.subject, OWNER_SUB);
    assert_eq!(verified.owner.email, OWNER_EMAIL);
    assert_eq!(verified.owner.tenant_id, OWNER_EMAIL);
}

#[tokio::test]
async fn lifecycle_rejects_invalid_create_policy_before_storage() {
    let (lifecycle, _pepper) = lifecycle().await;

    assert!(
        lifecycle
            .mint_for_owner(
                &owner(),
                CreatePatRequest {
                    name: " ".to_string(),
                    expires_in_days: Some(30),
                },
            )
            .await
            .is_err()
    );
    assert!(
        lifecycle
            .mint_for_owner(
                &owner(),
                CreatePatRequest {
                    name: "ok".to_string(),
                    expires_in_days: Some(0),
                },
            )
            .await
            .is_err()
    );
    assert!(
        lifecycle
            .mint_for_owner(
                &owner(),
                CreatePatRequest {
                    name: "ok".to_string(),
                    expires_in_days: Some(366),
                },
            )
            .await
            .is_err()
    );
}

#[tokio::test]
async fn lifecycle_verify_collapses_shape_miss_and_allowlist_failures() {
    let (lifecycle, _pepper) = lifecycle().await;
    let minted = lifecycle
        .mint_for_owner(
            &owner(),
            CreatePatRequest {
                name: "ci-runner".to_string(),
                expires_in_days: Some(30),
            },
        )
        .await
        .unwrap();

    assert_eq!(
        lifecycle
            .verify_bearer_token("ncdr_pat_too_short", &[])
            .await
            .unwrap_err(),
        VerifyPatError::Unauthorized
    );
    assert_eq!(
        lifecycle
            .verify_bearer_token(&minted.plaintext, &["someone@example.com".to_string()])
            .await
            .unwrap_err(),
        VerifyPatError::Unauthorized
    );
}
