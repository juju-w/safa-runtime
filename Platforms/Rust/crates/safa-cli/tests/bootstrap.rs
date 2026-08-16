use std::ffi::OsString;

use safa_cli::{
    run, Clock, RuntimeContext, UnavailableBrokerClient, EXIT_INVALID_INVOCATION,
    EXIT_RUNTIME_FAILURE, EXIT_SUCCESS,
};
use safa_runtime_core::{CapabilityStatus, PlatformSecurity, SecurityCapability};
use serde_json::Value;

struct FixedClock;

impl Clock for FixedClock {
    fn now_rfc3339(&self) -> String {
        "2026-08-16T09:30:00Z".to_owned()
    }
}

struct UnavailableSecurity;

impl PlatformSecurity for UnavailableSecurity {
    fn capability_status(&self, _capability: SecurityCapability) -> CapabilityStatus {
        CapabilityStatus::Unavailable
    }
}

fn context<'a>(security: &'a dyn PlatformSecurity, clock: &'a dyn Clock) -> RuntimeContext<'a> {
    RuntimeContext {
        runtime_version: "0.0.0",
        platform: "linux",
        security,
        broker: &UnavailableBrokerClient,
        clock,
    }
}

fn arguments(values: &[&str]) -> Vec<OsString> {
    values.iter().map(OsString::from).collect()
}

#[test]
fn version_matches_the_product_contract_fixture() {
    let security = UnavailableSecurity;
    let clock = FixedClock;
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let exit = run(
        arguments(&["version", "--json"]),
        &context(&security, &clock),
        &mut stdout,
        &mut stderr,
    );

    let actual: Value = serde_json::from_slice(&stdout).expect("valid CLI JSON");
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../../../conformance/cli-v1/version.completed.json"
    ))
    .expect("valid checked fixture");
    assert_eq!(exit, EXIT_SUCCESS);
    assert_eq!(actual, fixture);
    assert!(stderr.is_empty());
}

#[test]
fn doctor_reports_every_protected_capability_unavailable() {
    let security = UnavailableSecurity;
    let clock = FixedClock;
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let exit = run(
        arguments(&["doctor", "--json"]),
        &context(&security, &clock),
        &mut stdout,
        &mut stderr,
    );
    let actual: Value = serde_json::from_slice(&stdout).expect("valid CLI JSON");

    assert_eq!(exit, EXIT_RUNTIME_FAILURE);
    assert_eq!(actual["status"], "failed");
    assert_eq!(actual["data"]["error"]["code"], "broker_unavailable");
    assert_eq!(actual["data"]["broker"], "unavailable");
    assert_eq!(
        actual["data"]["capabilities"]["credential_storage"],
        "unavailable"
    );
    assert!(stderr.is_empty());
}

#[test]
fn unsupported_commands_fail_before_echoing_arguments() {
    let security = UnavailableSecurity;
    let clock = FixedClock;
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let sensitive_looking_value = "do-not-echo-this-value";

    let exit = run(
        arguments(&["resource", "show", sensitive_looking_value, "--json"]),
        &context(&security, &clock),
        &mut stdout,
        &mut stderr,
    );

    assert_eq!(exit, EXIT_INVALID_INVOCATION);
    assert!(!String::from_utf8_lossy(&stdout).contains(sensitive_looking_value));
    assert!(stderr.is_empty());
}
