use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io::Write;

use safa_runtime_core::{CapabilityStatus, PlatformSecurity, SecurityCapability, CLI_SCHEMA_V1};
use serde::Serialize;

use crate::arguments::{parse, ParseError, ParsedCommand};
use crate::clock::Clock;
use crate::envelope::{DoctorData, Envelope, ErrorPayload, FailureData, Status, VersionData};

/// Exit code for a successful local command.
pub const EXIT_SUCCESS: i32 = 0;
/// Exit code for a contract or invocation failure.
pub const EXIT_INVALID_INVOCATION: i32 = 40;
/// Exit code for an unavailable native platform Runtime.
pub const EXIT_RUNTIME_FAILURE: i32 = 45;
/// Exit code for an unexpected local presentation failure.
pub const EXIT_UNEXPECTED: i32 = 70;

const HELP: &str = "SAFA secure agent access\n\nUSAGE:\n  safa version [--json]\n  safa doctor [--json]\n\nThis Rust CLI is a non-shipping contract shell. Protected commands remain on the native Runtime until a reviewed Broker client is connected.\n";
const INVALID_INVOCATION_MESSAGE: &str =
    "The invocation does not match the supported SAFA CLI bootstrap surface.";
const RUNTIME_UNAVAILABLE_MESSAGE: &str =
    "No protected Broker client is connected to this Rust CLI build.";

/// Whether the CLI has a usable platform-native client for its trusted Broker.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BrokerStatus {
    /// A native client is connected and may accept typed Broker requests.
    Connected,
    /// No reviewed native client is available in this build.
    Unavailable,
}

impl BrokerStatus {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Connected => "connected",
            Self::Unavailable => "unavailable",
        }
    }
}

/// Narrow platform boundary that will carry typed requests to the trusted Broker.
///
/// The bootstrap exposes readiness only. Protected request methods are added only with their
/// versioned DTOs and platform peer-identity tests.
pub trait BrokerClient {
    /// Report whether a reviewed native Broker connection is available.
    fn status(&self) -> BrokerStatus;
}

/// Fail-closed Broker client used until a platform-native implementation is linked.
#[derive(Clone, Copy, Debug, Default)]
pub struct UnavailableBrokerClient;

impl BrokerClient for UnavailableBrokerClient {
    fn status(&self) -> BrokerStatus {
        BrokerStatus::Unavailable
    }
}

/// Non-secret dependencies supplied by the platform-specific executable root.
pub struct RuntimeContext<'a> {
    /// Exact Runtime `SemVer` for version negotiation.
    pub runtime_version: &'a str,
    /// Stable platform label defined by the public CLI contract.
    pub platform: &'a str,
    /// Capability reporter; it cannot return credential material.
    pub security: &'a dyn PlatformSecurity,
    /// Platform-native Broker client; the CLI never substitutes direct resource access.
    pub broker: &'a dyn BrokerClient,
    /// Time source used only for response metadata.
    pub clock: &'a dyn Clock,
}

/// Parse one CLI invocation and write either one JSON envelope or human-readable output.
///
/// This bootstrap intentionally implements only `version` and `doctor`. All other commands fail
/// before contacting a Broker or target resource.
pub fn run(
    arguments: impl IntoIterator<Item = OsString>,
    context: &RuntimeContext<'_>,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> i32 {
    match parse(arguments) {
        Ok(ParsedCommand::Help) => write_human(stdout, HELP, EXIT_SUCCESS),
        Ok(ParsedCommand::Version { json }) => version(json, context, stdout),
        Ok(ParsedCommand::Doctor { json }) => doctor(json, context, stdout),
        Err(error) => invalid_invocation(error, context, stdout, stderr),
    }
}

fn version(json: bool, context: &RuntimeContext<'_>, stdout: &mut dyn Write) -> i32 {
    let envelope = Envelope {
        schema: CLI_SCHEMA_V1,
        command: "version",
        status: Status::Completed,
        request_id: None,
        timestamp: context.clock.now_rfc3339(),
        data: VersionData {
            runtime_version: context.runtime_version,
            cli_schema: CLI_SCHEMA_V1,
            platform: context.platform,
        },
        warnings: Vec::new(),
        next_action: None,
    };
    if json {
        write_json(stdout, &envelope, EXIT_SUCCESS)
    } else {
        write_human(
            stdout,
            &format!(
                "SAFA {} ({CLI_SCHEMA_V1}, {})\n",
                context.runtime_version, context.platform
            ),
            EXIT_SUCCESS,
        )
    }
}

fn doctor(json: bool, context: &RuntimeContext<'_>, stdout: &mut dyn Write) -> i32 {
    let capabilities: BTreeMap<_, _> = SecurityCapability::ALL
        .into_iter()
        .map(|capability| {
            (
                capability.as_str(),
                context.security.capability_status(capability).as_str(),
            )
        })
        .collect();
    let broker_status = context.broker.status();
    let ready = broker_status == BrokerStatus::Connected
        && SecurityCapability::ALL.into_iter().all(|capability| {
            context.security.capability_status(capability) == CapabilityStatus::Available
        });
    let exit_code = if ready {
        EXIT_SUCCESS
    } else {
        EXIT_RUNTIME_FAILURE
    };
    let envelope = Envelope {
        schema: CLI_SCHEMA_V1,
        command: "doctor",
        status: if ready {
            Status::Completed
        } else {
            Status::Failed
        },
        request_id: None,
        timestamp: context.clock.now_rfc3339(),
        data: DoctorData {
            runtime_version: context.runtime_version,
            cli_schema: CLI_SCHEMA_V1,
            platform: context.platform,
            readiness: if ready { "ready" } else { "unavailable" },
            broker: broker_status.as_str(),
            capabilities,
            error: (!ready).then(|| {
                ErrorPayload::without_details(
                    "broker_unavailable",
                    RUNTIME_UNAVAILABLE_MESSAGE,
                    false,
                )
            }),
        },
        warnings: Vec::new(),
        next_action: None,
    };
    if json {
        write_json(stdout, &envelope, exit_code)
    } else if ready {
        write_human(stdout, "SAFA Runtime is ready.\n", exit_code)
    } else {
        write_human(
            stdout,
            &format!("{RUNTIME_UNAVAILABLE_MESSAGE}\n"),
            exit_code,
        )
    }
}

fn invalid_invocation(
    error: ParseError,
    context: &RuntimeContext<'_>,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> i32 {
    if error.json_requested {
        let envelope = Envelope {
            schema: CLI_SCHEMA_V1,
            command: "cli.parse",
            status: Status::Failed,
            request_id: None,
            timestamp: context.clock.now_rfc3339(),
            data: FailureData {
                error: ErrorPayload::without_details(
                    "invalid_invocation",
                    INVALID_INVOCATION_MESSAGE,
                    false,
                ),
            },
            warnings: Vec::new(),
            next_action: None,
        };
        write_json(stdout, &envelope, EXIT_INVALID_INVOCATION)
    } else {
        write_human(
            stderr,
            &format!("{INVALID_INVOCATION_MESSAGE}\n\n{HELP}"),
            EXIT_INVALID_INVOCATION,
        )
    }
}

fn write_json(writer: &mut dyn Write, envelope: &impl Serialize, success_code: i32) -> i32 {
    let Ok(mut bytes) = serde_json::to_vec(envelope) else {
        return EXIT_UNEXPECTED;
    };
    bytes.push(b'\n');
    if writer.write_all(&bytes).is_ok() {
        success_code
    } else {
        EXIT_UNEXPECTED
    }
}

fn write_human(writer: &mut dyn Write, message: &str, success_code: i32) -> i32 {
    if writer.write_all(message.as_bytes()).is_ok() {
        success_code
    } else {
        EXIT_UNEXPECTED
    }
}
