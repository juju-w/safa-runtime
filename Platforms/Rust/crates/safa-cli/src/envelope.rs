use std::collections::BTreeMap;

use serde::Serialize;

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Status {
    Completed,
    Failed,
}

#[derive(Debug, Serialize)]
pub(crate) struct Envelope<D> {
    pub(crate) schema: &'static str,
    pub(crate) command: &'static str,
    pub(crate) status: Status,
    pub(crate) request_id: Option<&'static str>,
    pub(crate) timestamp: String,
    pub(crate) data: D,
    pub(crate) warnings: Vec<String>,
    pub(crate) next_action: Option<NextAction>,
}

#[derive(Debug, Serialize)]
pub(crate) struct NextAction {
    pub(crate) kind: String,
    pub(crate) command: Vec<String>,
    pub(crate) safe_for_agent: bool,
}

#[derive(Debug, Serialize)]
pub(crate) struct VersionData<'a> {
    pub(crate) runtime_version: &'a str,
    pub(crate) cli_schema: &'static str,
    pub(crate) platform: &'a str,
}

#[derive(Debug, Serialize)]
pub(crate) struct DoctorData<'a> {
    pub(crate) runtime_version: &'a str,
    pub(crate) cli_schema: &'static str,
    pub(crate) platform: &'a str,
    pub(crate) readiness: &'static str,
    pub(crate) broker: &'static str,
    pub(crate) capabilities: BTreeMap<&'static str, &'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) error: Option<ErrorPayload>,
}

#[derive(Debug, Serialize)]
pub(crate) struct FailureData {
    pub(crate) error: ErrorPayload,
}

#[derive(Debug, Serialize)]
pub(crate) struct ErrorPayload {
    pub(crate) code: &'static str,
    pub(crate) message: &'static str,
    pub(crate) retryable: bool,
    pub(crate) details: BTreeMap<String, String>,
    pub(crate) remediation: Option<NextAction>,
}

impl ErrorPayload {
    pub(crate) fn without_details(
        code: &'static str,
        message: &'static str,
        retryable: bool,
    ) -> Self {
        Self {
            code,
            message,
            retryable,
            details: BTreeMap::new(),
            remediation: None,
        }
    }
}
