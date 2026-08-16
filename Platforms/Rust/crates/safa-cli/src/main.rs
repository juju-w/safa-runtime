use std::process::ExitCode;

#[cfg(target_os = "linux")]
use safa_platform_linux::LinuxPlatformSecurity;
#[cfg(not(target_os = "linux"))]
use safa_runtime_core::{CapabilityStatus, PlatformSecurity, SecurityCapability};

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
compile_error!("the SAFA CLI contract defines only macOS, Linux, and Windows platform labels");

#[cfg(not(target_os = "linux"))]
#[derive(Clone, Copy, Debug)]
struct UnavailablePlatformSecurity;

#[cfg(not(target_os = "linux"))]
impl PlatformSecurity for UnavailablePlatformSecurity {
    fn capability_status(&self, _capability: SecurityCapability) -> CapabilityStatus {
        CapabilityStatus::Unavailable
    }
}

fn main() -> ExitCode {
    #[cfg(target_os = "linux")]
    let security = LinuxPlatformSecurity;
    #[cfg(not(target_os = "linux"))]
    let security = UnavailablePlatformSecurity;

    let clock = safa_cli::SystemClock;
    let broker = safa_cli::UnavailableBrokerClient;
    let context = safa_cli::RuntimeContext {
        runtime_version: env!("CARGO_PKG_VERSION"),
        platform: platform_name(),
        security: &security,
        broker: &broker,
        clock: &clock,
    };
    let code = safa_cli::run(
        std::env::args_os().skip(1),
        &context,
        &mut std::io::stdout(),
        &mut std::io::stderr(),
    );
    ExitCode::from(u8::try_from(code).unwrap_or(70))
}

const fn platform_name() -> &'static str {
    if cfg!(target_os = "macos") {
        "macOS"
    } else if cfg!(target_os = "linux") {
        "linux"
    } else {
        "windows"
    }
}
