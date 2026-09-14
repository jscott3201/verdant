//! Separate current inventory; never edit the historical PR01 golden report.
pub const CURRENT: &str = "verdant capabilities v1\n\
setup: draft edit validate seal accept status read recovery (local synthetic access)\n\
compiled: storage access native semantics binding seal acceptance api inert-runtime\n\
run: no-field shell; runtime owner not configured or started\n\
runtime-api: explicit start; exact accepted/active content required; inert only\n\
availability: checked per operation; active pointer is not a lease\n\
qualification: unsupported; structural meaning is not observed qualification\n\
field-authority: none\n\
listener: none\n\
protocols: no BACnet Modbus COV discovery or writes\n";

pub fn command(args: &[String]) -> std::process::ExitCode {
    if !args.is_empty() {
        eprintln!("capabilities takes no arguments");
        return std::process::ExitCode::from(2);
    }
    print!("{CURRENT}");
    std::process::ExitCode::SUCCESS
}
