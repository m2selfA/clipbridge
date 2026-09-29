#![cfg(windows)]

use base64::{engine::general_purpose::STANDARD, Engine as _};
use std::{
    os::windows::process::CommandExt, path::PathBuf, process::Command, thread, time::Duration,
};

use crate::status::Status;

const CREATE_NO_WINDOW: u32 = 0x0800_0000;

const GROUP: &str = "ClipBridge";

/// Ensure the two inbound rules required by discovery and clipboard transport.
///
/// The rules are intentionally port-scoped rather than tied to the current EXE path,
/// so moving or updating the portable binary does not leave a stale program rule.
/// If either rule is missing, Windows PowerShell is relaunched with `runas`, which
/// gives the user the normal UAC consent dialog. The helper PowerShell processes are
/// hidden; only the UAC consent prompt is visible. A denied prompt never prevents the
/// application from starting; the returned message is shown in the status area.
pub fn ensure_rules(tcp_port: u16, udp_port: u16) -> Status {
    let names = rule_names(tcp_port, udp_port);
    if rules_present(&names) {
        return Status::FirewallReady {
            tcp: tcp_port,
            udp: udp_port,
        };
    }

    let script = install_script(tcp_port, udp_port, &names);
    match run_elevated(&script) {
        Ok(()) => {
            for _ in 0..20 {
                if rules_present(&names) {
                    return Status::FirewallAuthorized {
                        tcp: tcp_port,
                        udp: udp_port,
                    };
                }
                thread::sleep(Duration::from_millis(500));
            }
            Status::FirewallPending {
                tcp: tcp_port,
                udp: udp_port,
            }
        }
        Err(error) => Status::FirewallFailed {
            tcp: tcp_port,
            udp: udp_port,
            detail: error,
        },
    }
}

fn rule_names(tcp_port: u16, udp_port: u16) -> [String; 2] {
    [
        format!("{GROUP} TCP {tcp_port}"),
        format!("{GROUP} UDP {udp_port}"),
    ]
}

fn powershell_path() -> PathBuf {
    std::env::var_os("SystemRoot")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\Windows"))
        .join("System32")
        .join("WindowsPowerShell")
        .join("v1.0")
        .join("powershell.exe")
}

fn rules_present(names: &[String; 2]) -> bool {
    let names_literal = names
        .iter()
        .map(|name| ps_quote(name))
        .collect::<Vec<_>>()
        .join(",");
    let script = format!(
        "$names=@({names_literal}); $found=@(Get-NetFirewallRule -DisplayName $names -ErrorAction SilentlyContinue | Where-Object {{ $_.Enabled -eq 'True' -and $_.Action -eq 'Allow' -and $_.Direction -eq 'Inbound' }} | Select-Object -ExpandProperty DisplayName -Unique); if ($found.Count -ge $names.Count) {{ exit 0 }} else {{ exit 1 }}"
    );
    Command::new(powershell_path())
        .creation_flags(CREATE_NO_WINDOW)
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            &script,
        ])
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

fn install_script(tcp_port: u16, udp_port: u16, names: &[String; 2]) -> String {
    let tcp_name = ps_quote(&names[0]);
    let udp_name = ps_quote(&names[1]);
    format!(
        "$ErrorActionPreference='Stop'; $group={group}; $tcp={tcp_name}; $udp={udp_name}; Get-NetFirewallRule -DisplayName @($tcp,$udp) -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue; New-NetFirewallRule -DisplayName $tcp -Group $group -Direction Inbound -Action Allow -Enabled True -Profile Any -Protocol TCP -LocalPort {tcp_port} -Description 'ClipBridge clipboard transport'; New-NetFirewallRule -DisplayName $udp -Group $group -Direction Inbound -Action Allow -Enabled True -Profile Any -Protocol UDP -LocalPort {udp_port} -Description 'ClipBridge LAN discovery'",
        group = ps_quote(GROUP),
    )
}

fn run_elevated(script: &str) -> Result<(), String> {
    let encoded = encode_utf16_base64(script);
    let powershell = powershell_path();
    let child_args = format!(
        "@('-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-EncodedCommand','{encoded}')"
    );
    let command = format!(
        "$p=Start-Process -FilePath {powershell} -Verb RunAs -WindowStyle Hidden -Wait -PassThru -ArgumentList {child_args}; exit $p.ExitCode",
        powershell = ps_quote(&powershell.to_string_lossy()),
    );
    let status = Command::new(&powershell)
        .creation_flags(CREATE_NO_WINDOW)
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            &command,
        ])
        .status()
        .map_err(|error| error.to_string())?;
    if status.success() {
        Ok(())
    } else {
        Err("UAC 请求被取消或防火墙命令失败".to_owned())
    }
}

fn encode_utf16_base64(value: &str) -> String {
    let bytes: Vec<u8> = value.encode_utf16().flat_map(u16::to_le_bytes).collect();
    STANDARD.encode(bytes)
}

fn ps_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rule_names_are_stable_and_port_specific() {
        assert_eq!(
            rule_names(45821, 45822),
            [
                "ClipBridge TCP 45821".to_owned(),
                "ClipBridge UDP 45822".to_owned()
            ]
        );
    }

    #[test]
    fn powershell_quotes_single_quotes() {
        assert_eq!(ps_quote("ClipBridge's rule"), "'ClipBridge''s rule'");
    }

    #[test]
    fn install_script_contains_both_port_rules() {
        let names = rule_names(45821, 45822);
        let script = install_script(45821, 45822, &names);
        assert!(script.contains("-Protocol TCP -LocalPort 45821"));
        assert!(script.contains("-Protocol UDP -LocalPort 45822"));
        assert!(script.contains("-Profile Any"));
    }
}
