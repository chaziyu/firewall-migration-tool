use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};

use tauri::{Manager, WebviewUrl, WebviewWindowBuilder};
use tauri_plugin_shell::process::{CommandChild, CommandEvent};
use tauri_plugin_shell::ShellExt;
use tauri_plugin_updater::UpdaterExt;
use uuid::Uuid;

const READY_PREFIX: &str = "FWMIGRATE_DESKTOP_READY ";

struct DesktopSidecar {
    child: Mutex<Option<CommandChild>>,
    shutting_down: Arc<AtomicBool>,
    readiness: Mutex<Result<Option<u16>, String>>,
    started_at: std::time::Instant,
    token: String,
}

#[tauri::command]
fn desktop_runtime_status(webview: tauri::Webview) -> Result<Option<serde_json::Value>, String> {
    if webview.label() != "main" {
        return Err("Desktop runtime is unavailable".into());
    }
    let state = webview.state::<DesktopSidecar>();
    let mut readiness = state
        .readiness
        .lock()
        .map_err(|_| "Desktop startup state unavailable")?;
    if matches!(*readiness, Ok(None)) && state.started_at.elapsed().as_secs() >= 60 {
        *readiness = Err("Desktop backend startup timed out".into());
        stop_sidecar(webview.app_handle());
    }
    match readiness.as_ref() {
        Ok(Some(port)) => Ok(Some(serde_json::json!({
            "apiBase": format!("http://127.0.0.1:{port}"), "token": state.token,
        }))),
        Ok(None) => Ok(None),
        Err(error) => Err(error.clone()),
    }
}

fn stop_sidecar(handle: &tauri::AppHandle) {
    if let Some(state) = handle.try_state::<DesktopSidecar>() {
        state.shutting_down.store(true, Ordering::Relaxed);
        if let Ok(mut guard) = state.child.lock() {
            if let Some(child) = guard.take() {
                let _ = child.kill();
            }
        }
    }
}

fn fail_sidecar(handle: &tauri::AppHandle) {
    let state = handle.state::<DesktopSidecar>();
    let was_ready = {
        let mut readiness = state.readiness.lock().unwrap();
        let was_ready = matches!(*readiness, Ok(Some(_)));
        *readiness = Err("Desktop backend could not start or disconnected".into());
        was_ready
    };
    stop_sidecar(handle);
    if was_ready {
        handle.exit(1);
    }
}

fn valid_update_source(url: &tauri::Url, version: &str, signature: &str) -> bool {
    let prefix = format!("/chaziyu/firewall-migration-tool/releases/download/desktop-v{version}/");
    let valid_asset = url
        .path()
        .strip_prefix(&prefix)
        .is_some_and(|asset| !asset.contains('/') && asset.ends_with("-setup.exe"));
    url.scheme() == "https"
        && url.host_str() == Some("github.com")
        && url.port().is_none()
        && url.username().is_empty()
        && url.password().is_none()
        && url.query().is_none()
        && url.fragment().is_none()
        && valid_asset
        && !signature.trim().is_empty()
}

#[tauri::command]
async fn check_desktop_update(
    webview: tauri::Webview,
) -> Result<Option<serde_json::Value>, String> {
    let key = webview
        .config()
        .plugins
        .0
        .get("updater")
        .and_then(|config| config.get("pubkey"))
        .and_then(|key| key.as_str());
    if key.is_none_or(|key| key.trim().is_empty()) {
        return Err("Desktop update signing is not configured".into());
    }
    let handle = webview.app_handle().clone();
    let updater = webview
        .updater_builder()
        // Use the NSIS-preferred manifest entry even for an MSI-installed baseline.
        .target("windows-x86_64")
        .timeout(std::time::Duration::from_secs(30))
        .on_before_exit(move || {
            stop_sidecar(&handle);
            handle.cleanup_before_exit();
        })
        .build()
        .map_err(|error| error.to_string())?;
    let Some(update) = updater.check().await.map_err(|error| error.to_string())? else {
        return Ok(None);
    };
    if !valid_update_source(&update.download_url, &update.version, &update.signature) {
        return Err("Invalid GitHub release update metadata".into());
    }
    let metadata = serde_json::json!({
        "currentVersion": update.current_version,
        "version": update.version,
        "body": update.body,
        "rawJson": update.raw_json,
    });
    let rid = webview.resources_table().add(update);
    let mut metadata = metadata;
    metadata["rid"] = serde_json::json!(rid);
    Ok(Some(metadata))
}

#[cfg(test)]
mod tests {
    use super::valid_update_source;

    #[test]
    fn readiness_accepts_only_nonzero_port_markers() {
        assert_eq!(
            super::parse_ready_port(b"FWMIGRATE_DESKTOP_READY 12345\n"),
            Some(12345)
        );
        for line in [
            b"FWMIGRATE_DESKTOP_READY 0".as_slice(),
            b"FWMIGRATE_DESKTOP_READY 65536",
            b"other 12345",
        ] {
            assert_eq!(super::parse_ready_port(line), None);
        }
    }

    #[test]
    fn updater_accepts_only_matching_signed_github_release_assets() {
        let source = "https://github.com/chaziyu/firewall-migration-tool/releases/download/desktop-v0.2.1/tool-setup.exe";
        let url = tauri::Url::parse(source).unwrap();
        assert!(valid_update_source(&url, "0.2.1", "signature"));
        assert!(!valid_update_source(&url, "0.2.2", "signature"));
        assert!(!valid_update_source(&url, "0.2.1", ""));
        for invalid in [
            source.replace("https:", "http:"),
            source.replace("github.com", "example.com"),
            source.replace("chaziyu/", "other/"),
            source.replace("-setup.exe", ".msi"),
            format!("{source}?redirect=other"),
            format!("{source}#fragment"),
        ] {
            assert!(!valid_update_source(
                &tauri::Url::parse(&invalid).unwrap(),
                "0.2.1",
                "signature"
            ));
        }
    }
}

fn desktop_token() -> String {
    format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple())
}

fn parse_ready_port(line: &[u8]) -> Option<u16> {
    let text = String::from_utf8_lossy(line);
    text.trim()
        .strip_prefix(READY_PREFIX)
        .and_then(|value| value.parse::<u16>().ok())
        .filter(|port| *port != 0)
}

pub fn run() {
    let app = tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .invoke_handler(tauri::generate_handler![
            check_desktop_update,
            desktop_runtime_status
        ])
        .setup(|app| {
            let token = desktop_token();
            let shutting_down = Arc::new(AtomicBool::new(false));
            app.manage(DesktopSidecar {
                child: Mutex::new(None),
                shutting_down: Arc::clone(&shutting_down),
                readiness: Mutex::new(Ok(None)),
                started_at: std::time::Instant::now(),
                token: token.clone(),
            });
            WebviewWindowBuilder::new(app, "main", WebviewUrl::App("index.html".into()))
                .title("Firewall Migration Tool")
                .inner_size(1360.0, 880.0)
                .min_inner_size(960.0, 640.0)
                .initialization_script(
                    "window.__FWMIGRATE_DESKTOP__ = Object.freeze({ starting: true });",
                )
                .build()?;
            let spawned = app
                .shell()
                .sidecar("fwmigrate-backend")
                .and_then(|command| {
                    command
                        .args(["--port", "0", "--token", token.as_str()])
                        .spawn()
                });
            let (mut rx, child) = match spawned {
                Ok(child) => child,
                Err(_) => {
                    *app.state::<DesktopSidecar>().readiness.lock().unwrap() =
                        Err("Desktop backend could not start".into());
                    return Ok(());
                }
            };
            *app.state::<DesktopSidecar>().child.lock().unwrap() = Some(child);
            let monitor_shutdown = Arc::clone(&shutting_down);
            let handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                while let Some(event) = rx.recv().await {
                    match event {
                        CommandEvent::Stdout(line) => {
                            if let Some(port) = parse_ready_port(&line) {
                                let state = handle.state::<DesktopSidecar>();
                                let mut readiness = state.readiness.lock().unwrap();
                                if matches!(*readiness, Ok(None)) {
                                    *readiness = Ok(Some(port));
                                }
                            }
                        }
                        CommandEvent::Stderr(line) => {
                            eprintln!("desktop sidecar: {}", String::from_utf8_lossy(&line));
                        }
                        CommandEvent::Error(error) => {
                            eprintln!("desktop sidecar error: {error}");
                            if !monitor_shutdown.load(Ordering::Relaxed) {
                                fail_sidecar(&handle);
                            }
                            break;
                        }
                        CommandEvent::Terminated(status) => {
                            eprintln!("desktop sidecar terminated: {status:?}");
                            if !monitor_shutdown.load(Ordering::Relaxed) {
                                fail_sidecar(&handle);
                            }
                            break;
                        }
                        _ => {}
                    }
                }
                if !monitor_shutdown.load(Ordering::Relaxed) {
                    fail_sidecar(&handle);
                }
            });

            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("failed to build Firewall Migration Tool desktop application");

    app.run(|handle, event| {
        if matches!(event, tauri::RunEvent::ExitRequested { .. }) {
            stop_sidecar(handle);
        }
    });
}
