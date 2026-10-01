use std::io;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};

use tauri::{Manager, WebviewUrl, WebviewWindowBuilder};
use tauri_plugin_shell::process::{CommandChild, CommandEvent};
use tauri_plugin_shell::ShellExt;
use uuid::Uuid;

const READY_PREFIX: &str = "FWMIGRATE_DESKTOP_READY ";

struct DesktopSidecar {
    child: Mutex<Option<CommandChild>>,
    shutting_down: Arc<AtomicBool>,
}

fn desktop_token() -> String {
    format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple())
}

fn parse_ready_port(line: &[u8]) -> Option<u16> {
    let text = String::from_utf8_lossy(line);
    text.trim()
        .strip_prefix(READY_PREFIX)
        .and_then(|value| value.parse::<u16>().ok())
}

pub fn run() {
    let app = tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .setup(|app| {
            let token = desktop_token();
            let command = app
                .shell()
                .sidecar("fwmigrate-backend")?
                .args(["--port", "0", "--token", token.as_str()]);
            let (mut rx, child) = command.spawn()?;

            let port = tauri::async_runtime::block_on(async {
                loop {
                    match rx.recv().await {
                        Some(CommandEvent::Stdout(line)) => {
                            if let Some(port) = parse_ready_port(&line) {
                                break Ok(port);
                            }
                        }
                        Some(CommandEvent::Stderr(line)) => {
                            eprintln!("desktop sidecar: {}", String::from_utf8_lossy(&line));
                        }
                        Some(CommandEvent::Error(error)) => {
                            break Err(io::Error::other(format!(
                                "desktop sidecar startup error: {error}"
                            )));
                        }
                        Some(CommandEvent::Terminated(status)) => {
                            break Err(io::Error::other(format!(
                                "desktop sidecar exited before ready: {status:?}"
                            )));
                        }
                        Some(_) => {}
                        None => {
                            break Err(io::Error::other(
                                "desktop sidecar closed output before reporting readiness",
                            ));
                        }
                    }
                }
            })?;

            let shutting_down = Arc::new(AtomicBool::new(false));
            let monitor_shutdown = Arc::clone(&shutting_down);
            let handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                while let Some(event) = rx.recv().await {
                    match event {
                        CommandEvent::Stderr(line) => {
                            eprintln!("desktop sidecar: {}", String::from_utf8_lossy(&line));
                        }
                        CommandEvent::Error(error) => {
                            eprintln!("desktop sidecar error: {error}");
                            if !monitor_shutdown.load(Ordering::Relaxed) {
                                handle.exit(1);
                            }
                            break;
                        }
                        CommandEvent::Terminated(status) => {
                            eprintln!("desktop sidecar terminated: {status:?}");
                            if !monitor_shutdown.load(Ordering::Relaxed) {
                                handle.exit(1);
                            }
                            break;
                        }
                        _ => {}
                    }
                }
            });

            app.manage(DesktopSidecar {
                child: Mutex::new(Some(child)),
                shutting_down,
            });

            let init_script = format!(
                r#"window.__FWMIGRATE_DESKTOP__ = Object.freeze({{ apiBase: "http://127.0.0.1:{port}", token: "{token}" }});"#
            );
            WebviewWindowBuilder::new(app, "main", WebviewUrl::App("index.html".into()))
                .title("Firewall Migration Tool")
                .inner_size(1360.0, 880.0)
                .min_inner_size(960.0, 640.0)
                .initialization_script(init_script)
                .build()?;

            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("failed to build Firewall Migration Tool desktop application");

    app.run(|handle, event| {
        if matches!(event, tauri::RunEvent::ExitRequested { .. }) {
            if let Some(state) = handle.try_state::<DesktopSidecar>() {
                state.shutting_down.store(true, Ordering::Relaxed);
                if let Ok(mut guard) = state.child.lock() {
                    if let Some(child) = guard.take() {
                        let _ = child.kill();
                    }
                }
            }
        }
    });
}
