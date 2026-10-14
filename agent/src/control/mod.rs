//! Command dispatcher — receives CommandEnvelope from the server over the
//! dedicated CommandService stream and routes each to the right handler.
//!
//! Only small, latency-sensitive one-shot actions travel here (lock,
//! sign-out, popup, shutdown/restart, cancel). Interactive shell sessions
//! have their own stream/service (see shell_session.rs) so a stuck shell
//! can never delay a lock-screen or shutdown command queued behind it.

pub mod conpty_shell;
pub mod system_actions;

use crate::pb::{
    command_envelope::Command, command_result::Result as ResultKind, ActionResult,
    CommandEnvelope, CommandResult, PowerActionType,
};
use tokio::sync::mpsc;
use tracing::{error, info, warn};

/// Receives commands from the tunnel and dispatches them.
pub async fn run_dispatcher(
    mut cmd_rx: mpsc::Receiver<CommandEnvelope>,
    result_tx: mpsc::Sender<CommandResult>,
    agent_id: String,
) {
    while let Some(env) = cmd_rx.recv().await {
        info!(
            "command received: id={} type={:?}",
            env.command_id,
            env.command.as_ref().map(std::mem::discriminant)
        );

        let cmd_id = env.command_id.clone();
        let agent_id_c = agent_id.clone();
        let res_tx = result_tx.clone();

        match env.command {
            Some(Command::Lock(_)) => {
                let ok = system_actions::lock_screen();
                send_action(&res_tx, &cmd_id, &agent_id_c, ok, "lock failed").await;
            }

            Some(Command::SignOut(_)) => {
                let ok = system_actions::sign_out();
                send_action(&res_tx, &cmd_id, &agent_id_c, ok, "sign-out failed").await;
            }

            Some(Command::Popup(p)) => {
                if p.title == "KILL_PROCESS" {
                    if let Ok(pid) = p.message.parse::<u32>() {
                        let res = system_actions::kill_process(pid);
                        send_action(&res_tx, &cmd_id, &agent_id_c, res.is_ok(), &res.err().map(|e| e.to_string()).unwrap_or_default()).await;
                        continue;
                    }
                }
                if p.title == "UNINSTALL" {
                    let res = system_actions::uninstall_agent();
                    send_action(&res_tx, &cmd_id, &agent_id_c, res.is_ok(), &res.err().map(|e| e.to_string()).unwrap_or_default()).await;
                    continue;
                }
                if p.title == "INPUT_CLICK" || p.title == "INPUT_RIGHT_CLICK" || p.title == "INPUT_DOUBLE_CLICK" || p.title == "INPUT_MOUSEDOWN" || p.title == "INPUT_MOUSEUP" || p.title == "INPUT_MOVE" {
                    let action = match p.title.as_str() {
                        "INPUT_RIGHT_CLICK" => "right_click",
                        "INPUT_DOUBLE_CLICK" => "double_click",
                        "INPUT_MOUSEDOWN" => "mousedown",
                        "INPUT_MOUSEUP" => "mouseup",
                        "INPUT_MOVE" => "move",
                        _ => "click",
                    };
                    let parts: Vec<&str> = p.message.split(',').collect();
                    if parts.len() == 2 {
                        if let (Ok(x), Ok(y)) = (parts[0].parse::<i32>(), parts[1].parse::<i32>()) {
                            let res = system_actions::inject_mouse_action(action, x, y);
                            send_action(&res_tx, &cmd_id, &agent_id_c, res.is_ok(), "").await;
                            continue;
                        }
                    }
                }
                if p.title == "INPUT_KEY" {
                    let res = system_actions::inject_key_combo(&p.message);
                    send_action(&res_tx, &cmd_id, &agent_id_c, res.is_ok(), "").await;
                    continue;
                }
                if p.title == "SHELL_EXEC" {
                    let res = system_actions::exec_shell_command(&p.message);
                    match res {
                        Ok(output) => {
                            send_action(&res_tx, &cmd_id, &agent_id_c, true, &output).await;
                        }
                        Err(e) => {
                            send_action(&res_tx, &cmd_id, &agent_id_c, false, &e.to_string()).await;
                        }
                    }
                    continue;
                }
                if p.title == "FILE_LIST" {
                    let res = system_actions::list_directory(&p.message);
                    match res {
                        Ok(json) => {
                            send_action(&res_tx, &cmd_id, &agent_id_c, true, &json).await;
                        }
                        Err(e) => {
                            send_action(&res_tx, &cmd_id, &agent_id_c, false, &e.to_string()).await;
                        }
                    }
                    continue;
                }
                if p.title == "FILE_READ" {
                    let res = system_actions::read_file_hex(&p.message);
                    match res {
                        Ok(hex_data) => {
                            send_action(&res_tx, &cmd_id, &agent_id_c, true, &hex_data).await;
                        }
                        Err(e) => {
                            send_action(&res_tx, &cmd_id, &agent_id_c, false, &e.to_string()).await;
                        }
                    }
                    continue;
                }
                if p.title == "FILE_DELETE" {
                    let res = system_actions::delete_file_or_dir(&p.message);
                    match res {
                        Ok(msg) => {
                            send_action(&res_tx, &cmd_id, &agent_id_c, true, &msg).await;
                        }
                        Err(e) => {
                            send_action(&res_tx, &cmd_id, &agent_id_c, false, &e.to_string()).await;
                        }
                    }
                    continue;
                }
                if p.title == "FILE_WRITE" {
                    let parsed: std::result::Result<serde_json::Value, _> = serde_json::from_str(&p.message);
                    match parsed {
                        Ok(val) => {
                            let path = val.get("path").and_then(|v| v.as_str()).unwrap_or("");
                            let content_b64 = val.get("content_base64").and_then(|v| v.as_str()).unwrap_or("");
                            if path.is_empty() {
                                send_action(&res_tx, &cmd_id, &agent_id_c, false, "Missing 'path' in payload").await;
                            } else {
                                match system_actions::write_file_base64(path, content_b64) {
                                    Ok(bytes) => {
                                        send_action(&res_tx, &cmd_id, &agent_id_c, true, &format!("Wrote {} bytes", bytes)).await;
                                    }
                                    Err(e) => {
                                        send_action(&res_tx, &cmd_id, &agent_id_c, false, &e.to_string()).await;
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            send_action(&res_tx, &cmd_id, &agent_id_c, false, &format!("Invalid payload: {}", e)).await;
                        }
                    }
                    continue;
                }
                match system_actions::send_popup(&p.title, &p.message) {
                    Ok(()) => send_action(&res_tx, &cmd_id, &agent_id_c, true, "").await,
                    Err(e) => send_action(&res_tx, &cmd_id, &agent_id_c, false, &e.to_string()).await,
                }
            }

            Some(Command::PowerAction(p)) => {
                let restart = p.action() == PowerActionType::PowerActionRestart;
                match system_actions::power_action(
                    restart,
                    p.delay_seconds,
                    &p.message,
                    p.force_apps_closed,
                ) {
                    Ok(()) => send_action(&res_tx, &cmd_id, &agent_id_c, true, "").await,
                    Err(e) => {
                        send_action(&res_tx, &cmd_id, &agent_id_c, false, &e.to_string()).await
                    }
                }
            }

            Some(Command::CancelPowerAction(_)) => {
                match system_actions::cancel_power_action() {
                    Ok(()) => send_action(&res_tx, &cmd_id, &agent_id_c, true, "").await,
                    Err(e) => {
                        send_action(&res_tx, &cmd_id, &agent_id_c, false, &e.to_string()).await
                    }
                }
            }

            None => warn!("received empty command envelope"),
        }
    }
}

async fn send_action(
    tx: &mpsc::Sender<CommandResult>,
    command_id: &str,
    agent_id: &str,
    success: bool,
    error: &str,
) {
    let res = CommandResult {
        command_id: command_id.to_string(),
        agent_id: agent_id.to_string(),
        result: Some(ResultKind::Action(ActionResult {
            success,
            error: error.to_string(),
        })),
    };
    if tx.send(res).await.is_err() {
        error!("result_tx closed");
    }
}
