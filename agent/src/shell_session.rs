//! Owns the agent side of the dedicated ShellService stream.
//!
//! The server can open several concurrent interactive shells on one agent
//! (e.g. two admins at once); each gets a `shell_id`. This module just
//! routes: `ShellStart` spawns a new ConPTY session (control::conpty_shell),
//! `ShellInput` / `ShellResize` / `ShellClose` get forwarded to the right
//! session by id. All of a session's output/exit events are multiplexed
//! back onto the single shared outbound `ShellClientMsg` sender.
//!
//! Fully decoupled from CommandService and IngestionService — a busy shell
//! can't delay a lock/shutdown command, and a slow telemetry flush can't
//! delay a keystroke.

use crate::control::conpty_shell::{self, ShellMsg};
use crate::pb::{shell_server_msg::Msg as ServerMsgKind, ShellClientMsg, ShellServerMsg};
use std::collections::HashMap;
use tokio::sync::mpsc;
use tracing::{info, warn};

pub struct ShellSessions {
    agent_id: String,
    client_tx: mpsc::Sender<ShellClientMsg>,
    sessions: HashMap<String, mpsc::Sender<ShellMsg>>,
}

impl ShellSessions {
    /// `client_tx` is this connection's outbound ShellClientMsg channel —
    /// fresh per reconnect, since an in-flight shell naturally ends if the
    /// tunnel drops (there's no viewer to serve it mid-reconnect anyway).
    pub fn new(agent_id: String, client_tx: mpsc::Sender<ShellClientMsg>) -> Self {
        Self {
            agent_id,
            client_tx,
            sessions: HashMap::new(),
        }
    }

    /// Dispatch one inbound ShellServerMsg from the server.
    pub fn handle(&mut self, msg: ShellServerMsg) {
        match msg.msg {
            Some(ServerMsgKind::Start(s)) => {
                info!("shell: starting session {} ({}x{})", s.shell_id, s.cols, s.rows);
                let tx = conpty_shell::spawn_shell(
                    s.shell_id.clone(),
                    s.cols,
                    s.rows,
                    self.client_tx.clone(),
                    self.agent_id.clone(),
                );
                self.sessions.insert(s.shell_id, tx);
            }

            Some(ServerMsgKind::Input(i)) => {
                if let Some(tx) = self.sessions.get(&i.shell_id) {
                    let _ = tx.try_send(ShellMsg::Input(i.data));
                } else {
                    warn!("shell: input for unknown session {}", i.shell_id);
                }
            }

            Some(ServerMsgKind::Resize(r)) => {
                if let Some(tx) = self.sessions.get(&r.shell_id) {
                    let _ = tx.try_send(ShellMsg::Resize(r.cols, r.rows));
                } else {
                    warn!("shell: resize for unknown session {}", r.shell_id);
                }
            }

            Some(ServerMsgKind::Close(c)) => {
                if let Some(tx) = self.sessions.remove(&c.shell_id) {
                    let _ = tx.try_send(ShellMsg::Close);
                }
            }

            None => warn!("shell: empty ShellServerMsg"),
        }
    }
}
