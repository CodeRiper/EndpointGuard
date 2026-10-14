//! ConPTY interactive remote terminal.
//!
//! When the server sends ShellStart, this module:
//!   1. Creates a Win32 Pseudo Console (ConPTY) at the requested size.
//!   2. Spawns powershell.exe attached to that PTY.
//!   3. Pipes PTY output → gRPC ShellOutputChunk messages.
//!   4. Accepts ShellInputChunk / ShellResize / ShellClose messages.
//!
//! The agent Windows Service runs in Session 0 (isolated from user
//! desktops).  For now the shell runs in Session 0 too — a TODO
//! comment marks where WTSQueryUserToken / CreateProcessAsUserW would
//! elevate it into the user session instead.

use crate::pb::{shell_client_msg::Msg as ClientMsgKind, ShellClientMsg, ShellExited, ShellOutput};
use tokio::sync::mpsc;
use tracing::{error, info};

pub enum ShellMsg {
    Input(Vec<u8>),
    Resize(u32, u32),
    Close,
}

/// Spawns a ConPTY shell and returns a channel to send ShellMsg to it.
/// `client_tx` is the shared outbound channel for the whole ShellService
/// stream — this session's Output/Exited messages are multiplexed onto it
/// alongside any other concurrent shell sessions on this agent.
pub fn spawn_shell(
    shell_id: String,
    cols: u32,
    rows: u32,
    client_tx: mpsc::Sender<ShellClientMsg>,
    agent_id: String,
) -> mpsc::Sender<ShellMsg> {
    let (msg_tx, msg_rx) = mpsc::channel::<ShellMsg>(64);

    std::thread::spawn(move || {
        #[cfg(windows)]
        win::run_shell(shell_id, cols, rows, client_tx, agent_id, msg_rx);
        #[cfg(not(windows))]
        tracing::warn!("ConPTY shell is Windows-only");
    });

    msg_tx
}

// ─── Windows implementation ───────────────────────────────────────────────────
#[cfg(windows)]
mod win {
    use super::*;
    
    use std::ptr;
    use windows::core::PWSTR;
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::System::Console::{
        ClosePseudoConsole, CreatePseudoConsole, ResizePseudoConsole, COORD,
    };
    use windows::Win32::System::Pipes::CreatePipe;
    use windows::Win32::System::Threading::{
        CreateProcessW, DeleteProcThreadAttributeList,
        InitializeProcThreadAttributeList, UpdateProcThreadAttribute, EXTENDED_STARTUPINFO_PRESENT,
        PROCESS_INFORMATION, PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE,
        STARTUPINFOEXW, LPPROC_THREAD_ATTRIBUTE_LIST,
    };

    pub fn run_shell(
        shell_id: String,
        cols: u32,
        rows: u32,
        client_tx: mpsc::Sender<ShellClientMsg>,
        agent_id: String,
        mut msg_rx: mpsc::Receiver<ShellMsg>,
    ) {
        unsafe {
            // ── 1. Pipe pairs ──────────────────────────────────────────────
            // PTY reads from pipe_in_read; agent writes to pipe_in_write.
            // PTY writes to pipe_out_write; agent reads from pipe_out_read.
            let mut pipe_in_read  = HANDLE::default();
            let mut pipe_in_write = HANDLE::default();
            let mut pipe_out_read = HANDLE::default();
            let mut pipe_out_write= HANDLE::default();

            if CreatePipe(&mut pipe_in_read,  &mut pipe_in_write,  None, 0).is_err()
            || CreatePipe(&mut pipe_out_read, &mut pipe_out_write, None, 0).is_err() {
                error!("ConPTY: CreatePipe failed");
                return;
            }

            // ── 2. Create pseudo console ───────────────────────────────────
            let size = COORD { X: cols as i16, Y: rows as i16 };
            let hpc = match CreatePseudoConsole(size, pipe_in_read, pipe_out_write, 0) {
                Ok(h) => h,
                Err(e) => {
                    error!("ConPTY: CreatePseudoConsole failed: {:?}", e);
                    let _ = CloseHandle(pipe_in_read);  let _ = CloseHandle(pipe_in_write);
                    let _ = CloseHandle(pipe_out_read); let _ = CloseHandle(pipe_out_write);
                    return;
                }
            };

            // ── 3. Build STARTUPINFOEX with PTY attribute ──────────────────
            let mut attr_size = 0usize;
            let _ = InitializeProcThreadAttributeList(LPPROC_THREAD_ATTRIBUTE_LIST(ptr::null_mut()), 1, 0, &mut attr_size);
            let mut attr_buf = vec![0u8; attr_size];
            let attr_list = LPPROC_THREAD_ATTRIBUTE_LIST(attr_buf.as_mut_ptr() as *mut _);
            InitializeProcThreadAttributeList(attr_list, 1, 0, &mut attr_size)
                .expect("InitializeProcThreadAttributeList");
            UpdateProcThreadAttribute(
                attr_list, 0,
                PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE as usize,
                Some(hpc.0 as *const _),
                std::mem::size_of::<isize>(),
                None, None,
            ).expect("UpdateProcThreadAttribute");

            let mut si = STARTUPINFOEXW::default();
            si.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
            si.lpAttributeList = attr_list;

            // ── 4. Spawn powershell.exe ────────────────────────────────────
            // TODO: for user-session shell, replace CreateProcessW with
            // WTSQueryUserToken + CreateProcessAsUserW.
            let mut cmd: Vec<u16> = "powershell.exe\0".encode_utf16().collect();
            let mut pi = PROCESS_INFORMATION::default();
            if CreateProcessW(
                PWSTR::null(), PWSTR(cmd.as_mut_ptr()),
                None, None, false,
                EXTENDED_STARTUPINFO_PRESENT,
                None, PWSTR::null(),
                &si.StartupInfo, &mut pi,
            ).is_err() {
                error!("ConPTY: CreateProcessW failed");
                ClosePseudoConsole(hpc);
                return;
            }

            info!("ConPTY: shell started pid={}", pi.dwProcessId);

            // ── 5. Reader thread: PTY output → gRPC ShellOutputChunk ───────
            let sid_r = shell_id.clone();
            let aid_r = agent_id.clone();
            let tx_r = client_tx.clone();
            let out_pipe = pipe_out_read;

            std::thread::spawn(move || {
                let handle = windows::Win32::Foundation::HANDLE(out_pipe.0);
                let mut buf = [0u8; 4096];
                loop {
                    let mut read = 0u32;
                    let ok = windows::Win32::Storage::FileSystem::ReadFile(
                        handle, Some(&mut buf), Some(&mut read), None,
                    );
                    if ok.is_err() || read == 0 { break; }

                    let msg = ShellClientMsg {
                        agent_id: aid_r.clone(),
                        msg: Some(ClientMsgKind::Output(ShellOutput {
                            shell_id: sid_r.clone(),
                            data: buf[..read as usize].to_vec(),
                        })),
                    };
                    // Block-on-send from a non-async context
                    let _ = tx_r.blocking_send(msg);
                }
                // Shell exited — notify server
                let exited = ShellClientMsg {
                    agent_id: aid_r.clone(),
                    msg: Some(ClientMsgKind::Exited(ShellExited {
                        shell_id: sid_r.clone(),
                        exit_code: 0,
                    })),
                };
                let _ = tx_r.blocking_send(exited);
            });

            // ── 6. Main loop: handle ShellMsg from dispatcher ──────────────
            loop {
                // tokio receiver in a blocking thread — use blocking_recv
                match msg_rx.blocking_recv() {
                    Some(ShellMsg::Input(data)) => {
                        let mut written = 0u32;
                        let _ = windows::Win32::Storage::FileSystem::WriteFile(
                            pipe_in_write, Some(&data), Some(&mut written), None,
                        );
                    }
                    Some(ShellMsg::Resize(c, r)) => {
                        let new_size = COORD { X: c as i16, Y: r as i16 };
                        let _ = ResizePseudoConsole(hpc, new_size);
                    }
                    Some(ShellMsg::Close) | None => break,
                }
            }

            // ── 7. Cleanup ─────────────────────────────────────────────────
            ClosePseudoConsole(hpc);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            CloseHandle(pipe_in_read);
            CloseHandle(pipe_in_write);
            CloseHandle(pipe_out_write);
            // pipe_out_read is owned by the reader thread — it will see EOF and exit
            DeleteProcThreadAttributeList(attr_list);
            info!("ConPTY: shell {} closed", shell_id);
        }
    }
}
