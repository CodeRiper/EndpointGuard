use crate::pb::TelemetryEvent;
use tokio::sync::mpsc::Sender;

/// ETW process telemetry: Microsoft-Windows-Kernel-Process,
/// GUID {22FB2CD6-0E7B-4E8F-9D10-4A8A7C0C0F2F}, Event ID 1 (start) /
/// 2 (stop) — per the blueprint.
///
/// NOT implemented yet. A correct consumer needs:
///   1. StartTraceW to open a real-time trace session.
///   2. EnableTraceEx2 to subscribe the kernel-process provider on it.
///   3. OpenTraceW + ProcessTrace on a dedicated blocking thread
///      (ProcessTrace blocks the calling thread until the session
///      stops, so it can't just run on a tokio task).
///   4. A C-ABI EVENT_RECORD callback that calls
///      TdhGetEventInformation once per event for its
///      TRACE_EVENT_INFO, then TdhGetProperty per field
///      (ProcessId, ParentProcessId, ImageFileName, CommandLine,
///      UserSID, SessionId) — each with its own two-call buffer
///      sizing dance.
///
/// That TDH property loop alone is a few hundred lines of fiddly,
/// easy-to-get-subtly-wrong unsafe code, and it's the one piece here
/// I didn't want to hand you unverified. It's a clean, self-contained
/// next task — say the word and I'll build it as its own module.
pub async fn run(_tx: Sender<TelemetryEvent>, _agent_id: String) {
    tracing::warn!("process (ETW) collector not implemented yet — see module docs");
    std::future::pending::<()>().await;
}
