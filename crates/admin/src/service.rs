//! Server side of the admin API.

use std::io;
use std::os::unix::net::UnixListener as StdUnixListener;
use std::path::PathBuf;
use std::sync::Arc;

use delegate_guard_daemon::Allowlist;
use delegate_guard_daemon::SharedPolicy;
use delegate_guard_receipt as receipt;
use delegate_guard_state as state;
use jiff::Timestamp;
use tokio_stream::StreamExt;
use tokio_stream::wrappers::UnixListenerStream;
use tonic::{Request, Response, Status};

use crate::pb::admin_service_server::{AdminService, AdminServiceServer};
use crate::pb::{
    ChainState, GetStatusRequest, GetStatusResponse, HealthRequest, HealthResponse,
    ListSessionsRequest, ListSessionsResponse, ReloadOutcome, ReloadPolicyRequest,
    ReloadPolicyResponse, ServingStatus, SessionSummary, VerifyReceiptsRequest,
    VerifyReceiptsResponse,
};

/// What the admin API reports on and controls.
#[derive(Debug)]
pub struct AdminContext {
    /// Daemon version.
    pub version: String,
    /// When the daemon started.
    pub started_at: Timestamp,
    /// Hook socket path.
    pub hook_socket: PathBuf,
    /// Session state directory.
    pub state_dir: PathBuf,
    /// Policy shared with the hook server.
    pub policy: Arc<SharedPolicy>,
}

/// Why the admin server stopped.
#[derive(Debug, thiserror::Error)]
pub enum AdminError {
    /// The listener could not be handed to the runtime.
    #[error("admin listener: {0}")]
    Listener(#[from] io::Error),
    /// The gRPC server failed.
    #[error("admin server: {0}")]
    Transport(#[from] tonic::transport::Error),
}

/// Serves the admin API on `listener` (bound with
/// `delegate_guard_daemon::bind_private`) until the runtime stops.
///
/// # Errors
///
/// [`AdminError`] if the listener cannot be registered or the server fails.
pub async fn serve(
    listener: StdUnixListener,
    ctx: AdminContext,
    allowed: Allowlist,
) -> Result<(), AdminError> {
    listener.set_nonblocking(true)?;
    let listener = tokio::net::UnixListener::from_std(listener)?;
    // Authenticate at accept: a disallowed peer never reaches an RPC handler.
    let incoming = UnixListenerStream::new(listener).filter(move |conn| match conn {
        Ok(stream) => stream
            .peer_cred()
            .is_ok_and(|cred| allowed.admits(cred.uid())),
        Err(_) => false,
    });
    tonic::transport::Server::builder()
        .serve_with_incoming(
            AdminServiceServer::new(Admin { ctx: Arc::new(ctx) }),
            incoming,
        )
        .await?;
    Ok(())
}

struct Admin {
    ctx: Arc<AdminContext>,
}

fn rfc3339(t: Timestamp) -> String {
    t.strftime("%Y-%m-%dT%H:%M:%SZ").to_string()
}

/// Runs blocking file work (locks, fsync'd reads) off the async executor.
async fn blocking<T: Send + 'static>(
    f: impl FnOnce() -> Result<T, String> + Send + 'static,
) -> Result<T, Status> {
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| Status::internal(format!("worker failed: {e}")))?
        .map_err(Status::internal)
}

#[tonic::async_trait]
impl AdminService for Admin {
    async fn health(&self, _: Request<HealthRequest>) -> Result<Response<HealthResponse>, Status> {
        let info = self.ctx.policy.info();
        let (status, reason) = match info.last_error {
            None => (ServingStatus::Serving, String::new()),
            Some(e) => (
                ServingStatus::Degraded,
                format!("serving the previous policy; last reload rejected: {e}"),
            ),
        };
        Ok(Response::new(HealthResponse {
            status: status.into(),
            reason,
        }))
    }

    async fn get_status(
        &self,
        _: Request<GetStatusRequest>,
    ) -> Result<Response<GetStatusResponse>, Status> {
        let info = self.ctx.policy.info();
        Ok(Response::new(GetStatusResponse {
            version: self.ctx.version.clone(),
            started_at: rfc3339(self.ctx.started_at),
            hook_socket: self.ctx.hook_socket.display().to_string(),
            state_dir: self.ctx.state_dir.display().to_string(),
            policy_path: self.ctx.policy.path().display().to_string(),
            policy_sha256: info.sha256,
            policy_loaded_at: rfc3339(info.loaded_at),
            last_reload_error: info.last_error.unwrap_or_default(),
        }))
    }

    async fn list_sessions(
        &self,
        _: Request<ListSessionsRequest>,
    ) -> Result<Response<ListSessionsResponse>, Status> {
        let dir = self.ctx.state_dir.clone();
        // TODO(ckodex): include the per-caller `uid-<n>/` directories a Tier S daemon
        // keeps (and accept them in VerifyReceipts); until then use
        // `delegate-guard verify --state <state>/uid-<n>` as the service account.
        let sessions = blocking(move || {
            let stems = state::list(&dir).map_err(|e| e.to_string())?;
            let mut out = Vec::with_capacity(stems.len());
            for stem in stems {
                let Some(session) = state::inspect(&dir, &stem).map_err(|e| e.to_string())? else {
                    continue;
                };
                out.push(SessionSummary {
                    agents: u32::try_from(session.agents.len()).unwrap_or(u32::MAX),
                    pending: u32::try_from(session.pending.len()).unwrap_or(u32::MAX),
                    root_remaining: session
                        .agents
                        .get(delegate_guard_kernel::session::MAIN_ACTOR)
                        .map_or(0, |a| a.remaining),
                    file_stem: stem,
                });
            }
            Ok(out)
        })
        .await?;
        Ok(Response::new(ListSessionsResponse { sessions }))
    }

    async fn verify_receipts(
        &self,
        request: Request<VerifyReceiptsRequest>,
    ) -> Result<Response<VerifyReceiptsResponse>, Status> {
        let session_id = request.into_inner().session_id;
        if session_id.is_empty() {
            return Err(Status::invalid_argument("session_id is required"));
        }
        let receipts = state::paths(&self.ctx.state_dir, &session_id).receipts;
        let reply = blocking(move || {
            Ok(match receipt::verify(&receipts) {
                Ok(0) => VerifyReceiptsResponse {
                    state: ChainState::Empty.into(),
                    ..Default::default()
                },
                Ok(n) => VerifyReceiptsResponse {
                    state: ChainState::Intact.into(),
                    valid_records: u64::try_from(n).unwrap_or(u64::MAX),
                    head_hash: receipt::head(&receipts)
                        .map(|(_, h)| h)
                        .map_err(|e| e.to_string())?,
                    error: String::new(),
                },
                Err(f) => VerifyReceiptsResponse {
                    state: ChainState::Broken.into(),
                    valid_records: u64::try_from(f.valid).unwrap_or(u64::MAX),
                    head_hash: String::new(),
                    error: f.error.to_string(),
                },
            })
        })
        .await?;
        Ok(Response::new(reply))
    }

    async fn reload_policy(
        &self,
        _: Request<ReloadPolicyRequest>,
    ) -> Result<Response<ReloadPolicyResponse>, Status> {
        let policy = Arc::clone(&self.ctx.policy);
        let reply = blocking(move || {
            Ok(match policy.reload(Timestamp::now()) {
                Ok(info) => ReloadPolicyResponse {
                    outcome: ReloadOutcome::Applied.into(),
                    policy_sha256: info.sha256,
                    error: String::new(),
                },
                Err(e) => ReloadPolicyResponse {
                    outcome: ReloadOutcome::Rejected.into(),
                    policy_sha256: policy.info().sha256,
                    error: e,
                },
            })
        })
        .await?;
        Ok(Response::new(reply))
    }
}
