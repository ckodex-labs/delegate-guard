//! Client side: a gRPC channel over the admin Unix socket.

use std::io;
use std::path::Path;

use hyper_util::rt::TokioIo;
use tonic::transport::{Channel, Endpoint, Uri};

use crate::pb::admin_service_client::AdminServiceClient;

/// Connects to the admin API at `socket`. The URI is required by the HTTP/2
/// layer but never resolved: every connection goes to `socket`.
///
/// # Errors
///
/// The socket is missing, refuses the connection, or closes it (a disallowed uid).
pub async fn connect(
    socket: &Path,
) -> Result<AdminServiceClient<Channel>, tonic::transport::Error> {
    let path = socket.to_owned();
    let channel =
        Endpoint::from_static("http://delegate-guard.invalid")
            .connect_with_connector(tower::service_fn(move |_: Uri| {
                let path = path.clone();
                async move {
                    Ok::<_, io::Error>(TokioIo::new(tokio::net::UnixStream::connect(path).await?))
                }
            }))
            .await?;
    Ok(AdminServiceClient::new(channel))
}
