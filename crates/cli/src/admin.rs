//! `delegate-guard admin`: operator commands against a running daemon's admin
//! socket. Exit 0 when the answer is positive, 1 when it is negative (degraded,
//! broken chain, rejected reload), 69 when the daemon cannot be reached.

use std::ffi::OsString;
use std::path::Path;

use delegate_guard_admin::connect;
use delegate_guard_admin::pb::admin_service_client::AdminServiceClient;
use delegate_guard_admin::pb::{
    ChainState, GetStatusRequest, HealthRequest, ListSessionsRequest, ReloadOutcome,
    ReloadPolicyRequest, ServingStatus, VerifyReceiptsRequest,
};

use tonic::Status;
use tonic::transport::Channel;

use crate::EXIT_USAGE;
use crate::flags::Flags;

const EXIT_NEGATIVE: u8 = 1;
const EXIT_UNAVAILABLE: u8 = 69;

pub(crate) fn run(args: &[OsString]) -> u8 {
    let Some((command, rest)) = args
        .split_first()
        .and_then(|(c, r)| c.to_str().map(|c| (c.to_owned(), r)))
    else {
        eprintln!(
            "usage: delegate-guard admin (health | status | sessions | verify --session ID | reload) --admin-socket PATH"
        );
        return EXIT_USAGE;
    };
    let flags = match Flags::parse(rest, &["admin-socket", "session"]) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("delegate-guard admin: {e}");
            return EXIT_USAGE;
        }
    };
    let Some(socket) = flags.get("admin-socket").filter(|s| !s.is_empty()) else {
        eprintln!("delegate-guard admin: --admin-socket is required");
        return EXIT_USAGE;
    };
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("delegate-guard admin: runtime: {e}");
            return EXIT_UNAVAILABLE;
        }
    };
    runtime.block_on(dispatch(&command, Path::new(socket), flags.get("session")))
}

type Client = AdminServiceClient<Channel>;

async fn dispatch(command: &str, socket: &Path, session: Option<&str>) -> u8 {
    let mut client = match connect(socket).await {
        Ok(c) => c,
        Err(e) => {
            eprintln!(
                "delegate-guard admin: cannot reach {}: {e}",
                socket.display()
            );
            return EXIT_UNAVAILABLE;
        }
    };
    let result = match command {
        "health" => health(&mut client).await,
        "status" => status(&mut client).await,
        "sessions" => sessions(&mut client).await,
        "verify" => verify(&mut client, session.unwrap_or_default()).await,
        "reload" => reload(&mut client).await,
        other => {
            eprintln!("delegate-guard admin: unknown command {other:?}");
            return EXIT_USAGE;
        }
    };
    result.unwrap_or_else(|status| {
        eprintln!("delegate-guard admin: {command}: {status}");
        EXIT_UNAVAILABLE
    })
}

fn suffix(error: &str) -> String {
    if error.is_empty() {
        String::new()
    } else {
        format!(": {error}")
    }
}

async fn health(client: &mut Client) -> Result<u8, Status> {
    let r = client.health(HealthRequest {}).await?.into_inner();
    println!("status: {}{}", r.status().as_str_name(), suffix(&r.reason));
    Ok(if r.status() == ServingStatus::Serving {
        0
    } else {
        EXIT_NEGATIVE
    })
}

async fn status(client: &mut Client) -> Result<u8, Status> {
    let r = client.get_status(GetStatusRequest {}).await?.into_inner();
    println!("{r:#?}");
    Ok(0)
}

async fn sessions(client: &mut Client) -> Result<u8, Status> {
    for s in client
        .list_sessions(ListSessionsRequest {})
        .await?
        .into_inner()
        .sessions
    {
        println!(
            "{}\tagents={}\tpending={}\troot_remaining={}",
            s.file_stem, s.agents, s.pending, s.root_remaining
        );
    }
    Ok(0)
}

async fn verify(client: &mut Client, session_id: &str) -> Result<u8, Status> {
    let request = VerifyReceiptsRequest {
        session_id: session_id.to_owned(),
    };
    let r = client.verify_receipts(request).await?.into_inner();
    println!(
        "{} {} records, head {}{}",
        r.state().as_str_name(),
        r.valid_records,
        r.head_hash,
        suffix(&r.error)
    );
    Ok(if r.state() == ChainState::Broken {
        EXIT_NEGATIVE
    } else {
        0
    })
}

async fn reload(client: &mut Client) -> Result<u8, Status> {
    let r = client
        .reload_policy(ReloadPolicyRequest {})
        .await?
        .into_inner();
    println!(
        "{} policy {}{}",
        r.outcome().as_str_name(),
        r.policy_sha256,
        suffix(&r.error)
    );
    Ok(if r.outcome() == ReloadOutcome::Applied {
        0
    } else {
        EXIT_NEGATIVE
    })
}
