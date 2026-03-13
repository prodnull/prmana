//! Agent daemon with Unix socket IPC
//!
//! This module provides:
//! - JSON protocol for agent communication
//! - Unix socket server for the daemon
//! - Client for connecting to the daemon

pub mod peer_cred;
pub mod protocol;
pub mod socket;
pub mod sweep;

pub use protocol::{AgentRequest, AgentResponse, AgentResponseData};
pub use socket::{
    acquire_listener, spawn_refresh_task, AgentClient, AgentServer, AgentState, ClientError,
};
