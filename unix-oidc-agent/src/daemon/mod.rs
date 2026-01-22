//! Agent daemon with Unix socket IPC
//!
//! This module provides:
//! - JSON protocol for agent communication
//! - Unix socket server for the daemon
//! - Client for connecting to the daemon

pub mod protocol;
pub mod socket;

pub use protocol::{AgentRequest, AgentResponse, AgentResponseData};
pub use socket::{AgentClient, AgentServer, AgentState, ClientError};
