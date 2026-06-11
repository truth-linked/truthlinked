//! Truthlinked Net Src Tcp Config
//!
//! Owns TCP socket configuration for validator networking.
//! Transport changes must avoid blocking consensus progress and preserve authenticated peer identity.

use socket2::{Socket, TcpKeepalive};
use std::os::unix::io::AsRawFd;
use std::time::Duration;
use tokio::net::TcpStream;

/// Apply TCP_NODELAY + TCP keepalive to a tokio TcpStream.
/// Keepalive: start probing after 10s idle, probe every 5s, drop after 3 failed probes.
pub fn configure(stream: &TcpStream) {
    use std::os::unix::io::FromRawFd;
    let fd = stream.as_raw_fd();
    // SAFETY: we dup the fd so socket2 can configure it without taking ownership
    let fd_dup = unsafe { libc::dup(fd) };
    if fd_dup < 0 {
        return;
    }
    let sock = unsafe { Socket::from_raw_fd(fd_dup) };

    let _ = sock.set_nodelay(true);
    let keepalive = TcpKeepalive::new()
        .with_time(Duration::from_secs(10))
        .with_interval(Duration::from_secs(5))
        .with_retries(3);
    let _ = sock.set_tcp_keepalive(&keepalive);
    // sock drops here, closing the dup'd fd - original fd unaffected
}
