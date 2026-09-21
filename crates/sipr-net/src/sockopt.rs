//! SIPp's `sipp_customize_socket` (`socket.cpp`): the socket options sipr
//! sets on every SIP socket it opens — `-buff_size` and `-bind_to_device`.
//!
//! std exposes neither `SO_SNDBUF`/`SO_RCVBUF` nor `SO_BINDTODEVICE`, and
//! `unsafe` is forbidden in this workspace, so `socket2` borrows the already
//! open socket and sets them (docs/CONVENTIONS.md §Dependencies).

use socket2::SockRef;

/// A std socket `socket2` can borrow — `AsFd` on Unix, `AsSocket` on
/// Windows, which is socket2's own bound for [`SockRef::from`].
#[cfg(unix)]
pub trait SocketHandle: std::os::fd::AsFd {}
#[cfg(unix)]
impl<T: std::os::fd::AsFd> SocketHandle for T {}
#[cfg(windows)]
pub trait SocketHandle: std::os::windows::io::AsSocket {}
#[cfg(windows)]
impl<T: std::os::windows::io::AsSocket> SocketHandle for T {}

/// Options applied to each SIP socket after it is opened.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SocketOpts {
    /// `-buff_size`: `SO_SNDBUF` and `SO_RCVBUF`, in bytes. `None` keeps the
    /// OS default — SIPp instead always applies its own 65536 (§6 M44).
    pub buff_size: Option<usize>,
    /// `-bind_to_device`: interface name for `SO_BINDTODEVICE`. Linux only,
    /// and the CLI rejects it elsewhere before a socket is ever opened.
    pub bind_device: Option<String>,
}

impl SocketOpts {
    /// True when nothing would be set (the default, and the hot path).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.buff_size.is_none() && self.bind_device.is_none()
    }

    /// Apply the options to one freshly opened socket.
    ///
    /// # Errors
    ///
    /// The `setsockopt` failure verbatim — an unknown interface, or
    /// `SO_BINDTODEVICE` without the privileges it needs.
    pub fn apply<S: SocketHandle>(&self, socket: &S) -> std::io::Result<()> {
        if self.is_empty() {
            return Ok(());
        }
        let sock = SockRef::from(socket);
        if let Some(bytes) = self.buff_size {
            sock.set_send_buffer_size(bytes)?;
            sock.set_recv_buffer_size(bytes)?;
        }
        if let Some(device) = &self.bind_device {
            bind_device(&sock, device)?;
        }
        Ok(())
    }
}

#[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
fn bind_device(sock: &SockRef<'_>, device: &str) -> std::io::Result<()> {
    sock.bind_device(Some(device.as_bytes()))
}

/// Everywhere else there is no `SO_BINDTODEVICE`; SIPp compiles the call out
/// and silently does nothing, which is exactly the silent skip this project
/// does not inherit.
#[cfg(not(any(target_os = "android", target_os = "fuchsia", target_os = "linux")))]
fn bind_device(_sock: &SockRef<'_>, device: &str) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        format!("-bind_to_device {device}: SO_BINDTODEVICE is a Linux socket option"),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::UdpSocket;

    #[test]
    fn empty_options_touch_nothing() {
        let opts = SocketOpts::default();
        assert!(opts.is_empty());
        let sock = UdpSocket::bind("127.0.0.1:0").expect("bind");
        opts.apply(&sock).expect("no-op");
    }

    #[test]
    fn buff_size_sets_both_directions() {
        let sock = UdpSocket::bind("127.0.0.1:0").expect("bind");
        let opts = SocketOpts {
            buff_size: Some(65_536),
            bind_device: None,
        };
        assert!(!opts.is_empty());
        opts.apply(&sock).expect("setsockopt");
        let sock_ref = SockRef::from(&sock);
        // Kernels round the request up (Linux doubles it), never down.
        assert!(sock_ref.send_buffer_size().expect("sndbuf") >= 65_536);
        assert!(sock_ref.recv_buffer_size().expect("rcvbuf") >= 65_536);
    }

    #[test]
    #[cfg(not(any(target_os = "android", target_os = "fuchsia", target_os = "linux")))]
    fn bind_to_device_is_refused_where_the_option_does_not_exist() {
        let sock = UdpSocket::bind("127.0.0.1:0").expect("bind");
        let opts = SocketOpts {
            buff_size: None,
            bind_device: Some("eth0".into()),
        };
        let err = opts.apply(&sock).expect_err("no SO_BINDTODEVICE here");
        assert_eq!(err.kind(), std::io::ErrorKind::Unsupported);
    }
}
