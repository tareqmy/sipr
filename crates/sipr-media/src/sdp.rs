//! Where does the peer want media? A deliberately small SDP scan.
//!
//! SIPp (`call.cpp` `get_remote_media_addr` / `extract_rtp_remote_addr`)
//! does not parse SDP; it string-searches `c=IN IP4 ` and `m=audio `. This
//! does the same job a little more carefully — a media-level `c=` line
//! overrides the session-level one, and a stream offered with port 0
//! (declined/held) is skipped in favour of a later `m=` of the same kind,
//! as SIPp's rtpstream path does. Anything not parseable yields `None`;
//! the caller decides how loud to be.

use std::net::{IpAddr, SocketAddr};

/// The `(address, port)` the peer offered for the first live `m=<kind>`
/// stream in `body`. `kind` is `"audio"`, `"video"`, or `"image"`.
#[must_use]
pub fn remote_endpoint(body: &[u8], kind: &str) -> Option<SocketAddr> {
    let text = String::from_utf8_lossy(body);
    let mut session_addr: Option<IpAddr> = None;
    // (port, media-level c= seen so far) of the m= line we are inside.
    let mut current: Option<(u16, Option<IpAddr>)> = None;
    for raw in text.split('\n') {
        let line = raw.trim_end_matches('\r').trim();
        if let Some(rest) = line.strip_prefix("c=") {
            let addr = parse_connection(rest);
            match current.as_mut() {
                Some((_, media_addr)) => {
                    if media_addr.is_none() {
                        *media_addr = addr;
                    }
                }
                None => {
                    if session_addr.is_none() {
                        session_addr = addr;
                    }
                }
            }
        } else if let Some(rest) = line.strip_prefix("m=") {
            // Leaving a matching section: resolve it before moving on.
            if let Some(found) = finish(current.take(), session_addr) {
                return Some(found);
            }
            current = parse_media(rest, kind).map(|port| (port, None));
        }
    }
    finish(current, session_addr)
}

/// A matched `m=` section with its best connection address, if complete.
fn finish(current: Option<(u16, Option<IpAddr>)>, session: Option<IpAddr>) -> Option<SocketAddr> {
    let (port, media_addr) = current?;
    let ip = media_addr.or(session)?;
    Some(SocketAddr::new(ip, port))
}

/// `IN IP4 1.2.3.4[/ttl]` → the address; unspecified addresses (`0.0.0.0`,
/// `::`) mean "no media" and yield `None`.
fn parse_connection(rest: &str) -> Option<IpAddr> {
    let mut parts = rest.split_whitespace();
    if parts.next()? != "IN" {
        return None;
    }
    let family = parts.next()?;
    if family != "IP4" && family != "IP6" {
        return None;
    }
    let host = parts.next()?.split('/').next()?;
    let ip: IpAddr = host.parse().ok()?;
    (!ip.is_unspecified()).then_some(ip)
}

/// `<media> <port>[/count] <proto> ...` → the port when `<media>` is `kind`
/// and the stream is live (port ≠ 0).
fn parse_media(rest: &str, kind: &str) -> Option<u16> {
    let mut parts = rest.split_whitespace();
    if parts.next()? != kind {
        return None;
    }
    let port: u16 = parts.next()?.split('/').next()?.parse().ok()?;
    (port != 0).then_some(port)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    const ANSWER: &str = "v=0\r\n\
        o=- 1 1 IN IP4 10.0.0.9\r\n\
        s=-\r\n\
        c=IN IP4 10.0.0.9\r\n\
        t=0 0\r\n\
        m=audio 30000 RTP/AVP 0 8\r\n\
        a=rtpmap:0 PCMU/8000\r\n\
        m=video 30002 RTP/AVP 96\r\n\
        c=IN IP4 10.0.0.10\r\n";

    #[test]
    fn session_level_connection_applies_to_audio() {
        assert_eq!(
            remote_endpoint(ANSWER.as_bytes(), "audio"),
            Some("10.0.0.9:30000".parse().unwrap())
        );
    }

    #[test]
    fn media_level_connection_overrides_for_video() {
        assert_eq!(
            remote_endpoint(ANSWER.as_bytes(), "video"),
            Some("10.0.0.10:30002".parse().unwrap())
        );
    }

    #[test]
    fn missing_kind_or_connection_is_none() {
        assert_eq!(remote_endpoint(ANSWER.as_bytes(), "image"), None);
        assert_eq!(
            remote_endpoint(b"m=audio 4000 RTP/AVP 0\r\n", "audio"),
            None
        );
        assert_eq!(remote_endpoint(b"", "audio"), None);
        assert_eq!(remote_endpoint(b"garbage\r\nmore", "audio"), None);
    }

    #[test]
    fn port_zero_streams_are_skipped_for_a_later_offer() {
        let sdp = "c=IN IP4 1.2.3.4\r\nm=audio 0 RTP/AVP 0\r\nm=audio 5004 RTP/AVP 8\r\n";
        assert_eq!(
            remote_endpoint(sdp.as_bytes(), "audio"),
            Some("1.2.3.4:5004".parse().unwrap())
        );
        let held = "c=IN IP4 1.2.3.4\r\nm=audio 0 RTP/AVP 0\r\n";
        assert_eq!(remote_endpoint(held.as_bytes(), "audio"), None);
    }

    #[test]
    fn ipv6_and_ttl_suffix_and_bare_lf() {
        let sdp = "c=IN IP6 2001:db8::1\nm=audio 6000/2 RTP/AVP 0\n";
        assert_eq!(
            remote_endpoint(sdp.as_bytes(), "audio"),
            Some("[2001:db8::1]:6000".parse().unwrap())
        );
        let ttl = "c=IN IP4 224.0.0.1/127\r\nm=audio 6000 RTP/AVP 0\r\n";
        assert_eq!(
            remote_endpoint(ttl.as_bytes(), "audio"),
            Some("224.0.0.1:6000".parse().unwrap())
        );
    }

    #[test]
    fn unspecified_address_means_no_media() {
        let sdp = "c=IN IP4 0.0.0.0\r\nm=audio 6000 RTP/AVP 0\r\n";
        assert_eq!(remote_endpoint(sdp.as_bytes(), "audio"), None);
    }
}
