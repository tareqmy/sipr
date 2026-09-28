//! `-rtpcheck_debug`: a trace of the RTP echo check, packet by packet.
//!
//! SIPp writes two fixed-name files in the working directory, `debugafile`
//! for audio streams and `debugvfile` for video, and fills them with one
//! line per send, per datagram read back, and per comparison verdict, plus
//! the per-task tallies when the playback thread exits. sipr keeps the
//! file names, so scripts that collect them keep working, and writes the
//! same events in its own line format, one stream at a time:
//!
//! ```text
//! call 1-2@h rtp-audio: STREAM 127.0.0.1:6000 -> 127.0.0.1:7000
//! call 1-2@h rtp-audio: SEND LOG 1 172 [80080000...]
//! call 1-2@h rtp-audio: RECV LOG 172 [80080000...]
//! call 1-2@h rtp-audio: COMPARISON OK 0/1
//! call 1-2@h rtp-audio: NODATA 1/2
//! call 1-2@h rtp-audio: COMPARISON FAILED 2/3
//! call 1-2@h rtp-audio: RTPCHECKS 2 PACKET COUNTS 3 BYTES IN 172
//! ```
//!
//! `SEND LOG n len [hex]` is the n-th packet of the stream as sent, header
//! included; `RECV LOG` is every datagram drained before the comparison,
//! and the verdict line that follows carries the running `failed/sent`
//! tally. The final line is the stream's tally as the engine judges it
//! against `-audiotolerance`/`-videotolerance`.
//!
//! The files are created (truncated) when the media thread starts, so a
//! run that never streams leaves them empty; SIPp creates each on the
//! first stream of its kind. Write errors are ignored: this is a debug
//! aid, and losing a line must not disturb the stream it describes.

use std::fmt::Write as _;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;

/// SIPp's audio debug file name.
pub const AUDIO_FILE: &str = "debugafile";
/// SIPp's video debug file name.
pub const VIDEO_FILE: &str = "debugvfile";

/// The two open debug files. Owned by the media thread.
#[derive(Debug)]
pub struct CheckDebug {
    audio: BufWriter<File>,
    video: BufWriter<File>,
    /// Scratch for the hex dumps, reused so a 50 pps stream does not
    /// allocate per packet.
    line: String,
}

impl CheckDebug {
    /// Create (or truncate) `debugafile` and `debugvfile` in `dir`.
    ///
    /// # Errors
    ///
    /// The I/O error when either file cannot be created.
    pub fn open(dir: &Path) -> std::io::Result<Self> {
        Ok(Self {
            audio: BufWriter::new(File::create(dir.join(AUDIO_FILE))?),
            video: BufWriter::new(File::create(dir.join(VIDEO_FILE))?),
            line: String::new(),
        })
    }

    /// Write one event line for `stream`; `payload` is appended as a hex
    /// dump in brackets when given.
    pub(crate) fn event(&mut self, stream: &StreamId<'_>, what: &str, payload: Option<&[u8]>) {
        self.line.clear();
        let _ = write!(self.line, "call {} {}: {what}", stream.call_id, stream.tag);
        if let Some(bytes) = payload {
            self.line.push_str(" [");
            for b in bytes {
                let _ = write!(self.line, "{b:02X}");
            }
            self.line.push(']');
        }
        self.line.push('\n');
        let file = if stream.video {
            &mut self.video
        } else {
            &mut self.audio
        };
        let _ = file.write_all(self.line.as_bytes());
    }

    /// Push buffered lines to disk (the end of a stream, and shutdown).
    pub(crate) fn flush(&mut self) {
        let _ = self.audio.flush();
        let _ = self.video.flush();
    }
}

/// Which stream a debug line belongs to.
pub(crate) struct StreamId<'a> {
    pub call_id: &'a str,
    pub tag: &'a str,
    pub video: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lines_carry_the_stream_and_a_hex_dump() {
        let dir = std::env::temp_dir().join(format!("sipr-check-debug-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut d = CheckDebug::open(&dir).unwrap();
        let audio = StreamId {
            call_id: "1-2@h",
            tag: "rtp-audio",
            video: false,
        };
        let video = StreamId {
            call_id: "1-2@h",
            tag: "rtp-video",
            video: true,
        };
        d.event(&audio, "SEND LOG 1 3", Some(&[0x80, 0x08, 0xFF]));
        d.event(&audio, "NODATA 1/1", None);
        d.event(&video, "RTPCHECKS 0 PACKET COUNTS 0 BYTES IN 0", None);
        d.flush();
        let a = std::fs::read_to_string(dir.join(AUDIO_FILE)).unwrap();
        let v = std::fs::read_to_string(dir.join(VIDEO_FILE)).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(
            a,
            "call 1-2@h rtp-audio: SEND LOG 1 3 [8008FF]\ncall 1-2@h rtp-audio: NODATA 1/1\n"
        );
        assert_eq!(
            v,
            "call 1-2@h rtp-video: RTPCHECKS 0 PACKET COUNTS 0 BYTES IN 0\n"
        );
    }
}
