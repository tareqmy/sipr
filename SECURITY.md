# Security policy

## Reporting a vulnerability

Please report security issues privately through GitHub's private
vulnerability reporting for this repository:

https://github.com/tareqmy/sipr/security/advisories/new

Do not open a public issue for a security problem. You should hear back
within a week; fixes ship as a new release with a changelog entry crediting
the reporter unless they prefer otherwise.

## Supported versions

Only the latest release receives fixes. There are no long-term support
branches.

## What is in scope

sipr is a test tool that deliberately sends malformed and non-compliant SIP
when a scenario asks it to; that is a feature, not a vulnerability. Reports
that matter are about what sipr *accepts* and *exposes*:

- Crashes, hangs, or memory exhaustion triggered by inbound SIP, RTP, or
  SRTP traffic from a peer.
- Problems in scenario, injection-file, or pcap parsing that a hostile file
  could exploit (sipr reads these as trusted input from the operator, but a
  panic or unbounded allocation is still a bug).
- The control surfaces: the SIPp-compatible UDP control socket (`-cp`) and
  the HTTP/JSON API (`--sipr-http`). Both bind loopback by default and carry
  no authentication; exposing them on other interfaces is an explicit
  operator choice (`-ci`, `--sipr-http HOST:PORT`) and is documented in
  `docs/CONTROL_API.md`. A way to reach them without that choice is in scope.
- `exec command=` runs a shell with the rendered scenario text; the scenario
  author controls it by design. Keyword or variable rendering that lets a
  *peer's* message inject into that command is in scope.

The workspace forbids `unsafe` and has no C dependencies; TLS and SRTP are
pure Rust (`rustls`, in-tree AES-CM and HMAC-SHA1).
