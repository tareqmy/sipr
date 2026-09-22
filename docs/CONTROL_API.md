# Runtime control: the control socket and the HTTP API

sipr can be steered while it runs, two ways. Both drive the same commands
inside the engine's event loop; neither touches call state from outside it.

## 1. The control socket (`-cp`, `-ci`) — SIPp's protocol

SIPp's remote control is a UDP port that takes one command per datagram
(`socket.cpp` `handle_ctrl_socket`). sipr implements it as is, so
existing scripts keep working:

```bash
echo -n 'p' | nc -u -w0 127.0.0.1 8888          # hot key: pause/resume
echo -n 'cset rate 50' | nc -u -w0 127.0.0.1 8888  # command: rate to 50 cps
```

- **Byte 0 decides.** Anything but `c` is a hot key and the rest of the
  datagram is ignored: `+ - * /` step the rate (or the user count in
  `-users` mode) by `rate-scale`, `p` toggles pause, `q` drains and a
  second `q` aborts, `Q` aborts, `1`/`2`/`3` switch the TUI to the
  scenario / statistics / repartition screen (`4`..`9` are ignored).
- **`c` + a command line**, split on the first space (tabs do not
  separate), exactly SIPp's grammar and warning texts:

  | Command | Effect |
  |---|---|
  | `set rate N` | call rate (rate mode only) |
  | `set rate-scale N` | step multiplier for the rate keys (default 1) |
  | `set users N` | user count (`-users` mode only) |
  | `set limit N` | concurrent-call cap (rate mode only) |
  | `set display main\|ooc\|rx` | every screen (counters, statistics, repartitions, scenario page) shows the main / out-of-call / receive scenario (`ooc` needs `-oocsf`/`-oocsn`, `rx` needs `-rxsf`/`-rxsn`; SIPp's `display_scenario`) |
  | `set hide true\|false` | skip `hide="true"` steps on the scenario screen (default true) |
  | `trace messages\|error on\|off` | open/close the trace file at runtime (SIPp's file naming) |
  | `trace logs\|shortmessages on\|off` | not supported (warning) |
  | `dump tasks` | one line per active call into the error trace |
  | `reset stats` | zero the cumulative counters and histograms |

- **Fire-and-forget**, like SIPp: there is never a reply. Malformed or
  refused commands print SIPp's warning on stderr and into the error
  trace.
- **Binding:** `-cp PORT` is tried once and failure is fatal; without it,
  ports 8888..8947 are probed and running without a socket is only a
  warning (SIPp's rules). `-cp 0` disables the socket (sipr addition).
  The chosen address is printed at startup — SIPp never says which port it
  got.
- **Deliberate divergence:** the default bind address is `127.0.0.1`, not
  every interface. The socket can stop the run with no authentication;
  `-ci 0.0.0.0` opts into SIPp's behavior.

## 2. The HTTP API (`--sipr-http`) — sipr's addition

```bash
sipr -sn uac -r 10 -m 100000 --sipr-http 8080 127.0.0.1:5060
curl -s localhost:8080/stats | jq .created
curl -s -XPOST localhost:8080/control -d '{"rate": 25, "paused": false}'
curl -s -XPOST localhost:8080/quit -d '{"force": false}'
```

`--sipr-http PORT` binds loopback; `--sipr-http HOST:PORT` binds
elsewhere and then **requires `--sipr-http-token TOKEN`**, presented as
`Authorization: Bearer TOKEN` or `?token=TOKEN`. HTTP/1.1, one request per
connection, JSON in and out. Every error is `{"error":"..."}` with a
4xx/5xx status; control errors carry SIPp's own warning text.

| Method | Path | Body | Response |
|---|---|---|---|
| GET | `/health` | — | `{"status":"ok","version":"0.5.0"}` (never needs the token) |
| GET | `/stats` | — | the statistics snapshot (below), refreshed about once a second |
| GET | `/control` | — | the control state (below) |
| POST | `/control` | any of `rate`, `rate_scale`, `paused`, `users`, `limit` | the control state after applying them, in that order; `400` with SIPp's warning on the first refusal |
| POST | `/quit` | `{"force":false}` (default) drains, `true` aborts | `202` + control state |
| POST | `/command` | `{"command":"set rate 10"}` — any control-socket command line | the control state, or `400` + warning |
| GET | `/scenario` | — | `{"name","role","steps":[...]}` (the `--check` dump) |
| GET | `/metrics` | — | the same snapshot in Prometheus text format (below) |

Control state:

```json
{"rate":10,"rate_scale":1,"paused":false,"users":null,"limit":null,"quitting":"no"}
```

`quitting` is `no`, `soft` (draining), or `hard`.

Statistics snapshot — SIPp's counter names, durations in `_ms`:

```json
{"scenario":"uac","role":"UAC","elapsed_ms":12034,"live":3,
 "rate_target":10,"rate_period_cps":9.8,"rate_cumulative_cps":9.9,"paused":false,"hide":true,
 "display":"main","mixed":false,
 "created":120,"successful":117,"failed":0,
 "failed_unexpected":0,"failed_timeout":0,"failed_retrans":0,"failed_other":0,
 "messages_sent":360,"messages_matched":351,"retrans_sent":0,"retrans_recv":0,
 "auto_answered":0,"unexpected":0,"garbage":0,
 "rtp_streams_started":0,"rtp_packets_sent":0,"rtp_bytes_sent":0,"rtp_bytes_received":0,
 "rtp_echo_packets":0,"rtp_echo2_packets":0,"rtp_check_ok":0,"rtp_check_failed":0,
 "rtd":[{"name":"1","count":117,"mean_ms":12.5,"stddev_ms":3.1,"p99_ms":22,"max_ms":40}],
 "call_length":{"count":117,"mean_ms":3010.2,"max_ms":3050},
 "response_time_repartition":[{"label":"<10","count":40}],
 "call_length_repartition":[],
 "steps":[{"label":"send INVITE","hidden":false,"sent":120,"recv":0,"retrans":0,"timeouts":0,"unexpected":0}]}
```

The snapshot is the same object the TUI renders and the `-bg` stat line
summarizes, so the three never disagree.

## 3. Machine-readable statistics (M46)

Two ways out, both carrying the same snapshot as `/stats`.

**Scraping — `GET /metrics`.** Prometheus text exposition format, served
with `Content-Type: text/plain; version=0.0.4`, so a scrape config needs
nothing but the address:

```yaml
scrape_configs:
  - job_name: sipr
    static_configs: [{ targets: ['localhost:8080'] }]
```

Names are prefixed `sipr_`, cumulative counters end in `_total`, durations
are in **seconds** (the snapshot's milliseconds converted, since that is the
base unit Prometheus expects), and what would be several near-identical
names is one metric with a label:

```
sipr_run_info{scenario="uac",role="UAC",display="main"} 1
sipr_calls_created_total 20000
sipr_calls_failed_total{reason="recv_timeout"} 3
sipr_messages_total{kind="retrans_sent"} 12
sipr_calls_active 41
sipr_rtd_seconds{rtd="1",stat="p99"} 0.020000
sipr_step_messages_total{step="0",label="send INVITE",kind="sent"} 20000
```

`/metrics` needs the token like every path but `/health`. Prometheus sends
it with `authorization: { credentials: TOKEN }` in the scrape config.

**Streaming to a file — `--sipr-stats-json FILE`.** One JSON object per
snapshot tick, appended and flushed each second, so it can be tailed while
the run is live and replayed afterwards:

```bash
sipr -sn uac -r 10 -m 1000 --sipr-stats-json snaps.jsonl 127.0.0.1:5060
tail -f snaps.jsonl | jq -c '{t: .elapsed_ms, live, created, failed}'
```

Each line is exactly the object `/stats` returns, so anything that reads one
reads the other. The file is truncated at start-up; an unwritable path is a
start-up error, not a silent skip. This needs no HTTP listener — it is the
option for a CI job that wants the numbers afterwards rather than a dashboard
during.

### What the API does not do (yet)

No streaming/WebSocket over HTTP (poll `/stats`, or use
`--sipr-stats-json`), no scenario replacement, no per-call detail. The API is
a control plane for one run; orchestration of many runs belongs in whatever
launches them.
