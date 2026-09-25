//! Criterion benches for the per-message hot path (docs/TESTING.md §5).
//!
//! These measure the three things `docs/ARCHITECTURE.md` §3 makes rules
//! about — template fill, inbound parse plus the routing fields the engine
//! reads off every message, and timer churn — in isolation, where
//! `make bench-vs-sipp` measures the whole process against real sipp.
//!
//! Regression rule (TESTING.md §5): a >10% drop blocks merge. Record new
//! numbers in `benches/BASELINES.md` when they move materially.

// Bench code may unwrap/expect freely, as test code does (docs/CONVENTIONS.md
// §Errors); clippy's `*-in-tests` exemptions do not cover bench targets.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::time::{Duration, Instant};

use criterion::{Criterion, criterion_group, criterion_main};
use sipr_engine::{FieldSource, RenderCtx, RunInfo, render};
use sipr_net::timer::TimerQueue;
use sipr_net::{Inbound, MsgKind};
use sipr_scenario::model::Step;
use sipr_scenario::template::MsgTemplate;

/// The rendering context an in-dialog send uses, minus the optional parts a
/// plain INVITE never touches.
fn ctx(last: Option<&Inbound>) -> RenderCtx<'_> {
    RenderCtx {
        service: "service",
        remote_ip: "10.0.0.2",
        remote_port: 5060,
        local_ip: "10.0.0.1",
        server_ip: "10.0.0.1",
        local_port: 5061,
        media_ip: "10.0.0.1",
        media_port: 6000,
        rtpstream_ports: [0, 0],
        crypto: None,
        transport: "UDP",
        call_id: "1-99@10.0.0.1",
        call_number: 1,
        user_id: 0,
        users_total: 0,
        pid: 99,
        cseq: 1,
        msg_index: Some(0),
        call_msg_index: 0,
        peer_tag: None,
        routes: &[],
        last,
        var_ctx: None,
        fields: FieldSource::EMPTY,
        run: RunInfo::EMPTY,
    }
}

/// Step `index` of the embedded `uac` scenario, as a send template.
fn embedded_uac_step(index: usize) -> MsgTemplate {
    let xml = sipr_scenario::embedded("uac").expect("embedded uac");
    let scenario = sipr_scenario::compile("uac", xml)
        .scenario
        .expect("uac compiles");
    match &scenario.steps[index] {
        Step::Send(s) => s.template.clone(),
        other => panic!("step {index} is not a send: {other:?}"),
    }
}

/// A 200 OK as a UAS would answer the embedded INVITE: the message the
/// engine parses and routes on the hot path.
const RESPONSE_200: &[u8] = b"SIP/2.0 200 OK\r\n\
Via: SIP/2.0/UDP 10.0.0.1:5061;branch=z9hG4bK-99-1-4\r\n\
From: sipp <sip:sipp@10.0.0.1:5061>;tag=99SIPpTag001\r\n\
To: service <sip:service@10.0.0.2:5060>;tag=99SIPpTag011\r\n\
Call-ID: 1-99@10.0.0.1\r\n\
CSeq: 1 INVITE\r\n\
Contact: <sip:10.0.0.2:5060;transport=UDP>\r\n\
Content-Type: application/sdp\r\n\
Content-Length: 129\r\n\
\r\n\
v=0\r\n\
o=user1 53655765 2353687637 IN IP4 10.0.0.2\r\n\
s=-\r\n\
c=IN IP4 10.0.0.2\r\n\
t=0 0\r\n\
m=audio 6000 RTP/AVP 0\r\n\
a=rtpmap:0 PCMU/8000\r\n";

fn bench_template_fill(c: &mut Criterion) {
    let mut group = c.benchmark_group("template_fill");
    // The INVITE is the biggest template in the scenario (SDP body, [len]);
    // the ACK is the smallest in-dialog one.
    let invite = embedded_uac_step(0);
    group.bench_function("invite", |b| {
        b.iter(|| render(std::hint::black_box(&invite), &ctx(None)).expect("renders"));
    });
    let last = Inbound::parse(RESPONSE_200).expect("parses");
    let ack = embedded_uac_step(5);
    group.bench_function("ack_with_last_headers", |b| {
        b.iter(|| render(std::hint::black_box(&ack), &ctx(Some(&last))).expect("renders"));
    });
    group.finish();
}

fn bench_inbound_parse(c: &mut Criterion) {
    let mut group = c.benchmark_group("inbound_parse");
    group.bench_function("response_200", |b| {
        b.iter(|| Inbound::parse(std::hint::black_box(RESPONSE_200)).expect("parses"));
    });
    // Parse plus the fields the engine reads to route a message to its call,
    // which is what the receive path actually costs.
    group.bench_function("parse_and_route", |b| {
        b.iter(|| {
            let msg = Inbound::parse(std::hint::black_box(RESPONSE_200)).expect("parses");
            let routed = (
                msg.call_id(),
                msg.cseq(),
                msg.top_via_branch(),
                matches!(msg.kind(), MsgKind::Response { .. }),
            );
            std::hint::black_box(routed);
        });
    });
    group.finish();
}

fn bench_timer_churn(c: &mut Criterion) {
    let mut group = c.benchmark_group("timer_churn");
    // The retransmission pattern: arm a timer per send, cancel it when the
    // answer arrives before it fires. Nothing should ever reach `pop_due`.
    group.bench_function("arm_then_cancel", |b| {
        let mut queue: TimerQueue<u64> = TimerQueue::new();
        let deadline = Instant::now() + Duration::from_millis(500);
        b.iter(|| {
            let id = queue.arm(deadline, 1);
            queue.cancel(std::hint::black_box(id));
        });
    });
    // The other half: a thousand timers armed across a spread of deadlines,
    // then drained in order, as a burst of calls times out together.
    group.bench_function("arm_1000_then_drain", |b| {
        let base = Instant::now();
        b.iter(|| {
            let mut queue: TimerQueue<u64> = TimerQueue::new();
            for i in 0..1000u64 {
                queue.arm(base + Duration::from_micros(i), i);
            }
            let fired = queue.pop_due(base + Duration::from_secs(1));
            std::hint::black_box(fired.len());
        });
    });
    group.finish();
}

criterion_group!(
    hot_path,
    bench_template_fill,
    bench_inbound_parse,
    bench_timer_churn
);
criterion_main!(hot_path);
