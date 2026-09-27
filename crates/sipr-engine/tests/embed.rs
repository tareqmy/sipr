//! `sipr-engine` as a library (M49 D2, docs/LIBRARY_API.md): a harness
//! starts a run on its own thread, drives it through the handle, reads
//! its statistics, and gets a report — with no CLI, TUI or terminal.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::time::{Duration, Instant};

use sipr_engine::{EngineConfig, EngineError, NoticeSink, Run, run};
use sipr_scenario::model::Scenario;

fn embedded(name: &str) -> Scenario {
    sipr_scenario::compile(name, sipr_scenario::embedded(name).unwrap())
        .scenario
        .expect("embedded scenario compiles")
}

/// A quiet UAS on a free loopback port, with short pauses.
fn uas_config() -> EngineConfig {
    let mut config = EngineConfig::uas();
    config.local_ip = Some("127.0.0.1".parse().unwrap());
    config.port = Some(0);
    config.pause_default = Duration::from_millis(100);
    config.control_port = Some(0);
    config.notices = NoticeSink::Discard;
    config
}

#[test]
fn the_handle_drives_the_run_and_wait_reports_it() {
    let mut server = Run::start(embedded("uas"), uas_config()).expect("uas starts");
    let bound = server.local_addr();
    assert_eq!(bound.ip(), "127.0.0.1".parse::<std::net::IpAddr>().unwrap());
    assert_ne!(bound.port(), 0, "port 0 resolves to the bound port");

    let snapshots = server.snapshots();
    let first = snapshots
        .recv_timeout(Duration::from_secs(3))
        .expect("a snapshot within the first seconds");
    assert!(first.uas);
    assert!((first.rate_target - 10.0).abs() < f64::EPSILON);

    let control = server.control().clone();
    control.set_rate(20.0);
    control.pause();
    let paused = snapshots
        .iter()
        .take(4)
        .find(|s| s.paused && (s.rate_target - 20.0).abs() < f64::EPSILON);
    assert!(
        paused.is_some(),
        "pause and the new rate reach the snapshots"
    );
    control.resume();
    assert!(
        snapshots.iter().take(4).any(|s| !s.paused),
        "resume reaches the snapshots"
    );

    control.stop();
    let report = server.wait().expect("the run reports");
    assert_eq!(report.created, 0);
    assert_eq!(
        report.exit_code(),
        99,
        "no calls processed: {}",
        report.summary()
    );
    // The handle outlives the run harmlessly.
    control.abort();
}

#[test]
fn dropping_a_run_aborts_it_and_frees_its_port() {
    let server = Run::start(embedded("uas"), uas_config()).expect("uas starts");
    let port = server.local_addr().port();
    let started = Instant::now();
    drop(server);
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "drop joins promptly"
    );
    // The socket went with the thread: the port can be bound again.
    let mut again = uas_config();
    again.port = Some(port);
    let server = Run::start(embedded("uas"), again).expect("the port is free again");
    assert_eq!(server.local_addr().port(), port);
}

#[test]
fn start_reports_a_bad_configuration_before_spawning_anything() {
    let mut config = uas_config();
    config.tls = None;
    config.transport = sipr_engine::TransportKind::TlsMono;
    match Run::start(embedded("uas"), config) {
        Err(EngineError::Config(message)) => {
            assert_eq!(message, "TLS transport needs TLS configuration");
        }
        other => panic!("expected a Config error, got {:?}", other.map(|_| ())),
    }
    let err = Run::start(embedded("uac"), uas_config())
        .err()
        .expect("a UAC needs a target");
    assert!(matches!(err, EngineError::Config(_)), "{err}");
}

#[test]
fn a_uac_run_completes_calls_against_an_in_process_uas() {
    let server = Run::start(embedded("uas"), uas_config()).expect("uas starts");

    let mut client = EngineConfig::uac(server.local_addr());
    client.local_ip = Some("127.0.0.1".parse().unwrap());
    client.port = Some(0);
    client.pause_default = Duration::from_millis(100);
    client.rate = 50.0;
    client.max_calls = Some(3);
    client.timeout = Some(Duration::from_secs(20));
    client.control_port = Some(0);
    client.notices = NoticeSink::Discard;
    let report = run(&embedded("uac"), &client).expect("uac runs");
    assert_eq!(report.exit_code(), 0, "{}", report.summary());
    assert_eq!(report.successful, 3);
    assert_eq!(report.failed, 0);

    server.control().stop();
    let report = server.wait().expect("uas reports");
    assert_eq!(report.successful, 3, "{}", report.summary());
    assert_eq!(report.exit_code(), 0, "{}", report.summary());
}
