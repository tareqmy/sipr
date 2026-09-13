//! The engine↔UI bridge, tested without any terminal: snapshots flow out
//! about once a second, keys flow in and take effect ('p' pause, rate keys,
//! 'Q' hard quit).

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::sync::mpsc::channel;
use std::time::Duration;

use sipr_engine::{EngineConfig, UiChannels, run_with_ui};

fn uas_config() -> EngineConfig {
    EngineConfig {
        target: None,
        local_ip: Some(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
        port: None,
        service: "service".into(),
        rate: 10.0,
        rate_period: Duration::from_millis(1000),
        limit: None,
        max_calls: None,
        pause_default: Duration::from_millis(100),
        max_retrans: None,
        no_retrans: false,
        timeout: Some(Duration::from_secs(10)),
        base_cseq: 1,
        call_id_format: None,
        seed: 7,
        periodic_stats: false,
        auto_answer: false,
        auth_user: None,
        auth_password: None,
        auth_uri: None,
        trace_msg: None,
        trace_err: None,
        trace_stat: None,
        stat_interval: Duration::from_secs(1),
        inf_files: Vec::new(),
        rx_inf_files: Vec::new(),
        inf_index: Vec::new(),
        transport: sipr_engine::TransportKind::UdpMono,
        max_socket: 50_000,
        remote_sending_addr: None,
        ip_field: 0,
        max_reconnect: 0,
        reconnect_close: true,
        reconnect_sleep: std::time::Duration::from_millis(1000),
        twin_addr: None,
        users: None,
        tls: None,
        media_ip: None,
        media_port: None,
        max_rtp_port: None,
        rtp_payload: None,
        random_base_ssrc: false,
        scenario_dir: None,
        rate_increase: None,
        rate_max: None,
        rate_interval: None,
        rate_quit: true,
        rate_scale: None,
        rtp_echo: false,
        media_bufsize: None,
        audio_tolerance: None,
        video_tolerance: None,
        control_port: Some(0),
        control_ip: None,
        http_addr: None,
        http_token: None,
        trace_name_base: None,
    }
}

#[test]
fn snapshots_flow_and_keys_take_effect() {
    let scenario = sipr_scenario::compile("uas", sipr_scenario::embedded("uas").unwrap())
        .scenario
        .expect("uas compiles");
    let (snap_tx, snap_rx) = channel();
    let (key_tx, key_rx) = channel();
    let engine = std::thread::spawn(move || {
        run_with_ui(
            &scenario,
            &uas_config(),
            Some(UiChannels {
                snapshots: snap_tx,
                keys: key_rx,
            }),
        )
        .map(|(report, _)| report)
    });
    // First snapshot arrives within a couple of seconds.
    let first = snap_rx
        .recv_timeout(Duration::from_secs(3))
        .expect("first snapshot");
    assert!(first.uas);
    assert_eq!(first.scenario, "Basic UAS responder");
    assert!((first.rate_target - 10.0).abs() < f64::EPSILON);
    assert_eq!(first.steps.len(), 7, "uas step rows: {:?}", first.steps);
    assert!(
        first.steps[0].label.starts_with("recv INVITE"),
        "{:?}",
        first.steps[0].label
    );
    // Rate and pause keys are reflected in later snapshots.
    key_tx.send('*').expect("send *");
    key_tx.send('p').expect("send p");
    let mut saw = false;
    for _ in 0..4 {
        let snap = snap_rx
            .recv_timeout(Duration::from_secs(3))
            .expect("snapshot");
        if snap.paused && (snap.rate_target - 20.0).abs() < f64::EPSILON {
            saw = true;
            break;
        }
    }
    assert!(saw, "expected paused=true and rate 20 to show up");
    // 'Q' aborts promptly.
    key_tx.send('Q').expect("send Q");
    let report = engine.join().expect("engine thread").expect("engine ran");
    assert_eq!(report.created, 0);
    assert_eq!(report.exit_code(), 99, "no calls processed");
}
