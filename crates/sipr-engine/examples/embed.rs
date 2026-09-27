//! `sipr-engine` embedded in a program: an in-process UAS answers the calls
//! an in-process UAC places, both from SIPp's embedded scenarios, with the
//! engine's notices read as values and the reports checked at the end.
//!
//! ```sh
//! cargo run -p sipr-engine --example embed
//! ```

use std::error::Error;
use std::sync::mpsc::channel;
use std::time::Duration;

use sipr_engine::{EngineConfig, Notice, NoticeSink, Run, run};
use sipr_scenario::model::Scenario;
use sipr_scenario::{CompileOptions, compile_strict};

/// One of SIPp's embedded scenarios, compiled under the `--check` policy.
fn embedded(name: &str) -> Result<Scenario, Box<dyn Error>> {
    let xml = sipr_scenario::embedded(name).ok_or("no such embedded scenario")?;
    compile_strict(name, xml, &CompileOptions::default()).map_err(|diagnostics| {
        let lines: Vec<String> = diagnostics.iter().map(ToString::to_string).collect();
        lines.join("\n").into()
    })
}

fn main() -> Result<(), Box<dyn Error>> {
    // Every line the engine would print goes down this channel instead.
    let (notices, notice_rx) = channel::<Notice>();

    // A UAS on a free loopback port: `-d` short, no control socket.
    let mut server_cfg = EngineConfig::uas();
    server_cfg.local_ip = Some("127.0.0.1".parse()?);
    server_cfg.port = Some(0);
    server_cfg.pause_default = Duration::from_millis(100);
    server_cfg.control_port = Some(0);
    server_cfg.notices = NoticeSink::Channel(notices.clone());
    let server = Run::start(embedded("uas")?, server_cfg)?;
    println!("UAS listening on {}", server.local_addr());

    // A UAC placing 5 calls at it, 20 a second, and waiting for them.
    let mut client_cfg = EngineConfig::uac(server.local_addr());
    client_cfg.local_ip = Some("127.0.0.1".parse()?);
    client_cfg.port = Some(0);
    client_cfg.pause_default = Duration::from_millis(100);
    client_cfg.rate = 20.0;
    client_cfg.max_calls = Some(5);
    client_cfg.timeout = Some(Duration::from_secs(30));
    client_cfg.control_port = Some(0);
    client_cfg.notices = NoticeSink::Channel(notices);
    let client = run(&embedded("uac")?, &client_cfg)?;
    println!("UAC: {}", client.summary());

    // Let the UAS finish its calls' timewait, then read its report.
    server.control().stop();
    let server = server.wait()?;
    println!("UAS: {}", server.summary());

    for notice in notice_rx.try_iter() {
        println!("engine said: {notice}");
    }
    if client.exit_code() != 0 || server.exit_code() != 0 {
        return Err(format!(
            "calls failed: UAC exit {}, UAS exit {}",
            client.exit_code(),
            server.exit_code()
        )
        .into());
    }
    println!(
        "{} calls placed, {} answered, all successful",
        client.successful, server.successful
    );
    Ok(())
}
