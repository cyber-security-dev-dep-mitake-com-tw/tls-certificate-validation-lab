//! SVC1 fixture server. Private keys stay in the state directory.

use anyhow::{Context, Result};
use certs::{enable_lab_sha1, issue, IssuedLab, ListenerSpec};
use openssl::ssl::{SslAcceptor, SslMethod, SslOptions, SslVersion};
use openssl::x509::X509;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

pub struct LabConfig {
    pub domain: String,
    pub state_dir: PathBuf,
    pub trust_dir: PathBuf,
    pub bind: String,
    pub advertised_host: String,
    pub port_offset: u16,
    pub generate_script: PathBuf,
    pub possession_bin: PathBuf,
}

pub struct Running {
    shutdown: Arc<AtomicBool>,
    threads: Vec<JoinHandle<()>>,
    possession: Child,
}

impl Running {
    pub fn shutdown(mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        let _ = self.possession.kill();
        let _ = self.possession.wait();
        for thread in std::mem::take(&mut self.threads) {
            let _ = thread.join();
        }
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        let _ = self.possession.kill();
        let _ = self.possession.wait();
    }
}

pub fn prepare(config: &LabConfig) -> Result<IssuedLab> {
    enable_lab_sha1(&config.state_dir)?;
    issue(
        &config.domain,
        &config.state_dir,
        &config.trust_dir,
        &config.advertised_host,
        config.port_offset,
        &config.generate_script,
    )
}

pub fn serve(config: &LabConfig, issued: &IssuedLab) -> Result<Running> {
    let shutdown = Arc::new(AtomicBool::new(false));
    let mut threads = Vec::new();
    for listener in &issued.listeners {
        let spec = listener.clone();
        let bind = config.bind.clone();
        let flag = Arc::clone(&shutdown);
        let tcp = TcpListener::bind((bind.as_str(), spec.port))
            .with_context(|| format!("bind {}:{}", bind, spec.port))?;
        tcp.set_nonblocking(true)?;
        threads.push(thread::spawn(move || accept_loop(tcp, spec, flag)));
        println!(
            "LISTEN {bind}:{} tls={} fixture={}",
            listener.port, listener.version, listener.case_name
        );
    }
    let mut possession = Command::new(&config.possession_bin);
    possession
        .arg("--cert")
        .arg(&issued.possession_cert)
        .arg("--bind")
        .arg(&config.bind);
    for port in &issued.possession_ports {
        possession.arg("--port").arg(port.to_string());
        println!(
            "LISTEN {}:{} tls=incomplete fixture=possession_failed",
            config.bind, port
        );
    }
    let possession = possession.spawn().context("start possession listener")?;
    thread::sleep(Duration::from_millis(200));
    fs_ready(&config.state_dir.join("ready"))?;
    Ok(Running {
        shutdown,
        threads,
        possession,
    })
}

fn fs_ready(path: &Path) -> Result<()> {
    std::fs::write(path, b"ready\n")?;
    Ok(())
}

fn accept_loop(listener: TcpListener, spec: ListenerSpec, shutdown: Arc<AtomicBool>) {
    let acceptor = match acceptor(&spec) {
        Ok(acceptor) => acceptor,
        Err(err) => {
            eprintln!("svc1 {} tls{}: {err:#}", spec.case_name, spec.version);
            return;
        }
    };
    while !shutdown.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((stream, _)) => {
                let _ = stream.set_nonblocking(false);
                let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));
                let _ = handle(stream, &acceptor, &spec.body);
            }
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(30));
            }
            Err(_) => break,
        }
    }
}

fn acceptor(spec: &ListenerSpec) -> Result<SslAcceptor> {
    let mut builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls_server())?;
    builder.clear_options(SslOptions::NO_TLSV1 | SslOptions::NO_TLSV1_1);
    // Security level must be lowered before the certificate is installed,
    // or OpenSSL rejects the lab's short keys and SHA-1 fixtures.
    builder.set_security_level(0);
    builder.set_cipher_list("DEFAULT:@SECLEVEL=0")?;
    let cert = X509::from_pem(&spec.cert_pem)?;
    builder.set_certificate(&cert)?;
    builder.set_private_key_pem(&spec.key_pem)?;
    if let Some(chain) = &spec.chain_pem {
        builder.add_extra_chain_cert(X509::from_pem(chain)?)?;
    }
    builder.check_private_key()?;
    let version = match spec.version.as_str() {
        "1.1" => SslVersion::TLS1_1,
        "1.2" => SslVersion::TLS1_2,
        "1.3" => SslVersion::TLS1_3,
        _ => anyhow::bail!("bad tls version"),
    };
    builder.set_min_proto_version(Some(version))?;
    builder.set_max_proto_version(Some(version))?;
    builder.set_security_level(0);
    builder.set_cipher_list("DEFAULT:@SECLEVEL=0")?;
    Ok(builder.build())
}

trait PemKey {
    fn set_private_key_pem(&mut self, pem: &[u8]) -> Result<()>;
}

impl PemKey for openssl::ssl::SslAcceptorBuilder {
    fn set_private_key_pem(&mut self, pem: &[u8]) -> Result<()> {
        use openssl::pkey::PKey;
        let key = PKey::private_key_from_pem(pem)?;
        self.set_private_key(&key)?;
        Ok(())
    }
}

fn handle(stream: TcpStream, acceptor: &SslAcceptor, body: &[u8]) -> Result<()> {
    let mut tls = acceptor.accept(stream)?;
    let mut buf = [0u8; 1024];
    let _ = tls.read(&mut buf);
    let header =
        format!(
        "HTTP/1.1 200 OK\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        if body.starts_with(b"{") { "application/json" } else { "text/plain" },
        body.len()
    );
    tls.write_all(header.as_bytes())?;
    tls.write_all(body)?;
    Ok(())
}

pub fn config_from_env() -> LabConfig {
    LabConfig {
        domain: std::env::var("LAB_DOMAIN").unwrap_or_else(|_| "tls-lab.example.test".into()),
        state_dir: std::env::var("LAB_STATE")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("/state")),
        trust_dir: std::env::var("LAB_TRUST")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("/trust")),
        bind: std::env::var("LAB_BIND").unwrap_or_else(|_| "0.0.0.0".into()),
        advertised_host: std::env::var("LAB_ADVERTISED_HOST").unwrap_or_else(|_| "svc1".into()),
        port_offset: std::env::var("LAB_PORT_OFFSET")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(0),
        generate_script: std::env::var("JULIA_GENERATE")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("/opt/lab/julia/generate.jl")),
        possession_bin: std::env::var("POSSESSION_BIN")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("/usr/local/bin/possession")),
    }
}
