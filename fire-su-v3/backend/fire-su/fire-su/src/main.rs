use anyhow::{Context as _, bail};
use axum::{
    Json, Router,
    extract::State,
    http::StatusCode,
    routing::{get, post},
};
use aya::{
    maps::HashMap as BpfHashMap,
    programs::{CgroupSkb, CgroupSkbAttachType},
};
use clap::{Parser, Subcommand};
use fire_su_common::{BlockEvent, TrafficStats};
use futures::stream::StreamExt;
use log::{debug, info, warn};
use netlink_packet_core::NetlinkPayload;
use netlink_packet_route::{RouteNetlinkMessage, link::LinkAttribute};
use rtnetlink::new_connection;
use serde::Serialize;
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    fs,
    io::{Read, Write},
    net::TcpStream,
    os::fd::{AsFd, AsRawFd},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{sync::Mutex, time};

const DEFAULT_CONFIG_DIR: &str = "/data/adb/fire-su";
const DEFAULT_CGROUP_PATH: &str = "auto";
const ANDROID_BPF_CGROUP_PATH: &str = "/dev/cg2_bpf";
const LINUX_CGROUP_PATH: &str = "/sys/fs/cgroup";
const DEFAULT_BIND_ADDR: &str = "127.0.0.1:3000";
const BLOCK_INTERNET: u32 = 1 << 0;
const BLOCK_WIFI: u32 = 1 << 1;
const BLOCK_MOBILE: u32 = 1 << 2;
const BLOCK_VPN: u32 = 1 << 3;
const BLOCK_LAN: u32 = 1 << 4;
const BLOCK_DNS: u32 = 1 << 5;
const BPF_PROG_ATTACH: libc::c_uint = 8;
const BPF_PROG_DETACH: libc::c_uint = 9;
const BPF_CGROUP_INET_EGRESS: u32 = 1;

#[derive(Debug, Parser)]
#[command(name = "fire-su")]
struct Opt {
    #[arg(long, default_value = DEFAULT_CONFIG_DIR)]
    config_dir: PathBuf,

    #[arg(short, long, default_value = DEFAULT_CGROUP_PATH)]
    cgroup_path: PathBuf,

    #[arg(short, long, default_value = DEFAULT_BIND_ADDR)]
    bind_addr: String,

    #[command(subcommand)]
    command: Option<CliCommand>,
}

#[derive(Debug, Subcommand)]
enum CliCommand {
    List,
    Export,
    #[command(name = "list-apps")]
    ListApps,
    Apply,
    Disable,
    Status,
    Stats,
    Logs,
    Debug,
    Doctor,
    #[command(name = "profile-list")]
    ProfileList,
    #[command(name = "profile-save")]
    ProfileSave {
        name: String,
    },
    #[command(name = "profile-apply")]
    ProfileApply {
        name: String,
    },
    #[command(name = "temp-set")]
    TempSet {
        target: String,
        scope: String,
        value: String,
        seconds: u64,
    },
    Mode {
        mode: Option<String>,
    },
    #[command(name = "stage-mode")]
    StageMode {
        mode: String,
    },
    Set {
        target: String,
        scope: String,
        value: String,
    },
    #[command(name = "stage-set")]
    StageSet {
        target: String,
        scope: String,
        value: String,
    },
    Block {
        targets: Vec<String>,
    },
    Unblock {
        targets: Vec<String>,
    },
    Daemon,
}

#[derive(Clone, Debug, Serialize)]
struct AppInfo {
    #[serde(rename = "package")]
    package_name: String,
    uid: u32,
    user: u32,
    #[serde(rename = "userLabel")]
    user_label: String,
    kind: String,
}

impl AppInfo {
    fn target(&self) -> String {
        format!("{}@{}", self.package_name, self.user)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Mode {
    Blacklist,
    Whitelist,
}

impl Mode {
    fn parse(value: &str) -> anyhow::Result<Self> {
        match value {
            "blacklist" => Ok(Self::Blacklist),
            "whitelist" => Ok(Self::Whitelist),
            _ => bail!("invalid mode: {value}"),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Blacklist => "blacklist",
            Self::Whitelist => "whitelist",
        }
    }

    fn default_rule(self) -> RuleBits {
        match self {
            Self::Blacklist => RuleBits::default(),
            Self::Whitelist => RuleBits {
                internet: 1,
                wifi: 1,
                mobile: 1,
                vpn: 1,
                lan: 1,
                dns: 1,
            },
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
struct RuleBits {
    internet: u32,
    wifi: u32,
    mobile: u32,
    vpn: u32,
    lan: u32,
    dns: u32,
}

impl RuleBits {
    fn mask(self) -> u32 {
        (self.internet * BLOCK_INTERNET)
            | (self.wifi * BLOCK_WIFI)
            | (self.mobile * BLOCK_MOBILE)
            | (self.vpn * BLOCK_VPN)
            | (self.lan * BLOCK_LAN)
            | (self.dns * BLOCK_DNS)
    }

    fn any(self) -> bool {
        self.mask() != 0
    }

    fn set(&mut self, scope: &str, value: u32) -> anyhow::Result<()> {
        match scope {
            "internet" => self.internet = value,
            "wifi" => self.wifi = value,
            "mobile" => self.mobile = value,
            "vpn" => self.vpn = value,
            "lan" => self.lan = value,
            "dns" => self.dns = value,
            "all" => {
                self.internet = value;
                self.wifi = value;
                self.mobile = value;
                self.vpn = value;
                self.lan = value;
                self.dns = value;
            }
            _ => bail!("invalid scope: {scope}"),
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize)]
struct Rule {
    target: String,
    #[serde(rename = "package")]
    package_name: String,
    user: String,
    internet: u32,
    wifi: u32,
    mobile: u32,
    vpn: u32,
    lan: u32,
    dns: u32,
    #[serde(rename = "temporaryUntil", skip_serializing_if = "Option::is_none")]
    temporary_until: Option<u64>,
}

impl Rule {
    fn new(target: String, bits: RuleBits, temporary_until: Option<u64>) -> Self {
        let package_name = target_package(&target).to_string();
        let user = target_user(&target).unwrap_or("").to_string();
        Self {
            target,
            package_name,
            user,
            internet: bits.internet,
            wifi: bits.wifi,
            mobile: bits.mobile,
            vpn: bits.vpn,
            lan: bits.lan,
            dns: bits.dns,
            temporary_until,
        }
    }
}

// removed duplicate TrafficStats and BlockEvent

#[derive(Clone, Debug, Serialize)]
struct StatRow {
    uid: u32,
    scope: String,
    allowed_packets: u64,
    blocked_packets: u64,
    allowed_bytes: u64,
    blocked_bytes: u64,
}

#[derive(Clone, Debug, Serialize)]
struct LogRow {
    uid: u32,
    ifindex: u32,
    reason: String,
    bytes: u32,
}

#[derive(Clone, Debug, Serialize)]
struct DebugReport {
    now: u64,
    pid: u32,
    uid: u32,
    euid: u32,
    arch: String,
    kernel: String,
    config_dir: String,
    bind_addr: String,
    cgroup_path: String,
    cgroup_exists: bool,
    bpf_filesystem_exists: bool,
    cgroup_mounts: Vec<String>,
    daemon_reachable: bool,
    daemon_pid_file: Option<String>,
    rules_file: String,
    settings_file: String,
    temporary_file: String,
    active_rules: Vec<DebugRule>,
    installed_apps: Vec<DebugApp>,
    daemon_stats: Option<String>,
    daemon_logs: Option<String>,
    recent_daemon_log: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
struct DebugRule {
    target: String,
    internet: u32,
    wifi: u32,
    mobile: u32,
    vpn: u32,
    lan: u32,
    dns: u32,
}

#[derive(Clone, Debug, Serialize)]
struct DebugApp {
    package: String,
    target: String,
    uid: u32,
    user: u32,
    kind: String,
}

#[derive(Clone, Copy, Debug)]
struct TempRule {
    bits: RuleBits,
    expires_at: u64,
}

#[derive(Serialize)]
struct DoctorReport {
    engine: &'static str,
    daemon: &'static str,
    cgroup: bool,
    bpf_filesystem: bool,
    android_arm64: bool,
    warnings: Vec<String>,
}

#[derive(Serialize)]
struct ExportRules {
    version: u32,
    #[serde(rename = "defaultMode")]
    default_mode: String,
    rules: Vec<Rule>,
}

#[derive(Serialize)]
struct StatusResponse {
    status: String,
}

enum NotifyResult {
    Reloaded,
    Unreachable,
    Failed(String),
}

struct AppState {
    bpf_map: Mutex<BpfHashMap<aya::maps::MapData, u64, u32>>,
    stats_map: Mutex<BpfHashMap<aya::maps::MapData, u64, TrafficStats>>,
    events_map: Mutex<BpfHashMap<aya::maps::MapData, u64, BlockEvent>>,
    config_dir: PathBuf,
    iface_indexes: Mutex<HashMap<String, u32>>,
    log_tx: tokio::sync::broadcast::Sender<fire_su_common::ConnectionLog>,
}

type SharedState = Arc<AppState>;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut opt = Opt::parse();
    let _ = env_logger::try_init();

    let command = opt.command.take().unwrap_or(CliCommand::Status);
    match command {
        CliCommand::List => list_rules(&opt.config_dir)?,
        CliCommand::Export => export_rules(&opt.config_dir)?,
        CliCommand::ListApps => {
            for app in list_apps() {
                println!(
                    "{}|{}|{}|{}|{}",
                    app.package_name, app.uid, app.user, app.user_label, app.kind
                );
            }
        }
        CliCommand::Apply => apply_runtime(&opt).await?,
        CliCommand::Disable => disable_runtime(&opt)?,
        CliCommand::Status => status_runtime(&opt)?,
        CliCommand::Stats => print_daemon_json(&opt.bind_addr, "/api/stats")?,
        CliCommand::Logs => print_daemon_json(&opt.bind_addr, "/api/logs")?,
        CliCommand::Debug => print_debug_report(&opt)?,
        CliCommand::Doctor => print!("{}", serde_json::to_string(&doctor_report(&opt))?),
        CliCommand::ProfileList => list_profiles(&opt.config_dir)?,
        CliCommand::ProfileSave { name } => {
            save_profile(&opt.config_dir, &name)?;
            println!("Profile saved: {name}");
        }
        CliCommand::ProfileApply { name } => {
            apply_profile(&opt.config_dir, &name)?;
            apply_runtime(&opt).await?;
            println!("Profile applied: {name}");
        }
        CliCommand::TempSet {
            target,
            scope,
            value,
            seconds,
        } => {
            set_temp_rule(
                &opt.config_dir,
                &target,
                &scope,
                parse_enabled(&value)?,
                seconds,
            )?;
            apply_runtime(&opt).await?;
            println!(
                "Temporary rule set for {target} {scope}={} {seconds}s",
                parse_enabled(&value)?
            );
        }
        CliCommand::Mode { mode } => {
            if let Some(mode) = mode {
                set_default_mode(&opt.config_dir, Mode::parse(&mode)?)?;
                apply_runtime(&opt).await?;
                println!("Default mode set to {mode}");
            } else {
                println!("{}", get_default_mode(&opt.config_dir)?.as_str());
            }
        }
        CliCommand::StageMode { mode } => {
            set_default_mode(&opt.config_dir, Mode::parse(&mode)?)?;
            println!("Default mode staged: {mode}");
        }
        CliCommand::Set {
            target,
            scope,
            value,
        } => {
            set_rule(&opt.config_dir, &target, &scope, parse_enabled(&value)?)?;
            apply_runtime(&opt).await?;
            println!("Updated {target} {scope}={}", parse_enabled(&value)?);
        }
        CliCommand::StageSet {
            target,
            scope,
            value,
        } => {
            set_rule(&opt.config_dir, &target, &scope, parse_enabled(&value)?)?;
            println!("Staged {target} {scope}={}", parse_enabled(&value)?);
        }
        CliCommand::Block { targets } => {
            if targets.is_empty() {
                bail!("missing package");
            }
            for target in &targets {
                set_rule(&opt.config_dir, target, "all", 1)?;
            }
            apply_runtime(&opt).await?;
        }
        CliCommand::Unblock { targets } => {
            if targets.is_empty() {
                bail!("missing package");
            }
            if targets[0] == "all" {
                ensure_store(&opt.config_dir)?;
                fs::write(rules_file(&opt.config_dir), "")?;
                fs::write(temp_rules_file(&opt.config_dir), "")?;
                apply_runtime(&opt).await?;
                println!("Removed all fire-su rules");
            } else {
                for target in &targets {
                    set_rule(&opt.config_dir, target, "all", 0)?;
                }
                apply_runtime(&opt).await?;
            }
        }
        CliCommand::Daemon => run_daemon(opt).await?,
    }

    Ok(())
}

async fn run_daemon(opt: Opt) -> anyhow::Result<()> {
    ensure_store(&opt.config_dir)?;
    raise_memlock();
    let cgroup_path = resolve_cgroup_path(&opt.cgroup_path);
    eprintln!("--- fire-su daemon start {} ---", unix_now());
    eprintln!(
        "fire-su: pid={} uid={} euid={} arch={} kernel={}",
        std::process::id(),
        current_uid(),
        current_euid(),
        std::env::consts::ARCH,
        kernel_version()
    );
    eprintln!(
        "fire-su: config_dir={} bind_addr={}",
        opt.config_dir.display(),
        opt.bind_addr
    );
    eprintln!(
        "fire-su: requested_cgroup_path={} resolved_cgroup_path={} exists={}",
        opt.cgroup_path.display(),
        cgroup_path.display(),
        cgroup_path.exists()
    );
    eprintln!(
        "fire-su: bpf_fs=/sys/fs/bpf exists={}",
        Path::new("/sys/fs/bpf").exists()
    );
    for mount in read_cgroup_mounts() {
        eprintln!("fire-su: cgroup mount: {mount}");
    }

    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/fire-su"
    )))?;
    eprintln!("fire-su: eBPF object loaded");
    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        warn!("failed to initialize eBPF logger: {e}");
    }

    let block_list: BpfHashMap<_, u64, u32> = BpfHashMap::try_from(
        ebpf.take_map("BLOCK_LIST")
            .context("BLOCK_LIST map missing")?,
    )?;
    let stats_map: BpfHashMap<_, u64, TrafficStats> = BpfHashMap::try_from(
        ebpf.take_map("TRAFFIC_STATS")
            .context("TRAFFIC_STATS map missing")?,
    )?;
    let events_map: BpfHashMap<_, u64, BlockEvent> = BpfHashMap::try_from(
        ebpf.take_map("BLOCK_EVENTS")
            .context("BLOCK_EVENTS map missing")?,
    )?;

    let (log_tx, _) = tokio::sync::broadcast::channel(1000);

    let state = Arc::new(AppState {
        bpf_map: Mutex::new(block_list),
        stats_map: Mutex::new(stats_map),
        events_map: Mutex::new(events_map),
        config_dir: opt.config_dir.clone(),
        iface_indexes: Mutex::new(HashMap::new()),
        log_tx,
    });

    fetch_initial_interfaces(&state).await;
    let initial_interfaces = state.iface_indexes.lock().await.clone();
    eprintln!(
        "fire-su: initial interfaces: {}",
        format_iface_indexes(&initial_interfaces)
    );
    sync_bpf_map(&state).await?;

    let program: &mut CgroupSkb = ebpf
        .program_mut("fire_su")
        .context("fire_su missing")?
        .try_into()?;
    program.load().context("load fire_su eBPF program")?;
    eprintln!("fire-su: eBPF program loaded");
    let cgroup = fs::File::open(&cgroup_path).with_context(|| {
        format!(
            "open {} (exists={}, uid={}, euid={})",
            cgroup_path.display(),
            cgroup_path.exists(),
            current_uid(),
            current_euid()
        )
    })?;
    let program_fd = program.fd().context("get fire_su eBPF program fd")?;
    eprintln!(
        "fire-su: attaching eBPF program_fd={} cgroup_fd={} attach_type=egress",
        program_fd.as_fd().as_raw_fd(),
        cgroup.as_fd().as_raw_fd()
    );
    attach_cgroup_skb_legacy(
        program_fd.as_fd().as_raw_fd(),
        cgroup.as_fd().as_raw_fd(),
        CgroupSkbAttachType::Egress,
    )
    .context("attach fire_su eBPF program with BPF_PROG_ATTACH")?;
    eprintln!("fire-su: eBPF program attached");

    let state_clone = state.clone();
    tokio::spawn(async move {
        monitor_netlink(state_clone).await;
    });

    let state_clone = state.clone();
    tokio::spawn(async move {
        poll_config(state_clone).await;
    });

    let app = Router::new()
        .route("/api/health", get(handle_health))
        .route("/api/reload", post(handle_reload))
        .route("/api/stats", get(handle_stats))
        .route("/api/logs", get(handle_logs))
        .route("/api/monitor", get(handle_monitor))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind(&opt.bind_addr).await?;
    write_pid(&opt.config_dir)?;
    eprintln!("fire-su: API listening on {}", opt.bind_addr);
    info!("fire-su eBPF daemon listening on {}", opt.bind_addr);

    let serve_result = axum::serve(listener, app)
        .await
        .context("serve fire-su API")
        .map(|_| ());
    if let Err(error) = &serve_result {
        eprintln!("fire-su: API server stopped: {error:#}");
    } else {
        eprintln!("fire-su: API server stopped");
    }

    let _ = detach_cgroup_skb_legacy(
        program_fd.as_fd().as_raw_fd(),
        cgroup.as_fd().as_raw_fd(),
        CgroupSkbAttachType::Egress,
    );

    let _ = fs::remove_file(pid_file(&opt.config_dir));
    serve_result
}

#[derive(Clone, Debug, Serialize)]
struct ConnectionLogDto {
    uid: u32,
    protocol: u8,
    action: u8,
    src_ip: String,
    dst_ip: String,
    src_port: u16,
    dst_port: u16,
    bytes: u32,
}

impl From<fire_su_common::ConnectionLog> for ConnectionLogDto {
    fn from(log: fire_su_common::ConnectionLog) -> Self {
        Self {
            uid: log.uid,
            protocol: log.protocol,
            action: log.action,
            src_ip: format!(
                "{}.{}.{}.{}",
                (log.src_ip[0] >> 24) & 0xff,
                (log.src_ip[0] >> 16) & 0xff,
                (log.src_ip[0] >> 8) & 0xff,
                log.src_ip[0] & 0xff
            ), // simplistic
            dst_ip: format!(
                "{}.{}.{}.{}",
                (log.dst_ip[0] >> 24) & 0xff,
                (log.dst_ip[0] >> 16) & 0xff,
                (log.dst_ip[0] >> 8) & 0xff,
                log.dst_ip[0] & 0xff
            ),
            src_port: log.src_port,
            dst_port: log.dst_port,
            bytes: log.bytes,
        }
    }
}

async fn handle_monitor(State(state): State<SharedState>) -> axum::response::Response {
    let mut rx = state.log_tx.subscribe();
    let stream = async_stream::stream! {
        while let Ok(log) = rx.recv().await {
            let dto: ConnectionLogDto = log.into();
            if let Ok(json) = serde_json::to_string(&dto) {
                yield Ok::<_, std::convert::Infallible>(format!("{}\n", json));
            }
        }
    };
    axum::response::Response::builder()
        .header("Content-Type", "application/json-stream")
        .body(axum::body::Body::from_stream(stream))
        .unwrap()
}

async fn handle_stats(State(state): State<SharedState>) -> Json<Vec<StatRow>> {
    Json(read_stats(&state).await)
}

async fn handle_logs(State(state): State<SharedState>) -> Json<Vec<LogRow>> {
    Json(read_logs(&state).await)
}

async fn handle_health() -> Json<StatusResponse> {
    Json(StatusResponse {
        status: "ok".to_string(),
    })
}

async fn handle_reload(State(state): State<SharedState>) -> (StatusCode, Json<StatusResponse>) {
    match sync_bpf_map(&state).await {
        Ok(()) => (
            StatusCode::OK,
            Json(StatusResponse {
                status: "ok".to_string(),
            }),
        ),
        Err(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(StatusResponse {
                status: format!("error: {error}"),
            }),
        ),
    }
}

async fn sync_bpf_map(state: &AppState) -> anyhow::Result<()> {
    let mode = get_default_mode(&state.config_dir)?;
    let rules = effective_rules(&state.config_dir)?;
    let apps = list_apps();
    let iface_indexes = state.iface_indexes.lock().await.clone();
    eprintln!(
        "fire-su: sync start mode={} configured_rules={} apps={} interfaces={}",
        mode.as_str(),
        rules.len(),
        apps.len(),
        iface_indexes.len()
    );

    let mut bpf_map = state.bpf_map.lock().await;
    let keys: Vec<u64> = bpf_map
        .iter()
        .filter_map(Result::ok)
        .map(|(key, _)| key)
        .collect();
    let removed_keys = keys.len();
    for key in keys {
        let _ = bpf_map.remove(&key);
    }

    let generic_rules: BTreeMap<_, _> = rules
        .iter()
        .filter(|(target, _)| !target.contains('@'))
        .map(|(target, bits)| (target.clone(), *bits))
        .collect();
    let mut inserted_entries = 0usize;
    let mut matched_targets = BTreeSet::new();
    for app in apps {
        let target = app.target();
        let exact_bits = rules.get(&target).copied();
        let generic_bits = generic_rules.get(&app.package_name).copied();
        let bits = exact_bits
            .or(generic_bits)
            .unwrap_or_else(|| mode.default_rule());
        if exact_bits.is_some() {
            matched_targets.insert(target.clone());
        }
        if generic_bits.is_some() {
            matched_targets.insert(app.package_name.clone());
        }
        if exact_bits.is_some() || generic_bits.is_some() {
            eprintln!(
                "fire-su: sync match target={} package={} uid={} bits={}",
                target,
                app.package_name,
                app.uid,
                format_rule_bits(bits)
            );
        }
        if !bits.any() {
            continue;
        }
        inserted_entries += insert_uid_rules(&mut bpf_map, app.uid, bits, &iface_indexes)?;
    }
    for target in rules.keys() {
        if !matched_targets.contains(target) {
            eprintln!("fire-su: sync warning unmatched rule target={target}");
        }
    }

    eprintln!(
        "fire-su: sync complete removed_map_entries={} inserted_map_entries={}",
        removed_keys, inserted_entries
    );
    debug!("synchronized eBPF firewall map");
    Ok(())
}

fn insert_uid_rules(
    bpf_map: &mut BpfHashMap<aya::maps::MapData, u64, u32>,
    uid: u32,
    bits: RuleBits,
    iface_indexes: &HashMap<String, u32>,
) -> anyhow::Result<usize> {
    let mut inserted_entries = 0usize;
    let global_mask = bits.mask() & (BLOCK_INTERNET | BLOCK_LAN | BLOCK_DNS);
    if global_mask != 0 {
        bpf_map.insert(uid as u64, global_mask, 0)?;
        inserted_entries += 1;
        eprintln!(
            "fire-su: map insert uid={} key={} reason_mask={} bits={}",
            uid,
            uid,
            global_mask,
            format_rule_bits(bits)
        );
    }

    for (name, ifindex) in iface_indexes {
        let blocked = (bits.wifi == 1 && is_wifi(name))
            || (bits.mobile == 1 && is_mobile(name))
            || (bits.vpn == 1 && is_vpn(name));
        if blocked {
            let key = ((*ifindex as u64) << 32) | uid as u64;
            let reason = if bits.wifi == 1 && is_wifi(name) {
                BLOCK_WIFI
            } else if bits.mobile == 1 && is_mobile(name) {
                BLOCK_MOBILE
            } else {
                BLOCK_VPN
            };
            bpf_map.insert(key, reason, 0)?;
            inserted_entries += 1;
            eprintln!(
                "fire-su: map insert uid={} ifname={} ifindex={} key={} reason={}",
                uid,
                name,
                ifindex,
                key,
                reason_name(reason)
            );
        }
    }

    Ok(inserted_entries)
}

async fn read_stats(state: &AppState) -> Vec<StatRow> {
    let stats_map = state.stats_map.lock().await;
    let mut rows: Vec<_> = stats_map
        .iter()
        .filter_map(Result::ok)
        .map(|(key, stats)| StatRow {
            uid: (key >> 32) as u32,
            scope: reason_name(key as u32).to_string(),
            allowed_packets: stats.allowed_packets,
            blocked_packets: stats.blocked_packets,
            allowed_bytes: stats.allowed_bytes,
            blocked_bytes: stats.blocked_bytes,
        })
        .collect();
    rows.sort_by(|a, b| {
        b.blocked_packets
            .cmp(&a.blocked_packets)
            .then(b.allowed_packets.cmp(&a.allowed_packets))
    });
    rows
}

async fn read_logs(state: &AppState) -> Vec<LogRow> {
    let events_map = state.events_map.lock().await;
    let mut rows: Vec<_> = events_map
        .iter()
        .filter_map(Result::ok)
        .map(|(_, event)| LogRow {
            uid: event.uid,
            ifindex: event.ifindex,
            reason: reason_name(event.reason).to_string(),
            bytes: event.bytes,
        })
        .collect();
    rows.sort_by(|a, b| b.bytes.cmp(&a.bytes));
    rows.truncate(100);
    rows
}

async fn monitor_netlink(state: SharedState) {
    let Ok((connection, _, mut messages)) = new_connection() else {
        eprintln!("fire-su: netlink monitor failed to start");
        warn!("failed to open netlink monitor");
        return;
    };
    tokio::spawn(connection);

    while let Some((message, _)) = messages.next().await {
        if let NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewLink(msg)) = message.payload {
            let mut name = None;
            for attr in msg.attributes {
                if let LinkAttribute::IfName(ifname) = attr {
                    name = Some(ifname);
                    break;
                }
            }
            if let Some(name) = name {
                eprintln!(
                    "fire-su: netlink interface update ifname={} ifindex={}",
                    name, msg.header.index
                );
                state
                    .iface_indexes
                    .lock()
                    .await
                    .insert(name, msg.header.index);
                let _ = sync_bpf_map(&state).await;
            }
        }
    }
}

async fn fetch_initial_interfaces(state: &SharedState) {
    let Ok((connection, handle, _)) = new_connection() else {
        eprintln!("fire-su: failed to fetch initial interfaces");
        warn!("failed to fetch interfaces");
        return;
    };
    tokio::spawn(connection);

    let mut links = handle.link().get().execute();
    while let Some(Ok(msg)) = links.next().await {
        let mut name = None;
        for attr in msg.attributes {
            if let LinkAttribute::IfName(ifname) = attr {
                name = Some(ifname);
                break;
            }
        }
        if let Some(name) = name {
            eprintln!(
                "fire-su: found interface ifname={} ifindex={} class={}",
                name,
                msg.header.index,
                iface_class(&name)
            );
            state
                .iface_indexes
                .lock()
                .await
                .insert(name, msg.header.index);
        }
    }
}

async fn poll_config(state: SharedState) {
    let mut last = config_stamp(&state.config_dir);
    loop {
        time::sleep(Duration::from_secs(2)).await;
        let next = config_stamp(&state.config_dir);
        if next != last {
            eprintln!("fire-su: config change detected; reloading BPF map");
            last = next;
            if let Err(error) = sync_bpf_map(&state).await {
                eprintln!("fire-su: config reload failed: {error:#}");
            }
        }
    }
}

async fn apply_runtime(opt: &Opt) -> anyhow::Result<()> {
    ensure_store(&opt.config_dir)?;
    write_reload_stamp(&opt.config_dir)?;
    match notify_daemon(&opt.bind_addr) {
        NotifyResult::Reloaded => {}
        NotifyResult::Failed(error) => bail!("fire-su daemon reload failed: {error}"),
        NotifyResult::Unreachable => {
            start_daemon_background(opt)?;
            let mut last_error = None;
            for _ in 0..10 {
                time::sleep(Duration::from_millis(300)).await;
                match notify_daemon(&opt.bind_addr) {
                    NotifyResult::Reloaded => {
                        println!("fire-su eBPF rules applied");
                        return Ok(());
                    }
                    NotifyResult::Failed(error) => last_error = Some(error),
                    NotifyResult::Unreachable => {}
                }
            }
            if let Some(log) = read_daemon_log_tail(&opt.config_dir) {
                if let Some(error) = last_error {
                    bail!(
                        "fire-su eBPF daemon did not reload rules: {error}; recent daemon log:\n{log}"
                    );
                }
                bail!("fire-su eBPF daemon is not running; recent daemon log:\n{log}");
            }
            if let Some(error) = last_error {
                bail!("fire-su eBPF daemon did not reload rules: {error}");
            }
            bail!("fire-su eBPF daemon is not running");
        }
    }
    println!("fire-su eBPF rules applied");
    Ok(())
}

fn disable_runtime(opt: &Opt) -> anyhow::Result<()> {
    if let Ok(pid) = fs::read_to_string(pid_file(&opt.config_dir)) {
        if let Ok(pid) = pid.trim().parse::<i32>() {
            if pid_belongs_to_fire_su(pid) {
                unsafe {
                    libc::kill(pid, libc::SIGTERM);
                }
            }
        }
    }
    let _ = fs::remove_file(pid_file(&opt.config_dir));
    println!("fire-su eBPF daemon disabled");
    Ok(())
}

fn status_runtime(opt: &Opt) -> anyhow::Result<()> {
    ensure_store(&opt.config_dir)?;
    println!("engine=ebpf");
    println!("mode={}", get_default_mode(&opt.config_dir)?.as_str());
    println!(
        "daemon={}",
        if daemon_reachable(&opt.bind_addr) {
            "running"
        } else {
            "stopped"
        }
    );
    Ok(())
}

fn notify_daemon(bind_addr: &str) -> NotifyResult {
    let Ok(mut stream) = TcpStream::connect(bind_addr) else {
        return NotifyResult::Unreachable;
    };
    if let Err(error) = stream.set_read_timeout(Some(Duration::from_secs(2))) {
        return NotifyResult::Failed(error.to_string());
    }
    if let Err(error) = stream.write_all(http_request("POST", "/api/reload").as_bytes()) {
        return NotifyResult::Failed(error.to_string());
    }
    let mut response = String::new();
    if let Err(error) = stream.read_to_string(&mut response) {
        return NotifyResult::Failed(error.to_string());
    }
    if response.starts_with("HTTP/1.1 200") {
        NotifyResult::Reloaded
    } else {
        NotifyResult::Failed(http_error_summary(&response))
    }
}

fn daemon_reachable(bind_addr: &str) -> bool {
    let Ok(mut stream) = TcpStream::connect(bind_addr) else {
        return false;
    };
    if stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .is_err()
    {
        return false;
    }
    if stream
        .write_all(http_request("GET", "/api/health").as_bytes())
        .is_err()
    {
        return false;
    }
    let mut response = String::new();
    if stream.read_to_string(&mut response).is_err() {
        return false;
    }
    response.starts_with("HTTP/1.1 200")
}

fn http_error_summary(response: &str) -> String {
    let status = response.lines().next().unwrap_or("invalid daemon response");
    let body = response.split("\r\n\r\n").nth(1).unwrap_or("").trim();
    if body.is_empty() {
        status.to_string()
    } else {
        format!("{status}: {body}")
    }
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct BpfProgAttachAttr {
    target_fd: u32,
    attach_bpf_fd: u32,
    attach_type: u32,
    attach_flags: u32,
    replace_bpf_fd: u32,
    relative_fd: u32,
    expected_revision: u64,
}

fn attach_cgroup_skb_legacy(
    prog_fd: i32,
    cgroup_fd: i32,
    attach_type: CgroupSkbAttachType,
) -> anyhow::Result<()> {
    bpf_prog_attach_cmd(BPF_PROG_ATTACH, prog_fd, cgroup_fd, attach_type)
        .with_context(|| format!("bpf_prog_attach failed for cgroup fd {cgroup_fd}"))
}

fn detach_cgroup_skb_legacy(
    prog_fd: i32,
    cgroup_fd: i32,
    attach_type: CgroupSkbAttachType,
) -> anyhow::Result<()> {
    bpf_prog_attach_cmd(BPF_PROG_DETACH, prog_fd, cgroup_fd, attach_type)
        .with_context(|| format!("bpf_prog_detach failed for cgroup fd {cgroup_fd}"))
}

fn bpf_prog_attach_cmd(
    cmd: libc::c_uint,
    prog_fd: i32,
    cgroup_fd: i32,
    attach_type: CgroupSkbAttachType,
) -> anyhow::Result<()> {
    let mut attr = BpfProgAttachAttr {
        target_fd: cgroup_fd as u32,
        attach_bpf_fd: prog_fd as u32,
        attach_type: cgroup_skb_attach_type(attach_type),
        attach_flags: 0,
        replace_bpf_fd: 0,
        relative_fd: 0,
        expected_revision: 0,
    };
    let ret = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            cmd,
            &mut attr as *mut BpfProgAttachAttr,
            std::mem::size_of::<BpfProgAttachAttr>(),
        )
    };
    if ret == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error().into())
    }
}

fn cgroup_skb_attach_type(attach_type: CgroupSkbAttachType) -> u32 {
    match attach_type {
        CgroupSkbAttachType::Ingress => 0,
        CgroupSkbAttachType::Egress => BPF_CGROUP_INET_EGRESS,
    }
}

fn print_daemon_json(bind_addr: &str, path: &str) -> anyhow::Result<()> {
    print!("{}", daemon_request(bind_addr, "GET", path)?);
    Ok(())
}

fn print_debug_report(opt: &Opt) -> anyhow::Result<()> {
    ensure_store(&opt.config_dir)?;
    let cgroup_path = resolve_cgroup_path(&opt.cgroup_path);
    let daemon_reachable = daemon_reachable(&opt.bind_addr);
    let active_rules = effective_rules(&opt.config_dir)?
        .into_iter()
        .map(|(target, bits)| DebugRule {
            target,
            internet: bits.internet,
            wifi: bits.wifi,
            mobile: bits.mobile,
            vpn: bits.vpn,
            lan: bits.lan,
            dns: bits.dns,
        })
        .collect();
    let installed_apps = list_apps()
        .into_iter()
        .map(|app| {
            let target = app.target();
            DebugApp {
                package: app.package_name,
                target,
                uid: app.uid,
                user: app.user,
                kind: app.kind,
            }
        })
        .collect();
    let daemon_stats = if daemon_reachable {
        daemon_request(&opt.bind_addr, "GET", "/api/stats").ok()
    } else {
        None
    };
    let daemon_logs = if daemon_reachable {
        daemon_request(&opt.bind_addr, "GET", "/api/logs").ok()
    } else {
        None
    };
    let report = DebugReport {
        now: unix_now(),
        pid: std::process::id(),
        uid: current_uid(),
        euid: current_euid(),
        arch: std::env::consts::ARCH.to_string(),
        kernel: kernel_version(),
        config_dir: opt.config_dir.display().to_string(),
        bind_addr: opt.bind_addr.clone(),
        cgroup_path: cgroup_path.display().to_string(),
        cgroup_exists: cgroup_path.exists(),
        bpf_filesystem_exists: Path::new("/sys/fs/bpf").exists(),
        cgroup_mounts: read_cgroup_mounts(),
        daemon_reachable,
        daemon_pid_file: fs::read_to_string(pid_file(&opt.config_dir))
            .ok()
            .map(|pid| pid.trim().to_string())
            .filter(|pid| !pid.is_empty()),
        rules_file: fs::read_to_string(rules_file(&opt.config_dir)).unwrap_or_default(),
        settings_file: fs::read_to_string(settings_file(&opt.config_dir)).unwrap_or_default(),
        temporary_file: fs::read_to_string(temp_rules_file(&opt.config_dir)).unwrap_or_default(),
        active_rules,
        installed_apps,
        daemon_stats,
        daemon_logs,
        recent_daemon_log: read_daemon_log_tail(&opt.config_dir),
    };
    print!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

fn daemon_request(bind_addr: &str, method: &str, path: &str) -> anyhow::Result<String> {
    let mut stream = TcpStream::connect(bind_addr)?;
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.write_all(http_request(method, path).as_bytes())?;
    let mut response = String::new();
    let _ = stream.read_to_string(&mut response);
    if !response.starts_with("HTTP/1.1 200") {
        bail!("daemon request failed");
    }
    Ok(response.split("\r\n\r\n").nth(1).unwrap_or("").to_string())
}

fn http_request(method: &str, path: &str) -> String {
    format!(
        "{method} {path} HTTP/1.1\r\nHost: fire-su\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
    )
}

fn start_daemon_background(opt: &Opt) -> anyhow::Result<()> {
    let exe = std::env::current_exe()?;
    let cgroup_path = resolve_cgroup_path(&opt.cgroup_path);
    let mut log = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(daemon_log_file(&opt.config_dir))
        .context("open fire-su daemon log")?;
    let stderr = log.try_clone().context("clone fire-su daemon log")?;
    let _ = writeln!(log, "\n--- fire-su daemon start {} ---", unix_now());
    Command::new(exe)
        .arg("--config-dir")
        .arg(&opt.config_dir)
        .arg("--cgroup-path")
        .arg(&cgroup_path)
        .arg("--bind-addr")
        .arg(&opt.bind_addr)
        .arg("daemon")
        .stdin(Stdio::null())
        .stdout(Stdio::from(log))
        .stderr(Stdio::from(stderr))
        .spawn()
        .context("start fire-su eBPF daemon")?;
    Ok(())
}

fn read_daemon_log_tail(config_dir: &Path) -> Option<String> {
    let log = fs::read_to_string(daemon_log_file(config_dir)).ok()?;
    let current_attempt = log
        .rfind("--- fire-su daemon start ")
        .map(|index| &log[index..])
        .unwrap_or(&log);
    let mut lines: Vec<_> = current_attempt.lines().rev().take(30).collect();
    lines.reverse();
    let tail = lines.join("\n");
    if tail.trim().is_empty() {
        None
    } else {
        Some(tail)
    }
}

fn resolve_cgroup_path(configured: &Path) -> PathBuf {
    if configured.as_os_str() != DEFAULT_CGROUP_PATH {
        return configured.to_path_buf();
    }
    for candidate in [ANDROID_BPF_CGROUP_PATH, LINUX_CGROUP_PATH] {
        let path = Path::new(candidate);
        if path.exists() {
            return path.to_path_buf();
        }
    }
    PathBuf::from(LINUX_CGROUP_PATH)
}

fn raise_memlock() {
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }
}

fn ensure_store(config_dir: &Path) -> anyhow::Result<()> {
    fs::create_dir_all(config_dir)?;
    if !rules_file(config_dir).exists() {
        fs::write(rules_file(config_dir), "")?;
    }
    if !settings_file(config_dir).exists() {
        fs::write(settings_file(config_dir), "defaultMode=blacklist\n")?;
    }
    if !legacy_json_file(config_dir).exists() {
        fs::write(legacy_json_file(config_dir), "[]")?;
    }
    if !temp_rules_file(config_dir).exists() {
        fs::write(temp_rules_file(config_dir), "")?;
    }
    Ok(())
}

fn get_default_mode(config_dir: &Path) -> anyhow::Result<Mode> {
    ensure_store(config_dir)?;
    let settings = fs::read_to_string(settings_file(config_dir)).unwrap_or_default();
    for line in settings.lines().rev() {
        if let Some(mode) = line.strip_prefix("defaultMode=") {
            return Mode::parse(mode);
        }
    }
    Ok(Mode::Blacklist)
}

fn set_default_mode(config_dir: &Path, mode: Mode) -> anyhow::Result<()> {
    ensure_store(config_dir)?;
    fs::write(
        settings_file(config_dir),
        format!("defaultMode={}\n", mode.as_str()),
    )?;
    save_rules(config_dir, read_rules(config_dir)?)?;
    Ok(())
}

fn read_rules(config_dir: &Path) -> anyhow::Result<BTreeMap<String, RuleBits>> {
    ensure_store(config_dir)?;
    let mut rules = BTreeMap::new();
    for line in fs::read_to_string(rules_file(config_dir))
        .unwrap_or_default()
        .lines()
    {
        let parts: Vec<_> = line.split('|').collect();
        if parts.len() < 6 || !is_valid_target(parts[0]) {
            continue;
        }
        rules.insert(
            parts[0].to_string(),
            RuleBits {
                internet: bit(parts[1]),
                wifi: bit(parts[2]),
                mobile: bit(parts[3]),
                vpn: bit(parts[4]),
                lan: bit(parts[5]),
                dns: parts
                    .get(6)
                    .map(|value| bit(value))
                    .unwrap_or_else(|| bit(parts[1])),
            },
        );
    }
    Ok(rules)
}

fn save_rules(config_dir: &Path, rules: BTreeMap<String, RuleBits>) -> anyhow::Result<()> {
    let mode = get_default_mode(config_dir)?;
    let default = mode.default_rule();
    let mut out = String::new();
    for (target, bits) in rules {
        if bits == default {
            continue;
        }
        if mode == Mode::Blacklist && !bits.any() {
            continue;
        }
        out.push_str(&format!(
            "{}|{}|{}|{}|{}|{}|{}\n",
            target, bits.internet, bits.wifi, bits.mobile, bits.vpn, bits.lan, bits.dns
        ));
    }
    fs::write(rules_file(config_dir), out)?;
    sync_legacy_json(config_dir)?;
    Ok(())
}

fn read_temp_rules(config_dir: &Path) -> anyhow::Result<BTreeMap<String, TempRule>> {
    ensure_store(config_dir)?;
    let now = unix_now();
    let mut changed = false;
    let mut rules = BTreeMap::new();
    for line in fs::read_to_string(temp_rules_file(config_dir))
        .unwrap_or_default()
        .lines()
    {
        let parts: Vec<_> = line.split('|').collect();
        if parts.len() != 8 || !is_valid_target(parts[0]) {
            continue;
        }
        let Ok(expires_at) = parts[7].parse::<u64>() else {
            continue;
        };
        if expires_at <= now {
            changed = true;
            continue;
        }
        rules.insert(
            parts[0].to_string(),
            TempRule {
                bits: RuleBits {
                    internet: bit(parts[1]),
                    wifi: bit(parts[2]),
                    mobile: bit(parts[3]),
                    vpn: bit(parts[4]),
                    lan: bit(parts[5]),
                    dns: bit(parts[6]),
                },
                expires_at,
            },
        );
    }
    if changed {
        save_temp_rules(config_dir, &rules)?;
    }
    Ok(rules)
}

fn save_temp_rules(config_dir: &Path, rules: &BTreeMap<String, TempRule>) -> anyhow::Result<()> {
    let mut out = String::new();
    for (target, rule) in rules {
        out.push_str(&format!(
            "{}|{}|{}|{}|{}|{}|{}|{}\n",
            target,
            rule.bits.internet,
            rule.bits.wifi,
            rule.bits.mobile,
            rule.bits.vpn,
            rule.bits.lan,
            rule.bits.dns,
            rule.expires_at
        ));
    }
    fs::write(temp_rules_file(config_dir), out)?;
    Ok(())
}

fn remove_temp_rule(config_dir: &Path, target: &str) -> anyhow::Result<()> {
    let mut rules = read_temp_rules(config_dir)?;
    if rules.remove(target).is_some() {
        save_temp_rules(config_dir, &rules)?;
    }
    Ok(())
}

fn effective_rules(config_dir: &Path) -> anyhow::Result<BTreeMap<String, RuleBits>> {
    let mut rules = read_rules(config_dir)?;
    for (target, temp) in read_temp_rules(config_dir)? {
        rules.insert(target, temp.bits);
    }
    Ok(rules)
}

fn set_temp_rule(
    config_dir: &Path,
    target: &str,
    scope: &str,
    value: u32,
    seconds: u64,
) -> anyhow::Result<()> {
    ensure_store(config_dir)?;
    if !is_valid_target(target) {
        bail!("invalid package target: {target}");
    }
    let mode = get_default_mode(config_dir)?;
    let mut rules = read_temp_rules(config_dir)?;
    let mut bits = rules
        .get(target)
        .map(|rule| rule.bits)
        .or_else(|| {
            read_rules(config_dir)
                .ok()
                .and_then(|rules| rules.get(target).copied())
        })
        .unwrap_or_else(|| mode.default_rule());
    bits.set(scope, value)?;
    rules.insert(
        target.to_string(),
        TempRule {
            bits,
            expires_at: unix_now().saturating_add(seconds),
        },
    );
    save_temp_rules(config_dir, &rules)
}

fn list_profiles(config_dir: &Path) -> anyhow::Result<()> {
    ensure_store(config_dir)?;
    let dir = profiles_dir(config_dir);
    fs::create_dir_all(&dir)?;
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if let Some(name) = name.strip_suffix(".rules") {
            println!("{name}");
        }
    }
    Ok(())
}

fn save_profile(config_dir: &Path, name: &str) -> anyhow::Result<()> {
    ensure_store(config_dir)?;
    let name = profile_name(name)?;
    let dir = profiles_dir(config_dir);
    fs::create_dir_all(&dir)?;
    fs::copy(rules_file(config_dir), dir.join(format!("{name}.rules")))?;
    fs::copy(
        settings_file(config_dir),
        dir.join(format!("{name}.settings")),
    )?;
    Ok(())
}

fn apply_profile(config_dir: &Path, name: &str) -> anyhow::Result<()> {
    ensure_store(config_dir)?;
    let name = profile_name(name)?;
    let dir = profiles_dir(config_dir);
    let rules = dir.join(format!("{name}.rules"));
    let settings = dir.join(format!("{name}.settings"));
    if !rules.exists() || !settings.exists() {
        bail!("profile not found: {name}");
    }
    fs::copy(rules, rules_file(config_dir))?;
    fs::copy(settings, settings_file(config_dir))?;
    fs::write(temp_rules_file(config_dir), "")?;
    sync_legacy_json(config_dir)?;
    Ok(())
}

fn profile_name(name: &str) -> anyhow::Result<String> {
    if name.is_empty()
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        bail!("invalid profile name: {name}");
    }
    Ok(name.to_string())
}

fn set_rule(config_dir: &Path, target: &str, scope: &str, value: u32) -> anyhow::Result<()> {
    ensure_store(config_dir)?;
    if !is_valid_target(target) {
        bail!("invalid package target: {target}");
    }
    let mode = get_default_mode(config_dir)?;
    let mut rules = read_rules(config_dir)?;
    let mut bits = rules
        .get(target)
        .copied()
        .unwrap_or_else(|| mode.default_rule());
    bits.set(scope, value)?;
    rules.insert(target.to_string(), bits);
    save_rules(config_dir, rules)?;
    remove_temp_rule(config_dir, target)
}

fn list_rules(config_dir: &Path) -> anyhow::Result<()> {
    println!("defaultMode={}", get_default_mode(config_dir)?.as_str());
    let rules = read_rules(config_dir)?;
    if rules.is_empty() {
        println!("No fire-su rules configured");
    }
    let apps = list_apps();
    for (target, bits) in rules {
        let uid = apps
            .iter()
            .find(|app| app.target() == target || app.package_name == target)
            .map(|app| app.uid.to_string())
            .unwrap_or_else(|| "not-installed".to_string());
        println!(
            "{} uid={} internet={} wifi={} mobile={} vpn={} lan={} dns={}",
            target, uid, bits.internet, bits.wifi, bits.mobile, bits.vpn, bits.lan, bits.dns
        );
    }
    Ok(())
}

fn export_rules(config_dir: &Path) -> anyhow::Result<()> {
    let temp = read_temp_rules(config_dir)?;
    let mut merged = read_rules(config_dir)?
        .into_iter()
        .map(|(target, bits)| (target, bits, None))
        .collect::<Vec<_>>();
    for (target, rule) in temp {
        merged.retain(|(existing, _, _)| existing != &target);
        merged.push((target, rule.bits, Some(rule.expires_at)));
    }
    merged.sort_by(|a, b| a.0.cmp(&b.0));
    let rules = merged
        .into_iter()
        .map(|(target, bits, temporary_until)| Rule::new(target, bits, temporary_until))
        .collect();
    let export = ExportRules {
        version: 6,
        default_mode: get_default_mode(config_dir)?.as_str().to_string(),
        rules,
    };
    print!("{}", serde_json::to_string(&export)?);
    Ok(())
}

fn sync_legacy_json(config_dir: &Path) -> anyhow::Result<()> {
    let mut packages = BTreeSet::new();
    for (target, bits) in effective_rules(config_dir)? {
        if bits.any() {
            packages.insert(target_package(&target).to_string());
        }
    }
    fs::write(
        legacy_json_file(config_dir),
        serde_json::to_string(&packages)?,
    )?;
    Ok(())
}

fn list_apps() -> Vec<AppInfo> {
    let mut apps = BTreeMap::new();
    let users = list_user_ids();
    for user in users {
        let label = user_label(user);
        for (flag, kind) in [("-3", "user"), ("-s", "system")] {
            let output = command_output(
                "pm",
                &["list", "packages", flag, "-U", "--user", &user.to_string()],
            );
            for line in output.lines() {
                if let Some((package_name, uid)) = parse_pm_package(line) {
                    apps.insert(
                        format!("{package_name}@{user}"),
                        AppInfo {
                            package_name,
                            uid,
                            user,
                            user_label: label.clone(),
                            kind: kind.to_string(),
                        },
                    );
                }
            }
        }
    }

    if apps.is_empty() {
        if let Ok(packages) = fs::read_to_string("/data/system/packages.list") {
            for line in packages.lines() {
                let parts: Vec<_> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    if let Ok(uid) = parts[1].parse() {
                        apps.insert(
                            format!("{}@0", parts[0]),
                            AppInfo {
                                package_name: parts[0].to_string(),
                                uid,
                                user: 0,
                                user_label: "Owner".to_string(),
                                kind: "user".to_string(),
                            },
                        );
                    }
                }
            }
        }
    }

    apps.into_values().collect()
}

fn list_user_ids() -> Vec<u32> {
    let output = format!(
        "{}\n{}",
        command_output("cmd", &["user", "list"]),
        command_output("pm", &["list", "users"])
    );
    let mut users = BTreeSet::new();
    for line in output.lines() {
        if let Some(start) = line.find("UserInfo{") {
            let rest = &line[start + "UserInfo{".len()..];
            if let Some(end) = rest.find(':') {
                if let Ok(user) = rest[..end].parse() {
                    users.insert(user);
                }
            }
        }
    }
    if users.is_empty() {
        users.insert(0);
    }
    users.into_iter().collect()
}

fn user_label(user: u32) -> String {
    if user == 0 {
        "Owner".to_string()
    } else {
        format!("User {user}")
    }
}

fn parse_pm_package(line: &str) -> Option<(String, u32)> {
    let mut package_name = None;
    let mut uid = None;
    for field in line.split_whitespace() {
        if let Some(value) = field.strip_prefix("package:") {
            package_name = Some(value.to_string());
        } else if let Some(value) = field.strip_prefix("uid:") {
            uid = value.parse().ok();
        }
    }
    Some((package_name?, uid?))
}

fn command_output(program: &str, args: &[&str]) -> String {
    Command::new(program)
        .args(args)
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).into_owned())
        .unwrap_or_default()
}

fn parse_enabled(value: &str) -> anyhow::Result<u32> {
    match value {
        "1" | "true" | "TRUE" | "yes" | "YES" | "on" | "ON" => Ok(1),
        "0" | "false" | "FALSE" | "no" | "NO" | "off" | "OFF" => Ok(0),
        _ => bail!("invalid value: {value}"),
    }
}

fn bit(value: &str) -> u32 {
    matches!(value, "1" | "on" | "true").into()
}

fn is_valid_package(package: &str) -> bool {
    package.contains('.')
        && package
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_')
}

fn is_valid_target(target: &str) -> bool {
    let package = target_package(target);
    if !is_valid_package(package) {
        return false;
    }
    target_user(target)
        .map(|user| user.parse::<u32>().is_ok())
        .unwrap_or(true)
}

fn target_package(target: &str) -> &str {
    target
        .split_once('@')
        .map(|(package, _)| package)
        .unwrap_or(target)
}

fn target_user(target: &str) -> Option<&str> {
    target.split_once('@').map(|(_, user)| user)
}

fn is_wifi(name: &str) -> bool {
    name.starts_with("wlan") || name.starts_with("wifi") || name.starts_with("swlan")
}

fn is_mobile(name: &str) -> bool {
    ["rmnet", "ccmni", "ccemni", "pdp", "wwan", "cellular"]
        .iter()
        .any(|prefix| name.starts_with(prefix))
}

fn is_vpn(name: &str) -> bool {
    ["tun", "tap", "ppp", "wg", "ipsec"]
        .iter()
        .any(|prefix| name.starts_with(prefix))
}

fn iface_class(name: &str) -> &'static str {
    if is_wifi(name) {
        "wifi"
    } else if is_mobile(name) {
        "mobile"
    } else if is_vpn(name) {
        "vpn"
    } else {
        "other"
    }
}

fn format_iface_indexes(ifaces: &HashMap<String, u32>) -> String {
    let mut rows = ifaces
        .iter()
        .map(|(name, ifindex)| format!("{name}:{ifindex}:{}", iface_class(name)))
        .collect::<Vec<_>>();
    rows.sort();
    if rows.is_empty() {
        "none".to_string()
    } else {
        rows.join(",")
    }
}

fn format_rule_bits(bits: RuleBits) -> String {
    format!(
        "internet={} wifi={} mobile={} vpn={} lan={} dns={} mask={}",
        bits.internet,
        bits.wifi,
        bits.mobile,
        bits.vpn,
        bits.lan,
        bits.dns,
        bits.mask()
    )
}

fn current_uid() -> u32 {
    unsafe { libc::getuid() }
}

fn current_euid() -> u32 {
    unsafe { libc::geteuid() }
}

fn kernel_version() -> String {
    let version = command_output("uname", &["-a"]);
    if version.trim().is_empty() {
        "unknown".to_string()
    } else {
        version.trim().to_string()
    }
}

fn read_cgroup_mounts() -> Vec<String> {
    fs::read_to_string("/proc/mounts")
        .unwrap_or_default()
        .lines()
        .filter(|line| line.contains(" cgroup") || line.contains(" cgroup2 "))
        .map(ToString::to_string)
        .collect()
}

fn config_stamp(config_dir: &Path) -> String {
    let rules = fs::metadata(rules_file(config_dir))
        .and_then(|m| m.modified())
        .ok();
    let settings = fs::metadata(settings_file(config_dir))
        .and_then(|m| m.modified())
        .ok();
    let temp = fs::metadata(temp_rules_file(config_dir))
        .and_then(|m| m.modified())
        .ok();
    format!("{rules:?}:{settings:?}:{temp:?}:{}", unix_now() / 30)
}

fn write_reload_stamp(config_dir: &Path) -> anyhow::Result<()> {
    fs::write(reload_file(config_dir), format!("{}\n", std::process::id()))?;
    Ok(())
}

fn write_pid(config_dir: &Path) -> anyhow::Result<()> {
    fs::write(pid_file(config_dir), format!("{}\n", std::process::id()))?;
    Ok(())
}

fn pid_belongs_to_fire_su(pid: i32) -> bool {
    let cmdline = fs::read(format!("/proc/{pid}/cmdline")).unwrap_or_default();
    String::from_utf8_lossy(&cmdline).contains("fire-su")
}

fn rules_file(config_dir: &Path) -> PathBuf {
    config_dir.join("rules.db")
}

fn settings_file(config_dir: &Path) -> PathBuf {
    config_dir.join("settings.conf")
}

fn legacy_json_file(config_dir: &Path) -> PathBuf {
    config_dir.join("isolated.json")
}

fn reload_file(config_dir: &Path) -> PathBuf {
    config_dir.join("reload")
}

fn pid_file(config_dir: &Path) -> PathBuf {
    config_dir.join("fire-su.pid")
}

fn daemon_log_file(config_dir: &Path) -> PathBuf {
    config_dir.join("fire-su.log")
}

fn temp_rules_file(config_dir: &Path) -> PathBuf {
    config_dir.join("temporary.db")
}

fn profiles_dir(config_dir: &Path) -> PathBuf {
    config_dir.join("profiles")
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn reason_name(reason: u32) -> &'static str {
    match reason {
        0 => "allowed",
        BLOCK_INTERNET => "internet",
        BLOCK_WIFI => "wifi",
        BLOCK_MOBILE => "mobile",
        BLOCK_VPN => "vpn",
        BLOCK_LAN => "lan",
        BLOCK_DNS => "dns",
        _ => "blocked",
    }
}

fn doctor_report(opt: &Opt) -> DoctorReport {
    let daemon_running = daemon_reachable(&opt.bind_addr);
    let cgroup_path = resolve_cgroup_path(&opt.cgroup_path);
    let cgroup = cgroup_path.exists();
    let bpf_filesystem = Path::new("/sys/fs/bpf").exists();
    let android_arm64 = cfg!(target_arch = "aarch64") || std::env::consts::ARCH == "aarch64";
    let mut warnings = Vec::new();

    if !daemon_running {
        warnings.push("fire-su eBPF daemon is not reachable".to_string());
        if let Some(log) = read_daemon_log_tail(&opt.config_dir) {
            warnings.push(format!("recent daemon log: {log}"));
        }
    }
    if !cgroup {
        warnings.push(format!("cgroup path is missing: {}", cgroup_path.display()));
    }
    if !bpf_filesystem {
        warnings.push("BPF filesystem is not mounted at /sys/fs/bpf".to_string());
    }
    if !android_arm64 {
        warnings.push("this packaged binary is intended for Android ARM64".to_string());
    }

    DoctorReport {
        engine: "ebpf",
        daemon: if daemon_running { "running" } else { "stopped" },
        cgroup,
        bpf_filesystem,
        android_arm64,
        warnings,
    }
}
