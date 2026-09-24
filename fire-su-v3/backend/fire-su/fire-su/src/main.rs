use anyhow::{Context as _, bail};
use axum::{
    Json, Router,
    extract::State,
    http::StatusCode,
    routing::{get, post},
};
use aya::{
    maps::HashMap as BpfHashMap,
    programs::{CgroupSkb, CgroupSkbAttachType, loaded_programs},
};
use clap::{Parser, Subcommand};
use fire_su_common::{BlockEvent, TrafficStats};
use futures::stream::StreamExt;
use log::{debug, info, warn};
use netlink_packet_core::NetlinkPayload;
use netlink_packet_route::{RouteNetlinkMessage, link::LinkAttribute};
use rtnetlink::{MulticastGroup, new_connection, new_multicast_connection};
use serde::Serialize;
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    fs,
    io::{BufRead, Read, Write},
    os::{
        fd::{AsFd, AsRawFd},
        unix::{fs::PermissionsExt, net::UnixStream, process::CommandExt},
    },
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
const PACKAGES_LIST: &str = "/data/system/packages.list";
const USERS_DIR: &str = "/data/system/users";
const BLOCK_INTERNET: u32 = 1 << 0;
const BLOCK_WIFI: u32 = 1 << 1;
const BLOCK_MOBILE: u32 = 1 << 2;
const BLOCK_VPN: u32 = 1 << 3;
const BLOCK_LAN: u32 = 1 << 4;
const BPF_PROG_ATTACH: libc::c_uint = 8;
const BPF_PROG_DETACH: libc::c_uint = 9;
const BPF_PROG_QUERY: libc::c_uint = 16;
const BPF_CGROUP_INET_EGRESS: u32 = 1;
const BPF_F_ALLOW_MULTI: u32 = 1 << 1;

#[derive(Debug, Parser)]
#[command(name = "fire-su")]
struct Opt {
    #[arg(long, default_value = DEFAULT_CONFIG_DIR)]
    config_dir: PathBuf,

    #[arg(short, long, default_value = DEFAULT_CGROUP_PATH)]
    cgroup_path: PathBuf,

    /// Control socket, defaults to <config-dir>/fire-su.sock
    #[arg(short, long)]
    socket: Option<PathBuf>,

    #[command(subcommand)]
    command: Option<CliCommand>,
}

impl Opt {
    fn socket(&self) -> PathBuf {
        self.socket
            .clone()
            .unwrap_or_else(|| self.config_dir.join("fire-su.sock"))
    }
}

#[derive(Debug, Subcommand)]
enum CliCommand {
    List,
    Export,
    #[command(name = "list-apps")]
    ListApps,
    #[command(name = "app-icon")]
    AppIcon {
        package: String,
    },
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
    /// Replace whole rules from stdin, one `target|wifi|mobile|vpn|lan` per line
    #[command(name = "stage-rules")]
    StageRules,
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
            Self::Whitelist => RuleBits::from_visible(1, 1, 1, 1),
        }
    }
}

// `internet` is not set on its own: it is on exactly when Wi-Fi, mobile and
// VPN are all blocked, and then also covers interfaces we can't classify.
// Keeping it independent let the WebUI (which only shows the four visible
// bits) leave apps fully blocked after the user allowed a network.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
struct RuleBits {
    internet: u32,
    wifi: u32,
    mobile: u32,
    vpn: u32,
    lan: u32,
}

impl RuleBits {
    fn from_visible(wifi: u32, mobile: u32, vpn: u32, lan: u32) -> Self {
        let mut bits = Self {
            internet: 0,
            wifi,
            mobile,
            vpn,
            lan,
        };
        bits.normalize();
        bits
    }

    // Columns are internet|wifi|mobile|vpn|lan[|dns]. A lone internet=1 from
    // the CLI means all WAN blocked. With dns=1 it is the old whitelist default
    // after the user cleared every network in the WebUI, which meant "allow".
    fn from_columns(columns: &[&str]) -> Self {
        let internet = bit(columns[0]);
        let dns = columns.get(5).map(|value| bit(value)).unwrap_or(0);
        let (mut wifi, mut mobile, mut vpn) = (bit(columns[1]), bit(columns[2]), bit(columns[3]));
        if internet == 1 && dns == 0 && wifi == 0 && mobile == 0 && vpn == 0 {
            (wifi, mobile, vpn) = (1, 1, 1);
        }
        Self::from_visible(wifi, mobile, vpn, bit(columns[4]))
    }

    fn normalize(&mut self) {
        self.internet = self.wifi & self.mobile & self.vpn;
    }

    fn mask(self) -> u32 {
        (self.internet * BLOCK_INTERNET)
            | (self.wifi * BLOCK_WIFI)
            | (self.mobile * BLOCK_MOBILE)
            | (self.vpn * BLOCK_VPN)
            | (self.lan * BLOCK_LAN)
    }

    fn any(self) -> bool {
        self.mask() != 0
    }

    fn set(&mut self, scope: &str, value: u32) -> anyhow::Result<()> {
        match scope {
            "wifi" => self.wifi = value,
            "mobile" => self.mobile = value,
            "vpn" => self.vpn = value,
            "lan" => self.lan = value,
            "internet" => {
                self.wifi = value;
                self.mobile = value;
                self.vpn = value;
            }
            "visible" | "networks" | "all" => {
                self.wifi = value;
                self.mobile = value;
                self.vpn = value;
                self.lan = value;
            }
            "dns" => bail!("dns rules were removed; use internet or lan"),
            _ => bail!("invalid scope: {scope}"),
        }
        self.normalize();
        Ok(())
    }

    // Trailing 0 keeps the dns column so older builds still parse the file.
    fn columns(self) -> String {
        format!(
            "{}|{}|{}|{}|{}|0",
            self.internet, self.wifi, self.mobile, self.vpn, self.lan
        )
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
            temporary_until,
        }
    }
}

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
    iface: String,
    reason: String,
    bytes: u32,
    // seconds since the packet was dropped
    ago: u64,
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
    socket: String,
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
    program: Option<String>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    program: Option<&'static str>,
}

impl StatusResponse {
    fn ok() -> Self {
        Self {
            status: "ok".to_string(),
            program: None,
        }
    }
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
    program_mode: FirewallProgramMode,
    iface_indexes: Mutex<HashMap<String, u32>>,
    // `pm list packages` takes seconds per user, so only rerun it when the
    // package database changes.
    apps: Mutex<(String, Vec<AppInfo>)>,
}

type SharedState = Arc<AppState>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FirewallProgramMode {
    Advanced,
    Basic,
    UidOnly,
    Minimal,
}

impl FirewallProgramMode {
    fn program_name(self) -> &'static str {
        match self {
            Self::Advanced => "fire_su",
            Self::Basic => "fire_su_basic",
            Self::UidOnly => "fire_su_uid",
            Self::Minimal => "fire_su_min",
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Advanced => "advanced",
            Self::Basic => "basic",
            Self::UidOnly => "uid-only",
            Self::Minimal => "minimal",
        }
    }

    fn uses_interface_rules(self) -> bool {
        matches!(self, Self::Advanced | Self::Basic)
    }

    fn uid_mask(self, bits: RuleBits) -> u32 {
        match self {
            Self::Advanced | Self::Basic => bits.mask() & (BLOCK_INTERNET | BLOCK_LAN),
            Self::UidOnly | Self::Minimal => bits.mask(),
        }
    }
}

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
        CliCommand::AppIcon { package } => print_app_icon(&package)?,
        CliCommand::Apply => apply_runtime(&opt).await?,
        CliCommand::Disable => disable_runtime(&opt)?,
        CliCommand::Status => status_runtime(&opt)?,
        CliCommand::Stats => print!("{}", daemon_request(&opt.socket(), "GET", "/api/stats")?),
        CliCommand::Logs => print!("{}", daemon_request(&opt.socket(), "GET", "/api/logs")?),
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
        CliCommand::StageRules => {
            let count = stage_rules(&opt.config_dir, std::io::stdin().lock())?;
            println!("Staged {count} rules");
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
                write_atomic(&rules_file(&opt.config_dir), "")?;
                write_atomic(&temp_rules_file(&opt.config_dir), "")?;
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
    // Claim the socket before touching the kernel. A second daemon would
    // otherwise attach another copy of the program and only then fail.
    let socket = opt.socket();
    let listener = bind_control_socket(&socket)?;
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
        "fire-su: config_dir={} socket={}",
        opt.config_dir.display(),
        socket.display()
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
        debug!("failed to initialize eBPF logger: {e}");
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
    let program_mode = load_firewall_program(&mut ebpf)?;
    eprintln!(
        "fire-su: eBPF program loaded mode={} program={}",
        program_mode.label(),
        program_mode.program_name()
    );

    let state = Arc::new(AppState {
        bpf_map: Mutex::new(block_list),
        stats_map: Mutex::new(stats_map),
        events_map: Mutex::new(events_map),
        config_dir: opt.config_dir.clone(),
        program_mode,
        iface_indexes: Mutex::new(HashMap::new()),
        apps: Mutex::new((String::new(), Vec::new())),
    });

    fetch_initial_interfaces(&state).await;
    let initial_interfaces = state.iface_indexes.lock().await.clone();
    eprintln!(
        "fire-su: initial interfaces: {}",
        format_iface_indexes(&initial_interfaces)
    );
    sync_bpf_map(&state).await?;

    let program: &mut CgroupSkb = ebpf
        .program_mut(program_mode.program_name())
        .with_context(|| format!("{} missing", program_mode.program_name()))?
        .try_into()?;
    let cgroup = fs::File::open(&cgroup_path).with_context(|| {
        format!(
            "open {} (exists={}, uid={}, euid={})",
            cgroup_path.display(),
            cgroup_path.exists(),
            current_uid(),
            current_euid()
        )
    })?;
    let cgroup_fd = cgroup.as_fd().as_raw_fd();
    detach_stale_programs(cgroup_fd);
    let program_fd = program.fd().context("get fire_su eBPF program fd")?;
    let program_fd = program_fd.as_fd().as_raw_fd();
    eprintln!(
        "fire-su: attaching eBPF program_fd={program_fd} cgroup_fd={cgroup_fd} attach_type=egress"
    );
    attach_cgroup_skb_legacy(program_fd, cgroup_fd, CgroupSkbAttachType::Egress)
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
        .with_state(state);
    write_pid(&opt.config_dir)?;
    eprintln!("fire-su: API listening on {}", socket.display());
    info!("fire-su eBPF daemon listening on {}", socket.display());

    let serve_result = axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("serve fire-su API")
        .map(|_| ());
    if let Err(error) = &serve_result {
        eprintln!("fire-su: API server stopped: {error:#}");
    } else {
        eprintln!("fire-su: API server stopped");
    }

    // Legacy attachments outlive the process, so without this the last
    // rules would stay enforced until reboot.
    match detach_cgroup_skb_legacy(program_fd, cgroup_fd, CgroupSkbAttachType::Egress) {
        Ok(()) => eprintln!("fire-su: eBPF program detached"),
        Err(error) => eprintln!("fire-su: detach failed: {error:#}"),
    }

    let _ = fs::remove_file(pid_file(&opt.config_dir));
    let _ = fs::remove_file(&socket);
    serve_result
}

async fn shutdown_signal() {
    use tokio::signal::unix::{SignalKind, signal};
    let (Ok(mut term), Ok(mut int)) = (
        signal(SignalKind::terminate()),
        signal(SignalKind::interrupt()),
    ) else {
        std::future::pending::<()>().await;
        return;
    };
    tokio::select! {
        _ = term.recv() => eprintln!("fire-su: SIGTERM received"),
        _ = int.recv() => eprintln!("fire-su: SIGINT received"),
    }
}

fn bind_control_socket(path: &Path) -> anyhow::Result<tokio::net::UnixListener> {
    if UnixStream::connect(path).is_ok() {
        bail!("fire-su daemon already running on {}", path.display());
    }
    let _ = fs::remove_file(path);
    let listener = tokio::net::UnixListener::bind(path)
        .with_context(|| format!("bind control socket {}", path.display()))?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(listener)
}

async fn handle_stats(State(state): State<SharedState>) -> Json<Vec<StatRow>> {
    Json(read_stats(&state).await)
}

async fn handle_logs(State(state): State<SharedState>) -> Json<Vec<LogRow>> {
    Json(read_logs(&state).await)
}

async fn handle_health(State(state): State<SharedState>) -> Json<StatusResponse> {
    Json(StatusResponse {
        status: "ok".to_string(),
        program: Some(state.program_mode.label()),
    })
}

async fn handle_reload(State(state): State<SharedState>) -> (StatusCode, Json<StatusResponse>) {
    match sync_bpf_map(&state).await {
        Ok(()) => (StatusCode::OK, Json(StatusResponse::ok())),
        Err(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(StatusResponse {
                status: format!("error: {error}"),
                program: None,
            }),
        ),
    }
}

async fn sync_bpf_map(state: &AppState) -> anyhow::Result<()> {
    let mode = get_default_mode(&state.config_dir)?;
    let rules = effective_rules(&state.config_dir)?;
    let apps = cached_apps(state).await;
    let iface_indexes = state.iface_indexes.lock().await.clone();
    let desired = desired_entries(mode, &rules, &apps, state.program_mode, &iface_indexes);

    let mut bpf_map = state.bpf_map.lock().await;
    let current: HashMap<u64, u32> = bpf_map.iter().filter_map(Result::ok).collect();
    // Update in place instead of clearing first: a cleared map lets every
    // blocked app through until the refill finishes.
    let mut inserted = 0usize;
    for (key, value) in &desired {
        if current.get(key) != Some(value) {
            bpf_map.insert(*key, *value, 0)?;
            inserted += 1;
        }
    }
    let mut removed = 0usize;
    for key in current.keys() {
        if !desired.contains_key(key) {
            let _ = bpf_map.remove(key);
            removed += 1;
        }
    }
    eprintln!(
        "fire-su: sync mode={} program={} rules={} apps={} interfaces={} entries={} +{} -{}",
        mode.as_str(),
        state.program_mode.label(),
        rules.len(),
        apps.len(),
        iface_indexes.len(),
        desired.len(),
        inserted,
        removed
    );
    Ok(())
}

async fn cached_apps(state: &AppState) -> Vec<AppInfo> {
    let stamp = apps_stamp();
    let mut cache = state.apps.lock().await;
    if cache.0 != stamp || cache.1.is_empty() {
        let apps = tokio::task::spawn_blocking(list_apps)
            .await
            .unwrap_or_default();
        *cache = (stamp, apps);
    }
    cache.1.clone()
}

fn desired_entries(
    mode: Mode,
    rules: &BTreeMap<String, RuleBits>,
    apps: &[AppInfo],
    program_mode: FirewallProgramMode,
    iface_indexes: &HashMap<String, u32>,
) -> HashMap<u64, u32> {
    let mut entries = HashMap::new();
    for app in apps {
        let target = app.target();
        let bits = rules
            .get(&target)
            .or_else(|| rules.get(&app.package_name))
            .copied()
            .unwrap_or_else(|| default_rule_for(mode, app.uid));
        if !bits.any() {
            continue;
        }
        // Packages can share a UID; blocking wins over allowing.
        let global = program_mode.uid_mask(bits);
        if global != 0 {
            *entries.entry(app.uid as u64).or_insert(0) |= global;
        }
        // internet=1 already drops non-LAN traffic on every interface.
        if !program_mode.uses_interface_rules() || bits.internet == 1 {
            continue;
        }
        for (name, ifindex) in iface_indexes {
            let reason = match iface_class(name) {
                "wifi" if bits.wifi == 1 => BLOCK_WIFI,
                "mobile" if bits.mobile == 1 => BLOCK_MOBILE,
                "vpn" if bits.vpn == 1 => BLOCK_VPN,
                _ => continue,
            };
            entries.insert(((*ifindex as u64) << 32) | app.uid as u64, reason);
        }
    }
    entries
}

// Core Android UIDs (below 10000: system, network stack, bluetooth...) are not
// swept up by whitelist mode. Blocking them breaks connectivity checks and
// can make Android drop a working Wi-Fi. Explicit rules still apply.
fn default_rule_for(mode: Mode, uid: u32) -> RuleBits {
    if mode == Mode::Whitelist && uid % 100_000 < 10_000 {
        RuleBits::default()
    } else {
        mode.default_rule()
    }
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
    let now = monotonic_ns();
    let names: HashMap<u32, String> = state
        .iface_indexes
        .lock()
        .await
        .iter()
        .map(|(name, index)| (*index, name.clone()))
        .collect();
    let events_map = state.events_map.lock().await;
    let mut events: Vec<_> = events_map
        .iter()
        .filter_map(Result::ok)
        .map(|(_, event)| event)
        .filter(|event| event.reason != 0)
        .collect();
    events.sort_by_key(|event| std::cmp::Reverse(event.seen));
    events.truncate(100);
    events
        .into_iter()
        .map(|event| LogRow {
            uid: event.uid,
            ifindex: event.ifindex,
            iface: names.get(&event.ifindex).cloned().unwrap_or_default(),
            reason: reason_name(event.reason).to_string(),
            bytes: event.bytes,
            ago: now.saturating_sub(event.seen) / 1_000_000_000,
        })
        .collect()
}

fn link_name(attributes: &[LinkAttribute]) -> Option<String> {
    attributes.iter().find_map(|attr| match attr {
        LinkAttribute::IfName(name) => Some(name.clone()),
        _ => None,
    })
}

async fn monitor_netlink(state: SharedState) {
    // A plain connection never joins RTNLGRP_LINK, so no link events arrive.
    // That left VPN tunnels and mobile interfaces created after boot unfiltered.
    let Ok((connection, _, mut messages)) = new_multicast_connection(&[MulticastGroup::Link])
    else {
        eprintln!("fire-su: netlink monitor failed to start");
        warn!("failed to open netlink monitor");
        return;
    };
    tokio::spawn(connection);

    while let Some((message, _)) = messages.next().await {
        let change = match message.payload {
            NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewLink(msg)) => {
                let Some(name) = link_name(&msg.attributes) else {
                    continue;
                };
                let index = msg.header.index;
                let mut ifaces = state.iface_indexes.lock().await;
                if ifaces.get(&name) == Some(&index) {
                    continue;
                }
                ifaces.retain(|_, existing| *existing != index);
                ifaces.insert(name.clone(), index);
                format!(
                    "up ifname={name} ifindex={index} class={}",
                    iface_class(&name)
                )
            }
            NetlinkPayload::InnerMessage(RouteNetlinkMessage::DelLink(msg)) => {
                let index = msg.header.index;
                let mut ifaces = state.iface_indexes.lock().await;
                let before = ifaces.len();
                ifaces.retain(|_, existing| *existing != index);
                if ifaces.len() == before {
                    continue;
                }
                format!("down ifindex={index}")
            }
            _ => continue,
        };
        eprintln!("fire-su: interface {change}");
        if let Err(error) = sync_bpf_map(&state).await {
            eprintln!("fire-su: sync after interface change failed: {error:#}");
        }
    }
    eprintln!("fire-su: netlink monitor stopped");
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
        if let Some(name) = link_name(&msg.attributes) {
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
        let temp_due = next_temp_expiry(&state.config_dir).is_some_and(|at| at <= unix_now());
        if next == last && !temp_due {
            continue;
        }
        if let Err(error) = sync_bpf_map(&state).await {
            eprintln!("fire-su: config reload failed: {error:#}");
        }
        // Expired temp rules are pruned from the file during the sync.
        last = config_stamp(&state.config_dir);
    }
}

async fn apply_runtime(opt: &Opt) -> anyhow::Result<()> {
    ensure_store(&opt.config_dir)?;
    write_reload_stamp(&opt.config_dir)?;
    let socket = opt.socket();
    match notify_daemon(&socket) {
        NotifyResult::Reloaded => {}
        NotifyResult::Failed(error) => bail!("fire-su daemon reload failed: {error}"),
        NotifyResult::Unreachable => {
            start_daemon_background(opt)?;
            let mut last_error = None;
            for _ in 0..20 {
                time::sleep(Duration::from_millis(300)).await;
                match notify_daemon(&socket) {
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
    let pid = fs::read_to_string(pid_file(&opt.config_dir))
        .ok()
        .and_then(|pid| pid.trim().parse::<i32>().ok())
        .filter(|pid| pid_belongs_to_fire_su(*pid));
    if let Some(pid) = pid {
        unsafe {
            libc::kill(pid, libc::SIGTERM);
        }
        // Wait for the detach, callers like uninstall.sh delete the config dir next.
        for _ in 0..30 {
            if !Path::new(&format!("/proc/{pid}")).exists() {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
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
    let health = daemon_health(&opt.socket());
    println!(
        "daemon={}",
        if health.is_some() {
            "running"
        } else {
            "stopped"
        }
    );
    if let Some(program) = health.as_deref().and_then(health_program) {
        println!("program={program}");
    }
    Ok(())
}

fn notify_daemon(socket: &Path) -> NotifyResult {
    let Ok(mut stream) = UnixStream::connect(socket) else {
        return NotifyResult::Unreachable;
    };
    // A reload after an app install reruns `pm`, which can take a while.
    if let Err(error) = stream.set_read_timeout(Some(Duration::from_secs(20))) {
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

fn daemon_health(socket: &Path) -> Option<String> {
    daemon_request(socket, "GET", "/api/health").ok()
}

fn health_program(body: &str) -> Option<String> {
    serde_json::from_str::<serde_json::Value>(body)
        .ok()?
        .get("program")?
        .as_str()
        .map(ToString::to_string)
}

fn load_firewall_program(ebpf: &mut aya::Ebpf) -> anyhow::Result<FirewallProgramMode> {
    let mut errors = Vec::new();
    for mode in [
        FirewallProgramMode::Advanced,
        FirewallProgramMode::Basic,
        FirewallProgramMode::UidOnly,
        FirewallProgramMode::Minimal,
    ] {
        let Some(program) = ebpf.program_mut(mode.program_name()) else {
            errors.push(format!("{}: missing", mode.program_name()));
            continue;
        };
        let program: &mut CgroupSkb = match program.try_into() {
            Ok(program) => program,
            Err(error) => {
                errors.push(format!("{}: {error:#}", mode.program_name()));
                continue;
            }
        };
        match program.load() {
            Ok(()) => {
                if !errors.is_empty() {
                    eprintln!(
                        "fire-su: using fallback eBPF program mode={} after load errors: {}",
                        mode.label(),
                        errors.join(" | ")
                    );
                }
                return Ok(mode);
            }
            Err(error) => {
                errors.push(format!("{}: {error:#}", mode.program_name()));
            }
        }
    }
    bail!(
        "load fire-su eBPF program failed for all modes: {}",
        errors.join(" | ")
    );
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
    match bpf_prog_attach_cmd(
        BPF_PROG_ATTACH,
        prog_fd,
        cgroup_fd,
        attach_type,
        BPF_F_ALLOW_MULTI,
    ) {
        Ok(()) => Ok(()),
        Err(first_error) => {
            eprintln!(
                "fire-su: attach with BPF_F_ALLOW_MULTI failed: {first_error}; retrying without attach flags"
            );
            // Without ALLOW_MULTI the kernel swaps out whatever is attached,
            // usually netd's traffic accounting program. Leave a trace of it.
            for (id, name) in attached_programs(cgroup_fd) {
                eprintln!(
                    "fire-su: warning: exclusive attach replaces program id={id} name={name}"
                );
            }
            bpf_prog_attach_cmd(BPF_PROG_ATTACH, prog_fd, cgroup_fd, attach_type, 0)
                .with_context(|| {
                    format!(
                        "bpf_prog_attach failed for cgroup fd {cgroup_fd}; first BPF_F_ALLOW_MULTI error: {first_error}"
                    )
                })
        }
    }
}

fn detach_cgroup_skb_legacy(
    prog_fd: i32,
    cgroup_fd: i32,
    attach_type: CgroupSkbAttachType,
) -> anyhow::Result<()> {
    bpf_prog_attach_cmd(BPF_PROG_DETACH, prog_fd, cgroup_fd, attach_type, 0)
        .with_context(|| format!("bpf_prog_detach failed for cgroup fd {cgroup_fd}"))
}

fn bpf_prog_attach_cmd(
    cmd: libc::c_uint,
    prog_fd: i32,
    cgroup_fd: i32,
    attach_type: CgroupSkbAttachType,
    attach_flags: u32,
) -> anyhow::Result<()> {
    let mut attr = BpfProgAttachAttr {
        target_fd: cgroup_fd as u32,
        attach_bpf_fd: prog_fd as u32,
        attach_type: cgroup_skb_attach_type(attach_type),
        attach_flags,
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

#[repr(C)]
#[derive(Default)]
struct BpfProgQueryAttr {
    target_fd: u32,
    attach_type: u32,
    query_flags: u32,
    attach_flags: u32,
    prog_ids: u64,
    prog_cnt: u32,
    _pad: u32,
}

fn query_cgroup_programs(cgroup_fd: i32) -> anyhow::Result<Vec<u32>> {
    let mut ids = [0u32; 64];
    let mut attr = BpfProgQueryAttr {
        target_fd: cgroup_fd as u32,
        attach_type: BPF_CGROUP_INET_EGRESS,
        prog_ids: ids.as_mut_ptr() as u64,
        prog_cnt: ids.len() as u32,
        ..Default::default()
    };
    let ret = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            BPF_PROG_QUERY,
            &mut attr as *mut BpfProgQueryAttr,
            std::mem::size_of::<BpfProgQueryAttr>(),
        )
    };
    if ret != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(ids[..(attr.prog_cnt as usize).min(ids.len())].to_vec())
}

fn attached_programs(cgroup_fd: i32) -> Vec<(u32, String)> {
    let Ok(ids) = query_cgroup_programs(cgroup_fd) else {
        return Vec::new();
    };
    loaded_programs()
        .filter_map(Result::ok)
        .filter(|info| ids.contains(&info.id()))
        .map(|info| (info.id(), info.name_as_str().unwrap_or("?").to_string()))
        .collect()
}

// A daemon that died without detaching (crash, SIGKILL, old builds that
// ignored SIGTERM) leaves its program on the cgroup with frozen rules.
fn detach_stale_programs(cgroup_fd: i32) {
    let ids = match query_cgroup_programs(cgroup_fd) {
        Ok(ids) => ids,
        Err(error) => {
            eprintln!("fire-su: cannot query attached programs: {error:#}");
            return;
        }
    };
    for info in loaded_programs().filter_map(Result::ok) {
        if !ids.contains(&info.id()) {
            continue;
        }
        let name = info.name_as_str().unwrap_or("");
        if !name.starts_with("fire_su") {
            eprintln!(
                "fire-su: cgroup egress also has id={} name={name}",
                info.id()
            );
            continue;
        }
        let result = info.fd().map_err(anyhow::Error::from).and_then(|fd| {
            detach_cgroup_skb_legacy(
                fd.as_fd().as_raw_fd(),
                cgroup_fd,
                CgroupSkbAttachType::Egress,
            )
        });
        match result {
            Ok(()) => eprintln!(
                "fire-su: detached stale program id={} name={name}",
                info.id()
            ),
            Err(error) => eprintln!(
                "fire-su: failed to detach stale program id={}: {error:#}",
                info.id()
            ),
        }
    }
}

fn print_debug_report(opt: &Opt) -> anyhow::Result<()> {
    ensure_store(&opt.config_dir)?;
    let cgroup_path = resolve_cgroup_path(&opt.cgroup_path);
    let socket = opt.socket();
    let daemon_reachable = daemon_health(&socket).is_some();
    let active_rules = effective_rules(&opt.config_dir)?
        .into_iter()
        .map(|(target, bits)| DebugRule {
            target,
            internet: bits.internet,
            wifi: bits.wifi,
            mobile: bits.mobile,
            vpn: bits.vpn,
            lan: bits.lan,
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
        daemon_request(&socket, "GET", "/api/stats").ok()
    } else {
        None
    };
    let daemon_logs = if daemon_reachable {
        daemon_request(&socket, "GET", "/api/logs").ok()
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
        socket: socket.display().to_string(),
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

fn daemon_request(socket: &Path, method: &str, path: &str) -> anyhow::Result<String> {
    let mut stream = UnixStream::connect(socket)
        .with_context(|| format!("fire-su daemon is not running ({})", socket.display()))?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.write_all(http_request(method, path).as_bytes())?;
    let mut response = String::new();
    let _ = stream.read_to_string(&mut response);
    if !response.starts_with("HTTP/1.1 200") {
        bail!("daemon request failed: {}", http_error_summary(&response));
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
    let mut command = Command::new(exe);
    command
        .arg("--config-dir")
        .arg(&opt.config_dir)
        .arg("--cgroup-path")
        .arg(&cgroup_path)
        .arg("--socket")
        .arg(opt.socket())
        .arg("daemon")
        .stdin(Stdio::null())
        .stdout(Stdio::from(log))
        .stderr(Stdio::from(stderr));
    // Own session, so the daemon survives the WebUI shell that started it.
    unsafe {
        command.pre_exec(|| {
            libc::setsid();
            Ok(())
        });
    }
    command.spawn().context("start fire-su eBPF daemon")?;
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

// Rules are left alone on a mode switch. Pruning them against the new
// default used to wipe the whole allow-list when going whitelist -> blacklist.
fn set_default_mode(config_dir: &Path, mode: Mode) -> anyhow::Result<()> {
    ensure_store(config_dir)?;
    write_atomic(
        &settings_file(config_dir),
        format!("defaultMode={}\n", mode.as_str()),
    )
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
        rules.insert(parts[0].to_string(), RuleBits::from_columns(&parts[1..]));
    }
    Ok(rules)
}

fn save_rules(config_dir: &Path, rules: BTreeMap<String, RuleBits>) -> anyhow::Result<()> {
    let mut out = String::new();
    for (target, bits) in rules {
        out.push_str(&format!("{target}|{}\n", bits.columns()));
    }
    write_atomic(&rules_file(config_dir), out)?;
    sync_legacy_json(config_dir)?;
    Ok(())
}

// Blacklist allow-rules carry no information. Whitelist ones are kept even
// when they match the default, since core UIDs default to allowed there.
fn store_rule(rules: &mut BTreeMap<String, RuleBits>, mode: Mode, target: &str, bits: RuleBits) {
    if mode == Mode::Blacklist && !bits.any() {
        rules.remove(target);
    } else {
        rules.insert(target.to_string(), bits);
    }
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
                bits: RuleBits::from_columns(&parts[1..7]),
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
            "{target}|{}|{}\n",
            rule.bits.columns(),
            rule.expires_at
        ));
    }
    write_atomic(&temp_rules_file(config_dir), out)
}

fn next_temp_expiry(config_dir: &Path) -> Option<u64> {
    fs::read_to_string(temp_rules_file(config_dir))
        .ok()?
        .lines()
        .filter_map(|line| line.rsplit('|').next()?.parse().ok())
        .min()
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
        .unwrap_or_else(|| target_default(mode, target));
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
    let mut names = BTreeSet::new();
    for entry in fs::read_dir(dir)? {
        let name = entry?.file_name().to_string_lossy().into_owned();
        if let Some(name) = name.strip_suffix(".rules") {
            names.insert(name.to_string());
        }
    }
    for name in names {
        println!("{name}");
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
    write_atomic(&rules_file(config_dir), fs::read_to_string(rules)?)?;
    write_atomic(&settings_file(config_dir), fs::read_to_string(settings)?)?;
    write_atomic(&temp_rules_file(config_dir), "")?;
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
        .unwrap_or_else(|| target_default(mode, target));
    bits.set(scope, value)?;
    store_rule(&mut rules, mode, target, bits);
    save_rules(config_dir, rules)?;
    remove_temp_rule(config_dir, target)
}

// One process and one file write for the whole batch. The WebUI used to run
// a stage-set per toggle, which took minutes after a bulk template.
fn stage_rules(config_dir: &Path, input: impl BufRead) -> anyhow::Result<usize> {
    ensure_store(config_dir)?;
    let mut staged = Vec::new();
    for line in input.lines() {
        let line = line?;
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let parts: Vec<_> = line.split('|').collect();
        if parts.len() != 5 || !is_valid_target(parts[0]) {
            bail!("invalid rule line: {line}");
        }
        let bits = RuleBits::from_visible(
            parse_enabled(parts[1])?,
            parse_enabled(parts[2])?,
            parse_enabled(parts[3])?,
            parse_enabled(parts[4])?,
        );
        staged.push((parts[0].to_string(), bits));
    }
    let mode = get_default_mode(config_dir)?;
    let mut rules = read_rules(config_dir)?;
    let mut temp = read_temp_rules(config_dir)?;
    for (target, bits) in &staged {
        store_rule(&mut rules, mode, target, *bits);
        temp.remove(target);
    }
    save_rules(config_dir, rules)?;
    save_temp_rules(config_dir, &temp)?;
    Ok(staged.len())
}

fn target_default(mode: Mode, target: &str) -> RuleBits {
    match target_uid(target) {
        Some(uid) => default_rule_for(mode, uid),
        None => mode.default_rule(),
    }
}

// packages.list holds the app id; the per-user uid is user * 100000 + app id.
fn target_uid(target: &str) -> Option<u32> {
    let user: u32 = target_user(target).unwrap_or("0").parse().ok()?;
    let package = target_package(target);
    let list = fs::read_to_string(PACKAGES_LIST).ok()?;
    let app_id: u32 = list.lines().find_map(|line| {
        let mut fields = line.split_whitespace();
        (fields.next()? == package).then(|| fields.next()?.parse().ok())?
    })?;
    Some(user * 100_000 + app_id % 100_000)
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
            "{} uid={} internet={} wifi={} mobile={} vpn={} lan={}",
            target, uid, bits.internet, bits.wifi, bits.mobile, bits.vpn, bits.lan
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
        version: 7,
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

fn print_app_icon(package: &str) -> anyhow::Result<()> {
    if !is_valid_package(package) {
        bail!("invalid package: {package}");
    }
    for apk in package_apk_paths(package) {
        let mut candidates = icon_paths_from_badging(&apk);
        candidates.extend(fallback_icon_paths(&apk));
        let mut seen = BTreeSet::new();
        for entry in candidates {
            if !seen.insert(entry.clone()) {
                continue;
            }
            let Some(mime) = image_mime_for_path(&entry) else {
                continue;
            };
            if let Some(bytes) = extract_zip_entry(&apk, &entry) {
                if !bytes.is_empty() {
                    println!("data:{mime};base64,{}", base64_encode(&bytes));
                    return Ok(());
                }
            }
        }
    }
    bail!("app icon not found for {package}");
}

fn package_apk_paths(package: &str) -> Vec<PathBuf> {
    command_output("pm", &["path", package])
        .lines()
        .filter_map(|line| line.trim().strip_prefix("package:"))
        .map(PathBuf::from)
        .collect()
}

fn icon_paths_from_badging(apk: &Path) -> Vec<String> {
    let Some(apk_path) = apk.to_str() else {
        return Vec::new();
    };
    let mut output = command_output("aapt", &["dump", "badging", apk_path]);
    if output.is_empty() {
        output = command_output("aapt2", &["dump", "badging", apk_path]);
    }
    let mut density_icons = Vec::new();
    let mut generic_icons = Vec::new();
    for line in output.lines() {
        if let Some(rest) = line.strip_prefix("application-icon-") {
            if let Some((density, _)) = rest.split_once(':') {
                if let Some(path) = first_single_quoted(line) {
                    density_icons.push((density.parse::<u32>().unwrap_or(0), path));
                }
            }
        } else if line.starts_with("application-icon:") {
            if let Some(path) = first_single_quoted(line) {
                generic_icons.push(path);
            }
        } else if line.starts_with("application:") {
            if let Some(path) = quoted_attr(line, "icon") {
                generic_icons.push(path);
            }
        }
    }
    density_icons.sort_by(|a, b| b.0.cmp(&a.0));
    density_icons
        .into_iter()
        .map(|(_, path)| path)
        .chain(generic_icons)
        .collect()
}

fn fallback_icon_paths(apk: &Path) -> Vec<String> {
    let mut entries = zip_entries(apk);
    entries.retain(|entry| {
        let lower = entry.to_ascii_lowercase();
        image_mime_for_path(&lower).is_some()
            && (lower.contains("/ic_launcher")
                || lower.contains("/launcher_icon")
                || lower.contains("/icon.png")
                || lower.contains("/icon.webp"))
    });
    entries.sort_by_key(|entry| std::cmp::Reverse(icon_candidate_score(entry)));
    entries
}

fn icon_candidate_score(entry: &str) -> u32 {
    let lower = entry.to_ascii_lowercase();
    let mut score: u32 = 0;
    if lower.contains("/mipmap-") {
        score += 1000;
    }
    if lower.contains("ic_launcher") {
        score += 500;
    }
    if lower.contains("xxxhdpi") {
        score += 320;
    } else if lower.contains("xxhdpi") {
        score += 240;
    } else if lower.contains("xhdpi") {
        score += 160;
    } else if lower.contains("hdpi") {
        score += 120;
    } else if lower.contains("nodpi") {
        score += 80;
    } else if lower.contains("mdpi") {
        score += 40;
    }
    if lower.contains("round") {
        score = score.saturating_sub(100);
    }
    score
}

fn zip_entries(apk: &Path) -> Vec<String> {
    let mut stdout = Vec::new();
    for toybox in [false, true] {
        let output = if toybox {
            Command::new("toybox")
                .arg("unzip")
                .arg("-l")
                .arg(apk)
                .output()
        } else {
            Command::new("unzip").arg("-l").arg(apk).output()
        };
        if let Ok(output) = output {
            if output.status.success() && !output.stdout.is_empty() {
                stdout = output.stdout;
                break;
            }
        }
    }
    String::from_utf8_lossy(&stdout)
        .lines()
        .filter_map(|line| line.split_whitespace().last())
        .filter(|entry| entry.starts_with("res/"))
        .map(ToOwned::to_owned)
        .collect()
}

fn extract_zip_entry(apk: &Path, entry: &str) -> Option<Vec<u8>> {
    for toybox in [false, true] {
        let output = if toybox {
            Command::new("toybox")
                .arg("unzip")
                .arg("-p")
                .arg(apk)
                .arg(entry)
                .output()
        } else {
            Command::new("unzip").arg("-p").arg(apk).arg(entry).output()
        };
        if let Ok(output) = output {
            if output.status.success() && !output.stdout.is_empty() {
                return Some(output.stdout);
            }
        }
    }
    None
}

fn image_mime_for_path(path: &str) -> Option<&'static str> {
    let lower = path.to_ascii_lowercase();
    if lower.ends_with(".png") {
        Some("image/png")
    } else if lower.ends_with(".webp") {
        Some("image/webp")
    } else if lower.ends_with(".jpg") || lower.ends_with(".jpeg") {
        Some("image/jpeg")
    } else if lower.ends_with(".gif") {
        Some("image/gif")
    } else {
        None
    }
}

fn first_single_quoted(line: &str) -> Option<String> {
    let start = line.find('\'')? + 1;
    let end = line[start..].find('\'')? + start;
    Some(line[start..end].to_string())
}

fn quoted_attr(line: &str, name: &str) -> Option<String> {
    let pattern = format!("{name}='");
    let start = line.find(&pattern)? + pattern.len();
    let end = line[start..].find('\'')? + start;
    Some(line[start..end].to_string())
}

fn base64_encode(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut encoded = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0];
        let b1 = *chunk.get(1).unwrap_or(&0);
        let b2 = *chunk.get(2).unwrap_or(&0);
        encoded.push(TABLE[(b0 >> 2) as usize] as char);
        encoded.push(TABLE[(((b0 & 0b0000_0011) << 4) | (b1 >> 4)) as usize] as char);
        if chunk.len() > 1 {
            encoded.push(TABLE[(((b1 & 0b0000_1111) << 2) | (b2 >> 6)) as usize] as char);
        } else {
            encoded.push('=');
        }
        if chunk.len() > 2 {
            encoded.push(TABLE[(b2 & 0b0011_1111) as usize] as char);
        } else {
            encoded.push('=');
        }
    }
    encoded
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
    package == "android"
        || (package.contains('.')
            && package
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_'))
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
    ["wlan", "wifi", "swlan"]
        .iter()
        .any(|prefix| name.starts_with(prefix))
}

fn is_mobile(name: &str) -> bool {
    [
        "rmnet", "r_rmnet", "ccmni", "ccemni", "pdp", "wwan", "cellular", "seth_lte", "sipa_eth",
    ]
    .iter()
    .any(|prefix| name.starts_with(prefix))
}

fn is_vpn(name: &str) -> bool {
    ["tun", "tap", "ppp", "wg", "ipsec"]
        .iter()
        .any(|prefix| name.starts_with(prefix))
}

fn iface_class(name: &str) -> &'static str {
    // 464xlat puts IPv4 on a v4-<uplink> clat interface. Unmatched, it let
    // IPv4 through on IPv6-only carriers even with mobile data blocked.
    let name = name.strip_prefix("v4-").unwrap_or(name);
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

fn modified(path: &Path) -> Option<SystemTime> {
    fs::metadata(path).and_then(|m| m.modified()).ok()
}

// Installs and new users change these, so the app list must be rebuilt.
fn apps_stamp() -> String {
    format!(
        "{:?}:{:?}",
        modified(Path::new(PACKAGES_LIST)),
        modified(Path::new(USERS_DIR))
    )
}

fn config_stamp(config_dir: &Path) -> String {
    format!(
        "{:?}:{:?}:{:?}:{}",
        modified(&rules_file(config_dir)),
        modified(&settings_file(config_dir)),
        modified(&temp_rules_file(config_dir)),
        apps_stamp()
    )
}

// The daemon polls these files; a plain write can be caught half done and
// read as "no rules", which unblocks everything until the next poll.
fn write_atomic(path: &Path, contents: impl AsRef<[u8]>) -> anyhow::Result<()> {
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, contents)?;
    fs::rename(&tmp, path).with_context(|| format!("replace {}", path.display()))?;
    Ok(())
}

fn monotonic_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
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
        _ => "blocked",
    }
}

fn doctor_report(opt: &Opt) -> DoctorReport {
    let health = daemon_health(&opt.socket());
    let daemon_running = health.is_some();
    let program = health.as_deref().and_then(health_program);
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
    match program.as_deref() {
        Some("basic") => warnings.push(
            "kernel rejected the full program: LAN is not told apart, a LAN block drops all traffic"
                .to_string(),
        ),
        Some(mode @ ("uid-only" | "minimal")) => warnings.push(format!(
            "kernel only runs the {mode} program: any rule blocks the app on every network"
        )),
        _ => {}
    }

    DoctorReport {
        engine: "ebpf",
        daemon: if daemon_running { "running" } else { "stopped" },
        program,
        cgroup,
        bpf_filesystem,
        android_arm64,
        warnings,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn app(package: &str, uid: u32) -> AppInfo {
        AppInfo {
            package_name: package.to_string(),
            uid,
            user: uid / 100_000,
            user_label: "Owner".to_string(),
            kind: "user".to_string(),
        }
    }

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("fire-su-test-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn internet_follows_wan_bits() {
        assert_eq!(RuleBits::from_visible(1, 1, 1, 0).internet, 1);
        assert_eq!(RuleBits::from_visible(0, 1, 1, 1).internet, 0);
        let mut bits = Mode::Whitelist.default_rule();
        bits.set("wifi", 0).unwrap();
        assert_eq!(bits.internet, 0);
        assert!(bits.set("dns", 1).is_err());
    }

    #[test]
    fn legacy_columns_migrate() {
        // CLI "block internet"
        assert_eq!(
            RuleBits::from_columns(&["1", "0", "0", "0", "0", "0"]),
            RuleBits::from_visible(1, 1, 1, 0)
        );
        // old whitelist default with every network cleared in the WebUI
        assert_eq!(
            RuleBits::from_columns(&["1", "0", "0", "0", "0", "1"]),
            RuleBits::default()
        );
        // old whitelist "Wi-Fi allowed"
        assert_eq!(
            RuleBits::from_columns(&["1", "0", "1", "1", "1", "1"]),
            RuleBits::from_visible(0, 1, 1, 1)
        );
    }

    #[test]
    fn whitelist_spares_core_uids_and_honours_allows() {
        let ifaces = HashMap::from([("wlan0".to_string(), 30), ("rmnet_data0".to_string(), 40)]);
        let apps = [
            app("android", 1000),
            app("org.a", 10100),
            app("org.b", 10101),
        ];
        let rules = BTreeMap::from([("org.b@0".to_string(), RuleBits::from_visible(0, 1, 0, 0))]);
        let entries = desired_entries(
            Mode::Whitelist,
            &rules,
            &apps,
            FirewallProgramMode::Advanced,
            &ifaces,
        );
        assert!(!entries.contains_key(&1000));
        assert_eq!(entries.get(&10100), Some(&(BLOCK_INTERNET | BLOCK_LAN)));
        // org.b: Wi-Fi allowed, mobile blocked per interface, nothing global
        assert!(!entries.contains_key(&10101));
        assert_eq!(entries.get(&((40u64 << 32) | 10101)), Some(&BLOCK_MOBILE));
        assert!(!entries.contains_key(&((30u64 << 32) | 10101)));
    }

    #[test]
    fn shared_uid_blocking_wins() {
        let apps = [app("org.a", 10200), app("org.a.helper", 10200)];
        let rules = BTreeMap::from([("org.a@0".to_string(), RuleBits::from_visible(1, 1, 1, 1))]);
        let entries = desired_entries(
            Mode::Blacklist,
            &rules,
            &apps,
            FirewallProgramMode::Advanced,
            &HashMap::new(),
        );
        assert_eq!(entries.get(&10200), Some(&(BLOCK_INTERNET | BLOCK_LAN)));
    }

    #[test]
    fn clat_interface_counts_as_mobile() {
        assert_eq!(iface_class("v4-rmnet_data0"), "mobile");
        assert_eq!(iface_class("v4-wlan0"), "wifi");
        assert_eq!(iface_class("tun0"), "vpn");
        assert_eq!(iface_class("dummy0"), "other");
    }

    #[test]
    fn mode_switch_keeps_allow_list() {
        let dir = temp_dir("mode");
        set_default_mode(&dir, Mode::Whitelist).unwrap();
        stage_rules(&dir, "org.a@0|0|0|0|0\norg.b@0|0|1|1|1\n".as_bytes()).unwrap();
        set_default_mode(&dir, Mode::Blacklist).unwrap();
        set_default_mode(&dir, Mode::Whitelist).unwrap();
        let rules = read_rules(&dir).unwrap();
        assert_eq!(rules.get("org.a@0"), Some(&RuleBits::default()));
        assert_eq!(
            rules.get("org.b@0"),
            Some(&RuleBits::from_visible(0, 1, 1, 1))
        );
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn stage_rules_is_all_or_nothing() {
        let dir = temp_dir("stage");
        stage_rules(&dir, "org.a@0|1|1|1|1\n".as_bytes()).unwrap();
        assert!(stage_rules(&dir, "org.b@0|1|0|0|0\nbad target|1|1|1|1\n".as_bytes()).is_err());
        let rules = read_rules(&dir).unwrap();
        assert_eq!(rules.len(), 1);
        // blacklist allow-rules are dropped
        stage_rules(&dir, "org.a@0|0|0|0|0\n".as_bytes()).unwrap();
        assert!(read_rules(&dir).unwrap().is_empty());
        fs::remove_dir_all(dir).unwrap();
    }
}
