const COMMAND = "fire-su";
const scopes = [
	{ key: "wifi", label: "Wi-Fi" },
	{ key: "mobile", label: "Mobile" },
	{ key: "vpn", label: "VPN" },
	{ key: "lan", label: "LAN" },
];
const backendScopes = [
	{ key: "internet", label: "Net" },
	...scopes,
	{ key: "dns", label: "DNS" },
];

let callbackId = 0;
let apps = [];
let rules = new Map();
let originalRules = new Map();
let defaultMode = "blacklist";
let originalMode = "blacklist";
let stats = [];
let logs = [];
let doctor = null;
let filter = "all";
let profileFilter = readPref("profileFilter", "owner");
let query = "";
let showSystem = readPref("showSystem", "0") === "1";
let busy = false;
let dirty = false;
let renderQueued = false;
let currentView = "rules";
let expandedActivityUid = null;
let expandedAppTarget = null;
let groupFilter = readPref("groupFilter", "all");
let appGroups = readJsonPref("appGroups", {});

const list = document.getElementById("apps-list");
const empty = document.getElementById("empty");
const search = document.getElementById("search");
const status = document.getElementById("status");
const totalCount = document.getElementById("total-count");
const blockedCount = document.getElementById("blocked-count");
const activeCount = document.getElementById("active-count");
const blockedPackets = document.getElementById("blocked-packets");
const statsList = document.getElementById("stats-list");
const logsList = document.getElementById("logs-list");
const doctorList = document.getElementById("doctor-list");
const statsCount = document.getElementById("stats-count");
const logsCount = document.getElementById("logs-count");
const healthState = document.getElementById("health-state");
const refreshButton = document.getElementById("refresh");
const applyButton = document.getElementById("apply");
const bulkAllowButton = document.getElementById("bulk-allow");
const bulkBlockButton = document.getElementById("bulk-block");
const settingsToggle = document.getElementById("settings-toggle");
const settingsPanel = document.getElementById("settings-panel");
const showSystemInput = document.getElementById("show-system");
const profileNameInput = document.getElementById("profile-name");
const profileSaveButton = document.getElementById("profile-save");
const profileApplyButton = document.getElementById("profile-apply");
const firstRun = document.getElementById("first-run");
const firstBlacklistButton = document.getElementById("first-blacklist");
const firstWhitelistButton = document.getElementById("first-whitelist");
const backupData = document.getElementById("backup-data");
const backupExportButton = document.getElementById("backup-export");
const backupImportButton = document.getElementById("backup-import");
const groupFilterInput = document.getElementById("group-filter");
const groupNameInput = document.getElementById("group-name");
const templateButtons = Array.from(document.querySelectorAll(".template-action"));
const modeButtons = Array.from(document.querySelectorAll(".mode"));
const profileButtons = Array.from(document.querySelectorAll(".profile"));
const filterButtons = Array.from(document.querySelectorAll(".filter"));
const viewButtons = Array.from(document.querySelectorAll(".view-tab"));
const viewPanels = {
	rules: document.getElementById("rules-view"),
	activity: document.getElementById("activity-view"),
	health: document.getElementById("health-view"),
};

if (!window.ksu && new URLSearchParams(location.search).has("mock")) installMockBridge();

function installMockBridge() {
	const sampleApps = [
		"org.mozilla.firefox|10150|0|Owner|user",
		"com.whatsapp|10151|0|Owner|user",
		"com.termux|10152|0|Owner|user",
		"com.android.vending|10035|0|Owner|system",
		"com.google.android.gms|10012|0|Owner|system",
		"com.example.workmail|20145|10|User 10|user",
	].join("\n");
	let sampleMode = "blacklist";
	let sampleRules = [
		{ target: "org.mozilla.firefox@0", package: "org.mozilla.firefox", user: "0", internet: 1, wifi: 0, mobile: 1, vpn: 0, lan: 0, dns: 1 },
		{ target: "com.whatsapp@0", package: "com.whatsapp", user: "0", internet: 0, wifi: 0, mobile: 1, vpn: 0, lan: 0, dns: 0 },
		{ target: "com.example.workmail@10", package: "com.example.workmail", user: "10", internet: 1, wifi: 1, mobile: 1, vpn: 1, lan: 0, dns: 1 },
	];
	window.ksu = {
		exec(command, _options, callbackName) {
			let stdout = "";
			let stderr = "";
			let errno = 0;
			try {
				stdout = mockCommand(command);
			} catch (error) {
				errno = 1;
				stderr = error.message;
			}
			setTimeout(() => window[callbackName]?.(errno, stdout, stderr), 20);
		},
		toast() {
		},
	};
	function mockCommand(command) {
		if (command === `${COMMAND} list-apps`) return sampleApps;
		if (command === `${COMMAND} export`) return JSON.stringify({ version: 6, defaultMode: sampleMode, rules: sampleRules });
		if (command === `${COMMAND} stats`) return JSON.stringify([
			{ uid: 10150, scope: "internet", allowed_packets: 88, blocked_packets: 34, allowed_bytes: 900120, blocked_bytes: 24480 },
			{ uid: 10151, scope: "mobile", allowed_packets: 120, blocked_packets: 9, allowed_bytes: 1800120, blocked_bytes: 8080 },
			{ uid: 20145, scope: "dns", allowed_packets: 3, blocked_packets: 17, allowed_bytes: 3200, blocked_bytes: 6400 },
		]);
		if (command === `${COMMAND} logs`) return JSON.stringify([
			{ uid: 10150, ifindex: 23, reason: "internet", bytes: 1440 },
			{ uid: 10151, ifindex: 24, reason: "mobile", bytes: 700 },
			{ uid: 10152, ifindex: 23, reason: "allowed", bytes: 1200 },
		]);
		if (command === `${COMMAND} doctor`) return JSON.stringify({ engine: "ebpf", daemon: "running", cgroup: true, bpf_filesystem: true, android_arm64: true, warnings: [] });
		if (command.startsWith(`${COMMAND} stage-mode `)) {
			sampleMode = command.includes("whitelist") ? "whitelist" : "blacklist";
			return "";
		}
		if (command.startsWith(`${COMMAND} stage-set `) || command.startsWith(`${COMMAND} temp-set `) || command === `${COMMAND} apply`) return "";
		if (command.startsWith(`${COMMAND} profile-`)) return "";
		throw new Error(`Unhandled mock command: ${command}`);
	}
}

function readPref(key, fallback) {
	try {
		return localStorage.getItem(`fire-su:${key}`) || fallback;
	} catch {
		return fallback;
	}
}

function writePref(key, value) {
	try {
		localStorage.setItem(`fire-su:${key}`, value);
	} catch {
	}
}

function readJsonPref(key, fallback) {
	try {
		return JSON.parse(localStorage.getItem(`fire-su:${key}`) || JSON.stringify(fallback));
	} catch {
		return fallback;
	}
}

function writeJsonPref(key, value) {
	writePref(key, JSON.stringify(value));
}

function makeCallbackName() {
	return `firesu_callback_${Date.now()}_${callbackId++}`;
}

function exec(command, options = {}) {
	return new Promise((resolve, reject) => {
		if (!window.ksu || typeof window.ksu.exec !== "function") {
			reject(new Error("KernelSU/MMRL WebUI exec API is unavailable"));
			return;
		}
		const callbackName = makeCallbackName();
		window[callbackName] = (errno, stdout, stderr) => {
			delete window[callbackName];
			resolve({ errno, stdout: stdout || "", stderr: stderr || "" });
		};
		try {
			window.ksu.exec(command, JSON.stringify(options), callbackName);
		} catch (error) {
			delete window[callbackName];
			reject(error);
		}
	});
}

async function run(command) {
	const result = await exec(command);
	if (result.errno !== 0) {
		throw new Error((result.stderr || result.stdout || `Command failed: ${command}`).trim());
	}
	return result.stdout;
}

async function runCommands(commands) {
	for (const command of commands) await run(command);
}

function toast(message) {
	if (window.ksu && typeof window.ksu.toast === "function") window.ksu.toast(message);
}

function shellQuote(value) {
	return `'${String(value).replace(/'/g, `'\\''`)}'`;
}

function emptyRule() {
	return { internet: 0, wifi: 0, mobile: 0, vpn: 0, lan: 0, dns: 0 };
}

function blockedRule() {
	return { internet: 0, wifi: 1, mobile: 1, vpn: 1, lan: 1, dns: 0 };
}

function defaultRuleFor(mode) {
	return mode === "whitelist" ? blockedRule() : emptyRule();
}

function defaultRule() {
	return defaultRuleFor(defaultMode);
}

function cloneRule(rule) {
	const next = Object.fromEntries(backendScopes.map((scope) => [scope.key, Number(rule?.[scope.key]) || 0]));
	if (rule?.temporaryUntil) next.temporaryUntil = Number(rule.temporaryUntil);
	return next;
}

function sameRule(a, b) {
	return backendScopes.every((scope) => Number(a?.[scope.key]) === Number(b?.[scope.key]));
}

function targetFor(app) {
	return `${app.packageName}@${app.user || "0"}`;
}

function effectiveRule(app) {
	return rules.get(targetFor(app)) || rules.get(app.packageName) || defaultRule();
}

function activeScopes(rule) {
	return scopes.filter((scope) => Number(rule[scope.key]) === 1);
}

function isBlocked(rule) {
	return activeScopes(rule).length > 0;
}

function ruleState(rule) {
	const count = activeScopes(rule).length;
	if (count === 0) return "allow";
	if (count === scopes.length) return "block";
	return "partial";
}

function setStatus(message, kind = "") {
	status.textContent = message;
	status.className = `status${kind ? ` is-${kind}` : ""}`;
}

function setBusy(value) {
	busy = value;
	for (const item of [
		refreshButton,
		applyButton,
		settingsToggle,
		bulkAllowButton,
		bulkBlockButton,
		showSystemInput,
		profileNameInput,
		backupData,
		backupExportButton,
		backupImportButton,
		groupFilterInput,
		groupNameInput,
		profileSaveButton,
		profileApplyButton,
		firstBlacklistButton,
		firstWhitelistButton,
		...templateButtons,
		...modeButtons,
		...profileButtons,
		...filterButtons,
		...viewButtons,
		...list.querySelectorAll("button"),
	]) {
		item.disabled = value;
	}
}

function parseApps(output) {
	const byTarget = new Map();
	for (const line of output.split("\n")) {
		const parts = line.trim().split("|");
		if (!parts[0]) continue;
		const [packageName, uid = "", user = "0", userLabel = "Owner", kind = "user"] = parts;
		const normalizedUser = user || "0";
		const target = `${packageName}@${normalizedUser}`;
		const nextKind = kind === "system" ? "system" : "user";
		const current = byTarget.get(target);
		if (current) {
			if (uid && !current.uid.split(", ").includes(uid)) {
				current.uid = [current.uid, uid].filter(Boolean).join(", ");
			}
			if (nextKind === "system") current.kind = "system";
			continue;
		}
		byTarget.set(target, {
			packageName,
			uid,
			user: normalizedUser,
			userLabel: userLabel || (normalizedUser === "0" ? "Owner" : `User ${normalizedUser}`),
			kind: nextKind,
			profile: normalizedUser === "0" ? "owner" : "private",
		});
	}
	return Array.from(byTarget.values());
}

function parseRules(output) {
	const data = output ? JSON.parse(output) : { rules: [] };
	defaultMode = data.defaultMode === "whitelist" ? "whitelist" : "blacklist";
	const next = new Map();
	for (const item of data.rules || []) {
		const target = item.target || `${item.package}${item.user ? `@${item.user}` : ""}`;
		next.set(target, cloneRule(item));
	}
	return next;
}

function normalizeVisibleRule(rule) {
	const next = cloneRule(rule);
	next.internet = 0;
	next.dns = 0;
	return next;
}

function visibleApp(app) {
	if (!showSystem && app.kind === "system") return false;
	if (profileFilter !== "all" && app.profile !== profileFilter) return false;
	const rule = effectiveRule(app);
	const text = [
		app.packageName,
		app.uid,
		app.user,
		app.userLabel,
		app.kind,
		displayName(app),
		groupFor(app),
		activeScopes(rule).map((scope) => scope.label).join(" "),
	].join(" ").toLowerCase();
	if (query && !text.includes(query)) return false;
	if (filter === "all") return true;
	if (filter === "blocked") return isBlocked(rule);
	return Number(rule[filter]) === 1;
}

function sortedVisibleApps() {
	return apps.filter((app) => {
		if (!visibleApp(app)) return false;
		if (groupFilter === "all") return true;
		const group = groupFor(app);
		return groupFilter === "ungrouped" ? !group : group === groupFilter;
	}).sort((a, b) => {
		const stateOrder = { block: 0, partial: 1, allow: 2 };
		const ar = ruleState(effectiveRule(a));
		const br = ruleState(effectiveRule(b));
		if (stateOrder[ar] !== stateOrder[br]) return stateOrder[ar] - stateOrder[br];
		if (a.profile !== b.profile) return a.profile === "owner" ? -1 : 1;
		if (a.kind !== b.kind) return a.kind === "user" ? -1 : 1;
		return a.packageName.localeCompare(b.packageName);
	});
}

function compactNumber(value) {
	const number = Number(value) || 0;
	if (number >= 1000000) return `${(number / 1000000).toFixed(1)}M`;
	if (number >= 1000) return `${(number / 1000).toFixed(1)}K`;
	return String(number);
}

function statsForUid(uid) {
	const id = Number(uid);
	return stats.filter((item) => Number(item.uid) === id);
}

function logsForUid(uid) {
	const id = Number(uid);
	return logs.filter((item) => Number(item.uid) === id);
}

function appsForUid(uid) {
	const id = String(uid);
	return apps.filter((app) => String(app.uid).split(", ").includes(id));
}

function droppedPacketsForUid(uid) {
	return statsForUid(uid).reduce((sum, item) => sum + Number(item.blocked_packets || 0), 0);
}

function markDirty() {
	const pending = stageCommands();
	dirty = pending.length > 0;
	applyButton.classList.toggle("is-dirty", dirty);
	applyButton.textContent = "✓";
	applyButton.setAttribute("aria-label", dirty ? `Apply ${pending.length} changes` : "Apply");
	activeCount.textContent = String(pending.length);
	if (dirty) setStatus("Changes staged", "warn");
}

function render() {
	renderQueued = false;
	const visible = sortedVisibleApps();
	list.textContent = "";
	const fragment = document.createDocumentFragment();
	for (const app of visible) {
		fragment.appendChild(renderRow(app));
		if (expandedAppTarget === targetFor(app)) fragment.appendChild(renderAppDetail(app));
	}
	list.appendChild(fragment);
	empty.hidden = visible.length > 0;
	renderSummary(visible);
	renderControls();
	renderGroupControls();
	renderActivity();
	renderDoctor();
	markDirty();
}

function queueRender() {
	if (renderQueued) return;
	renderQueued = true;
	requestAnimationFrame(render);
}

function renderSummary(visible) {
	let blocked = 0;
	for (const app of visible) {
		if (isBlocked(effectiveRule(app))) blocked++;
	}
	totalCount.textContent = String(visible.length);
	blockedCount.textContent = String(blocked);
	blockedPackets.textContent = compactNumber(stats.reduce((sum, item) => sum + Number(item.blocked_packets || 0), 0));
}

function renderControls() {
	for (const button of modeButtons) {
		const active = button.dataset.mode === defaultMode;
		button.classList.toggle("is-active", active);
		button.setAttribute("aria-pressed", String(active));
	}
	for (const button of profileButtons) {
		const active = button.dataset.profile === profileFilter;
		button.classList.toggle("is-active", active);
		button.setAttribute("aria-pressed", String(active));
	}
	for (const button of filterButtons) {
		const active = button.dataset.filter === filter;
		button.classList.toggle("is-active", active);
		button.setAttribute("aria-pressed", String(active));
	}
	showSystemInput.checked = showSystem;
}

function renderGroupControls() {
	const groups = Array.from(new Set(Object.values(appGroups).filter(Boolean))).sort();
	const current = groupFilter;
	groupFilterInput.textContent = "";
	for (const [value, label] of [["all", "All groups"], ["ungrouped", "Ungrouped"], ...groups.map((group) => [group, group])]) {
		const option = document.createElement("option");
		option.value = value;
		option.textContent = label;
		groupFilterInput.appendChild(option);
	}
	groupFilterInput.value = groups.includes(current) || ["all", "ungrouped"].includes(current) ? current : "all";
	groupFilter = groupFilterInput.value;
}

function renderRow(app) {
	const rule = effectiveRule(app);
	const state = ruleState(rule);
	const row = document.createElement("article");
	row.className = `rule-row${state !== "allow" ? " is-blocked" : ""}`;

	const iconWrapper = document.createElement("div");
	iconWrapper.className = "app-icon-wrapper";
	
	const iconImg = document.createElement("img");
	iconImg.className = "app-icon-img";
	iconImg.src = `android.resource://${app.packageName}/mipmap/ic_launcher`;
	iconImg.setAttribute("alt", "");
	iconImg.onerror = () => {
		iconImg.style.display = "none";
		const initialsDiv = document.createElement("div");
		initialsDiv.className = "app-icon";
		initialsDiv.textContent = initials(app.packageName);
		iconWrapper.appendChild(initialsDiv);
	};
	iconWrapper.appendChild(iconImg);
	row.appendChild(iconWrapper);

	for (const scope of scopes) {
		const on = Number(rule[scope.key]) === 1;
		const button = document.createElement("button");
		button.type = "button";
		button.className = `scope-toggle${on ? " is-on" : ""}`;
		button.textContent = "";
		button.title = `${scope.label}: ${on ? "blocked" : "allowed"}`;
		button.setAttribute("aria-pressed", String(on));
		button.addEventListener("click", () => toggleScope(app, scope.key));
		row.appendChild(button);
	}

	const main = document.createElement("div");
	main.className = "app-main";
	const nameLine = document.createElement("div");
	nameLine.className = "app-name";
	const packageName = document.createElement("span");
	packageName.className = "package";
	packageName.textContent = displayName(app);
	const pill = document.createElement("span");
	pill.className = `state-pill${state !== "allow" ? " is-blocked" : ""}`;
	pill.textContent = state;
	nameLine.append(packageName, pill);

	const meta = document.createElement("div");
	meta.className = "app-meta";
	for (const text of appMeta(app, rule)) {
		const item = document.createElement("span");
		item.textContent = text;
		meta.appendChild(item);
	}
	main.append(nameLine, meta);
	main.addEventListener("click", () => {
		expandedAppTarget = expandedAppTarget === targetFor(app) ? null : targetFor(app);
		queueRender();
	});
	row.appendChild(main);

	return row;
}

function renderAppDetail(app) {
	const rule = effectiveRule(app);
	const detail = document.createElement("section");
	detail.className = "app-detail";

	const summary = document.createElement("div");
	summary.className = "app-detail-summary";
	summary.textContent = `${app.packageName} · UID ${app.uid || "unknown"} · ${app.userLabel} · ${app.kind}`;
	detail.appendChild(summary);

	const actions = document.createElement("div");
	actions.className = "app-detail-actions";
	for (const [label, nextRule] of [
		["Allow all", emptyRule()],
		["Block all", blockedRule()],
		["Wi-Fi only", templateRule("wifi-only")],
		["No mobile", templateRule("mobile-off")],
	]) {
		const button = document.createElement("button");
		button.type = "button";
		button.textContent = label;
		button.addEventListener("click", () => setAllScopes(app, nextRule));
		actions.appendChild(button);
	}
	for (const [label, value, seconds] of [["Block 15m", "on", 900], ["Allow 1h", "off", 3600]]) {
		const button = document.createElement("button");
		button.type = "button";
		button.textContent = label;
		button.addEventListener("click", () => setTemporary(app, value, seconds));
		actions.appendChild(button);
	}
	const groupButton = document.createElement("button");
	groupButton.type = "button";
	groupButton.textContent = "Set group";
	groupButton.addEventListener("click", () => setGroup(app));
	actions.appendChild(groupButton);
	detail.appendChild(actions);

	const warnings = ruleWarnings(app, rule);
	if (warnings.length) {
		const warning = document.createElement("div");
		warning.className = "app-warning";
		warning.textContent = warnings.join(" · ");
		detail.appendChild(warning);
	}

	const traffic = document.createElement("div");
	traffic.className = "app-traffic";
	const uidStats = statsForUid(app.uid);
	const allowed = uidStats.reduce((sum, row) => sum + Number(row.allowed_packets || 0), 0);
	const blocked = uidStats.reduce((sum, row) => sum + Number(row.blocked_packets || 0), 0);
	traffic.textContent = `${compactNumber(allowed)} allowed · ${compactNumber(blocked)} blocked · ${logsForUid(app.uid).length} recent decisions · rule ${activeScopes(rule).map((scope) => scope.label).join("/") || "allow"}`;
	detail.appendChild(traffic);
	return detail;
}

function initials(packageName) {
	const parts = packageName.split(".").filter(Boolean);
	const last = parts[parts.length - 1] || packageName;
	return last.slice(0, 2);
}

function appMeta(app, rule) {
	const meta = [
		app.uid ? `UID ${app.uid}` : "UID unknown",
		app.profile === "owner" ? "Owner" : app.userLabel,
		app.kind === "system" ? "System" : "User app",
	];
	const dropped = droppedPacketsForUid(app.uid);
	const group = groupFor(app);
	if (group) meta.push(group);
	if (dropped > 0) meta.push(`${compactNumber(dropped)} drops`);
	const active = activeScopes(rule).map((scope) => scope.label);
	if (active.length && active.length < scopes.length) meta.push(active.join(" / "));
	if (rule.temporaryUntil) meta.push(`temp ${timeUntil(rule.temporaryUntil)}`);
	return meta;
}

function displayName(app) {
	const last = app.packageName.split(".").filter(Boolean).pop() || app.packageName;
	return last
		.replace(/[_-]+/g, " ")
		.replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function groupFor(app) {
	return appGroups[targetFor(app)] || "";
}

function setGroup(app) {
	const name = groupNameInput.value.trim();
	const target = targetFor(app);
	if (name) appGroups[target] = name;
	else delete appGroups[target];
	writeJsonPref("appGroups", appGroups);
	queueRender();
}

function ruleWarnings(app, rule) {
	const warnings = [];
	if (app.kind === "system" && isBlocked(rule)) warnings.push("Blocking system apps can break services");
	if (rule.lan && !rule.wifi) warnings.push("LAN block affects local-address traffic only");
	if (rule.vpn && !rule.wifi && !rule.mobile) warnings.push("VPN blocked while base networks are allowed");
	return warnings;
}

function templateRule(name) {
	switch (name) {
		case "wifi-only":
		case "mobile-off":
			return { internet: 0, wifi: 0, mobile: 1, vpn: 0, lan: 0, dns: 0 };
		case "lan-open":
			return { internet: 0, wifi: 1, mobile: 1, vpn: 1, lan: 0, dns: 0 };
		case "offline":
		default:
			return blockedRule();
	}
}

function timeUntil(timestamp) {
	const seconds = Math.max(0, Number(timestamp) - Math.floor(Date.now() / 1000));
	if (seconds >= 3600) return `${Math.ceil(seconds / 3600)}h`;
	if (seconds >= 60) return `${Math.ceil(seconds / 60)}m`;
	return `${seconds}s`;
}

function storeNextRule(app, nextRule) {
	const target = targetFor(app);
	const normalized = cloneRule(nextRule);
	normalized.internet = 0;
	normalized.dns = 0;
	if (!originalRules.has(target) && sameRule(normalized, defaultRule())) {
		rules.delete(target);
		return;
	}
	if (defaultMode === "blacklist" && !isBlocked(normalized)) {
		rules.delete(target);
		return;
	}
	rules.set(target, normalized);
}

function toggleScope(app, scope) {
	if (busy) return;
	const current = cloneRule(effectiveRule(app));
	current[scope] = Number(current[scope]) === 1 ? 0 : 1;
	storeNextRule(app, current);
	queueRender();
}

function setAllScopes(app, nextRule) {
	if (busy) return;
	storeNextRule(app, nextRule);
	queueRender();
}

function bulkSet(nextRule) {
	if (busy) return;
	for (const app of sortedVisibleApps()) storeNextRule(app, nextRule);
	queueRender();
}

async function setTemporary(app, value, seconds) {
	if (busy) return;
	setBusy(true);
	setStatus("Applying temporary rule");
	try {
		await run(`${COMMAND} temp-set ${shellQuote(targetFor(app))} visible ${value} ${seconds}`);
		await load();
		setStatus("Temporary rule active", "ok");
	} catch (error) {
		setStatus(error.message, "error");
		toast(error.message);
	} finally {
		setBusy(false);
	}
}

function stageCommands() {
	const commands = [];
	if (defaultMode !== originalMode) commands.push(`${COMMAND} stage-mode ${shellQuote(defaultMode)}`);
	const targets = new Set([...originalRules.keys(), ...rules.keys()]);
	for (const target of Array.from(targets).sort()) {
		const current = rules.get(target) || defaultRuleFor(defaultMode);
		const original = originalRules.get(target) || defaultRuleFor(originalMode);
		if (sameRule(current, original)) continue;
		for (const scope of backendScopes) {
			if (Number(current[scope.key]) !== Number(original[scope.key])) {
				commands.push(`${COMMAND} stage-set ${shellQuote(target)} ${scope.key} ${current[scope.key] ? "on" : "off"}`);
			}
		}
	}
	return commands;
}

async function load() {
	setBusy(true);
	setStatus("Loading firewall state");
	try {
		const [appsOutput, rulesOutput, statsOutput, logsOutput, doctorOutput] = await Promise.all([
			run(`${COMMAND} list-apps`),
			run(`${COMMAND} export`),
			run(`${COMMAND} stats`).catch(() => "[]"),
			run(`${COMMAND} logs`).catch(() => "[]"),
			run(`${COMMAND} doctor`).catch(() => "{}"),
		]);
		apps = parseApps(appsOutput);
		const parsedRules = parseRules(rulesOutput);
		originalRules = new Map(Array.from(parsedRules, ([key, value]) => [key, cloneRule(value)]));
		rules = new Map(Array.from(parsedRules, ([key, value]) => [key, normalizeVisibleRule(value)]));
		stats = JSON.parse(statsOutput || "[]");
		logs = JSON.parse(logsOutput || "[]");
		doctor = JSON.parse(doctorOutput || "{}");
		originalMode = defaultMode;
		dirty = false;
		render();
		if (!dirty) setStatus(`Ready: ${apps.length} apps`, "ok");
	} catch (error) {
		apps = [];
		rules = new Map();
		stats = [];
		logs = [];
		doctor = null;
		list.textContent = "";
		renderSummary([]);
		setStatus(error.message, "error");
		toast(error.message);
	} finally {
		setBusy(false);
	}
}

function renderActivity() {
	statsList.textContent = "";
	logsList.textContent = "";
	statsCount.textContent = String(stats.length);
	logsCount.textContent = String(logs.length);

	const statItems = stats.slice(0, 24);
	if (!statItems.length) {
		statsList.appendChild(emptyMetric("No traffic counters yet."));
	} else {
		for (const item of statItems) {
			statsList.appendChild(activityRow(
				item.uid,
				item.scope || "traffic",
				`${compactNumber(item.allowed_packets)} allowed / ${compactNumber(item.blocked_packets)} blocked`,
				Number(item.blocked_packets) > 0 ? "bad" : "good"
			));
			if (expandedActivityUid === Number(item.uid)) statsList.appendChild(activityDetail(item.uid));
		}
	}

	const logItems = logs.slice(0, 32);
	if (!logItems.length) {
		logsList.appendChild(emptyMetric("No decisions recorded."));
	} else {
		for (const item of logItems) {
			const blocked = item.reason && item.reason !== "allowed";
			logsList.appendChild(activityRow(
				item.uid,
				item.reason || "allowed",
				`ifindex ${item.ifindex} / ${compactNumber(item.bytes)} B`,
				blocked ? "bad" : "good"
			));
			if (expandedActivityUid === Number(item.uid)) logsList.appendChild(activityDetail(item.uid));
		}
	}
}

function activityRow(uid, badge, detail, tone) {
	const row = metricRow(`UID ${uid}`, badge, detail, tone);
	row.classList.add("is-clickable");
	row.addEventListener("click", () => {
		const next = Number(uid);
		expandedActivityUid = expandedActivityUid === next ? null : next;
		renderActivity();
	});
	return row;
}

function activityDetail(uid) {
	const item = document.createElement("div");
	item.className = "activity-detail";
	const uidApps = appsForUid(uid);
	const uidStats = statsForUid(uid);
	const uidLogs = logsForUid(uid);
	const allowed = uidStats.reduce((sum, row) => sum + Number(row.allowed_packets || 0), 0);
	const blocked = uidStats.reduce((sum, row) => sum + Number(row.blocked_packets || 0), 0);
	const packages = uidApps.map((app) => app.packageName).join(", ") || "package not listed";
	const rulesText = uidApps
		.map((app) => `${app.packageName}: ${activeScopes(effectiveRule(app)).map((scope) => scope.label).join("/") || "allow"}`)
		.join(" | ") || "no visible rule";
	item.textContent = `${packages} · ${compactNumber(allowed)} allowed · ${compactNumber(blocked)} blocked · ${uidLogs.length} recent · ${rulesText}`;
	return item;
}

function renderDoctor() {
	doctorList.textContent = "";
	const daemon = doctor?.daemon || "unknown";
	const ok = daemon === "running" && doctor?.cgroup && doctor?.bpf_filesystem;
	healthState.textContent = ok ? "ready" : "check";
	const checks = [
		["Engine", doctor?.engine || "ebpf", "good"],
		["Daemon", daemon, daemon === "running" ? "good" : "bad"],
		["Cgroup", doctor?.cgroup ? "ready" : "missing", doctor?.cgroup ? "good" : "bad"],
		["BPF FS", doctor?.bpf_filesystem ? "ready" : "missing", doctor?.bpf_filesystem ? "good" : "bad"],
		["Binary", doctor?.android_arm64 ? "Android ARM64" : "check build", doctor?.android_arm64 ? "good" : "bad"],
	];
	for (const [title, badge, tone] of checks) doctorList.appendChild(metricRow(title, badge, "", tone));
	for (const warning of doctor?.warnings || []) doctorList.appendChild(metricRow("Warning", "check", warning, "bad"));
}

function metricRow(title, badge, detail, tone = "") {
	const row = document.createElement("div");
	row.className = `metric-row${tone ? ` is-${tone}` : ""}`;
	const main = document.createElement("span");
	main.textContent = title;
	const pill = document.createElement("strong");
	pill.textContent = badge;
	const sub = document.createElement("small");
	sub.textContent = detail;
	row.append(main, pill, sub);
	return row;
}

function emptyMetric(text) {
	const item = document.createElement("div");
	item.className = "metric-empty";
	item.textContent = text;
	return item;
}

async function applyRules() {
	if (busy) return;
	setBusy(true);
	setStatus(dirty ? "Saving and applying firewall rules" : "Applying firewall rules");
	try {
		const commands = stageCommands();
		commands.push(`${COMMAND} apply`);
		await runCommands(commands);
		await load();
		setStatus("Firewall rules applied", "ok");
	} catch (error) {
		setStatus(error.message, "error");
		toast(error.message);
		await load();
	} finally {
		setBusy(false);
	}
}

async function saveProfile() {
	const name = profileNameInput.value.trim() || "daily";
	setBusy(true);
	setStatus("Saving profile");
	try {
		await run(`${COMMAND} profile-save ${shellQuote(name)}`);
		setStatus(`Profile saved: ${name}`, "ok");
	} catch (error) {
		setStatus(error.message, "error");
		toast(error.message);
	} finally {
		setBusy(false);
	}
}

async function applyProfile() {
	const name = profileNameInput.value.trim() || "daily";
	setBusy(true);
	setStatus("Applying profile");
	try {
		await run(`${COMMAND} profile-apply ${shellQuote(name)}`);
		await load();
		setStatus(`Profile applied: ${name}`, "ok");
	} catch (error) {
		setStatus(error.message, "error");
		toast(error.message);
	} finally {
		setBusy(false);
	}
}

function exportBackup() {
	const payload = {
		version: 1,
		defaultMode,
		rules: Array.from(rules, ([target, rule]) => ({ target, ...cloneRule(rule) })),
		groups: appGroups,
	};
	backupData.value = JSON.stringify(payload, null, 2);
	setStatus("Profile JSON exported", "ok");
}

function importBackup() {
	try {
		const data = JSON.parse(backupData.value || "{}");
		if (!Array.isArray(data.rules)) throw new Error("Backup JSON has no rules array");
		if (data.defaultMode === "blacklist" || data.defaultMode === "whitelist") defaultMode = data.defaultMode;
		rules = new Map(data.rules.map((item) => [item.target, normalizeVisibleRule(item)]));
		appGroups = data.groups && typeof data.groups === "object" ? data.groups : appGroups;
		writeJsonPref("appGroups", appGroups);
		queueRender();
		setStatus("Backup imported. Tap apply.", "warn");
	} catch (error) {
		setStatus(error.message, "error");
		toast(error.message);
	}
}

search.addEventListener("input", (event) => {
	query = event.target.value.trim().toLowerCase();
	queueRender();
});

for (const button of filterButtons) {
	button.addEventListener("click", () => {
		filter = button.dataset.filter;
		queueRender();
	});
}

for (const button of viewButtons) {
	button.addEventListener("click", () => {
		currentView = button.dataset.view;
		for (const item of viewButtons) item.classList.toggle("is-active", item === button);
		for (const [view, panel] of Object.entries(viewPanels)) panel.hidden = view !== currentView;
	});
}

for (const button of modeButtons) {
	button.addEventListener("click", () => {
		if (busy || button.dataset.mode === defaultMode) return;
		defaultMode = button.dataset.mode;
		queueRender();
	});
}

for (const button of profileButtons) {
	button.addEventListener("click", () => {
		profileFilter = button.dataset.profile;
		writePref("profileFilter", profileFilter);
		queueRender();
	});
}

for (const button of templateButtons) {
	button.addEventListener("click", () => bulkSet(templateRule(button.dataset.template)));
}

settingsToggle.addEventListener("click", () => {
	const expanded = settingsPanel.hidden;
	settingsPanel.hidden = !expanded;
	settingsToggle.setAttribute("aria-expanded", String(expanded));
});

showSystemInput.addEventListener("change", () => {
	showSystem = showSystemInput.checked;
	writePref("showSystem", showSystem ? "1" : "0");
	queueRender();
});

groupFilterInput.addEventListener("change", () => {
	groupFilter = groupFilterInput.value;
	writePref("groupFilter", groupFilter);
	queueRender();
});

const columnHeaders = Array.from(document.querySelectorAll(".column-header"));
for (const header of columnHeaders) {
	header.addEventListener("click", () => {
		if (busy) return;
		const scope = header.dataset.scope;
		const visible = sortedVisibleApps();
		if (!visible.length) return;
		let onCount = 0;
		for (const app of visible) {
			if (Number(effectiveRule(app)[scope]) === 1) onCount++;
		}
		const nextState = onCount > visible.length / 2 ? 0 : 1;
		for (const app of visible) {
			const current = cloneRule(effectiveRule(app));
			if (Number(current[scope]) !== nextState) {
				current[scope] = nextState;
				storeNextRule(app, current);
			}
		}
		queueRender();
	});
	header.addEventListener("contextmenu", (event) => {
		event.preventDefault();
		if (busy) return;
		const scope = header.dataset.scope;
		for (const app of sortedVisibleApps()) {
			const current = cloneRule(effectiveRule(app));
			current[scope] = Number(current[scope]) === 1 ? 0 : 1;
			storeNextRule(app, current);
		}
		queueRender();
	});
}

bulkAllowButton.addEventListener("click", () => bulkSet(emptyRule()));
bulkBlockButton.addEventListener("click", () => bulkSet(blockedRule()));
backupExportButton.addEventListener("click", exportBackup);
backupImportButton.addEventListener("click", importBackup);
firstBlacklistButton.addEventListener("click", () => {
	defaultMode = "blacklist";
	writePref("firstRunDone", "1");
	firstRun.hidden = true;
	queueRender();
});
firstWhitelistButton.addEventListener("click", () => {
	defaultMode = "whitelist";
	writePref("firstRunDone", "1");
	firstRun.hidden = true;
	queueRender();
});
refreshButton.addEventListener("click", load);
applyButton.addEventListener("click", applyRules);
profileSaveButton.addEventListener("click", saveProfile);
profileApplyButton.addEventListener("click", applyProfile);
firstRun.hidden = readPref("firstRunDone", "0") === "1";
load();
