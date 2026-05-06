# fire-su

`fire-su` is a rooted Android network firewall built around a Rust userspace daemon and cgroup eBPF filters. It ships as a Magisk/KernelSU/APatch style module with a small WebUI for managing per-app rules.

The project is meant for devices where Android's normal VPN-based firewall approach is not ideal. Rules are applied below the app layer, so the firewall can block traffic without holding a VPN slot.

## What It Does

- Blocks or allows apps by Android package and user profile.
- Supports blacklist and whitelist modes.
- Applies scoped rules for internet, Wi-Fi, mobile data, VPN, LAN, and DNS.
- Tracks traffic counters and recent blocked events from eBPF maps.
- Provides temporary rules, saved profiles, and a local WebUI.
- Falls back between several eBPF program variants for devices with stricter verifier limits.

## Install

Use the release module in this repository:

```sh
fire-su.zip
```

Flash it from Magisk, KernelSU, APatch, MMRL, or another compatible module manager, then reboot. Open the module action to launch the WebUI through KSU WebUI Standalone or MMRL.

Device requirements:

- Root with module support.
- Android kernel with cgroup eBPF support.
- A writable `/data/adb` module environment.

## Build

Install Rust, the Android NDK, and `bpf-linker` first:

```sh
rustup toolchain install stable
rustup toolchain install nightly --component rust-src
cargo install bpf-linker
```

Put the Android NDK LLVM tools on `PATH`, then build the Android binary:

```sh
./build-android.sh
```

Package the module zip:

```sh
./package-release.sh
```

The packaging command writes `fire-su.zip` at the repository root. That zip is the only release artifact intentionally kept in Git.

## Repository Layout

```text
fire-su-v3/backend/fire-su/   Rust workspace for userspace and eBPF code
system/bin/fire-su            Android module binary
webroot/                      WebUI bundle used by module managers
META-INF/                     Flashable module compatibility files
customize.sh                  Install-time module setup
service.sh                    Boot-time daemon launcher
action.sh                     WebUI launcher action
uninstall.sh                  Cleanup hook
```

## CLI Notes

The module normally starts the daemon at boot, but the binary also exposes direct commands:

```sh
fire-su status
fire-su list-apps
fire-su mode whitelist
fire-su set com.example.app@0 internet 1
fire-su apply
fire-su disable
```

Rules are stored under `/data/adb/fire-su`, so module upgrades keep the firewall configuration unless the module is uninstalled.

## License

Userspace code is licensed under MIT or Apache-2.0. eBPF code is licensed under MIT or GPL-2.0. See the license files in `fire-su-v3/backend/fire-su/` for the exact terms.
