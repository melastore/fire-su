# fire-su

**fire-su** is a root firewall for Android that blocks app traffic with cgroup eBPF instead of a VPN service.

It is built for people who want a fast per-app firewall without giving up Android's VPN slot. Flash the module, open the WebUI, pick an app, and decide where it is allowed to connect: Wi-Fi, mobile data, VPN, LAN, or nowhere.

## Why Use It

- No always-on VPN firewall service.
- Per-app rules for the owner profile and work/private profiles.
- Quick templates like Offline, Wi-Fi only, No mobile, and LAN open.
- Blacklist mode for normal use and whitelist mode for stricter setups.
- Temporary rules when you only want to block something for a short time.
- Saved profiles for switching between daily, travel, work, or lockdown setups.
- Traffic counters and recent firewall decisions from the eBPF layer.
- Small module package: the release artifact is just `fire-su.zip`.

## How It Works

Android gives every app a Linux UID. `fire-su` reads the installed app list, stores your rules in `/data/adb/fire-su`, and loads an eBPF program on the device cgroup. When an app opens a network connection, the eBPF program checks that UID and the outgoing network type.

The result is simple:

```text
app UID + network type -> allow or block
```

The daemon keeps the eBPF maps synced with your WebUI changes. If a device kernel rejects the most advanced eBPF program, `fire-su` automatically tries smaller fallback programs so more devices can still run basic blocking.

Note: older builds had a DNS rule field. The latest WebUI does not expose DNS as a separate control; rules are focused on internet, Wi-Fi, mobile data, VPN, and LAN.

## Install

Download or build:

```text
fire-su.zip
```

Flash it with Magisk, KernelSU, APatch, MMRL, or another compatible module manager, then reboot.

Open the module action to launch the WebUI. It works with KSU WebUI Standalone or MMRL WebUI.

## Requirements

- Root with module support.
- Android kernel with cgroup eBPF support.
- `/data/adb` module environment.
- KSU WebUI Standalone or MMRL if you want the graphical interface.

## WebUI

The WebUI is the main way to use `fire-su`.

You can:

- Search installed apps.
- Filter owner, work/private, or all profiles.
- Switch between blacklist and whitelist mode.
- Toggle Wi-Fi, mobile, VPN, and LAN per app.
- Apply bulk templates to many apps.
- Save and apply named profiles.
- Export/import rule data.
- View traffic counters and recent blocked decisions.

## CLI

The module starts the daemon at boot, but the binary can also be used directly:

```sh
fire-su status
fire-su list-apps
fire-su mode blacklist
fire-su set com.example.app@0 mobile 1
fire-su set com.example.app@0 wifi 0
fire-su temp-set com.example.app@0 visible 1 900
fire-su profile-save daily
fire-su apply
fire-su disable
```

Rule values use `1` for blocked and `0` for allowed.

Common scopes:

```text
internet
wifi
mobile
vpn
lan
visible
all
```

`visible` means Wi-Fi, mobile, VPN, and LAN together. It is useful for simple temporary blocks from the WebUI.

## Build

Install Rust, the Android NDK, and `bpf-linker`:

```sh
rustup toolchain install stable
rustup toolchain install nightly --component rust-src
cargo install bpf-linker
```

Put the Android NDK LLVM tools on `PATH`, then build:

```sh
./build-android.sh
```

Package the module:

```sh
./package-release.sh
```

The script creates `fire-su.zip` at the repository root.

## Project Layout

```text
fire-su-v3/backend/fire-su/   Rust userspace daemon and eBPF workspace
system/bin/fire-su            Android module binary
webroot/                      WebUI bundle
META-INF/                     Flashable module compatibility files
customize.sh                  Install-time setup
service.sh                    Boot-time daemon launcher
action.sh                     WebUI launcher
uninstall.sh                  Cleanup hook
fire-su.zip                   Flashable release package
```

## Status

This project is still low-level Android firewall software. Test on your own device carefully, keep a way to disable modules from recovery, and report device-specific kernel issues with logs from:

```sh
fire-su doctor
fire-su logs
```

## License

Userspace code is licensed under MIT or Apache-2.0. eBPF code is licensed under MIT or GPL-2.0. See the license files in `fire-su-v3/backend/fire-su/` for the exact terms.
