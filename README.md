# Rex's Network Watcher

![Rex Wolf at the cabin bench](art/rex-wolf.jpg)

Defensive census of a network you own.

It ping-sweeps your private IPv4 LAN, reads the ARP table, reverse-resolves hostnames, and stores a baseline on that machine. The next day's run prints only what changed. Nothing is uploaded. There is no port scan and no credential use.

Use it only on a network you are allowed to inventory.

## Your router

The router address is required. It is not pinned to one cabin. Set the gateway on the machine you are watching, then sweep. Change it any time.

```bash
python3 rex-network-watcher.py router 192.168.1.1
python3 rex-network-watcher.py sweep
```

That address is saved in `~/.local/share/rex-network-watcher/router` and reused until you set a different one. A sweep with no router set refuses to run.

## Run

Python 3.9+ and the system `ping` plus `ip` (Linux) or `arp` (macOS). No third-party packages.

```bash
python3 rex-network-watcher.py selftest
python3 rex-network-watcher.py router 192.168.1.1
python3 rex-network-watcher.py sweep
python3 rex-network-watcher.py accept
python3 rex-network-watcher.py diff
```

`sweep --router 192.168.1.1` sets the gateway and sweeps in one step. `sweep --json` prints a census the desk can import. Only private /24 prefixes are swept.

## What the flags mean

- **NEW** — answered, and the MAC is not in the baseline yet
- **OK** — MAC is in the baseline
- **Since yesterday** — new, gone, or a changed IP versus the previous census

`accept` trusts every host in the latest census. Run that once you recognize the wire, then let `diff` be the daily alarm.

## The desk

The visual watch (cabin lab, new-host alert, trust list, daily delta) is the standalone Rex's Network Watcher page. A browser cannot ARP a house, so the cabin wire is a local lab. Import `sweep --json` from this script when you want the real census in that desk. The baseline in the page stays in the browser. This script's baseline stays on the machine.
