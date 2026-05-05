# Network Monitor IDS Guide
This Repository contains the combined work of Chitransh Saxena and Divyanshu Arora.
This guide explains how to run the detector, tune thresholds, and decide what to do when alerts fire.

## What this script does

The script detects:

- Port scanning (many destination ports in a short window)
- High-frequency traffic (many packets from one source in a short window)

It logs alerts to `suspicious_ips.log` and prints details in the terminal.

Current alert details include:

- Direction: INBOUND, OUTBOUND, LOCAL, or TRANSIT/UNKNOWN
- Protocol: TCP, UDP, or IP
- Process: best-effort Windows process mapping (when available)
- Flow: source_ip:source_port -> dest_ip:dest_port

## Requirements

- Windows PowerShell
- Python 3.10+
- Administrator privileges for live packet capture
- Scapy package

Install dependency:

```powershell
pip install scapy
```

## How to run

From `D:\Network Monitor`:

### 1) Demo mode (safe offline test)

```powershell
python "network_monitor (1).py" --demo
```

Use this first to verify alerts/logging format.

### 2) Live capture mode

Run PowerShell as Administrator, then:

```powershell
python "network_monitor (1).py"
```

Optional interface selection:

```powershell
python "network_monitor (1).py" --iface "Wi-Fi"
```

## Threshold model (current)

High-frequency alerts are tiered and direction-aware:

- Inbound warning: 300 packets per 5 seconds
- Inbound critical: 1000 packets per 5 seconds
- Outbound warning: 300 packets per 5 seconds
- Outbound critical: 1000 packets per 5 seconds

Port scan threshold:

- 10 unique destination ports within 5 seconds

## Runtime tuning flags

You can tune without editing code:

- `--hf-warn-in`
- `--hf-crit-in`
- `--hf-warn-out`
- `--hf-crit-out`
- `--no-proc-map` (disable process mapping)

Example:

```powershell
python "network_monitor (1).py" --hf-warn-in 250 --hf-crit-in 800 --hf-warn-out 400 --hf-crit-out 1200
```

## How to read alerts

### HIGH-FREQ

- WARNING: source is noisy; monitor and correlate with process/app
- CRITICAL: sustained high traffic; investigate immediately

### PORT-SCAN

- Usually suspicious if from unknown IP/device
- Confirm if it is a known scanner, router utility, or security tool

### Direction meaning

- INBOUND: traffic toward your machine
- OUTBOUND: traffic from your machine
- LOCAL: your host to your host
- TRANSIT/UNKNOWN: could not confidently map to local interface list

## What to do when an alert appears

1. Check Process field.
2. If process is known (browser, VS Code, update client), verify expected behavior.
3. If process is unknown, inspect it:

```powershell
tasklist /FI "PID eq <pid>"
```

4. For external IPs, identify owner/ASN:

```powershell
nslookup <ip>
tracert -d <ip>
```

5. For local private IPs (for example 192.168.x.x), check router/DHCP client list to identify device.
6. If traffic is suspicious, block at firewall/router and keep log evidence.

## Log file

Alerts append to:

- `suspicious_ips.log`

Tip: old entries may have older format. New entries include DIR, PROTO, PROC, and FLOW.

## Common troubleshooting

### Script exits with permission/raw socket error

- Re-run PowerShell as Administrator.

### Process shows UNKNOWN

- The socket may be short-lived and already closed.
- Keep process mapping enabled and watch repeated alerts.

### Too many alerts

- Increase warning/critical thresholds.
- Use separate inbound/outbound tuning based on your traffic pattern.

### Too few alerts

- Lower warning/critical thresholds.
- Confirm you are sniffing the correct interface.

## Suggested baseline workflow

1. Run demo once.
2. Run live mode for 10-15 minutes during normal usage.
3. Note typical packet rates and noisy apps.
4. Tune warning first, then critical.
5. Re-check weekly or after major app/network changes.
