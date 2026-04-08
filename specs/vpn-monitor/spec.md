# VPN Monitor Module

## Goal
Add VPN connectivity monitoring to system-monitor. Detect F5 and Tailscale VPN status,
report health to the dashboard and brain integration API.

## Approach
- Check VPN process presence (F5TrafficSrv.exe, tailscaled.exe, f5fpclientW.exe)
- Ping internal endpoints to verify tunnel is actually up (not just process running)
- Expose via CLI (`system-monitor vpn`) and API (`GET /api/vpn`)
- Integrate into guard loop — periodic check every 60s
- Emit brain events on VPN disconnect/reconnect

## Data Model
```rust
struct VpnStatus {
    provider: String,       // "f5" | "tailscale"
    process_running: bool,
    tunnel_up: bool,        // ping test result
    checked_at: String,     // ISO timestamp
}
```

## Endpoints
- `GET /api/vpn` — current VPN status for all detected providers
- Guard integration — emits events on state changes (up→down, down→up)

## Non-goals
- VPN reconnection (that's the VPN client's job)
- VPN configuration management
