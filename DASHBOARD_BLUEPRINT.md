# Sentinel AI dashboard blueprint

## Purpose

Help a signed-in site owner understand whether Sentinel is connected, what recent request telemetry and security alerts it has received, and how to reach the next response action.

## Screen plan

1. Keep the current navigation rail, account controls, mobile menu, and top action bar. Preserve every existing handler and modal destination.
2. Lead with the dashboard title and a compact defense-status row. Show the real threat level, risk score, active threats, and blocked count; use an unavailable mark while metrics load.
3. Present host CPU, memory, network I/O, and process readings as one compact measurement strip. Label them as Sentinel host resources.
4. Make a live request timeline the main visual. Range controls select 15 minutes, one hour, or 24 hours; metric controls switch between request count and average risk. Render only packets already received. Empty ranges explain how to connect telemetry.
5. Pair the timeline with a severity summary derived from the current alert feed. Show an explicit empty state when there are no alerts.
6. Keep the existing searchable, severity-filtered activity table below the summary, with row selection opening the existing remediation detail.

## Visual system

- Console theme: graphite surfaces, hairline dividers, one restrained green action accent, cool blue telemetry, and semantic warning/error colours.
- Host Grotesk for interface text; Atkinson Hyperlegible Mono for measured values and timestamps.
- Keep the existing icon library, use compact controls, clear focus rings, and reduced-motion fallbacks.
- No sample events, placeholder counts, decorative graph points, or fabricated site health.

## Data and interactions

- Dashboard metrics, alerts, and packets continue to come from the existing REST and WebSocket connections.
- Range and metric selectors only transform already loaded traffic packets; they do not send requests.
- Add website, simulate, live traffic, threat map, firewall, reports, alert details, IP block/unblock, sound, and sign-out continue to use their existing handlers.
- Empty activity and disconnected/loading behavior stay explicit. No success claims are shown when the corresponding action has not completed.
