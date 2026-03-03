# Tuning options

Use these options to balance scan quality and speed.

## Timeout (`--timeout`)

- Sets per-request timeout in seconds.
- Start around `5-8` seconds for internet targets.
- Increase timeout for slow applications or high-latency VPN paths.

## Concurrency (`--concurrency`)

- Controls parallel worker count for target processing.
- Higher values increase throughput but can create load spikes.
- For cautious engagements, begin with `2-4` and ramp slowly.

## Depth (`--depth`)

- Controls crawl breadth over internal links.
- `1` = landing page + immediate links.
- `2+` discovers broader parameter/form coverage but increases runtime and duplicate noise.

## Practical baseline profiles

- **Low impact**: `--depth 1 --timeout 6 --concurrency 2`
- **Balanced**: `--depth 2 --timeout 6 --concurrency 4`
- **Broad sweep**: `--depth 3 --timeout 8 --concurrency 6`

Tune conservatively on production systems and follow change-control constraints.
