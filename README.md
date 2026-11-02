# AntiZapret domain checker

Check AntiZapret domain availability from the **client VPS** and produce a reviewable list of possible WARP/donor candidates. This is separate from [antizapret-relay](https://github.com/kura4ka/antizapret-relay).

Version **0.4.0** uses generated routing lists by default, audits exactly where its domain count comes from, and discovers AntiZapret's saved DNS configuration. Checks run in resumable stages. The checker writes its own reports and checkpoint; it does not change AntiZapret routing or restart its services.

## On the client VPS

Use the VPS running AntiZapret on Debian 13 or Ubuntu 24.04. Nothing needs to be installed on the donor.

```bash
curl -fSL https://raw.githubusercontent.com/kura4ka/antizapret-domain-check/main/install.sh -o install.sh
bash install.sh
antizapret-domain-check audit --compare-download
cat /root/antizapret-domain-check/reports/inventory-audit.txt
antizapret-domain-check scan --one-batch
```

The **audit makes no DNS or HTTPS requests**. It reads local lists and saved DNS configuration, writes the selected domain inventory, and compares its count with optional raw-registry expansion. Check that report before starting a large scan.

The installer provides Python 3, `python3-dnspython`, and curl. Running it again updates the program and keeps the existing timer setting. Version 0.4 upgrades configurations from versions 1–3 to disable the old raw-expansion default and clear the old hardcoded Cloudflare DoH default. It preserves a custom nondefault DoH URL and other supported settings, adds the new DNS options, and backs up changed configuration as `config.json.before-v0.4.*.bak`. Explicit version-4 choices are preserved.

## Which domains are selected?

The default inventory starts with generated routing hostnames in:

```text
/root/antizapret/result/include-hosts.txt
/root/antizapret/result/include-warp-hosts.txt
/root/antizapret/result/proxy.rpz
/root/antizapret/result/warp.rpz
/root/antizapret/result/warp2.rpz
```

Generated RPZ policies are authoritative when available: a passthru exception also filters hostnames found in the generated include lists. Duplicate names from host lists and their RPZ copies count once.

`active_routed_domains` counts generated proxy/WARP routing coverage. It does not prove that an earlier client-facing deny or custom DNS policy permits the name: the inventory does not model that policy precedence. The native real-answer DNS check still applies its own active policies, and DNS-error outcomes remain inconclusive.

Explicit additions from `config/*include-hosts.txt`, `config/*include-warp-hosts.txt`, and supported literal routing records in `config/*proxy-rpz.txt`/`*warp-rpz.txt` remain visible. An addition not covered by generated routes is recorded as **pending**, rather than claimed to be an active route. Source changes are applied to AntiZapret separately with its normal `parse.sh` workflow.

The downloaded bol-van and AntiFilter registries are intentional **upstream AntiZapret sources**. They already contribute to AntiZapret's generated results. Re-expanding their raw subdomains in the checker is now opt-in:

```bash
antizapret-domain-check scan --one-batch --include-download
```

This also reads `download/*include-hosts.txt`, `*include-warp-hosts.txt`, and `*domain.txt`. Only known raw names covered by the effective policies survive expansion, with exact removals and applicable exclusions taken into account. The audit's contribution counts distinguish additional unique targets from duplicates and filtered source occurrences.

A large count does not itself establish a bug: the reported `result/include-hosts.txt` already contained a rule on line 569,107. Generated results can therefore still contain hundreds of thousands of names after raw expansion is disabled. The checker cannot reproduce the exact reported count of 779,454 without those VPS files; `audit --compare-download` explains the current local count.

Valid suffix rules such as `goog`, `google`, and `ua`, wildcard rules, and catch-all rules influence coverage but do not become invented HTTPS targets. Invalid names are skipped. Both are counted separately in the audit. Adblock/deny lists and IP routes are not hostname target lists; arbitrary destinations under full-VPN, wildcard, or IP routes cannot be exhaustively enumerated from static files.

To inspect or add named targets:

```bash
antizapret-domain-check inventory
antizapret-domain-check scan --one-batch --file /root/user-domains.txt
antizapret-domain-check scan --one-batch --domain example.com
```

`--file` and `--domain` **add to** the inventory; they do not restrict the scan to those targets. External user files accept one domain or HTTP(S) URL per line, blank lines, and `#` comments. Native AntiZapret lists retain their native syntax.

The [source map](docs/upstream-sources.md) and [0.4 audit](docs/audit-v0.4.md) describe the complete pipeline and findings.

## Which DNS resolvers are used?

The default reads these installed files without executing their Lua, Python, or shell code:

```text
/etc/knot-resolver/kresd.conf
/etc/knot-resolver/dns.lua
/etc/knot-resolver/custom3.lua
/root/antizapret/proxy.py
/usr/lib/knot-resolver/kres_modules/fallback.lua   # when enabled
```

AntiZapret's client-facing DNS can return fake addresses for routing. Its proxy obtains real destination answers through the local Knot listener **`127.3.3.3:53`**. The checker uses that real-answer listener as its DNS reference, then queries every endpoint in the selected proxy DNS group and any applicable custom/fallback policies for comparison. It preserves configured ports and records each DNS response. Definitions for unused DNS groups are not extra scan endpoints.

For example, the upstream `world_dns` group includes Cloudflare and Quad9 addresses, including `9.9.9.10`, rather than assuming `9.9.9.9`. The selected `russia_dns` group contains MSK-IX and other Russian endpoints. The checker reads the actual saved values; it does not substitute a provider list or system resolver.

HTTPS uses a public IPv4 address returned by the native reference. A missing or nonpublic reference answer does not cause a silent switch to a different DNS provider. Native Knot queries retain Knot's own DNS routing and custom policies. Direct endpoint comparisons run as the checker user, so their egress can differ from Knot, for example when `DNS_WARP` uses UID-based routing. Saved configuration discovery does not prove that services are running or account for arbitrary command-line overrides.

Unsupported or ambiguous custom configuration produces a clear discovery error. After reviewing the audit, explicit overrides are available when needed:

```bash
antizapret-domain-check scan --one-batch \
  --resolver udp://1.1.1.1:53 --resolver udp://9.9.9.9:53
```

The first explicit endpoint becomes the HTTPS DNS reference; other listed endpoints are comparisons. UDP, TCP, and TLS endpoints are supported; TLS uses `tls://IP:853#certificate-hostname`. `--resolver-url https://.../dns-query` retains the explicit legacy DNS-JSON DoH mode. Overrides are reported as overrides and cannot be combined with each other. There is no automatic Cloudflare or system-DNS fallback.

## Run in stages

Defaults: **500 domains per stage**, **5 minutes between stages**, **2 workers**, and at least **0.5 seconds between domain-attempt starts**. Individual DNS queries across workers are additionally paced at least **0.25 seconds apart**. Checking multiple relevant resolvers increases the work per domain.

```bash
# One stage, then exit. Repeat to resume.
antizapret-domain-check scan --one-batch

# Continue automatically through stages and pauses.
antizapret-domain-check scan

# A smaller stage and longer pause for this invocation.
antizapret-domain-check scan --one-batch --batch-size 100 --batch-pause 600
```

Every completed domain is saved to `reports/checkpoint.sqlite3`. Ctrl+C stops new work and drains bounded in-flight requests; completed checks are retained. A domain whose DNS matrix was interrupted remains pending. Re-running the command respects saved cooldowns and resumes unfinished work. Current include/exclude rules are reapplied to cached outcomes and suggestions.

A changed DNS plan or probe context invalidates incompatible cached outcomes, including old hardcoded-DoH results, while preserving cooldowns. A completed run starts a new run on the next invocation. To deliberately restart an unfinished run:

```bash
antizapret-domain-check scan --restart --one-batch
```

An HTTP `429` stops the run and saves a cooldown of at least one hour, extended by a longer valid `Retry-After`. Restarting the command preserves that cooldown. Staging reduces traffic; provider usage rules still apply. Large inventories can take many days.

## Read the reports

Everything below defaults to **`/root/antizapret-domain-check/reports/`**:

| File | Contents |
| --- | --- |
| `inventory-audit.txt` | Human-readable count, source accounting, DNS discovery, warnings, and optional raw-expansion comparison |
| `inventory-audit.json` | Full audit metadata, per-file statistics, contributions, and DNS plan/error |
| `inventory.tsv` | Exactly the selected domain names, WARP states, and source references |
| `checkpoint.sqlite3` | Durable outcomes, probe context, and persistent pauses |
| `latest.txt`, `latest.json` | Latest stage details and cumulative progress while unfinished; complete run after final completion |
| `suggested-include-warp-hosts.txt` | Cumulative tentative candidates under current rules |
| `runs/<run-id>/batch-000001/` etc. | Stage-by-stage report history |

```bash
cat /root/antizapret-domain-check/reports/latest.txt
cat /root/antizapret-domain-check/reports/suggested-include-warp-hosts.txt
```

Live output identifies domain attempts, individual DNS queries/responses, and HTTPS responses. Reports record resolver identity, DNS result, selected IP, HTTP/curl outcome, and timing. `latest.json` uses `progress.completed`, `progress.total`, and `progress.counts` for the whole run; `progress.scope` is `latest_batch` or `full_run`. Use `scan --quiet` to suppress terminal output.

Checks use verified HTTPS HEAD on port 443 without following redirects. A curl `92` HTTP/2 stream error gets one verified HTTP/1.1 retry to the same IP; a known `429` is not retried that way. DNS errors, certificate failures, server errors, and rate limits do not establish a donor-routing fix. Repeated selected transport failures or HTTP `403`/`451` can produce tentative candidates. They require review because HEAD rejection, an outage, or site policy can cause similar results. The donor, browser login, playback, and complete VPN-client path are not tested.

For confirmed candidates, edit `/root/antizapret/config/include-warp-hosts.txt` on the client and then run `/root/antizapret/parse.sh`. Existing WARP exclusions are respected. The checker never copies suggestions into native lists automatically.

## Configuration

The installed command reads `/etc/antizapret-domain-check/config.json`:

```json
{
  "config_version": 4,
  "antizapret_dir": "/root/antizapret",
  "report_dir": "/root/antizapret-domain-check/reports",
  "timeout_seconds": 8,
  "attempts": 2,
  "workers": 2,
  "interval_seconds": 0.5,
  "include_download": false,
  "batch_size": 500,
  "batch_pause_seconds": 300,
  "resolver_url": "",
  "resolvers": [],
  "dns_config_dir": "/etc/knot-resolver",
  "dns_interval_seconds": 0.25
}
```

Empty `resolver_url` and `resolvers` select native discovery. A version-4 configuration may deliberately set `include_download: true` to retain raw expansion. Keep `report_dir` outside the AntiZapret directory; paths inside it are rejected so generated reports cannot become native routing inputs.

## Optional daily scans and removal

```bash
bash install.sh --enable-timer
systemctl list-timers antizapret-domain-check.timer
journalctl -u antizapret-domain-check.service
```

The daily timer uses the same resumable stages and cooldowns. A large service run can span several days; systemd does not start another copy while it is active. Disable scheduled scans with `bash install.sh --disable-timer`. Remove the checker with `bash install.sh --uninstall`; configuration and reports are retained.

## Development

Runtime dependencies are Python 3, dnspython, and curl:

```bash
python3 -m pip install -r requirements.txt
python3 -m azcheck audit --az-dir /root/antizapret --compare-download
python3 -m unittest discover -s tests -v
python3 tools/build.py
python3 tools/build.py --check
bash -n install.sh
shellcheck -S warning install.sh
```

`install.sh` contains a reproducible payload built from `azcheck/*.py` and the two systemd units. Edit package sources and `tools/install.template.sh`, then rebuild before publishing.
