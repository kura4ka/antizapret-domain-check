# AntiZapret domain checker

Check the domains added to AntiZapret from the **client VPS** and report possible candidates for `include-warp-hosts.txt`. This is a separate project from [antizapret-relay](https://github.com/kura4ka/antizapret-relay).

The checker rereads AntiZapret's parsed routing lists, downloaded domain registries, and user lists on every scan. It checks them in resumable stages, shows each domain and its response, and saves reports and a candidate list. You decide which domains to route through WARP or your donor. AntiZapret and relay settings are never edited or restarted by this tool.

## On the client VPS

Use the VPS running AntiZapret, with Debian 13 or Ubuntu 24.04 and root access. Nothing needs to be installed on the donor.

Download and run the standalone installer on the client VPS:

```bash
curl -fSL https://raw.githubusercontent.com/kura4ka/antizapret-domain-check/main/install.sh -o install.sh
bash install.sh
antizapret-domain-check inventory
antizapret-domain-check scan --one-batch
```

The installer provides Python 3 and curl if they are missing. The default installation uses manual scans. Running the installer again updates the program and keeps your existing timer setting. Version `0.3.0` adds stage settings to older configurations and backs up the previous configuration as `config.json.before-v0.3.*.bak`. Custom settings are preserved. Upgrades from the original configuration also enable downloaded routing domains and change the old default report location to `/root/antizapret-domain-check/reports/`; historical reports in `/var/lib` remain in place.

Version `0.3.0` also recognizes single-label RPZ suffix policies, retries an HTTP/2 stream failure once over HTTP/1.1, and displays timing and completion progress.

### Run in stages

The default stage contains **up to 500 domains**, followed by a **5-minute pause**. Within a stage, the checker keeps its existing two-worker limit and minimum 0.5-second interval between attempt starts.

Run one stage, save its results, and exit:

```bash
antizapret-domain-check scan --one-batch
```

Run the same command again to continue with the next stage. It waits for any remaining saved cooldown before making requests. To continue automatically through all stages and their pauses:

```bash
antizapret-domain-check scan
```

For smaller stages, for example 100 domains with a 10-minute pause:

```bash
antizapret-domain-check scan --one-batch --batch-size 100 --batch-pause 600
```

These flags apply to that invocation. Set `batch_size` and `batch_pause_seconds` in the configuration below to keep your preferred values.

Every completed domain is committed to `/root/antizapret-domain-check/reports/checkpoint.sqlite3`. After an interruption, run `scan` again to resume without repeating saved checks. Ctrl+C stops new work, lets the bounded set of requests already in flight finish, and retains their results. Each invocation rereads the current inventory; completed domains still in that inventory are reused during an unfinished run.

An HTTP `429` from a target or the DNS resolver stops the run after in-flight checks finish. The saved cooldown is at least one hour and honors a longer valid `Retry-After`. Run `scan` later to resume; restarting the command does not skip the cooldown. Rate limits do not become WARP suggestions.

After a run finishes completely, the next `scan` starts fresh checks. To deliberately discard an unfinished run and start again:

```bash
antizapret-domain-check scan --restart --one-batch
```

`--restart` also respects an existing cooldown. Staging and conservative pacing reduce traffic, but cannot guarantee how a site or VPS provider will classify it. Follow their usage rules.

### Which domains are checked?

The default scan covers the finite set of named routing destinations in:

```text
/root/antizapret/config/*include-hosts.txt
/root/antizapret/config/*include-warp-hosts.txt
/root/antizapret/result/include-hosts.txt
/root/antizapret/result/include-warp-hosts.txt
/root/antizapret/download/*include-hosts.txt
/root/antizapret/download/*include-warp-hosts.txt
/root/antizapret/download/*domain.txt
```

AntiZapret fetches the bol-van and antifilter registries into `download/bol-van-domain.txt` and `download/antifilter-download-domain.txt`. Its `parse.sh` applies filters and creates `result/include-hosts.txt` and the WARP lists. The checker uses those generated lists to identify routing coverage, then includes the known downloaded subdomains that remain covered after exclusions and removals. Names explicitly added in `config/` are always visible, including additions not parsed yet. Adblock and deny lists are not routing destinations.

This includes user lists such as `relay-include-warp-hosts.txt`. Literal hostname routing records in `result/proxy.rpz`, `result/warp.rpz`, `result/warp2.rpz` and custom `config/*proxy-rpz.txt`/`*warp-rpz.txt` are also read. Supported policies are hostname `CNAME .` routing and `rpz-passthru.` exceptions. Unsupported RPZ records are reported as warnings. The [source map](docs/upstream-sources.md) documents the upstream logic and limits.

The checker also reads native WARP include and exclude rules so it can identify already routed or explicitly excluded domains. Excluded domains are never proposed for addition. Domains already covered by a WARP rule are checked and reported without being proposed again.

Downloaded registries are included by default and can contain hundreds of thousands of names. No scan limit is silently applied. To omit the raw registry expansion while keeping generated routing lists and user additions:

```bash
antizapret-domain-check scan --no-include-download
```

For example, 776,634 domains require days of work: launch pacing alone is about **4.49 days**, and the default stage pauses add roughly **5.4 days**, before DNS/HTTPS delays and retries. The scan prints its pacing lower bound and stage settings before querying. It also prints a completion count, percentage, elapsed time, and a rough remaining-time estimate about once per minute while checks finish. Timing estimates can change substantially as slower domains and stage pauses are encountered. `--no-include-download` can still leave a large generated inventory.

If generated lists are missing, the checker warns and falls back to source lists. If source files are newer, it warns that routing coverage reflects the last parse. It does not run `update.sh` or `parse.sh` itself. Full VPN, catch-all `.` rules, IP/CIDR routes, and wildcard policies cannot enumerate every Internet hostname; only the finite names present in the lists can be checked.

To check an additional text file or one submitted domain:

```bash
antizapret-domain-check scan --file /root/user-domains.txt
antizapret-domain-check scan --domain example.com
```

Use one domain or HTTP(S) URL per line in a user file; blank lines and `#` comments are supported. `--file` and `--domain` add targets to the current inventory; they do not restrict the scan to those targets. Native AntiZapret lists retain their own host-list syntax. The checker does not add submitted domains to AntiZapret automatically.

### Review the result

```bash
cat /root/antizapret-domain-check/reports/latest.txt
cat /root/antizapret-domain-check/reports/suggested-include-warp-hosts.txt
```

Reports are refreshed after each stage or interrupted stage. While a run is unfinished, `latest.txt` and `latest.json` contain the latest stage's detailed results and cumulative progress. In `latest.json`, `progress.completed`, `progress.total`, and `progress.counts` describe the whole run; `progress.scope` identifies `latest_batch` or `full_run`. The candidate file is cumulative across completed checks in the current run. Stage history is stored under `reports/runs/<run-id>/batch-000001/`, `batch-000002/`, and so on. Once the entire inventory is finished, the root `latest.*` files contain the full run.

Every completed check is saved to the checkpoint even before the stage report is refreshed. Reports identify each domain's source files and each attempt's response, public IP, duration, and error detail; check report timestamps when resuming an interrupted run.

Normal terminal output shows `QUERY` when an attempt starts and `RESPONSE` when it finishes, including HTTP status or DNS/curl failure. A curl `92` HTTP/2 stream error gets one HTTP/1.1 retry to the same public IP, with certificate verification still enabled; the final detail identifies that fallback. A known HTTP `429` is never retried through this fallback. Use `scan --quiet` to suppress live output.

Common messages during a full scan:

| Message | Meaning |
| --- | --- |
| `suffix rule 'goog'`, `'google'`, or `'ua'` | Valid native suffix policies. They apply to known child domains; the suffix itself is not an HTTPS probe target. |
| `skipped invalid native entry` / `invalid registry entries` | Those source entries are not valid probe hostnames and are skipped. File and line details identify individual native entries. |
| `downloaded entries ... omitted` | Source occurrences were filtered against effective routing coverage, exclusions, or removals. This count is not a count of unique failed domains. |
| `IP/CIDR routes do not enumerate hostnames` | An IP route does not supply a finite list of every hostname using that address. |
| `Resolver returned DNS status 3` | NXDOMAIN: the resolver reports that the name does not exist. |
| `curl 28` / `curl 60` | A timeout / certificate verification failure. Neither proves that the donor will fix access. |
| `HTTP 429` | The target or DNS resolver requested less traffic. The scan stops and saves a cooldown. |

Valid single-label RPZ owners such as `goog CNAME .` and `*.goog CNAME .` are recognized in `0.3.0`; they no longer inflate the unsupported-RPZ count. Other unsupported or malformed records still generate a warning.

Checks resolve public IPv4 addresses using DNS over HTTPS, then make verified HTTPS HEAD requests from the client VPS. Redirects and environment proxies are not followed. This checks reachability of the listed hostname over HTTPS; it does not test the whole website, browser login, video playback, every endpoint, or the VPN path from a user's device.

Repeated HTTP `403`/`451` responses or connection failures can produce **tentative candidates**. They can also reflect an access policy, an outage, or a site rejecting HEAD requests. DNS errors, rate limits, server errors, and certificate errors are inconclusive. Because the donor is not tested, a candidate does not establish that routing through the donor will fix access.

For a domain you have confirmed should use the donor, add it on the client to:

```text
/root/antizapret/config/include-warp-hosts.txt
```

Then apply the native lists:

```bash
/root/antizapret/parse.sh
```

Existing `exclude-warp-hosts.txt` rules still take precedence. The checker never removes them.

## Optional daily scans

Daily scanning is opt-in:

```bash
bash install.sh --enable-timer
systemctl list-timers antizapret-domain-check.timer
```

The systemd timer triggers once daily with a scheduling delay of up to 15 minutes. It uses the same resumable stages and cooldowns. A large run can last multiple days; systemd does not start another copy while the service is already active. After a rate-limit stop or interruption, a later invocation resumes saved work. To run the service immediately:

```bash
systemctl start antizapret-domain-check.service
journalctl -u antizapret-domain-check.service
```

To stop daily scans while keeping manual checks:

```bash
bash install.sh --disable-timer
```

## Configuration

The installed command reads `/etc/antizapret-domain-check/config.json`. Its initial contents are:

```json
{
  "config_version": 3,
  "antizapret_dir": "/root/antizapret",
  "report_dir": "/root/antizapret-domain-check/reports",
  "timeout_seconds": 8,
  "attempts": 2,
  "workers": 2,
  "interval_seconds": 0.5,
  "include_download": true,
  "batch_size": 500,
  "batch_pause_seconds": 300,
  "resolver_url": "https://1.1.1.1/dns-query"
}
```

`batch_size` accepts 1–5,000 domains; `batch_pause_seconds` accepts 60–86,400 seconds. The defaults keep concurrency low, pause between stages, and repeat potential routing failures before reporting candidates. Lists are not silently truncated; a large scan can take time.

Keep `report_dir` outside your AntiZapret directory. Paths inside it, including paths reached through a symbolic link, are rejected to keep reports separate from native configuration.

For a one-off override, use flags after the subcommand, for example:

```bash
antizapret-domain-check scan --attempts 3 --timeout 10 --workers 2 --interval 1
antizapret-domain-check scan --az-dir /root/antizapret --report-dir /root/antizapret-domain-check/reports
```

## Remove the checker

```bash
bash install.sh --uninstall
```

This removes the program and timer. Your configuration remains in `/etc/antizapret-domain-check`, and reports remain in `/root/antizapret-domain-check/reports/` or your configured report directory. AntiZapret and antizapret-relay are unchanged.

## Development

The runtime uses the Python standard library and the system curl executable. You can run the package directly from the repository:

```bash
python3 -m azcheck inventory --az-dir /root/antizapret
python3 -m azcheck scan --domain example.com --report-dir ./reports
python3 -m unittest discover -s tests -v
python3 tools/build.py
python3 tools/build.py --check
bash -n install.sh
shellcheck -S warning install.sh
```

`install.sh` contains a reproducible compressed payload built from `azcheck/*.py` and the two systemd units. Edit the package and `tools/install.template.sh`, then rebuild the installer before publishing.
