# AntiZapret domain checker

Check the domains added to AntiZapret from the **client VPS** and report possible candidates for `include-warp-hosts.txt`. This is a separate project from [antizapret-relay](https://github.com/kura4ka/antizapret-relay).

The checker rereads AntiZapret's parsed routing lists, downloaded domain registries, and user lists on every scan. It shows each domain being checked and the response, then creates a report and a candidate list. You decide which domains to route through WARP or your donor. AntiZapret and relay settings are never edited or restarted by this tool.

## On the client VPS

Use the VPS running AntiZapret, with Debian 13 or Ubuntu 24.04 and root access. Nothing needs to be installed on the donor.

Download and run the standalone installer on the client VPS:

```bash
curl -fSL https://raw.githubusercontent.com/kura4ka/antizapret-domain-check/main/install.sh -o install.sh
bash install.sh
antizapret-domain-check inventory
antizapret-domain-check scan
```

The installer provides Python 3 and curl if they are missing. The default installation uses manual scans. Running the installer again updates the program and keeps your existing timer setting. Version `0.2.0` upgrades old scope defaults to include downloaded routing domains and changes the old default report location to `/root/antizapret-domain-check/reports/`. It backs up the previous configuration; custom report paths and unrelated settings are preserved. Historical reports in `/var/lib` remain in place.

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

If generated lists are missing, the checker warns and falls back to source lists. If source files are newer, it warns that routing coverage reflects the last parse. It does not run `update.sh` or `parse.sh` itself. Full VPN, catch-all `.` rules, IP/CIDR routes, and wildcard policies cannot enumerate every Internet hostname; only the finite names present in the lists can be checked.

To check an additional text file or one submitted domain:

```bash
antizapret-domain-check scan --file /root/user-domains.txt
antizapret-domain-check scan --domain example.com
```

Use one domain or HTTP(S) URL per line in a user file; blank lines and `#` comments are supported. Native AntiZapret lists retain their own host-list syntax. The checker does not add submitted domains to AntiZapret automatically.

### Review the result

```bash
cat /root/antizapret-domain-check/reports/latest.txt
cat /root/antizapret-domain-check/reports/suggested-include-warp-hosts.txt
```

`latest.json` contains the machine-readable result and source coverage metadata. Reports identify each domain's source files and each attempt's response, public IP, duration, and error detail. Normal terminal output shows `QUERY` when an attempt starts and `RESPONSE` when it finishes, including HTTP status or DNS/curl failure. Use `scan --quiet` to suppress live output.

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

The systemd timer runs once daily with a random delay of up to 15 minutes. It refreshes the report without editing routing rules. To run the service immediately:

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
  "config_version": 2,
  "antizapret_dir": "/root/antizapret",
  "report_dir": "/root/antizapret-domain-check/reports",
  "timeout_seconds": 8,
  "attempts": 2,
  "workers": 2,
  "interval_seconds": 0.5,
  "include_download": true,
  "resolver_url": "https://1.1.1.1/dns-query"
}
```

The defaults keep concurrency low and repeat checks before reporting candidates. Lists are not silently truncated; a large scan can take time.

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
