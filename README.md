# AntiZapret domain checker

Check the domains added to AntiZapret from the **client VPS** and report possible candidates for `include-warp-hosts.txt`. This is a separate project from [antizapret-relay](https://github.com/kura4ka/antizapret-relay).

The checker rereads your native lists on every scan, including files added by users or other modules. It creates a report and a candidate list; you decide which domains to route through WARP or your donor. AntiZapret and relay settings are never edited or restarted by this tool.

## On the client VPS

Use the VPS running AntiZapret, with Debian 13 or Ubuntu 24.04 and root access. Nothing needs to be installed on the donor.

Download and run the standalone installer on the client VPS:

```bash
curl -fSL https://raw.githubusercontent.com/kura4ka/antizapret-domain-check/main/install.sh -o install.sh
bash install.sh
antizapret-domain-check inventory
antizapret-domain-check scan
```

The installer provides Python 3 and curl if they are missing. The default installation uses manual scans. Running the installer again updates the program and preserves your configuration, reports, and existing timer setting.

### Which domains are checked?

By default, every unique domain in these files is checked:

```text
/root/antizapret/config/*include-hosts.txt
/root/antizapret/config/*include-warp-hosts.txt
```

This includes the main `include-hosts.txt`, `include-warp-hosts.txt`, and additional files such as `relay-include-warp-hosts.txt`. User-added domains in those lists are included automatically on the next scan. A parent entry covers its subdomains for routing classification; checking that entry probes the listed hostname, not every possible subdomain.

The checker also reads native WARP include and exclude rules so it can identify already routed or explicitly excluded domains. Excluded domains are never proposed for addition. Domains already covered by a WARP rule are checked and reported without being proposed again.

Downloaded upstream host lists can be much larger. They are included as check inputs only when you request them:

```bash
antizapret-domain-check scan --include-download
```

To check an additional text file or one submitted domain:

```bash
antizapret-domain-check scan --file /root/user-domains.txt
antizapret-domain-check scan --domain example.com
```

Use one domain or HTTP(S) URL per line in a user file; blank lines and `#` comments are supported. Native AntiZapret lists retain their own host-list syntax. The checker does not add submitted domains to AntiZapret automatically.

### Review the result

```bash
cat /var/lib/antizapret-domain-check/reports/latest.txt
cat /var/lib/antizapret-domain-check/reports/suggested-include-warp-hosts.txt
```

`latest.json` contains the machine-readable result. Reports identify the source lists for each domain.

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
  "antizapret_dir": "/root/antizapret",
  "report_dir": "/var/lib/antizapret-domain-check/reports",
  "timeout_seconds": 8,
  "attempts": 2,
  "workers": 2,
  "interval_seconds": 0.5,
  "include_download": false,
  "resolver_url": "https://1.1.1.1/dns-query"
}
```

The defaults keep concurrency low and repeat checks before reporting candidates. Lists are not silently truncated; a large scan can take time.

Keep `report_dir` outside your AntiZapret directory. Paths inside it, including paths reached through a symbolic link, are rejected to keep reports separate from native configuration.

For a one-off override, use flags after the subcommand, for example:

```bash
antizapret-domain-check scan --attempts 3 --timeout 10 --workers 2 --interval 1
antizapret-domain-check scan --az-dir /root/antizapret --report-dir /var/lib/antizapret-domain-check/reports
```

## Remove the checker

```bash
bash install.sh --uninstall
```

This removes the program and timer. Your configuration and reports remain in `/etc/antizapret-domain-check` and `/var/lib/antizapret-domain-check`. AntiZapret and antizapret-relay are unchanged.

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
