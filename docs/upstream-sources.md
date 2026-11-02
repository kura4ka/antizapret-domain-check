# AntiZapret routing and DNS source map

The download/parse audit used [GubernievS/AntiZapret-VPN at `aabea42bb51520371c8afc2b9b82cc6966068660`](https://github.com/GubernievS/AntiZapret-VPN/tree/aabea42bb51520371c8afc2b9b82cc6966068660). DNS templates were also inspected from the fetched current upstream source tree during the 0.4 audit. The checker discovers the **installed files on each VPS**, not a hardcoded copy of either version.

All AntiZapret-relative paths below are under `/root/antizapret/`.

## Downloads

[`update.sh`](https://github.com/GubernievS/AntiZapret-VPN/blob/aabea42bb51520371c8afc2b9b82cc6966068660/setup/root/antizapret/update.sh) downloads the raw inputs before running custom update hooks.

| Local input | Verified upstream origin/purpose |
| --- | --- |
| `download/bol-van-domain.txt` | `https://raw.githubusercontent.com/bol-van/rulist/main/reestr_hostname.txt` |
| `download/antifilter-download-domain.txt` | `https://antifilter.download/list/domains.lst`; the upstream update tolerates this optional download failing |
| `download/include-hosts.txt` | AntiZapret's bundled normal includes |
| `download/include-warp-hosts.txt` | AntiZapret's bundled WARP includes |
| `download/exclude-hosts.txt` | Bundled normal exceptions; selected source depends on `ROUTE_ALL` |
| `download/remove-hosts.txt` | Bundled removal list, downloaded compressed and unpacked |
| `download/*include-adblock-hosts.txt`, AdGuard/OISD inputs, and deny RPZ inputs | DNS blocking inputs, not routed-host target lists |
| `download/*ips.txt` | IP/network routing inputs, not an enumeration of hostnames |
| `config/*.txt`, `custom-update.sh` outputs | User additions and custom sources consumed by the corresponding globs |

Bol-van and AntiFilter are intentional native AntiZapret sources. The standalone checker does not download or refresh these files.

## Native processing and outputs

[`parse.sh`](https://github.com/GubernievS/AntiZapret-VPN/blob/aabea42bb51520371c8afc2b9b82cc6966068660/setup/root/antizapret/parse.sh) creates working files under `temp/` and then generated files under `result/`.

1. Native host-list inputs have whitespace removed, leading punctuation/comment lines discarded, native path/comment suffixes cut off, and case normalized. `.` is retained only for normal/WARP include lists.
2. `download/*domain.txt` names are stripped of edge punctuation, restricted to the upstream character/label format, and converted to IDNA/Punycode.
3. Normal includes are combined with `config/*include-hosts.txt` and bundled/custom download includes. `CLEAR_HOSTS` optionally removes matching categories/keywords. The parser sorts and deduplicates the combined input.
4. Exact removal-list entries are removed. Selected `www`/`hd`/numeric subdomain prefixes are normalized; parent rules compress redundant children. Normal exclusions participate in compression and are removed from the final normal include list.
5. WARP includes and WARP exclusions are normalized and deduplicated into separate files. Their exceptions are represented in the generated RPZ policy rather than assuming an include file alone describes the complete route.
6. Host rules are expanded into paired exact and wildcard RPZ records; custom RPZ records are appended. Generated policies are copied to `/etc/knot-resolver/` when changed. The native parser may clear DNS caches and perform its usual service/network operations. The checker never invokes it.

| Generated file | What native AntiZapret writes |
| --- | --- |
| `result/include-hosts.txt` | Normal routing rules after native filtering/compression; may contain a catch-all or single-label suffix |
| `result/exclude-hosts.txt` | Normal exception rules after native removal processing |
| `result/include-warp-hosts.txt` | Normalized/deduplicated WARP include rules |
| `result/exclude-warp-hosts.txt` | Normalized/deduplicated WARP exceptions from user configuration |
| `result/proxy.rpz` | Normal routing rules, passthru exceptions, and appended custom proxy RPZ records |
| `result/warp.rpz` | WARP routing and exceptions, optionally based on the normal proxy policy according to the native WARP mode |
| `result/warp2.rpz` | Full-VPN WARP policy when enabled, otherwise an empty file |
| `result/route-ips.txt` | Generated CIDR routes; their hostnames cannot be inferred exhaustively |
| `result/deny*.rpz`, adblock host files | DNS blocking policy, not routed-host target inventory |

## Checker inventory in 0.4

Generated RPZ policies take precedence over the host lists they encode. If the corresponding RPZ is unavailable, generated native include/exclude lists supply coverage. A newer source file is not merged into an existing generated policy as though it were already active.

The checker validates and normalizes probe hostnames, deduplicates the union by ASCII IDNA name, filters generated candidates against effective routing, and retains explicit user additions with pending provenance where necessary. Custom RPZ support includes literal/wildcard hostname `CNAME .` policies and `CNAME rpz-passthru.` exceptions. Unsupported or malformed records are reported.

This coverage concerns generated proxy/WARP routing. The inventory does not model the precedence of earlier client-facing deny/custom DNS policies or subtract their overlapping names, so `active_routed_domains` is not proof that those policies permit a hostname. The native real-answer listener still applies its active policies; DNS-error outcomes remain inconclusive.

Raw registry expansion is disabled by default. With `--include-download`, known downloaded children of routed parents are considered separately, with effective routing and exact removal checks. This opt-in mode can add substantial work under broad suffix rules. When no generated results exist, source fallback is clearly reported; it cannot reproduce every setup-dependent native filter.

Valid suffixes and wildcards supply coverage, not invented probe targets. Catch-all/full-VPN/IP rules cannot enumerate every possible hostname. See [the audit findings](audit-v0.4.md) for count accounting and corrected behavior.

## Native DNS path

Relevant installed source files:

| File | Role |
| --- | --- |
| `/etc/knot-resolver/kresd.conf` | Selects DNS groups and defines Knot instances/listeners/policies |
| `/etc/knot-resolver/dns.lua` | Defines resolver endpoint groups and ports |
| `/etc/knot-resolver/custom3.lua` | Custom policy for the real-answer proxy DNS instance |
| `/root/antizapret/proxy.py` | Native proxy's default real-answer DNS target: `127.3.3.3:53` |
| `/usr/lib/knot-resolver/kres_modules/fallback.lua` | Active fallback resolver action when loaded by the proxy DNS instance |

Upstream templates: [Knot configuration](https://github.com/GubernievS/AntiZapret-VPN/blob/main/setup/etc/knot-resolver/kresd.conf), [DNS groups](https://github.com/GubernievS/AntiZapret-VPN/blob/main/setup/etc/knot-resolver/dns.lua), [proxy](https://github.com/GubernievS/AntiZapret-VPN/blob/main/setup/root/antizapret/proxy.py), and [fallback module](https://github.com/GubernievS/AntiZapret-VPN/blob/main/setup/usr/lib/knot-resolver/kres_modules/fallback.lua).

The native proxy sends real-address DNS queries to Knot instance `@3`, listening on `127.3.3.3:53`. That instance loads `custom3.lua`, its configured DNS actions, and applicable fallback/deny/renumber policy. Client-facing AntiZapret DNS may return fake routing IPs, so it is not interchangeable with the real-answer listener for HTTPS destination checks.

The checker statically discovers the selected `proxy_dns` action and literal endpoint lists, following the template's selected-group mapping. It queries the local listener as reference. Full mode also queries every applicable selected/custom/fallback endpoint as a direct comparison. Since 0.5, `scan --fast` uses the reference only, allowing Knot to select upstreams normally and recording direct diagnostics as skipped. It does not query unused groups merely because their definitions exist in `dns.lua`. Configured ports are preserved. Unknown active custom expressions fail clearly rather than being executed or silently ignored.

These direct comparisons do not reproduce Knot's process identity or every egress rule. In particular, DNS_WARP may route Knot's UID differently from root. The local reference retains Knot's actual DNS policy path; the checker records direct comparisons separately. Discovery reflects saved supported configuration, not proof of running service state or arbitrary runtime overrides.

The previous hardcoded Cloudflare DNS-JSON lookup has been removed from the default. Explicit numeric UDP/TCP/TLS endpoints or an explicit legacy DoH URL remain available as reported overrides. Domain resolution never silently switches to system DNS or an unconfigured provider.
