# AntiZapret routing sources

Inspected [GubernievS/AntiZapret-VPN](https://github.com/GubernievS/AntiZapret-VPN) at commit `aabea42bb51520371c8afc2b9b82cc6966068660`. All paths below are relative to `/root/antizapret/` on the client VPS.

[`update.sh`](https://github.com/GubernievS/AntiZapret-VPN/blob/aabea42bb51520371c8afc2b9b82cc6966068660/setup/root/antizapret/update.sh) downloads the raw inputs. [`parse.sh`](https://github.com/GubernievS/AntiZapret-VPN/blob/aabea42bb51520371c8afc2b9b82cc6966068660/setup/root/antizapret/parse.sh) combines them with user configuration and writes effective host lists and RPZ policies. The checker reads local copies and never executes these scripts or sources the shell `setup` file.

| Input or result | Purpose |
| --- | --- |
| `download/bol-van-domain.txt` | `bol-van/rulist` registry, fetched from `reestr_hostname.txt` |
| `download/antifilter-download-domain.txt` | Registry fetched from `antifilter.download/list/domains.lst` |
| `download/*include-hosts.txt`, `config/*include-hosts.txt` | Additional normal AntiZapret domain includes |
| `download/*exclude-hosts.txt`, `config/*exclude-hosts.txt` | Exceptions to normal domain routing |
| `download/*remove-hosts.txt`, `config/*remove-hosts.txt` | Names removed during parsing |
| `download/*include-warp-hosts.txt`, `config/*include-warp-hosts.txt` | WARP domain includes |
| `config/*exclude-warp-hosts.txt` | WARP exceptions |
| `result/include-hosts.txt`, `result/exclude-hosts.txt` | Normal routed domain rules after filtering and redundant-subdomain removal |
| `result/include-warp-hosts.txt`, `result/exclude-warp-hosts.txt` | Generated WARP host rules |
| `result/proxy.rpz`, `result/warp.rpz`, `result/warp2.rpz` | Generated resolver routing policies |
| `config/*proxy-rpz.txt`, `config/*warp-rpz.txt` | Custom RPZ routing policies appended by the parser |
| `result/route-ips.txt` | IP/CIDR routes; these do not identify all corresponding hostnames |

The normal parser also applies `CLEAR_HOSTS`, removal lists, exclusions and parent-domain compression. Downloaded raw names are therefore checked against generated routing coverage rather than all being assumed routed. Known finite children of a routed parent are retained as distinct probe targets even when the parser compressed those children into the parent rule. User configuration additions remain visible immediately, with a warning when source files are newer than generated lists.

When generated routing files are missing, the checker uses source lists and reports that coverage is a fallback. It cannot reproduce every setup-dependent filter without the parsed results. Run AntiZapret's normal parser separately if you need the generated policy refreshed.

Supported custom RPZ syntax includes literal and wildcard hostname `CNAME .` routing and `CNAME rpz-passthru.` exceptions. Wildcards affect classification and downloaded-name coverage; the checker does not invent an apex hostname for a wildcard. Other record types and special RPZ IP triggers produce warnings.

The inventory contains names, not a packet capture or a complete DNS query history. Full VPN and catch-all policies can carry arbitrary destinations; parent and wildcard rules cover unlisted children, and IP routes can carry services with no listed hostname. These cannot be exhaustively enumerated from static lists. Adblock/deny lists describe rejected DNS traffic and are not treated as routed-domain inputs.

Each check still runs from the client VPS's direct egress using public IPv4 DNS and HTTPS HEAD on port 443. It does not reproduce the user's full VPN path, test the donor, follow redirects, or establish that all website features work.
