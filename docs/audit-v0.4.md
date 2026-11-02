# Domain and DNS pipeline audit — 0.4.0

This audit covers the standalone checker's collection, normalization, filtering, DNS checks, checkpoint reuse, and report writing against AntiZapret's native download/parse/DNS design. It uses repository source inspection and network-free regression tests. The native domain-processing block and DNS templates were also compared with upstream commit `c853c13b6dff140d23ddb9e10dfbe69d853ce225`; the relevant logic was unchanged from the inspected `aabea42` revision. The VPS's local routing files were not provided, so its exact 779,454-domain snapshot cannot be independently reproduced here.

## Findings and corrections

| Finding in the previous checker | Result in 0.4 |
| --- | --- |
| Raw downloaded registry expansion was enabled by default | Generated routing inventory is the default; raw expansion requires `--include-download` |
| Generated hostnames and literal RPZ additions could bypass the final routing predicate | Passthru/current policy filtering applies to generated candidates too |
| Unparsed source exclusions/custom RPZs could alter generated policy coverage | Existing generated policies remain authoritative; new explicit additions are visible as pending |
| Some WARP exclusion checks ignored more-specific generated routes | Coverage uses policy specificity; explicit user WARP exclusion preferences remain respected for suggestions |
| A missing generated policy could promote its config sources as active | Partial generated inventories retain pending provenance for missing-policy additions |
| The same malformed names appeared in a host list and its RPZ copy | Each invalid source occurrence is reported, while none becomes a probe target |
| Valid `goog`, `google`, and `ua` suffix rules looked like errors | Valid policy occurrences are informational and contribute zero standalone probe names |
| Native `.` exception handling and registry punctuation differed from upstream | `.` in exclude/remove lists is ignored; registry ASCII edge punctuation matches native parsing |
| DNS used one hardcoded Cloudflare DoH endpoint | Supported installed native DNS configuration is discovered; the native real-answer listener and every applicable configured endpoint are checked |
| Old outcomes could survive a DNS-context change | Probe-context fingerprinting invalidates incompatible cache results while retaining pauses |
| Suggestions could remain stale until another stage finished | Current rules/context refresh suggestions before waiting or sending new traffic |

The checker still does not decide that a domain is useful merely because it exists. Static routing lists can contain obsolete sites and mirrors. DNS/HTTPS observations report accessibility and tentative routing candidates, not editorial relevance or proof that the donor will work.

## 1. Where domains come from

Native AntiZapret `update.sh` intentionally downloads:

- Bol-van: `https://raw.githubusercontent.com/bol-van/rulist/main/reestr_hostname.txt` → `/root/antizapret/download/bol-van-domain.txt`.
- AntiFilter: `https://antifilter.download/list/domains.lst` → `/root/antizapret/download/antifilter-download-domain.txt`.
- AntiZapret's bundled include/exclude/remove inputs, optional blocking/IP inputs, and custom-update inputs.

The checker reads these **local files**; it does not download registries, execute the updater, or refresh AntiZapret policies. User additions come from the native `config/` globs and explicit `--file`/`--domain` arguments.

## 2. How names are processed

Native AntiZapret first normalizes source text, converts registry IDNs, applies optional `CLEAR_HOSTS` filtering and exact removals, normalizes selected redundant subdomain prefixes, sorts/deduplicates, and compresses child names under parent rules. It writes normal and WARP include/exclude lists and the generated RPZ policies.

The checker reads generated lists/policies, converts valid hostnames to lowercase ASCII IDNA, removes a trailing DNS dot, validates DNS labels and lengths, rejects IP literals/invalid names as hostname targets, and deduplicates the full inventory by normalized hostname. Duplicate rows or host/RPZ copies preserve source references but do not add extra targets.

Generated RPZ policy is preferred over its corresponding host-list sources. Coverage respects exact and wildcard specificity and passthru exceptions. Explicit config additions are retained as requested checks even if not yet generated; `pending_config_domains` distinguishes them from current routed names. New source exceptions do not silently rewrite generated routing inside the checker.

`active_routed_domains` measures generated proxy/WARP routing coverage. Earlier client-facing deny or custom DNS policies can prevent access even when that routing coverage exists; the inventory does not model their precedence or subtract overlapping deny-policy names. The native real-answer listener applies its own active policies during a scan. A DNS-error outcome is inconclusive and does not establish that donor routing would help.

Raw expansion is a separate opt-in step. It reads local downloaded include/registry names and retains only eligible names under the effective coverage/removal rules. It can restore known children that native compression removed as redundant entries. It is not required to discover the base generated inventory.

## 3. Which files receive output

The [source map](upstream-sources.md) describes each native generated file. In particular:

| Writer | Destination | Contents |
| --- | --- | --- |
| AntiZapret updater | `/root/antizapret/download/` | Downloaded source inputs |
| AntiZapret parser | `/root/antizapret/temp/` | Intermediate normalized, filtered, and sorted working lists |
| AntiZapret parser | `/root/antizapret/result/include-hosts.txt` | Normal routing rules after native filters/compression |
| AntiZapret parser | `/root/antizapret/result/exclude-hosts.txt` | Normal exceptions after native removal processing |
| AntiZapret parser | `/root/antizapret/result/include-warp-hosts.txt`, `exclude-warp-hosts.txt` | Normalized WARP includes and exceptions |
| AntiZapret parser | `/root/antizapret/result/proxy.rpz`, `warp.rpz`, `warp2.rpz` | Generated exact/wildcard policies, exceptions, and applicable custom records |
| AntiZapret parser | `/etc/knot-resolver/*.rpz` | Installed copies of changed generated resolver policies |
| Checker `audit` | `reports/inventory.tsv` | Exactly the selected unique domains, current WARP states, and source references |
| Checker `audit` | `reports/inventory-audit.txt`, `.json` | Count/source accounting and DNS discovery evidence/error |
| Checker scan | `reports/checkpoint.sqlite3` | Committed outcomes, current targets, context fingerprint, and pauses |
| Checker scan | `reports/latest.txt`, `.json` | Latest stage details with cumulative progress; full run after completion |
| Checker scan | `reports/suggested-include-warp-hosts.txt` | Current cumulative tentative candidates, never an automatically installed route list |
| Checker scan | `reports/runs/<run-id>/batch-*/` | Stage report history |

`reports/` defaults to `/root/antizapret-domain-check/reports/`. Reports are staged into temporary files before replacement and full-run results are streamed from the checkpoint. The checker writes no native AntiZapret list, RPZ policy, or DNS configuration. A custom report path inside the AntiZapret tree is rejected.

## 4. Why 779,454 names were selected

In the previous version, the selected inventory was the **unique union** of generated normal/WARP hostnames, supported literal RPZ routing owners, explicit config/user additions, and raw downloaded children that matched routing coverage. A broad suffix such as `ua` covers finite registry names under that suffix; its presence can therefore admit many raw children during expansion.

The warning about **2,041,122 omitted entries** counted source occurrences. The two registries overlap, and a name can also occur in bundled lists and generated policies. That omitted count cannot be added to or subtracted from a unique-domain count as if each row were a different domain.

The invalid-entry warnings and standalone suffix rules do not explain the high count: none is a probe hostname. The user's warning references line **569,107** of `result/include-hosts.txt`, establishing that the generated source itself is already large. Disabling raw expansion can reduce extra work but does not promise a small inventory.

To measure the actual current VPS files without network checks:

```bash
antizapret-domain-check audit --compare-download
cat /root/antizapret-domain-check/reports/inventory-audit.txt
```

`--compare-download` additionally builds the expanded inventory; this can use substantial memory on a small VPS. Run plain `audit` first if RAM is limited.

The audit records:

- `unique_count` / `total_unique_domains`: selected normalized names.
- `unique_contributions`: disjoint additions by collection stage; their sum equals the selected count.
- `source_stats`: each file's rows, valid/invalid entries, suffix occurrences, unique source hostnames, newly added targets, duplicates, filtered entries, and reasons.
- `active_routed_domains` and pending config names/count.
- Optional `comparison`: the raw-expanded union and its corresponding source statistics.

`added_unique` belongs to the first processing stage/file that adds a name, so per-source contributions depend on the documented collection order; the final union does not. No claims of an exact reproduced 779,454 split are made without the source snapshot.

## 5. Were Bol-van and AntiFilter accidental sources?

They are intentional **upstream AntiZapret** sources. The checker also intentionally added raw registry expansion when its earlier scope was widened to include all known routed names. The audit found that making this expansion the default was too broad for the practical default inventory: generated lists already contain the native filtered result.

Version 0.4 disables raw expansion by default. Configuration versions 1–3 are migrated to that corrected default; explicit version-4 settings can retain expansion. `--include-download` enables it for a deliberate scan or audit. This changes checker inventory selection, not native AntiZapret downloads or routing.

## 6. Does checking use AntiZapret's actual DNS infrastructure?

Previously, no: default domain lookups used hardcoded `https://1.1.1.1/dns-query`, not AntiZapret's configured resolver plan. They were not arbitrary system-DNS lookups, but they still lacked native DNS parity.

Version 0.4 reads supported saved `kresd.conf`, `dns.lua`, `custom3.lua`, native `proxy.py`, and the active fallback action. The native proxy's real-answer DNS target is **`127.3.3.3:53`**, served by Knot instance `@3`. Client-facing AntiZapret DNS may return fake routing IPs and is not interchangeable with that real-answer listener.

For every domain, the checker queries the native reference plus every applicable endpoint in the selected proxy group, active FORWARD fallback action, and supported domain-specific custom policy. It preserves explicit ports and records every response. Unused groups in `dns.lua` are not queried simply because they are defined. HTTPS uses the native reference's public IPv4 answer; direct comparison answers do not silently replace a failed reference.

This distinction matters for names such as Quad9: the shipped `world_dns` group includes `9.9.9.10` and alternate ports, rather than an assumed `9.9.9.9`. MSK-IX and other endpoints are included when selected/applicable in the installed plan.

The native reference preserves Knot's policy and DNS egress path. Direct comparisons run as the checker user and can use different egress, particularly with UID-based DNS_WARP routing. Saved supported configuration discovery cannot prove service runtime state or arbitrary launch overrides. Unknown custom expressions stop discovery with a useful error instead of being executed or replaced by a hardcoded provider. Explicit `--resolver` or legacy `--resolver-url` overrides are clearly reported.

A DNS-plan/probe-context change invalidates incompatible cached outcomes. Current exclusion/include rules are reapplied to candidates without repeating unchanged network checks.

## 7. Are invalid names and suffix rules handled correctly?

- Invalid native/registry names are skipped and counted as source diagnostics. They add **zero** probe targets.
- A malformed hostname can appear once in a generated host list and twice in paired exact/wildcard RPZ records. Four unsupported RPZ records are therefore consistent with two malformed generated names; their exact content still requires inspecting those local lines.
- `goog`, `google`, and `ua` are valid suffix policies. Their occurrences are informational; the suffix alone is not probed as an HTTPS hostname.
- Wildcards and `.` are policy coverage, not invented apex names. A literal hostname present elsewhere may still be a valid target under that coverage.
- Duplicate normalized names count once across every source.
- IP/CIDR-only routes do not enumerate all associated names and are reported as a finite-inventory limitation.

## Practical upgrade and first check

```bash
curl -fSL https://raw.githubusercontent.com/kura4ka/antizapret-domain-check/main/install.sh -o install.sh
bash install.sh
antizapret-domain-check audit --compare-download
antizapret-domain-check scan --one-batch
```

Checking every applicable DNS endpoint adds traffic and time: with the stock 12 diagnostic endpoints plus the local reference, 779,454 names imply about 10.1 million first-attempt queries. The 0.25-second global DNS pacing alone is about 29.3 days for a fresh run, before retries and stage pauses. The CLI reports the applicable query count and separate domain/DNS pacing floors.

Defaults retain 500-domain stages and five-minute pauses, add pacing for individual DNS queries, and save completed work immediately. HTTP `429` stops scanning and persists its cooldown. DNS/HTTPS checks remain client-only observations; a tentative candidate does not establish donor accessibility or full browser/application functionality.

## Performance option added in 0.5

The 0.4 full matrix remains available with `--dns-checks all`. `scan --fast` uses native/reference DNS only, up to 128 workers, no artificial domain/DNS pacing, 5000-domain stages, and no inter-stage pauses. It preserves the full selected inventory and reports skipped direct diagnostics. For the observed 627,432-name inventory, checker DNS calls drop from 8,156,616 to 627,432 before retries; the 23.6-day artificial pacing floor disappears. Runtime depends on observed throughput, timeouts, retries and VPS resources. TLS certificate and public-IP checks remain enabled. `scan --fast --retry-failed` requeues saved candidate/inconclusive outcomes while retaining successful checks and honoring saved cooldowns. See the [current guide](../README.md#fast-scan-for-large-inventories) for usage and resume behavior.

## Site-rate-limit correction in 0.5.1

Earlier versions paused the entire inventory after any HTTP 429. Version 0.5.1 records HTTPS-origin limits separately, saves the affected domain's cooldown and continues unrelated checks. Shared explicit-DoH/unknown limits retain a global pause. A proven old native/explicit HTTPS429 pause is migrated to origin cooldowns without discarding cached results or changing the probe context. `--retry-failed` respects those deadlines. TLS verification, destination validation and Retry-After handling remain enabled.
