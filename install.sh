#!/usr/bin/env bash
# Generated standalone installer. Edit tools/install.template.sh and run tools/build.py.
set -Eeuo pipefail
umask 077

VERSION=0.1.0
PROGRAM_DIR=/opt/antizapret-domain-check
WRAPPER=/usr/local/bin/antizapret-domain-check
CONFIG_DIR=/etc/antizapret-domain-check
STATE_DIR=/var/lib/antizapret-domain-check
UNIT_DIR=/etc/systemd/system
SERVICE=antizapret-domain-check.service
TIMER=antizapret-domain-check.timer

log() { printf '[antizapret-domain-check] %s\n' "$*"; }
die() { printf '[antizapret-domain-check] ERROR: %s\n' "$*" >&2; exit 1; }
usage() {
    cat <<'USAGE'
Install on the AntiZapret client VPS as root:
  bash install.sh                 Install or update; keep existing configuration
  bash install.sh --enable-timer  Install or update and enable one daily scan
  bash install.sh --disable-timer Stop and disable daily scans
  bash install.sh --uninstall     Remove program and timer; keep config and reports

After installation:
  antizapret-domain-check inventory
  antizapret-domain-check scan

This tool creates suggestions. It does not edit AntiZapret or relay settings.
USAGE
}

require_systemd() {
    command -v systemctl >/dev/null && [[ -d /run/systemd/system ]] || die 'A running systemd host is required for this action.'
}

stop_timer() {
    if systemctl cat "$TIMER" >/dev/null 2>&1; then
        systemctl disable --now "$TIMER"
    fi
}

install_program() (
    [[ -f /etc/os-release ]] || die 'Supported systems: Debian and Ubuntu.'
    # shellcheck disable=SC1091
    source /etc/os-release
    [[ ${ID:-} == debian || ${ID:-} == ubuntu ]] || die 'Supported systems: Debian and Ubuntu.'
    if [[ ! -x /usr/bin/python3 ]] || ! command -v curl >/dev/null; then
        apt-get update
        DEBIAN_FRONTEND=noninteractive apt-get install -y python3 curl
    fi
    [[ -x /usr/bin/python3 ]] && command -v curl >/dev/null || die 'Python 3 and curl are required.'
    [[ ! -L $PROGRAM_DIR && ! -L $WRAPPER && ! -L $CONFIG_DIR && ! -L $STATE_DIR && ! -L $STATE_DIR/reports ]] || die 'An installation path is a symbolic link; resolve it before installing.'
    if [[ -e $PROGRAM_DIR && ! -f $PROGRAM_DIR/.antizapret-domain-check ]]; then
        die "The reserved program path already exists without an installation marker: $PROGRAM_DIR"
    fi
    if [[ $timer_action == enable ]]; then require_systemd; fi

    local stage program_stage previous=''
    stage=$(mktemp -d)
    program_stage=''
    trap 'rm -rf -- "$stage"; if [[ -n $program_stage ]]; then rm -rf -- "$program_stage"; fi' EXIT
    /usr/bin/python3 - "$stage" <<'AZCHECK_PAYLOAD_PY'
import base64
import io
from pathlib import Path, PurePosixPath
import sys
import tarfile

payload = '''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
XJtrc22uzbW5Ntfm2lyb6x/g+h/Z4k+bAMgAAA=='''
destination = Path(sys.argv[1])
with tarfile.open(fileobj=io.BytesIO(base64.b64decode(payload)), mode='r:gz') as archive:
    for member in archive.getmembers():
        name = PurePosixPath(member.name)
        module = len(name.parts) == 2 and name.parts[0] == 'azcheck' and name.suffix == '.py'
        unit = member.name in ('systemd/antizapret-domain-check.service', 'systemd/antizapret-domain-check.timer')
        if not member.isfile() or name.is_absolute() or '..' in name.parts or not (module or unit):
            sys.exit('Invalid installer payload member.')
        target = destination.joinpath(*name.parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        with archive.extractfile(member) as source:
            target.write_bytes(source.read())
AZCHECK_PAYLOAD_PY
    install -d -m 0755 /opt
    program_stage=$(mktemp -d /opt/.antizapret-domain-check.new.XXXXXX)
    chmod 0755 "$program_stage"
    install -d -m 0755 "$program_stage/azcheck"
    install -m 0644 "$stage"/azcheck/*.py "$program_stage/azcheck/"
    printf '%s\n' "$VERSION" > "$program_stage/.antizapret-domain-check"
    chmod 0644 "$program_stage/.antizapret-domain-check"
    if [[ -d $PROGRAM_DIR ]]; then
        previous=$(mktemp -d /opt/.antizapret-domain-check.old.XXXXXX)
        rmdir -- "$previous"
        mv -- "$PROGRAM_DIR" "$previous"
    fi
    if ! mv -- "$program_stage" "$PROGRAM_DIR"; then
        if [[ -n $previous ]]; then mv -- "$previous" "$PROGRAM_DIR"; fi
        die 'Could not replace the installed program.'
    fi
    program_stage=''
    if [[ -n $previous ]]; then rm -rf -- "$previous"; fi

    install -d -m 0755 /usr/local/bin
    cat > "$stage/wrapper" <<'WRAPPER_SH'
#!/usr/bin/env bash
exec /usr/bin/python3 -I -c 'import runpy, sys; sys.path.insert(0, "/opt/antizapret-domain-check"); runpy.run_module("azcheck", run_name="__main__")' "$@"
WRAPPER_SH
    install -m 0755 "$stage/wrapper" "$WRAPPER"
    install -d -m 0700 "$CONFIG_DIR" "$STATE_DIR" "$STATE_DIR/reports"
    [[ ! -L $CONFIG_DIR/config.json ]] || die 'The config path is a symbolic link; existing configuration was kept.'
    if [[ ! -e $CONFIG_DIR/config.json ]]; then
        cat > "$stage/config.json" <<'CONFIG_JSON'
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
CONFIG_JSON
        install -m 0600 "$stage/config.json" "$CONFIG_DIR/config.json"
    fi
    install -d -m 0755 "$UNIT_DIR"
    [[ ! -L $UNIT_DIR/$SERVICE && ! -L $UNIT_DIR/$TIMER ]] || die 'An existing unit path is a symbolic link; resolve it before installing units.'
    install -m 0644 "$stage/systemd/$SERVICE" "$UNIT_DIR/$SERVICE"
    install -m 0644 "$stage/systemd/$TIMER" "$UNIT_DIR/$TIMER"
    if command -v systemctl >/dev/null && [[ -d /run/systemd/system ]]; then
        systemctl daemon-reload
    fi
    if [[ $timer_action == enable ]]; then
        systemctl enable --now "$TIMER"
        log 'Daily scans enabled. Run systemctl list-timers antizapret-domain-check.timer to see the next run.'
    fi
    log "Installed v$VERSION on this client VPS. Existing configuration and reports are preserved."
    log 'Check the inventory: antizapret-domain-check inventory'
    log 'Run a check now: antizapret-domain-check scan'
    log 'Report: /var/lib/antizapret-domain-check/reports/latest.txt'
    log 'Review candidates: /var/lib/antizapret-domain-check/reports/suggested-include-warp-hosts.txt'
    log 'Suggestions are tentative. Add only confirmed domains to /root/antizapret/config/include-warp-hosts.txt, then run /root/antizapret/parse.sh.'
)

uninstall_program() {
    [[ ! -L $PROGRAM_DIR && ! -L $WRAPPER ]] || die 'An installed program path is a symbolic link; resolve it before uninstalling.'
    if [[ -e $PROGRAM_DIR && ! -f $PROGRAM_DIR/.antizapret-domain-check ]]; then
        die 'Installation marker is missing; refusing to remove an unrelated directory.'
    fi
    if command -v systemctl >/dev/null && [[ -d /run/systemd/system ]]; then
        stop_timer
        # Stop a scan started by the timer before removing its program files.
        if systemctl cat "$SERVICE" >/dev/null 2>&1; then systemctl stop "$SERVICE"; fi
    fi
    rm -f -- "$UNIT_DIR/$SERVICE" "$UNIT_DIR/$TIMER" "$WRAPPER"
    if [[ -d $PROGRAM_DIR ]]; then rm -rf -- "$PROGRAM_DIR"; fi
    if command -v systemctl >/dev/null && [[ -d /run/systemd/system ]]; then systemctl daemon-reload; fi
    log 'Program and timer removed. Configuration and reports are preserved.'
}

main() {
    local action=install timer_action=keep
    case ${1:-} in
        -h|--help) [[ $# -eq 1 ]] || die 'Use --help by itself.'; usage; return ;;
        --version) [[ $# -eq 1 ]] || die 'Use --version by itself.'; printf '%s\n' "$VERSION"; return ;;
    esac
    [[ $# -le 1 ]] || die 'Use one installer action at a time. See --help.'
    case ${1:-} in
        '') ;;
        --enable-timer) timer_action=enable ;;
        --disable-timer) action=disable ;;
        --uninstall) action=uninstall ;;
        *) die 'Unknown installer option. See --help.' ;;
    esac
    [[ $EUID -eq 0 ]] || die 'Run as root: sudo bash install.sh'
    command -v flock >/dev/null || die 'The flock command from util-linux is required.'
    exec 9>/run/lock/antizapret-domain-check-install.lock
    flock -n 9 || die 'Another domain-check installer is running.'
    case "$action" in
        install) install_program ;;
        disable) require_systemd; stop_timer; log 'Daily scans disabled. Manual scans remain available.' ;;
        uninstall) uninstall_program ;;
    esac
}

main "$@"
