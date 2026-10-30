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

payload = '''@@AZCHECK_PAYLOAD@@'''
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
