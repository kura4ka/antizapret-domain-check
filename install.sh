#!/usr/bin/env bash
# Generated standalone installer. Edit tools/install.template.sh and run tools/build.py.
set -Eeuo pipefail
umask 077

VERSION=0.2.0
PROGRAM_DIR=/opt/antizapret-domain-check
WRAPPER=/usr/local/bin/antizapret-domain-check
CONFIG_DIR=/etc/antizapret-domain-check
STATE_DIR=/root/antizapret-domain-check
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

payload = '''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'''
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
CONFIG_JSON
        install -m 0600 "$stage/config.json" "$CONFIG_DIR/config.json"
    else
        /usr/bin/python3 -I - "$CONFIG_DIR/config.json" "$PROGRAM_DIR" <<'MIGRATE_CONFIG_PY'
import json
import os
from pathlib import Path
import sys
import tempfile

sys.path.insert(0, sys.argv[2])
from azcheck.cli import _pairs, migrate_config

config_path = Path(sys.argv[1])
if config_path.is_symlink() or not config_path.is_file() or config_path.stat().st_size > 1024 * 1024:
    sys.exit('Existing configuration must be a regular file smaller than 1 MiB.')
original = config_path.read_bytes()
document = json.loads(original.decode('utf-8'), object_pairs_hook=_pairs)
upgraded = migrate_config(document)
if upgraded != document:
    descriptor, backup_name = tempfile.mkstemp(prefix='config.json.before-v0.2.', suffix='.bak', dir=str(config_path.parent))
    with os.fdopen(descriptor, 'wb') as backup:
        os.chmod(backup_name, 0o600)
        backup.write(original)
        backup.flush()
        os.fsync(backup.fileno())
    descriptor, temporary = tempfile.mkstemp(prefix='.config.json.', dir=str(config_path.parent))
    try:
        with os.fdopen(descriptor, 'w', encoding='utf-8', newline='\n') as output:
            os.chmod(temporary, 0o600)
            json.dump(upgraded, output, indent=2)
            output.write('\n')
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, config_path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    print('[antizapret-domain-check] Updated old scope/report defaults; previous config saved at ' + backup_name)
MIGRATE_CONFIG_PY
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
    log 'Default report: /root/antizapret-domain-check/reports/latest.txt'
    log 'Default candidates: /root/antizapret-domain-check/reports/suggested-include-warp-hosts.txt'
    log 'Custom report_dir settings are preserved. Historical reports in /var/lib are left in place.'
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
