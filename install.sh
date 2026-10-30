#!/usr/bin/env bash
# Generated standalone installer. Edit tools/install.template.sh and run tools/build.py.
set -Eeuo pipefail
umask 077

VERSION=0.3.0
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
    descriptor, backup_name = tempfile.mkstemp(prefix='config.json.before-v0.3.', suffix='.bak', dir=str(config_path.parent))
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
    log 'Run stages with saved progress: antizapret-domain-check scan'
    log 'Run one stage only: antizapret-domain-check scan --one-batch'
    log 'Default stages: 500 domains, then a 5-minute pause. Re-run scan to resume interrupted work.'
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
