#!/usr/bin/env python3
"""Pure-standard-library init/service definition generator for Shadow6."""

from __future__ import annotations

import re
import shlex
import argparse
import unicodedata
from pathlib import Path
from xml.sax.saxutils import escape as xml_escape

SAFE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
INIT_ALIASES = {
    "freebsd": "rc.d", "rcd": "rc.d", "openwrt": "procd",
    "macos": "launchd", "darwin": "launchd", "guixsd": "guix",
    "guix-system": "guix",
}
INIT_SYSTEMS = {"systemd", "openrc", "runit", "sysv", "rc.d", "procd", "launchd", "guix"}


def normalize_init_system(system: str) -> str:
    normalized = INIT_ALIASES.get(system.lower(), system.lower())
    if normalized not in INIT_SYSTEMS:
        raise ValueError(f"unsupported init system: {system}")
    return normalized


def _scheme_quote(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def rc_variable(name: str) -> str:
    """FreeBSD rc.subr names also appear in shell variable identifiers."""
    return "s6_" + name.replace("-", "_").replace(".", "_")


def generate_init_script(system: str, name: str, bin_path: str, conf_path: str) -> str:
    if not SAFE_NAME_RE.fullmatch(name):
        raise ValueError(f"unsafe service name: {name!r}")
    if any(unicodedata.category(character) in {"Cc", "Cs"} for character in bin_path + conf_path) or not Path(bin_path).is_absolute() or not Path(conf_path).is_absolute():
        raise ValueError("service paths must be absolute and contain no control characters")
    system = normalize_init_system(system)
    shell_bin, shell_conf = shlex.quote(bin_path), shlex.quote(conf_path)
    # rc frameworks interpret command_args a second time; quote each argv
    # member before quoting the shell assignment itself.
    command_args = shlex.quote(shlex.join(["--config", conf_path]))
    if system == "systemd":
        quote = lambda value: '"' + value.replace("%", "%%").replace("\\", "\\\\").replace('"', '\\"') + '"'
        exec_quote = lambda value: quote(value).replace("$", "$$")
        return f"[Unit]\nDescription={name}\nAfter=network-online.target\nWants=network-online.target\n[Service]\nType=simple\nExecStart={exec_quote(bin_path)} --config {exec_quote(conf_path)}\nRestart=on-failure\nRestartSec=5\nUMask=0077\nLimitCORE=0\nLimitNOFILE=4096\nTasksMax=512\nNoNewPrivileges=true\nPrivateTmp=true\nProtectSystem=strict\nProtectHome=true\nProtectKernelTunables=true\nProtectKernelModules=true\nProtectControlGroups=true\nRestrictSUIDSGID=true\nLockPersonality=true\nMemoryDenyWriteExecute=true\nReadOnlyPaths={quote(conf_path)}\n[Install]\nWantedBy=multi-user.target\n"
    if system == "openrc":
        return f"#!/sbin/openrc-run\numask 077\nname=\"{name}\"\ncommand={shell_bin}\ncommand_args={command_args}\ncommand_background=true\npidfile=\"/run/{name}.pid\"\n"
    if system == "runit":
        return f"#!/bin/sh\numask 077\nexec {shell_bin} --config {shell_conf}\n"
    if system == "sysv":
        return f"#!/bin/sh\n### BEGIN INIT INFO\n# Provides: {name}\n### END INIT INFO\nexec {shell_bin} --config {shell_conf}\n"
    if system == "rc.d":
        variable = rc_variable(name)
        daemon_args = shlex.quote(shlex.join(["-p", f"/var/run/{name}.pid", "-f", bin_path, "--config", conf_path]))
        return (
            f"#!/bin/sh\n# PROVIDE: {name}\n# REQUIRE: NETWORKING\n# KEYWORD: shutdown\n\n"
            f". /etc/rc.subr\numask 077\nname=\"{variable}\"\nrcvar=\"${{name}}_enable\"\ncommand=/usr/sbin/daemon\n"
            f"procname={shell_bin}\ncommand_args={daemon_args}\n"
            f"pidfile=\"/var/run/{name}.pid\"\nload_rc_config \"$name\"\n: ${{{variable}_enable:=NO}}\nrun_rc_command \"$1\"\n"
        )
    if system == "procd":
        return (
            "#!/bin/sh /etc/rc.common\nSTART=95\nSTOP=05\nUSE_PROCD=1\n\nstart_service() {\n"
            f"    procd_open_instance\n    procd_set_param command {shell_bin} --config {shell_conf}\n"
            "    procd_set_param respawn 3600 5 5\n    procd_set_param stdout 1\n    procd_set_param stderr 1\n"
            "    procd_set_param limits core=\"0\" nofile=\"4096 4096\"\n    procd_close_instance\n}\n\n"
            f"service_triggers() {{\n    procd_add_reload_trigger {shlex.quote(name)}\n}}\n"
        )
    if system == "launchd":
        binary, config = [xml_escape(value, {'"': "&quot;", "'": "&apos;"}) for value in (bin_path, conf_path)]
        return (
            '<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n'
            f'<plist version="1.0">\n<dict>\n  <key>Label</key><string>org.shadow6.{name}</string>\n'
            f'  <key>ProgramArguments</key><array><string>{binary}</string><string>--config</string><string>{config}</string></array>\n'
            '  <key>RunAtLoad</key><true/>\n  <key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>\n'
            '  <key>ProcessType</key><string>Background</string>\n  <key>Umask</key><integer>63</integer>\n'
            f'  <key>StandardOutPath</key><string>/var/log/{name}.log</string>\n  <key>StandardErrorPath</key><string>/var/log/{name}.err</string>\n</dict>\n</plist>\n'
        )
    return (
        ";; Add shadow6-service to the services field of your operating-system.\n"
        "(use-modules (gnu services) (gnu services shepherd))\n\n(define shadow6-service\n  (shepherd-service\n"
        f"    (provision (list (string->symbol \"{name}\")))\n    (requirement '(networking))\n    (documentation \"Shadow6 service {name}\")\n"
        f"    (start #~(make-forkexec-constructor\n               (list {_scheme_quote(bin_path)} \"--config\" {_scheme_quote(conf_path)})\n"
        f"               #:log-file \"/var/log/{name}.log\"))\n    (stop #~(make-kill-destructor))))\n\n"
        f"(simple-service '{name}-service shepherd-root-service-type\n                (list shadow6-service))\n"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--system", required=True)
    parser.add_argument("--name", required=True)
    parser.add_argument("--binary", required=True)
    parser.add_argument("--config", required=True)
    args = parser.parse_args()
    try:
        print(generate_init_script(args.system, args.name, args.binary, args.config), end="")
    except ValueError as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
