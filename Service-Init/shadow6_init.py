#!/usr/bin/env python3
"""Pure-standard-library init/service definition generator for Shadow6."""

from __future__ import annotations

import re
import shlex
import argparse
import unicodedata
from pathlib import Path, PurePosixPath, PureWindowsPath
from xml.sax.saxutils import escape as xml_escape

SAFE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
INIT_ALIASES = {
    "freebsd": "rc.d", "rcd": "rc.d", "openwrt": "procd",
    "macos": "launchd", "darwin": "launchd", "guixsd": "guix",
    "guix-system": "guix",
    "windows": "windows-service", "win32": "windows-service",
    "illumos": "smf", "omnios": "smf", "solaris": "smf",
}
INIT_SYSTEMS = {"systemd", "openrc", "runit", "sysv", "rc.d", "procd", "launchd", "guix", "windows-service", "smf"}


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


def generate_init_script(system: str, name: str, bin_path: str, conf_path: str, *, fd_ceiling: int | None = None) -> str:
    if fd_ceiling is not None and (type(fd_ceiling) is not int or not 1 <= fd_ceiling <= 2**53 - 1):
        raise ValueError("invalid locked descriptor ceiling")
    nofile = 4096 if fd_ceiling is None else fd_ceiling
    if not SAFE_NAME_RE.fullmatch(name):
        raise ValueError(f"unsafe service name: {name!r}")
    system = normalize_init_system(system)
    def absolute(value):
        return PurePosixPath(value).is_absolute() or (system == "windows-service" and PureWindowsPath(value).is_absolute())
    if any(unicodedata.category(character) in {"Cc", "Cs"} for character in bin_path + conf_path) or not absolute(bin_path) or not absolute(conf_path):
        raise ValueError("service paths must be absolute and contain no control characters")
    shell_bin, shell_conf = shlex.quote(bin_path), shlex.quote(conf_path)
    # rc frameworks interpret command_args a second time; quote each argv
    # member before quoting the shell assignment itself.
    command_args = shlex.quote(shlex.join(["--config", conf_path]))
    if system == "systemd":
        quote = lambda value: '"' + value.replace("%", "%%").replace("\\", "\\\\").replace('"', '\\"') + '"'
        exec_quote = lambda value: quote(value).replace("$", "$$")
        return f"[Unit]\nDescription={name}\nAfter=network-online.target\nWants=network-online.target\n[Service]\nType=simple\nExecStart={exec_quote(bin_path)} --config {exec_quote(conf_path)}\nRestart=on-failure\nRestartSec=5\nUMask=0077\nLimitCORE=0\nLimitNOFILE={nofile}\nTasksMax=512\nNoNewPrivileges=true\nPrivateTmp=true\nProtectSystem=strict\nProtectHome=true\nProtectKernelTunables=true\nProtectKernelModules=true\nProtectControlGroups=true\nRestrictSUIDSGID=true\nLockPersonality=true\nMemoryDenyWriteExecute=true\nReadOnlyPaths={quote(conf_path)}\n[Install]\nWantedBy=multi-user.target\n"
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
            f"    procd_set_param limits core=\"0\" nofile=\"{nofile} {nofile}\"\n    procd_close_instance\n}}\n\n"
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
    if system == "windows-service":
        # Typed definition consumed by the host-owned SCM adapter; no shell or
        # arbitrary command is embedded in the contract.
        import json
        return json.dumps({"schema":"shadow6.windows-service-definition.v1",
            "serviceName":name,"binary":bin_path,"config":conf_path,
            "restart":"on-failure","fdCeiling":nofile,"owner":"shadow6"}, sort_keys=True) + "\n"
    if system == "smf":
        xml_name = xml_escape(name)
        xml_bin = xml_escape(bin_path, {'"': '&quot;', "'": '&apos;'})
        xml_conf = xml_escape(conf_path, {'"': '&quot;', "'": '&apos;'})
        return (f'<?xml version="1.0"?>\n<!DOCTYPE service_bundle SYSTEM "/usr/share/lib/xml/dtd/service_bundle.dtd.1">\n'
            f'<service_bundle type="manifest" name="shadow6:{xml_name}">\n  <service name="site/shadow6/{xml_name}" type="service" version="1">\n'
            f'    <create_default_instance enabled="false"/>\n    <single_instance/>\n    <dependency name="network" grouping="require_all" restart_on="restart" type="service">\n'
            '      <service_fmri value="svc:/milestone/network:default"/>\n    </dependency>\n'
            '    <exec_method type="method" name="start" exec="' + xml_bin + ' --config ' + xml_conf + '" timeout_seconds="30"/>\n'
            '    <exec_method type="method" name="stop" exec=":kill" timeout_seconds="30"/>\n'
            f'    <property_group name="startd" type="framework"><propval name="duration" type="astring" value="transient"/></property_group>\n'
            f'    <property_group name="method_context" type="method"><method_credential user="shadow6"/></property_group>\n'
            '  </service>\n</service_bundle>\n')
    return (
        ";; Add the resulting simple-service to your operating-system services.\n"
        "(use-modules (gnu services) (gnu services shepherd) (guix gexp))\n\n(define shadow6-service\n  (shepherd-service\n"
        f"    (provision (list (string->symbol \"{name}\")))\n    (requirement '(networking))\n    (documentation \"Shadow6 service {name}\")\n"
        f"    (start #~(make-forkexec-constructor\n               (list {_scheme_quote(bin_path)} \"--config\" {_scheme_quote(conf_path)})\n"
        f"               #:log-file \"/var/log/{name}.log\"))\n    (stop #~(make-kill-destructor))))\n\n"
        f"(simple-service '{name}-service shepherd-root-service-type\n                (list shadow6-service))\n"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--system", required=True)
    parser.add_argument("--name")
    parser.add_argument("--binary")
    parser.add_argument("--config")
    parser.add_argument("--named-service")
    parser.add_argument("--registry",type=Path)
    parser.add_argument("--capabilities",action='store_true')
    parser.add_argument("--operation",choices=("install-definition", "activate", "deactivate",
        "restart", "status", "remove-definition", "logs"),
        help="emit a lock-bound request for an external system-operations provider")
    args = parser.parse_args()
    try:
        if args.named_service or args.capabilities or args.operation:
            import sys,json,hashlib
            here=Path(__file__).resolve().parent
            root=here.parent if here.name not in {'bin','modules'} else (here.parent/'share/shadow6/tree' if here.name=='bin' else here.parent/'tree')
            sys.path.insert(0,str(root))
            from Deployment.supervisor_contract import capabilities
            backend=normalize_init_system(args.system)
            if args.capabilities:
                print(json.dumps(capabilities(backend),sort_keys=True));return 0
            if args.operation and not args.named_service:
                raise ValueError("--operation requires --named-service")
            if args.binary or args.config or args.name:
                raise ValueError('Named Service realization cannot override binary/config/name')
            from Deployment.service_registry import ServiceRegistry
            from Deployment.core_catalog import CoreCatalog
            registry=ServiceRegistry(args.registry,catalog=CoreCatalog(root))
            plan_path,plan=registry.launch_plan(args.named_service)
            from Deployment.profile_registry import HostBudget
            locked_fds=HostBudget.from_dict(plan["limitResolution"]["host_budget"]).fd_ceiling
            if here.name == 'bin':
                runner = here/'shadow6-service-runner'
            elif here.name == 'modules':
                runner = here.parents[2]/'bin/shadow6-service-runner'
            else:
                runner = root/'Service-Init/shadow6_service_runner.py'
            name='shadow6-'+hashlib.sha256(args.named_service.encode()).hexdigest()[:24]
            definition=generate_init_script(backend,name,str(runner),str(plan_path),fd_ceiling=locked_fds)
            if args.operation:
                from Deployment.system_operations import operation_request
                request=operation_request(backend=backend,operation=args.operation,
                    service=args.named_service,plan_path=str(plan_path),
                    lock_digest=plan['lockDigest'],
                    definition_digest='sha256:'+hashlib.sha256(definition.encode()).hexdigest())
                print(json.dumps(request,sort_keys=True,separators=(',',':')))
                return 0
            print(definition,end='')
            return 0
        if not all((args.name,args.binary,args.config)):
            raise ValueError('legacy service requires --name/--binary/--config')
        print(generate_init_script(args.system, args.name, args.binary, args.config), end="")
    except ValueError as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
