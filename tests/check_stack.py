#!/usr/bin/env python3
"""Read-only checks by default. Use --stop-lab only on an isolated project."""
import argparse
import json
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent.parent


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project", default="cyberarena")
    parser.add_argument("--base", default="http://127.0.0.1:8080")
    parser.add_argument("--stop-lab", action="store_true")
    args = parser.parse_args()
    endpoint = urlparse(args.base)
    if (endpoint.scheme != "http" or endpoint.hostname not in ("127.0.0.1", "localhost")
            or not endpoint.port or endpoint.username is not None or endpoint.path not in ("", "/")
            or endpoint.query or endpoint.fragment):
        parser.error("--base must be HTTP on an explicit loopback port")
    if args.stop_lab and (not args.project.startswith(("cyberarena-test-", "cyberarena-demo-"))
                          or endpoint.port == 8080):
        parser.error("--stop-lab requires a separate project and port")
    results = []

    def report(label, result):
        status = "NOT TESTED" if result is None else ("PASS" if result else "FAIL")
        print(f"{status:10} {label}", flush=True)
        results.append(status)

    def docker(*command):
        try:
            return subprocess.run(["docker", *command], cwd=ROOT, text=True,
                                  capture_output=True, timeout=60)
        except (OSError, subprocess.TimeoutExpired):
            return None

    def compose(*command):
        return docker("compose", "--env-file", "/dev/null", "-f", str(ROOT / "compose.yaml"),
                      "-p", args.project, *command)

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs):
            return None

    browser = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

    def http(path):
        try:
            with browser.open(args.base.rstrip("/") + path, timeout=3) as response:
                return response.status, response.headers
        except urllib.error.HTTPError as err:
            return err.code, err.headers
        except OSError:
            return 0, {}

    def check_http():
        for path in ("/", "/health", "/lab/", "/lab/health", "/register", "/login", "/leaderboard",
                     "/static/tasks/web02/vault.js", "/static/tasks/crypto01/cipher.txt"):
            report(f"{path} returns 200", http(path)[0] == 200)
        status, headers = http("/lab")
        report("/lab redirects to /lab/ without losing the public port",
               status in (301, 308) and headers.get("Location") == "/lab/")

    daemon = docker("version", "--format", "{{.Server.Version}}")
    if daemon is None or daemon.returncode:
        check_http()
        report("Docker API, health, isolation, limits, resources and lab outage", None)
        return 1 if "FAIL" in results else 2

    def inspect(service, fields):
        found = compose("ps", "-q", service)
        if found is None or found.returncode or not found.stdout.strip():
            return None
        container_id = found.stdout.strip()
        command = docker("inspect", "--format", fields, container_id)
        if command is None or command.returncode:
            return None
        try:
            return json.loads(command.stdout)
        except json.JSONDecodeError:
            return None

    ports = inspect("nginx", "{{json .NetworkSettings.Ports}}")
    matching_endpoint = ports is not None and {key: bindings for key, bindings in ports.items() if bindings} == {
        "8080/tcp": [{"HostIp": "127.0.0.1", "HostPort": str(endpoint.port)}],
    }
    report("HTTP endpoint belongs to the selected project and is loopback-only",
           None if ports is None else matching_endpoint)
    if not matching_endpoint:
        return 1 if "FAIL" in results else 2

    check_http()
    health = {}
    for service in ("nginx", "app", "lab-web"):
        health[service] = inspect(service, "{{json .State.Health.Status}}")
        report(f"{service} healthcheck", None if health[service] is None else health[service] == "healthy")

    for service in ("app", "lab-web"):
        bindings = inspect(service, "{{json .NetworkSettings.Ports}}")
        report(f"{service} publishes no host ports", None if bindings is None else not any(bindings.values()))

    host = inspect("lab-web", "{{json .HostConfig}}")
    report("lab is unprivileged, read-only, drops all capabilities and forbids privilege elevation",
           None if host is None else host["Privileged"] is False and host["ReadonlyRootfs"] is True
           and host["NetworkMode"] == f"{args.project}_lab-net" and host["CapDrop"] == ["ALL"] and "no-new-privileges:true" in host["SecurityOpt"])
    report("lab limits: RAM 256 MiB, CPU 0.5, PIDs 100",
           None if host is None else (host["Memory"], host["NanoCpus"], host["PidsLimit"])
           == (256 * 1024**2, 500_000_000, 100))
    mounts = inspect("lab-web", "{{json .Mounts}}")
    report("lab mounts only the read-only WEB-01 material volume",
           None if mounts is None else [(m["Destination"], m["RW"]) for m in mounts if m["Type"] != "tmpfs"]
           == [("/lab-flags", False)])
    for service, expected in (("app", {"app-net"}), ("lab-web", {"lab-net"}),
                              ("nginx", {"app-net", "lab-net"})):
        networks = inspect(service, "{{json .NetworkSettings.Networks}}")
        report(f"{service} network membership",
               None if networks is None else set(networks) == {f"{args.project}_{name}" for name in expected})
    net = docker("network", "inspect", "--format", "{{.Internal}}", f"{args.project}_lab-net")
    report("lab-net is internal", None if net is None or net.returncode else net.stdout.strip() == "true")

    app_networks = inspect("app", "{{json .NetworkSettings.Networks}}")
    app_ip = None if app_networks is None else app_networks.get(f"{args.project}_app-net", {}).get("IPAddress")
    app_healthy = compose("exec", "-T", "nginx", "wget", "-q", "-O", "/dev/null",
                          f"http://{app_ip}:8000/health") if app_ip else None
    lab_healthy = compose("exec", "-T", "lab-web", "python", "-c",
                          "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5000/health', timeout=3)")
    probe = compose("exec", "-T", "lab-web", "python", "-c", """
import json, os, socket, sys
from pathlib import Path
def reachable(host, port):
    try:
        with socket.create_connection((host, port), 2):
            return True
    except OSError:
        return False
status = dict(line.split(':', 1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
def limits_applied():
    path = Path('/sys/fs/cgroup')
    if not all((path / name).is_file() for name in ('cpu.max', 'memory.max', 'pids.max')):
        return None
    quota, period = (path / 'cpu.max').read_text().split()
    return (quota != 'max' and int(quota) * 2 == int(period)
            and (path / 'memory.max').read_text().strip() == '268435456'
            and (path / 'pids.max').read_text().strip() == '100')
print(json.dumps({'non_root': os.getuid() != 0, 'no_socket': not os.path.lexists('/var/run/docker.sock'),
                  'no_data': not os.path.exists('/data/cyberarena.db'),
                  'no_capabilities': int(status['CapEff'], 16) == 0,
                  'no_privilege_gain': status['NoNewPrivs'].strip() == '1',
                   'no_app_dns_route': not reachable('app', 8000),
                  'no_app_ip_route': not reachable(sys.argv[1], 8000) if sys.argv[1] else None,
                  'no_egress_to_sample_endpoint': not reachable('1.1.1.1', 443), 'cgroup_limits_applied': limits_applied()}))
""", app_ip or "")
    facts = None
    if probe is not None and not probe.returncode:
        try:
            facts = json.loads(probe.stdout)
        except json.JSONDecodeError:
            pass
    for fact in ("non_root", "no_socket", "no_data", "no_capabilities",
                 "no_privilege_gain", "no_app_dns_route", "no_app_ip_route", "no_egress_to_sample_endpoint", "cgroup_limits_applied"):
        value = None if not isinstance(facts, dict) else facts.get(fact)
        if fact in ("no_app_dns_route", "no_app_ip_route") and (
                app_healthy is None or app_healthy.returncode or lab_healthy is None or lab_healthy.returncode):
            value = None
        report(f"lab runtime {fact}", value if type(value) is bool else None)
    syntax = compose("exec", "-T", "nginx", "nginx", "-t")
    report("nginx -t", None if syntax is None else syntax.returncode == 0)
    stats = compose("stats", "--no-stream", "--format", "{{.Name}} {{.CPUPerc}} {{.MemUsage}}")
    measured = set()
    if stats is not None and not stats.returncode:
        for line in stats.stdout.splitlines():
            fields = line.split()
            if len(fields) >= 5 and fields[1].endswith("%") and fields[3] == "/":
                measured.add(fields[0])
    expected = {f"{args.project}-{service}-1" for service in ("nginx", "app", "lab-web")}
    report("resource measurements for all three services",
           None if stats is None or stats.returncode else expected <= measured)
    if stats is not None and not stats.returncode:
        print(stats.stdout.rstrip())

    if args.stop_lab and health["lab-web"] == "healthy" and http("/lab/health")[0] == 200:
        stopped = None
        try:
            stopped = compose("stop", "lab-web")
            if stopped is None or stopped.returncode:
                report("lab outage", None)
            else:
                report("lab outage leaves platform available",
                       http("/lab/")[0] == 503 and all(http(path)[0] == 200 for path in
                                                      ("/", "/health", "/register", "/login", "/leaderboard")))
        finally:
            started = None
            if stopped is not None and not stopped.returncode:
                started = compose("start", "--wait", "--wait-timeout", "45", "lab-web")
            restored = False
            if started is not None and not started.returncode:
                for _ in range(30):
                    if http("/lab/health")[0] == 200:
                        restored = True
                        break
                    time.sleep(1)
            report("lab restored after test", restored)
    else:
        report("lab outage and recovery", None)

    print(" ".join(f"{status}={results.count(status)}" for status in ("PASS", "FAIL", "NOT TESTED")))
    return 1 if "FAIL" in results else 2 if "NOT TESTED" in results else 0


if __name__ == "__main__":
    sys.exit(main())
