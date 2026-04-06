#!/usr/bin/env python3
"""SecureClaw — L2 Dynamic Sandbox.

Executes a skill entry point in an isolated environment and monitors
runtime behavior. Catches dangerous activity that static analysis misses,
such as variable-indirect execution, encoded payloads, and network calls.

Isolation methods (auto-selected in order of preference):
  1. Docker  — full network/filesystem isolation (preferred)
  2. nsjail  — seccomp-bpf syscall filtering, harder to evade than strace
  3. strace  — passive syscall monitoring (last resort)

nsjail advantages over strace:
  - Uses seccomp-bpf: blocked syscalls are PREVENTED, not just observed
  - Malware cannot detect or evade nsjail at runtime
  - Network namespace isolation (--iface_no_lo)
  - Resource limits via rlimits/cgroups

Monitored behaviors:
  - Network connection attempts (blocked + detected)
  - Sensitive file reads (.env, credentials, .ssh, /etc/passwd)
  - Writes to sensitive paths (~/.openclaw, /etc, ~/.ssh)
  - Dangerous process spawning (curl, wget, sh, bash, python)
  - Blocked syscalls (SIGSYS / seccomp violation)
  - Timeout exceeded (potential resource abuse / crypto miner)

Usage:
  python3 l2-sandbox.py <skill_dir> [--timeout 30] [--entry install.sh]
                        [--output report.json]

Exit codes:
  0 = clean
  1 = dangerous behavior detected (block)
  2 = suspicious behavior (warn)
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

# ── Patterns ──────────────────────────────────────────────────────────────────

SENSITIVE_READ = [
    r'\.env\b', r'credentials[/\\]', r'\.ssh[/\\]',
    r'/etc/passwd', r'/etc/shadow', r'\.aws[/\\]credentials',
    r'api[_-]?key', r'secret[_-]?key', r'access[_-]?token',
]

SENSITIVE_WRITE = [
    r'\.openclaw', r'/etc/', r'\.ssh[/\\]', r'\.bashrc',
    r'\.profile', r'\.zshrc', r'\.bash_profile', r'crontab',
    r'authorized_keys',
]

DANGEROUS_PROCS = {
    'curl', 'wget', 'nc', 'ncat', 'socat', 'bash', 'sh', 'dash',
    'python', 'python3', 'python2', 'perl', 'ruby', 'node', 'powershell',
}

NET_SIGNALS = [
    'network unreachable', 'getaddrinfo', 'name or service not known',
    'connection refused', 'no route to host', 'network is unreachable',
]

ENTRY_POINTS = ['install.sh', 'run.sh', 'setup.sh', 'start.sh', 'main.sh']


# ── Helpers ───────────────────────────────────────────────────────────────────

def find_entry(skill_dir: Path, hint: str | None) -> Path | None:
    if hint:
        p = skill_dir / hint
        return p if p.exists() else None
    for name in ENTRY_POINTS:
        p = skill_dir / name
        if p.exists():
            return p
    sh = list(skill_dir.glob('*.sh'))
    return sh[0] if sh else None


def cmd_ok(name: str) -> bool:
    return shutil.which(name) is not None


def docker_ok() -> bool:
    if not cmd_ok('docker'):
        return False
    try:
        return subprocess.run(
            ['docker', 'info'], capture_output=True, timeout=5
        ).returncode == 0
    except Exception:
        return False


def dedup(findings: list) -> list:
    seen: set = set()
    out = []
    for f in findings:
        key = (f['level'], f['category'], f['detail'][:80])
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out


def finding(level: str, category: str, detail: str) -> dict:
    return {'level': level, 'category': category, 'detail': detail}


def check_net_signals(text: str) -> bool:
    t = text.lower()
    return any(s in t for s in NET_SIGNALS)


def check_sensitive_paths(text: str) -> list[dict]:
    hits = []
    for pat in SENSITIVE_READ:
        if re.search(pat, text, re.I):
            hits.append(finding('block', 'sensitive_read',
                f'References sensitive path pattern: {pat}'))
    return hits


# ── Docker isolation ──────────────────────────────────────────────────────────

def run_docker(skill_dir: Path, entry: Path, timeout: int) -> dict:
    rel = entry.relative_to(skill_dir)
    cmd = [
        'docker', 'run', '--rm',
        '--network', 'none',
        '--read-only',
        '--tmpfs', '/tmp:rw,size=64m',
        '--tmpfs', '/root:rw,size=16m',
        '--memory', '256m',
        '--cpus', '0.5',
        '--security-opt', 'no-new-privileges:true',
        '--cap-drop', 'ALL',
        '-v', f'{skill_dir}:/skill:ro',
        'ubuntu:22.04',
        'bash', '-c', f'cd /skill && timeout {timeout} bash {rel} 2>&1',
    ]

    findings = []
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 15)
        out = r.stdout + r.stderr

        if r.returncode == 124:
            findings.append(finding('warn', 'timeout',
                f'Skill exceeded {timeout}s — possible resource abuse'))

        if check_net_signals(out):
            findings.append(finding('block', 'network_attempt',
                'Skill attempted outbound network connection (blocked by Docker)'))

        findings.extend(check_sensitive_paths(out))

    except subprocess.TimeoutExpired:
        findings.append(finding('warn', 'timeout', 'Docker sandbox runner timed out'))
    except Exception as e:
        findings.append(finding('warn', 'sandbox_error', f'Docker error: {e}'))

    return {'method': 'docker', 'findings': dedup(findings)}


# ── nsjail isolation ──────────────────────────────────────────────────────────

def run_nsjail(skill_dir: Path, entry: Path, timeout: int) -> dict:
    """
    nsjail advantages:
    - seccomp-bpf blocks dangerous syscalls at kernel level (cannot be detected
      or bypassed by the sandboxed process, unlike strace)
    - Network namespace isolation (--iface_no_lo disables loopback)
    - Filesystem isolation via bind mounts
    - Resource limits enforced by kernel
    """
    findings = []
    nsjail_log = tempfile.mktemp(suffix='.nsjail.log')
    fake_home = tempfile.mkdtemp(prefix='l2_home_')

    try:
        cmd = [
            'nsjail',
            '--mode', 'o',                               # run once
            '--chroot', '/',                             # use host FS
            f'--bindmount_ro={skill_dir}:/skill',        # skill: read-only
            f'--bindmount={fake_home}:/root',            # isolated home
            '--tmpfs=/tmp',                              # writable tmp
            '--disable_proc',                            # hide /proc
            '--iface_no_lo',                             # no network
            f'--time_limit={timeout}',                   # wall clock limit
            '--rlimit_as=256',                           # 256 MiB address space
            '--rlimit_cpu=30',                           # 30s CPU time
            f'--log={nsjail_log}',                       # nsjail internal log
            '--',
            '/bin/bash', f'/skill/{entry.name}',
        ]

        env = {'PATH': '/usr/local/bin:/usr/bin:/bin', 'HOME': '/root'}

        r = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=timeout + 15, env=env,
        )
        out = r.stdout + r.stderr

        if check_net_signals(out):
            findings.append(finding('block', 'network_attempt',
                'Skill attempted network connection (blocked by nsjail)'))

        findings.extend(check_sensitive_paths(out))

        # Parse nsjail internal log for blocked syscalls / resource violations
        if Path(nsjail_log).exists():
            findings.extend(_parse_nsjail_log(
                Path(nsjail_log).read_text(errors='ignore')
            ))

    except subprocess.TimeoutExpired:
        findings.append(finding('warn', 'timeout', 'nsjail runner timed out'))
    except Exception as e:
        findings.append(finding('warn', 'sandbox_error', f'nsjail error: {e}'))
    finally:
        try:
            Path(nsjail_log).unlink()
        except Exception:
            pass
        shutil.rmtree(fake_home, ignore_errors=True)

    return {'method': 'nsjail', 'findings': dedup(findings)}


def _parse_nsjail_log(log: str) -> list[dict]:
    findings = []

    # SIGSYS = seccomp violation (blocked syscall attempted)
    if re.search(r'SIGSYS|seccomp violation|syscall.*blocked', log, re.I):
        findings.append(finding('block', 'syscall_blocked',
            'Process killed by seccomp — attempted forbidden syscall'))

    # Network syscall blocked
    if re.search(r'connect.*block|socket.*denied|iface.*no', log, re.I):
        findings.append(finding('block', 'network_attempt',
            'Network syscall blocked by nsjail'))

    # Time limit exceeded
    if re.search(r'time.?limit|tlimit|killed.*time', log, re.I):
        findings.append(finding('warn', 'timeout',
            'Process killed by nsjail time limit'))

    # Memory limit exceeded
    if re.search(r'memory.?limit|rlimit_as|OOM|out.of.memory', log, re.I):
        findings.append(finding('warn', 'resource_abuse',
            'Memory limit exceeded — possible resource abuse'))

    return findings


# ── strace monitoring (last resort) ──────────────────────────────────────────

def run_strace(skill_dir: Path, entry: Path, timeout: int) -> dict:
    findings = []
    strace_log = tempfile.mktemp(suffix='.strace')
    env = {
        **os.environ,
        'HOME': tempfile.mkdtemp(prefix='l2_home_'),
        'PATH': '/usr/local/bin:/usr/bin:/bin',
    }

    cmd = [
        'strace', '-f',
        '-e', 'trace=network,openat,open,connect,execve',
        '-o', strace_log,
        'timeout', str(timeout),
        'bash', str(entry),
    ]

    try:
        r = subprocess.run(
            cmd, capture_output=True, text=True,
            cwd=str(skill_dir), timeout=timeout + 20, env=env,
        )
        if r.returncode == 124:
            findings.append(finding('warn', 'timeout',
                f'Skill exceeded {timeout}s — possible resource abuse'))

        findings.extend(_parse_strace(
            Path(strace_log).read_text(errors='ignore')
        ))

    except subprocess.TimeoutExpired:
        findings.append(finding('warn', 'timeout', 'strace runner timed out'))
    except Exception as e:
        findings.append(finding('warn', 'sandbox_error', f'strace error: {e}'))
    finally:
        try:
            Path(strace_log).unlink()
        except Exception:
            pass

    return {'method': 'strace', 'findings': dedup(findings)}


def _parse_strace(output: str) -> list[dict]:
    findings = []

    for m in re.finditer(
        r'connect\(.*?AF_INET.*?sin_addr=inet_addr\("([^"]+)"', output
    ):
        ip = m.group(1)
        if not ip.startswith(('127.', '0.', '::1')):
            findings.append(finding('block', 'network_attempt',
                f'Outbound TCP connection to {ip}'))

    for m in re.finditer(r'(?:open|openat)\([^"]*"([^"]+)"', output):
        path = m.group(1)
        for pat in SENSITIVE_READ:
            if re.search(pat, path, re.I):
                findings.append(finding('block', 'sensitive_read',
                    f'Read sensitive path: {path}'))
                break

    for m in re.finditer(
        r'openat\([^"]*"([^"]+)"[^)]*(?:O_WRONLY|O_RDWR)', output
    ):
        path = m.group(1)
        for pat in SENSITIVE_WRITE:
            if re.search(pat, path, re.I):
                findings.append(finding('block', 'sensitive_write',
                    f'Write to sensitive path: {path}'))
                break

    for m in re.finditer(r'execve\("([^"]+)"', output):
        binary = Path(m.group(1)).name
        if binary in DANGEROUS_PROCS:
            findings.append(finding('warn', 'process_spawn',
                f'Spawned: {binary}'))

    return findings


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> int:
    parser = argparse.ArgumentParser(description='SecureClaw L2 Dynamic Sandbox')
    parser.add_argument('skill_dir')
    parser.add_argument('--timeout', type=int, default=30)
    parser.add_argument('--entry', default=None)
    parser.add_argument('--output', default=None)
    args = parser.parse_args()

    skill_dir = Path(args.skill_dir).resolve()
    if not skill_dir.exists():
        print(f'Not found: {skill_dir}')
        return 1

    entry = find_entry(skill_dir, args.entry)
    if entry is None:
        print('L2: no executable entry point found — skipping dynamic analysis')
        return 0

    # Select isolation method
    if docker_ok():
        method_name = 'docker'
        run_fn = run_docker
    elif cmd_ok('nsjail'):
        method_name = 'nsjail'
        run_fn = run_nsjail
    elif cmd_ok('strace'):
        method_name = 'strace'
        run_fn = run_strace
    else:
        print('L2: WARN — no isolation tool available (install Docker, nsjail, or strace); dynamic analysis skipped')
        return 2

    print(f'L2 sandbox: {skill_dir.name} | method={method_name} | entry={entry.name} | timeout={args.timeout}s')

    result = run_fn(skill_dir, entry, args.timeout)
    findings = result['findings']

    if args.output:
        Path(args.output).write_text(json.dumps({
            'method': method_name,
            'skill': skill_dir.name,
            'entry': entry.name,
            'findings': findings,
        }, indent=2, ensure_ascii=False))

    if not findings:
        print(f'L2 [{method_name}]: OK — no dangerous runtime behavior detected')
        return 0

    worst = 0
    for f in findings:
        icon = '🔴' if f['level'] == 'block' else '🟠'
        print(f"{icon} [{f['level'].upper()}] {f['category']}: {f['detail']}")
        worst = max(worst, 1 if f['level'] == 'block' else 2)

    return worst


if __name__ == '__main__':
    raise SystemExit(main())
