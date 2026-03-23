#!/usr/bin/env python3
"""SecureClaw — L2 Dynamic Sandbox.

Executes a skill entry point in an isolated environment and monitors
runtime behavior. Catches dangerous activity that static analysis misses,
such as variable-indirect execution, encoded payloads, and network calls.

Isolation methods (auto-selected in order of preference):
  1. Docker  — full network/filesystem isolation (preferred)
  2. strace  — syscall-level monitoring, no root required

Monitored behaviors:
  - Network connection attempts (even if blocked)
  - Sensitive file reads (.env, credentials, .ssh, /etc/passwd)
  - Writes to sensitive paths (~/.openclaw, /etc, ~/.ssh)
  - Dangerous process spawning (curl, wget, sh, bash, python)
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
import sys
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


def docker_ok() -> bool:
    if not shutil.which('docker'):
        return False
    try:
        return subprocess.run(
            ['docker', 'info'], capture_output=True, timeout=5
        ).returncode == 0
    except Exception:
        return False


def strace_ok() -> bool:
    return shutil.which('strace') is not None


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


# ── Docker isolation ──────────────────────────────────────────────────────────

def run_docker(skill_dir: Path, entry: Path, timeout: int) -> dict:
    rel = entry.relative_to(skill_dir)
    cmd = [
        'docker', 'run', '--rm',
        '--network', 'none',           # block all network
        '--read-only',                 # immutable filesystem
        '--tmpfs', '/tmp:rw,size=64m',
        '--tmpfs', '/root:rw,size=16m',
        '--memory', '256m',
        '--cpus', '0.5',
        '--security-opt', 'no-new-privileges:true',
        '--cap-drop', 'ALL',
        '-v', f'{skill_dir}:/skill:ro',
        'ubuntu:22.04',
        'bash', '-c',
        f'cd /skill && timeout {timeout} bash {rel} 2>&1',
    ]

    findings = []
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 15)
        out = r.stdout + r.stderr

        if r.returncode == 124:
            findings.append(finding('warn', 'timeout',
                f'Skill exceeded {timeout}s — possible resource abuse'))

        # Network blocked → specific error messages in output
        net_signals = [
            'Network unreachable', 'getaddrinfo', 'Name or service not known',
            'Connection refused', 'network is unreachable',
        ]
        if any(s.lower() in out.lower() for s in net_signals):
            findings.append(finding('block', 'network_attempt',
                'Skill attempted outbound network connection (blocked by sandbox)'))

        # Sensitive paths mentioned in output
        for pat in SENSITIVE_READ:
            if re.search(pat, out, re.I):
                findings.append(finding('block', 'sensitive_read',
                    f'Output references sensitive path pattern: {pat}'))

    except subprocess.TimeoutExpired:
        findings.append(finding('warn', 'timeout', 'Docker sandbox runner timed out'))
    except Exception as e:
        findings.append(finding('warn', 'sandbox_error', f'Docker error: {e}'))

    return {'method': 'docker', 'findings': dedup(findings)}


# ── strace monitoring ─────────────────────────────────────────────────────────

def run_strace(skill_dir: Path, entry: Path, timeout: int) -> dict:
    findings = []
    strace_log = tempfile.mktemp(suffix='.strace')

    # Restrict HOME/PATH so skill cannot easily reach real user files
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

        strace_out = Path(strace_log).read_text(errors='ignore')
        findings.extend(_parse_strace(strace_out))

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

    # Network: connect() to external IPs
    for m in re.finditer(
        r'connect\(.*?AF_INET.*?sin_addr=inet_addr\("([^"]+)"', output
    ):
        ip = m.group(1)
        if not ip.startswith(('127.', '0.', '::1')):
            findings.append(finding('block', 'network_attempt',
                f'Outbound TCP connection to {ip}'))

    # Sensitive reads
    for m in re.finditer(r'(?:open|openat)\([^"]*"([^"]+)"', output):
        path = m.group(1)
        for pat in SENSITIVE_READ:
            if re.search(pat, path, re.I):
                findings.append(finding('block', 'sensitive_read',
                    f'Read sensitive path: {path}'))
                break

    # Sensitive writes (O_WRONLY or O_RDWR flag)
    for m in re.finditer(
        r'openat\([^"]*"([^"]+)"[^)]*(?:O_WRONLY|O_RDWR)', output
    ):
        path = m.group(1)
        for pat in SENSITIVE_WRITE:
            if re.search(pat, path, re.I):
                findings.append(finding('block', 'sensitive_write',
                    f'Write to sensitive path: {path}'))
                break

    # Dangerous process spawning
    for m in re.finditer(r'execve\("([^"]+)"', output):
        binary = Path(m.group(1)).name
        if binary in DANGEROUS_PROCS:
            findings.append(finding('warn', 'process_spawn',
                f'Spawned: {binary}'))

    return findings


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> int:
    parser = argparse.ArgumentParser(description='SecureClaw L2 Dynamic Sandbox')
    parser.add_argument('skill_dir', help='Path to skill directory')
    parser.add_argument('--timeout', type=int, default=30,
                        help='Max execution time in seconds (default: 30)')
    parser.add_argument('--entry', default=None,
                        help='Entry point script (default: auto-detect)')
    parser.add_argument('--output', default=None,
                        help='Write JSON report to this path')
    args = parser.parse_args()

    skill_dir = Path(args.skill_dir).resolve()
    if not skill_dir.exists():
        print(f'Not found: {skill_dir}')
        return 1

    entry = find_entry(skill_dir, args.entry)
    if entry is None:
        print('L2: no executable entry point found — skipping dynamic analysis')
        return 0

    print(f'L2 sandbox: {skill_dir.name} | entry={entry.name} | timeout={args.timeout}s')

    if docker_ok():
        result = run_docker(skill_dir, entry, args.timeout)
    elif strace_ok():
        result = run_strace(skill_dir, entry, args.timeout)
    else:
        print('L2: Docker and strace unavailable — skipping dynamic analysis')
        return 0

    method = result['method']
    findings = result['findings']

    if args.output:
        Path(args.output).write_text(json.dumps({
            'method': method,
            'skill': skill_dir.name,
            'entry': entry.name,
            'findings': findings,
        }, indent=2, ensure_ascii=False))

    if not findings:
        print(f'L2 [{method}]: OK — no dangerous runtime behavior detected')
        return 0

    worst = 0
    for f in findings:
        icon = '🔴' if f['level'] == 'block' else '🟠'
        print(f"{icon} [{f['level'].upper()}] {f['category']}: {f['detail']}")
        worst = max(worst, 1 if f['level'] == 'block' else 2)

    return worst


if __name__ == '__main__':
    raise SystemExit(main())
