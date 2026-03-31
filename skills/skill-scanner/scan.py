#!/usr/bin/env python3
"""
skill-scanner wrapper
Creates isolated venv and runs Cisco AI Skill Scanner
"""

import os
import sys
import subprocess
import venv
from pathlib import Path

VENV_DIR = Path.home() / ".openclaw" / "venvs" / "skill-scanner"
SKILL_SCANNER = VENV_DIR / "bin" / "skill-scanner"

def ensure_venv():
    """Create venv and install skill-scanner if needed"""
    if SKILL_SCANNER.exists():
        return True
    
    print("🔧 Setting up skill-scanner environment...")
    VENV_DIR.parent.mkdir(parents=True, exist_ok=True)
    
    # Create venv
    venv.create(VENV_DIR, with_pip=True)
    
    # Install cisco-ai-skill-scanner
    pip = VENV_DIR / "bin" / "pip"
    subprocess.run([str(pip), "install", "cisco-ai-skill-scanner"], check=True)
    print("✅ skill-scanner installed")
    return True

def main():
    if len(sys.argv) < 2:
        print("Usage: skill-scanner <skill-path-or-url>")
        sys.exit(1)
    
    target = sys.argv[1]
    
    ensure_venv()
    
    # Run scan
    result = subprocess.run([str(SKILL_SCANNER), "scan", target])
    sys.exit(result.returncode)

if __name__ == "__main__":
    main()
