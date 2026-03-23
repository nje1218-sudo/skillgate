/*
 * SkillGate — Supply Chain Attack YARA Rules
 * Based on YARA Forge community patterns + 2025 npm/pip attack campaigns
 * Coverage: remote exec, obfuscation, credential theft, crypto-stealing,
 *           ClawHavoc campaign, infostealer patterns
 */

// ── Remote Code Execution ──────────────────────────────────────────────────

rule sc_pipe_to_shell {
    meta:
        description = "curl/wget/fetch piped directly to shell"
        severity    = "CRITICAL"
        owasp_asi   = "ASI02"
    strings:
        $a = /curl\s+\S+\s*\|\s*(sh|bash|zsh|dash)/ nocase
        $b = /wget\s+\S+\s*\|\s*(sh|bash|zsh|dash)/ nocase
        $c = /fetch\s*\(\s*['"][^'"]+['"]\s*\)\s*\.\s*then/ nocase
        $d = /\$\(curl/ nocase
        $e = /`curl / nocase
    condition:
        any of them
}

rule sc_one_liner_execution {
    meta:
        description = "One-liner remote execution via scripting tools"
        severity    = "CRITICAL"
    strings:
        $a = /perl\s+-e\s+['"]/ nocase
        $b = /ruby\s+-e\s+['"]/ nocase
        $c = /python[23]?\s+-c\s+['"]/ nocase
        $d = /node\s+-e\s+['"]/ nocase
        $e = /php\s+-r\s+['"]/ nocase
        $f = /Invoke-Expression\s*\(/ nocase
        $g = /iex\s*\(/ nocase
    condition:
        any of them
}

// ── Obfuscation & Encoding ─────────────────────────────────────────────────

rule sc_base64_execute {
    meta:
        description = "Base64-encoded payload executed at runtime"
        severity    = "HIGH"
    strings:
        $a = /base64\s+(-d|--decode)\s*\|\s*(sh|bash|python|perl)/ nocase
        $b = /atob\s*\([^)]+\)\s*[;\n]\s*(eval|exec|Function)/ nocase
        $c = /eval\s*\(\s*(atob|Buffer\.from|btoa)/ nocase
        $d = /Buffer\.from\s*\([^,]+,\s*['"]base64['"]\)/ nocase
        $e = /base64_decode\s*\([^)]+\)\s*[;\n]\s*(eval|exec)/ nocase
    condition:
        any of them
}

rule sc_char_code_obfuscation {
    meta:
        description = "String.fromCharCode obfuscation (common in npm malware)"
        severity    = "HIGH"
    strings:
        $a = "String.fromCharCode"
        $b = /eval\s*\(\s*String\.fromCharCode/ nocase
        $c = /\[(\d+,\s*){10,}\d+\]/ // large integer arrays (encoded payload)
    condition:
        $a or ($b) or ($c and #c > 2)
}

rule sc_hex_string_execution {
    meta:
        description = "Hex-encoded string executed via eval"
        severity    = "MEDIUM"
    strings:
        $a = /eval\s*\(\s*['"]\\x[0-9a-fA-F]{2}/ nocase
        $b = /exec\s*\(\s*bytes\.fromhex\s*\(/ nocase
        $c = /\\x[0-9a-fA-F]{2}(\\x[0-9a-fA-F]{2}){15,}/ // 16+ hex bytes
    condition:
        any of them
}

// ── Credential & Secret Theft ──────────────────────────────────────────────

rule sc_env_exfiltration {
    meta:
        description = "Reads env vars and exfiltrates via network"
        severity    = "CRITICAL"
        owasp_asi   = "ASI05"
    strings:
        $env1 = "process.env" nocase
        $env2 = "os.environ" nocase
        $env3 = "$ENV:" nocase
        $net1 = /https?:\/\// nocase
        $net2 = "fetch(" nocase
        $net3 = "XMLHttpRequest" nocase
        $net4 = "requests.post" nocase
        $net5 = "axios.post" nocase
    condition:
        any of ($env*) and any of ($net*)
}

rule sc_openclaw_credential_access {
    meta:
        description = "Reads OpenClaw credentials or .env file (infostealer target)"
        severity    = "CRITICAL"
    strings:
        $a = "/.openclaw/.env" nocase
        $b = "/.openclaw/credentials" nocase
        $c = "/.clawdbot/.env" nocase
        $d = "/.moltbot/.env" nocase
        $e = "readFileSync" nocase
        $f = "open(" nocase
    condition:
        (any of ($a,$b,$c,$d)) and (any of ($e,$f))
}

rule sc_aws_key_theft {
    meta:
        description = "Reads AWS credentials file"
        severity    = "CRITICAL"
    strings:
        $a = ".aws/credentials"
        $b = "AWS_ACCESS_KEY_ID" nocase
        $c = "AWS_SECRET_ACCESS_KEY" nocase
        $d = /AKIA[0-9A-Z]{16}/
    condition:
        2 of them
}

rule sc_ssh_key_access {
    meta:
        description = "Reads SSH private keys"
        severity    = "CRITICAL"
    strings:
        $a = "/.ssh/id_rsa"
        $b = "/.ssh/id_ed25519"
        $c = "/.ssh/id_ecdsa"
        $d = "BEGIN RSA PRIVATE KEY"
        $e = "BEGIN OPENSSH PRIVATE KEY"
    condition:
        any of them
}

// ── Crypto / Wallet Theft (2025 npm Campaign) ─────────────────────────────

rule sc_crypto_wallet_hook {
    meta:
        description = "Hooks Ethereum wallet API to replace addresses (2025 campaign)"
        severity    = "CRITICAL"
        ref         = "npm Shai-Hulud worm 2025"
    strings:
        $a = "window.ethereum" nocase
        $b = "web3.eth" nocase
        $c = ".replace(" nocase
        $d = /0x[a-fA-F0-9]{40}/  // Ethereum address pattern
        $e = "sendTransaction" nocase
        $f = "eth_sendTransaction" nocase
    condition:
        ($a or $b) and ($c or $d) and ($e or $f)
}

rule sc_clipboard_hijack {
    meta:
        description = "Monitors clipboard for crypto wallet addresses"
        severity    = "HIGH"
    strings:
        $a = "clipboard" nocase
        $b = "readText" nocase
        $c = "writeText" nocase
        $d = /0x[a-fA-F0-9]{40}/
        $e = "execSync" nocase
        $f = "pbpaste" nocase
        $g = "xclip" nocase
    condition:
        ($a and ($b or $c) and $d) or
        ($d and ($f or $g) and $e)
}

// ── ClawHavoc Campaign Patterns ────────────────────────────────────────────

rule sc_clawhavoc_c2 {
    meta:
        description = "Known ClawHavoc C2 server IP"
        severity    = "CRITICAL"
        ref         = "ClawHavoc campaign 2026-02"
    strings:
        $c2 = "91.92.242.30"
    condition:
        $c2
}

rule sc_clawhavoc_patterns {
    meta:
        description = "ClawHavoc campaign indicators"
        severity    = "CRITICAL"
    strings:
        $a = "ClickFix" nocase
        $b = "webhook.site" nocase
        $c = "osascript" nocase
        $d = "xattr -d com.apple.quarantine" nocase
        $e = "prerequisite" nocase
        $f = "polymarket" nocase
    condition:
        2 of ($a,$b,$c,$d) or $b or $d
}

rule sc_macos_gatekeeper_bypass {
    meta:
        description = "macOS Gatekeeper bypass (removes quarantine xattr)"
        severity    = "CRITICAL"
    strings:
        $a = "xattr" nocase
        $b = "quarantine" nocase
        $c = "com.apple.quarantine" nocase
    condition:
        ($a and $b) or $c
}

// ── Persistence & Config Tampering ─────────────────────────────────────────

rule sc_cron_persistence {
    meta:
        description = "Installs cron job for persistence"
        severity    = "HIGH"
    strings:
        $a = "crontab" nocase
        $b = "cron.d" nocase
        $c = "*/\d+ \* \* \* \*" // cron schedule pattern
        $d = "@reboot" nocase
    condition:
        any of them
}

rule sc_shell_profile_modification {
    meta:
        description = "Modifies shell startup files for persistence"
        severity    = "HIGH"
    strings:
        $a = ".bashrc" nocase
        $b = ".zshrc" nocase
        $c = ".bash_profile" nocase
        $d = ".profile" nocase
        $e = "echo " nocase
        $f = ">>" nocase
    condition:
        any of ($a,$b,$c,$d) and $e and $f
}

// ── Dynamic Code Execution ─────────────────────────────────────────────────

rule sc_dynamic_import_exec {
    meta:
        description = "Dynamic import or require used for code execution"
        severity    = "HIGH"
    strings:
        $a = /eval\s*\(/ nocase
        $b = /new\s+Function\s*\(/ nocase
        $c = /require\s*\(\s*['"]child_process['"]/ nocase
        $d = /import\s*\(\s*[^'"]+\s*\)/ nocase  // dynamic import with variable
        $e = /__import__\s*\(/ nocase
        $f = /importlib\.import_module/ nocase
    condition:
        any of ($a,$b,$c,$e,$f)
}

rule sc_subprocess_shell_true {
    meta:
        description = "Python subprocess with shell=True (command injection risk)"
        severity    = "HIGH"
    strings:
        $a = /subprocess\.(call|run|Popen|check_output)\s*\([^)]*shell\s*=\s*True/ nocase
        $b = /os\.(system|popen)\s*\(/ nocase
    condition:
        any of them
}
