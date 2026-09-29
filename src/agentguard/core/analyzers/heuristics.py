"""Shared, deterministic text heuristics used by several analyzers."""

from __future__ import annotations

import regex

from ..textutil import TIMEOUT

_F = regex.IGNORECASE | regex.MULTILINE

AGENT_DIRECTED = regex.compile(
    r"\b(?:ignore|disregard|forget|override|bypass)\b.{0,40}\b(?:instruction|rule|prompt|guideline|previous|above|system|safety)"
    r"|\b(?:you|assistant|agent|claude|the model|ai|llm)\b.{0,60}\b(?:must|should|shall|need to|have to|are required|will now|always|never)\b"
    r"|^\s*(?:always|never|do not|don't|make sure|be sure|you must|important\s*:|note to (?:the )?(?:ai|assistant|agent|model)|system\s*:|assistant\s*:)"
    r"|\b(?:run|execute|send|upload|post|curl|wget|fetch|download|read|cat|copy|exfiltrate|delete)\b.{0,80}"
    r"(?:https?://|~/|\$HOME|\.ssh|\.env\b|/etc/|token|secret|password|credential|api[_ -]?key)",
    _F,
)

_COMMANDS = (
    r"\b(?:curl|wget|bash|zsh|powershell|pwsh|iex|invoke-expression|invoke-webrequest|eval|exec|chmod\s+\+x|"
    r"python3?\s+-c|node\s+-e|nc\s+-[a-z]|/dev/tcp/|base64\s+-d|certutil|mshta|rundll32|osascript)\b"
)
EXECUTABLE_CONTENT = regex.compile(_COMMANDS + r"|https?://[^\s\"'<>]+", _F)
# For percent-encoded text inside a URL, where decoding a URL trivially yields a URL.
EXECUTABLE_COMMANDS = regex.compile(_COMMANDS, _F)

NETWORK_FETCH = regex.compile(
    r"\b(?:curl|wget|invoke-webrequest|iwr|invoke-restmethod|irm|nc|ncat|netcat|aria2c|fetch)\b[^\n]{0,200}"
    r"(?:https?://|ftp://|\b\d{1,3}(?:\.\d{1,3}){3}\b)",
    _F,
)

CREDENTIAL_PATH = regex.compile(
    r"(?:~|\$HOME|%USERPROFILE%|\$env:USERPROFILE|/home/[^/\s]+|/Users/[^/\s]+|/root)?[/\\]?"
    r"(?:\.ssh[/\\](?:id_[a-z0-9_]+|authorized_keys|known_hosts|config)|\.aws[/\\](?:credentials|config)|"
    r"\.config[/\\]gcloud|\.azure[/\\]|\.kube[/\\]config|\.docker[/\\]config\.json|\.npmrc|\.pypirc|\.netrc|"
    r"\.git-credentials|\.gnupg[/\\]|\.password-store|Login Data|Cookies\.sqlite|key4\.db|logins\.json|"
    r"Local State|wallet\.dat|\.electrum|\.ethereum[/\\]keystore|Exodus[/\\]|MetaMask|nkbihfbeogaeaoehlefnkodbefgpgknn|"
    # `.env` the file, not an attribute (self.env, process.env, or regex-escaped
    # process\.env) and not a template (.env.example)
    r"keychain|login\.keychain-db|\.config[/\\]gh[/\\]hosts\.yml|\.claude[/\\]\.credentials\.json|"
    r"(?<![\w$)\]?])(?<!\b(?:process|os|self|this|meta)\\)\.env(?!\.(?:example|sample|template|dist)\b)(?:\.[a-z]+)?\b)",
    _F,
)

READ_VERB = regex.compile(
    r"\b(?:cat|type|get-content|gc|less|more|head|tail|read|reads|reading|open|load|copy|cp|scp|rsync|tar|zip|7z|base64|"
    r"upload|send|post|exfiltrate|collect|harvest|grab|dump|steal|extract|include|attach|readFile(?:Sync)?|read_text|"
    r"read_bytes|security\s+find-(?:generic|internet)-password|cmdkey|vaultcmd)\b",
    _F,
)

# Environment copies handed only to a child process are filtered out by
# envcopy.env_dumps(); use that instead of matching ENV_DUMP directly on code.
ENV_DUMP = regex.compile(
    # same command forms as AG-SKL-CRED-002
    r"(?:^[ \t]*(?:\$\s+)?|[;&|]\s*|(?<![\w\].])\(\s*)(?:env|printenv|export\s+-p|Get-ChildItem\s+env:|gci\s+env:|dir\s+env:)[ \t]*(?:$|[|>;&)`])"
    r"|`(?:env|printenv|export\s+-p|Get-ChildItem\s+env:|gci\s+env:|dir\s+env:)[ \t]*[|>;&]"
    r"|(?:\b(?:run|runs|running|execute|exec|type|call|invoke|print|paste|dump|echo|output\s+of)\s+(?:the\s+)?|=\s*)`(?:env|printenv|export\s+-p)`"
    # ("X" in os.environ is a membership test, not a dump)
    r"|(?<![\"']\s+(?:not\s+)?in\s+)\bos\.environ(?:\.copy\(\)|\.items\(\)|\b(?!\s*[\[.]))|dict\(os\.environ\)"
    r"|json\.dumps\(\s*(?:dict\()?os\.environ"
    r"|JSON\.stringify\(\s*process\.env\s*\)|Object\.(?:entries|keys|assign)\(\s*(?:\{\}\s*,\s*)?process\.env\s*\)"
    r"|\{\s*\.\.\.process\.env\s*\}",
    _F,
)

TOKEN_ENV = regex.compile(
    r"\b(?:GITHUB_TOKEN|GH_TOKEN|GITLAB_TOKEN|NPM_TOKEN|PYPI_TOKEN|AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN|"
    r"OPENAI_API_KEY|ANTHROPIC_API_KEY|GEMINI_API_KEY|GOOGLE_API_KEY|AZURE_[A-Z_]*KEY|HF_TOKEN|SLACK_[A-Z_]*TOKEN|"
    r"DISCORD_TOKEN|STRIPE_[A-Z_]*KEY|DATABASE_URL|[A-Z0-9_]*(?:SECRET|PASSWORD|PRIVATE_KEY)[A-Z0-9_]*)\b"
)

EGRESS_CODE = regex.compile(
    r"\b(?:curl|wget|Invoke-WebRequest|Invoke-RestMethod|iwr|irm)\b"
    r"|\brequests\.(?:get|post|put|patch|request|Session)\b|\bhttpx\.(?:get|post|put|AsyncClient|Client)\b"
    r"|\burllib\.request\.(?:urlopen|Request)\b|\burlopen\(|\bhttp\.client\.|\baiohttp\.ClientSession\b"
    # fetch("/api/x") / fetch("./data.json") is same-origin, not egress
    r"|\bfetch\((?!\s*[`'\"](?:/(?!/)|\.\.?/))|\baxios(?:\.(?:get|post|put|request))?\((?!\s*[`'\"](?:/(?!/)|\.\.?/))"
    r"|\bhttps?\.(?:get|request)\("
    # local IPC (AF_UNIX) and loopback connections are not egress
    r"|\bnet\.(?:connect|createConnection)\(|\bsocket\.socket\((?!\s*(?:socket\.)?AF_UNIX\b)"
    r"|\bsocket\.create_connection\((?!\s*\(\s*[\"'](?:localhost|127\.0\.0\.1|::1)[\"'])"
    r"|\bsmtplib\.|\bnc\s+-|/dev/tcp/"
    r"|\bdns\.resolve|\bnslookup\b|\bdig\s",
    regex.MULTILINE,
)

EXEC_CODE = regex.compile(
    r"\bsubprocess\.(?:run|call|check_output|check_call|Popen|getoutput|getstatusoutput)\b|\bos\.(?:system|popen|exec[lv]p?e?)\("
    r"|\bchild_process\b|\b(?:execSync|spawnSync|execFileSync)\(|\bexec\(\s*[`'\"]|\bspawn\(|\bexeca\("
    r"|\beval\(|\bnew\s+Function\(|\bFunction\(",
    regex.MULTILINE,
)

PERSISTENCE = regex.compile(
    r"(?:~|\$HOME|%USERPROFILE%)?[/\\]?(?:\.bashrc|\.bash_profile|\.zshrc|\.zprofile|\.profile|\.config[/\\]fish[/\\]config\.fish)\b"
    r"|\bcrontab\b|/etc/cron|Library[/\\]LaunchAgents|Library[/\\]LaunchDaemons|launchctl\s+load|systemctl\s+--user\s+enable|"
    r"\.config[/\\]systemd[/\\]user|\\CurrentVersion\\Run\b|Start Menu\\Programs\\Startup|schtasks\s+/create|"
    r"\.config[/\\]autostart|Register-ScheduledTask|\$PROFILE\b|Microsoft\.PowerShell_profile\.ps1",
    _F,
)

INSTRUCTION_FILES = regex.compile(
    r"\b(?:AGENTS|CLAUDE|GEMINI|SOUL|MEMORY|IDENTITY)\.md\b|\.cursor[/\\]rules|copilot-instructions\.md|\.windsurfrules|\.cursorrules",
    _F,
)

DESTRUCTIVE = regex.compile(
    r"\brm\s+-(?:rf|fr|r)\b|\bshutil\.rmtree\(|\bfs\.(?:rm|rmSync|unlink|unlinkSync|rmdir)\(|\bos\.(?:remove|unlink|rmdir)\("
    r"|\bDROP\s+(?:TABLE|DATABASE)\b|\bTRUNCATE\s+TABLE\b|\bgit\s+push\s+--force|\bRemove-Item\b.*-Recurse|\bdel\s+/[sq]",
    _F,
)


def search(pattern: regex.Pattern[str], text: str) -> regex.Match[str] | None:
    try:
        return pattern.search(text, timeout=TIMEOUT)
    except TimeoutError:
        return None


def finditer(pattern: regex.Pattern[str], text: str) -> list[regex.Match[str]]:
    try:
        return list(pattern.finditer(text, timeout=TIMEOUT))
    except TimeoutError:
        return []


def word_count(text: str) -> int:
    return len(regex.findall(r"[A-Za-z]{2,}", text, timeout=TIMEOUT))


def damerau_levenshtein(a: str, b: str, cap: int = 3) -> int:
    """Optimal string alignment distance, early exit above ``cap``."""
    la, lb = len(a), len(b)
    if abs(la - lb) > cap:
        return cap + 1
    prev2: list[int] | None = None
    prev = list(range(lb + 1))
    for i in range(1, la + 1):
        cur = [i] + [0] * lb
        row_min = cur[0]
        for j in range(1, lb + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            if prev2 is not None and i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                cur[j] = min(cur[j], prev2[j - 2] + 1)
            row_min = min(row_min, cur[j])
        if row_min > cap:
            return cap + 1
        prev2, prev = prev, cur
    return prev[lb]
