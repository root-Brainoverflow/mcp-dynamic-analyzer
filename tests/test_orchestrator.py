"""Tests for default sequence selection in the orchestrator."""

from __future__ import annotations

from mcp_dynamic_analyzer.config import AnalysisConfig
from mcp_dynamic_analyzer.orchestrator import build_default_sequences
from mcp_dynamic_analyzer.scanners.r5_input_validation import FuzzingSequence
from mcp_dynamic_analyzer.scanners.r6_stability import StabilityFuzzingSequence


class TestBuildDefaultSequences:
    def test_default_sequences_include_r5_and_r6(self) -> None:
        cfg = AnalysisConfig()
        sequences = build_default_sequences(cfg, "ses-test")
        assert any(isinstance(seq, FuzzingSequence) for seq in sequences)
        assert any(isinstance(seq, StabilityFuzzingSequence) for seq in sequences)

    def test_default_sequences_respect_disabled_scanners(self) -> None:
        cfg = AnalysisConfig.model_validate(
            {
                "scanners": {
                    "r5_input_validation": {"enabled": False},
                    "r6_stability": {"enabled": False},
                }
            }
        )
        sequences = build_default_sequences(cfg, "ses-test")
        assert not any(isinstance(seq, FuzzingSequence) for seq in sequences)
        assert not any(isinstance(seq, StabilityFuzzingSequence) for seq in sequences)


class TestRetryReinit:
    """After a ServerCrashError the orchestrator restarts the sandbox.

    The new sandbox spawns a fresh server process with no MCP protocol
    state, so every subsequent ``tools/call`` is rejected with
    ``-32602 Invalid request parameters`` until the JSON-RPC
    ``initialize`` handshake runs. The retry loop must therefore prepend
    ``InitSequence`` to ``remaining`` whenever it isn't already first.

    Regression: sessions where mcp-server-git's first crash during
    ``fuzz_input_validation`` left ``remaining = [Fuzz, Stab]``; the
    fresh sandbox bypassed init and emitted "Received request before
    initialization was complete" for every call.
    """

    def test_remaining_without_init_gets_init_prepended(self) -> None:
        from mcp_dynamic_analyzer.protocol.sequencer import InitSequence
        from mcp_dynamic_analyzer.scanners.r5_input_validation import FuzzingSequence
        from mcp_dynamic_analyzer.scanners.r6_stability import StabilityFuzzingSequence

        # State emitted by the sequencer after FuzzingSequence crashed.
        remaining = [FuzzingSequence("s"), StabilityFuzzingSequence("s")]

        # Apply the orchestrator's prepend guard.
        if not isinstance(remaining[0], InitSequence):
            remaining = [InitSequence("s"), *remaining]

        assert isinstance(remaining[0], InitSequence)
        assert isinstance(remaining[1], FuzzingSequence)
        assert isinstance(remaining[2], StabilityFuzzingSequence)

    def test_remaining_already_starting_with_init_unchanged(self) -> None:
        """First sandbox attempt — ``remaining`` already starts with Init,
        guard must NOT duplicate it."""
        from mcp_dynamic_analyzer.protocol.sequencer import InitSequence
        from mcp_dynamic_analyzer.scanners.r5_input_validation import FuzzingSequence

        remaining = [InitSequence("s"), FuzzingSequence("s")]
        original_first = remaining[0]

        if not isinstance(remaining[0], InitSequence):
            remaining = [InitSequence("s"), *remaining]

        assert len(remaining) == 2
        assert remaining[0] is original_first


class TestPrerequisiteRetry:
    """The server stays up but its tool responses are degraded by a missing
    runtime prerequisite (chrome-devtools-mcp without Chrome, a server whose
    tool shells out to a binary that isn't installed). ``_collect`` detects
    that generically from the responses, hands the offending text to the next
    sandbox, which re-resolves it via recipe ``stderr_tokens_any`` / the apt
    heuristic and rebuilds the image, and the collection re-runs once.
    """

    async def test_detect_chrome_missing(self) -> None:
        from mcp_dynamic_analyzer.models import Event
        from mcp_dynamic_analyzer.orchestrator import _detect_missing_prerequisite

        class R:
            async def events_by_type(self, t: str):
                if t != "test_result":
                    return
                for i in range(40):
                    yield Event(
                        session_id="s", source="test", type="test_result",
                        data={
                            "tool": ["navigate_page", "new_page", "click", "evaluate_script"][i % 4],
                            "response_preview": (
                                '{"content": [{"type": "text", "text": "Could not find Google Chrome '
                                "executable for channel 'stable' at: /opt/google/chrome/chrome.\"}], "
                                '"isError": true}'
                            ),
                        },
                    )

        hint = await _detect_missing_prerequisite(R())
        assert hint is not None and "could not find google chrome" in hint.lower()

    async def test_detect_python_module_missing(self) -> None:
        from mcp_dynamic_analyzer.models import Event
        from mcp_dynamic_analyzer.orchestrator import _detect_missing_prerequisite

        class R:
            async def events_by_type(self, t: str):
                if t != "test_result":
                    return
                for i in range(30):
                    yield Event(
                        session_id="s", source="test", type="test_result",
                        data={"tool": f"tool_{i % 5}",
                              "response_preview": "Error executing tool tool_x: No module named 'spotipy'"},
                    )

        hint = await _detect_missing_prerequisite(R())
        assert hint is not None and "no module named" in hint.lower()

    async def test_stray_module_error_does_not_trigger(self) -> None:
        from mcp_dynamic_analyzer.models import Event
        from mcp_dynamic_analyzer.orchestrator import _detect_missing_prerequisite

        class R:
            async def events_by_type(self, t: str):
                if t != "test_result":
                    return
                for i in range(30):
                    txt = "No module named 'weird'" if i == 0 else '{"content": [{"type":"text","text":"ok"}], "isError": false}'
                    yield Event(session_id="s", source="test", type="test_result",
                                data={"tool": f"t{i % 4}", "response_preview": txt})

        assert await _detect_missing_prerequisite(R()) is None

    async def test_too_few_results_does_not_trigger(self) -> None:
        from mcp_dynamic_analyzer.models import Event
        from mcp_dynamic_analyzer.orchestrator import _detect_missing_prerequisite

        class R:
            async def events_by_type(self, t: str):
                if t != "test_result":
                    return
                for i in range(5):
                    yield Event(session_id="s", source="test", type="test_result",
                                data={"tool": f"t{i}", "response_preview": "Could not find Chrome"})

        assert await _detect_missing_prerequisite(R()) is None

    def test_chrome_error_hint_drives_recipe_match(self) -> None:
        """A bare ``chrome-not-found`` error — even from a server with no chrome
        name or declared dependency — re-resolves to the system-Chrome recipe
        via its ``stderr_tokens_any`` (this is the plan-building half that
        ``Sandbox(prereq_hint=...)`` feeds into ``_prepare_bootstrap_image``)."""
        from mcp_dynamic_analyzer.config import ServerConfig
        from mcp_dynamic_analyzer.infrastructure.bootstrap import plan_bootstrap
        from mcp_dynamic_analyzer.infrastructure.runtime_resolver import ResolvedRuntime

        rt = ResolvedRuntime(image="mcp-sandbox-node22", command="npx", reason="npx")
        plan = plan_bootstrap(
            ServerConfig(command="npx", args=["some-headless-thing"]), rt,
            stderr_snippet="Could not find Google Chrome executable for channel 'stable' at: /opt/google/chrome/chrome",
        )
        assert plan is not None
        assert any(a.action_id == "system-chrome" for a in plan.actions)

    def test_sandbox_carries_prereq_hint(self) -> None:
        from mcp_dynamic_analyzer.config import SandboxConfig, ServerConfig
        from mcp_dynamic_analyzer.infrastructure.sandbox import Sandbox

        sb = Sandbox(ServerConfig(command="node", args=["x.js"]), SandboxConfig(),
                     prereq_hint="Could not find Google Chrome executable")
        assert sb._prereq_hint == "Could not find Google Chrome executable"  # noqa: SLF001
        # a hint with no apt-recognisable package yields no apt action
        assert sb._apt_bootstrap_action(sb._prereq_hint) is None  # noqa: SLF001

    # -- generic missing-prerequisite resolution -----------------------------

    def test_missing_prerequisite_name_extraction(self) -> None:
        from mcp_dynamic_analyzer.payloads.stability import (
            looks_like_missing_prerequisite,
            missing_prerequisite_name,
        )
        cases = [
            ("Could not find Google Chrome executable for channel 'stable' at: /opt/google/chrome/chrome.", "Google Chrome"),
            ("Error executing tool foo: No module named 'spotipy'", "spotipy"),
            ("Error: spawn geckodriver ENOENT", "geckodriver"),
            ("/bin/sh: 1: pandoc: command not found", "pandoc"),
            ("Error: Cannot find module '@scope/thing'", "@scope/thing"),
        ]
        for text, expected in cases:
            assert looks_like_missing_prerequisite(text), text
            assert missing_prerequisite_name(text) == expected, (text, missing_prerequisite_name(text))
        assert not looks_like_missing_prerequisite("perfectly fine, here are your results")
        assert missing_prerequisite_name("perfectly fine") is None

    def test_generic_apt_guess_for_unknown_command(self) -> None:
        from mcp_dynamic_analyzer.infrastructure.sandbox import _apt_packages_from_stderr
        # unknown command → best-effort guess (package name == command name)
        assert _apt_packages_from_stderr("/bin/sh: 1: pandoc: command not found") == ["pandoc"]
        assert "geckodriver" in _apt_packages_from_stderr("Error: spawn geckodriver ENOENT")
        # curated command → its mapped package
        assert _apt_packages_from_stderr("ffmpeg: command not found") == ["ffmpeg"]
        # interpreters / runners are never guessed as packages
        assert _apt_packages_from_stderr("node: command not found") == []
        assert _apt_packages_from_stderr("python3: command not found") == []
        # a missing browser isn't an apt package — handled by a recipe instead
        assert _apt_packages_from_stderr("Could not find Google Chrome executable") == []

    def test_apt_bootstrap_action_is_best_effort(self) -> None:
        from mcp_dynamic_analyzer.config import SandboxConfig, ServerConfig
        from mcp_dynamic_analyzer.infrastructure.sandbox import Sandbox
        sb = Sandbox(ServerConfig(command="node", args=["x.js"]), SandboxConfig(),
                     prereq_hint="myrandocli: command not found")
        action = sb._apt_bootstrap_action(sb._prereq_hint)  # noqa: SLF001
        assert action is not None
        run = " ".join(action.dockerfile_lines)
        assert "apt-get install -y --no-install-recommends myrandocli" in run
        assert "|| true" in run  # a wrong guess must not break the image build

    async def test_detect_threshold_params(self) -> None:
        from mcp_dynamic_analyzer.models import Event
        from mcp_dynamic_analyzer.orchestrator import _detect_missing_prerequisite

        # 40% of 20 results match, spread over only 2 tools
        class R:
            async def events_by_type(self, t: str):
                if t != "test_result":
                    return
                for i in range(20):
                    txt = "spawn geckodriver ENOENT" if i % 5 < 2 else "ok"
                    yield Event(session_id="s", source="test", type="test_result",
                                data={"tool": ["a", "b"][i % 2], "response_preview": txt})

        # default fraction 0.25 → 40% ≥ 25% → detected
        assert await _detect_missing_prerequisite(R()) is not None
        # fraction 0.5 → 40% < 50% AND only 2 distinct tools < huge min → not detected
        assert await _detect_missing_prerequisite(R(), fraction=0.5, min_distinct_tools=10**6) is None

    async def test_only_tag_isolates_the_rerun_from_the_degraded_first_pass(self) -> None:
        """The post-retry "is it still broken?" check passes ``only_tag``. The
        degraded first pass (untagged) must not count toward it — only the
        rebuilt-image re-run (tagged ``prereq-retry``) does. So: a clean re-run
        is *not* detected as broken even though the log still holds the first
        pass's "no Chrome" responses."""
        from mcp_dynamic_analyzer.models import Event
        from mcp_dynamic_analyzer.orchestrator import _PREREQ_RETRY_TAG, _detect_missing_prerequisite

        chrome_err = (
            '{"content": [{"type": "text", "text": "Could not find Google Chrome '
            "executable for channel 'stable'.\"}], \"isError\": true}"
        )
        ok = '{"content": [{"type":"text","text":"navigated"}], "isError": false}'

        def _ev(tool: str, text: str, tag: str | None):
            return Event(session_id="s", source="test", type="test_result",
                         data={"tool": tool, "response_preview": text}, variation_tag=tag)

        class CleanRerun:
            async def events_by_type(self, t: str):
                if t != "test_result":
                    return
                for i in range(20):  # degraded first pass — all "no Chrome", untagged
                    yield _ev(["nav", "click", "eval", "snap"][i % 4], chrome_err, None)
                for i in range(20):  # rebuilt-image re-run — all clean, tagged
                    yield _ev(["nav", "click", "eval", "snap"][i % 4], ok, _PREREQ_RETRY_TAG)

        # untagged view (the *trigger* check) still sees the degraded first pass
        assert await _detect_missing_prerequisite(CleanRerun()) is not None
        # tagged view (the *post-retry* check) sees only the clean re-run → fixed
        assert await _detect_missing_prerequisite(CleanRerun(), only_tag=_PREREQ_RETRY_TAG) is None

        class StillBrokenRerun:
            async def events_by_type(self, t: str):
                if t != "test_result":
                    return
                for i in range(20):
                    yield _ev(["nav", "click", "eval", "snap"][i % 4], chrome_err, None)
                for i in range(20):  # re-run still fails for the same reason
                    yield _ev(["nav", "click", "eval", "snap"][i % 4], chrome_err, _PREREQ_RETRY_TAG)

        # the post-retry check sees the still-failing re-run → caveat will be emitted
        hint = await _detect_missing_prerequisite(StillBrokenRerun(), only_tag=_PREREQ_RETRY_TAG)
        assert hint is not None and "could not find google chrome" in hint.lower()


class TestPrerequisiteCaveat:
    async def test_r6_emits_low_caveat_from_prerequisite_missing_event(self, event_store) -> None:  # type: ignore[no-untyped-def]
        from mcp_dynamic_analyzer.models import Severity
        from mcp_dynamic_analyzer.scanners.r6_stability import R6StabilityScanner
        async with event_store.writer as w:
            from tests.conftest import make_event
            await w.write(make_event("orchestrator", "prerequisite_missing", name="geckodriver", hint="spawn geckodriver ENOENT"))
        from mcp_dynamic_analyzer.models import AnalysisContext
        ctx = AnalysisContext(session_id="s", event_reader=event_store.reader, tools=[], config={}, static_context=None)
        findings = await R6StabilityScanner().analyze(ctx)
        hits = [f for f in findings if "geckodriver" in f.title.lower()]
        assert len(hits) == 1
        assert hits[0].severity == Severity.LOW
        assert "coverage incomplete" in hits[0].title.lower()

    async def test_r6_no_caveat_without_prerequisite_event(self, event_store) -> None:  # type: ignore[no-untyped-def]
        from mcp_dynamic_analyzer.models import AnalysisContext
        from mcp_dynamic_analyzer.scanners.r6_stability import R6StabilityScanner
        ctx = AnalysisContext(session_id="s", event_reader=event_store.reader, tools=[], config={}, static_context=None)
        findings = await R6StabilityScanner().analyze(ctx)
        assert not any("coverage incomplete" in f.title.lower() for f in findings)

    def test_caveat_finding_downgrades_clean_approve_to_conditional(self) -> None:
        from mcp_dynamic_analyzer.models import Finding, RiskType, Severity
        from mcp_dynamic_analyzer.output.scorer import Scorer

        caveat = Finding(
            risk_type=RiskType.R6, severity=Severity.LOW, confidence=0.7,
            title="Scan coverage incomplete — server needs 'geckodriver' (not installed)",
            description="partial scan", reproduction="x",
        )
        # the caveat alone would score as APPROVE → bumped to CONDITIONAL
        assert Scorer().score([caveat]).verdict == "CONDITIONAL"
        # an ordinary LOW finding does NOT trigger the bump
        other = Finding(
            risk_type=RiskType.R6, severity=Severity.LOW, confidence=0.7,
            title="Some other minor note", description="x", reproduction="x",
        )
        assert Scorer().score([other]).verdict == "APPROVE"
        # a genuinely bad result stays REJECT even with the caveat present
        crit = Finding(
            risk_type=RiskType.R2, severity=Severity.CRITICAL, confidence=0.95,
            title="RCE", description="x", reproduction="x",
        )
        assert Scorer().score([caveat, crit, crit]).verdict == "REJECT"

    def test_caveat_weight_excluded_from_summation(self) -> None:
        """ses-8bf23f91 regression: HIGH crash + two MEDIUM timeouts scored to
        CONDITIONAL (0.69). Adding the LOW "coverage incomplete" caveat must
        not push the verdict to REJECT — caveats report missing measurement,
        not measured risk, so they're excluded from the sum (only the
        APPROVE→CONDITIONAL bump rule still consults them)."""
        from mcp_dynamic_analyzer.models import Finding, RiskType, Severity
        from mcp_dynamic_analyzer.output.scorer import Scorer

        high_crash = Finding(
            risk_type=RiskType.R6, severity=Severity.HIGH, confidence=0.9,
            title="Server crash triggered by 'memory_bomb' payload",
            description="x", reproduction="x",
        )
        med_timeout = Finding(
            risk_type=RiskType.R6, severity=Severity.MEDIUM, confidence=0.7,
            title="Timeout / hang on category 'slow_path'",
            description="x", reproduction="x",
        )
        caveat = Finding(
            risk_type=RiskType.R6, severity=Severity.LOW, confidence=0.7,
            title="Scan coverage incomplete — server needs 'Google Chrome' (not installed)",
            description="x", reproduction="x",
        )
        without = Scorer().score([high_crash, med_timeout, med_timeout])
        withc = Scorer().score([high_crash, med_timeout, med_timeout, caveat])
        # caveat must not change the numeric R6 score nor the verdict
        assert without.per_risk["R6"] == withc.per_risk["R6"]
        assert without.verdict == "CONDITIONAL"
        assert withc.verdict == "CONDITIONAL"  # <-- the bug was: REJECT here


class TestServerIdentity:
    """The report's ``Server:`` line should show the MCP server's
    self-declared identity from its `initialize` reply (e.g. ``drawio-mcp
    1.0.0``), not the raw launcher (``npx``, ``docker``, ``uvx``). The
    launcher stays available parenthetically so "what we actually ran" is
    still visible.
    """

    async def test_extract_server_info_picks_up_initialize_reply(self, event_store) -> None:  # type: ignore[no-untyped-def]
        from mcp_dynamic_analyzer.orchestrator import _extract_server_info
        from tests.conftest import make_event
        async with event_store.writer as w:
            await w.write(make_event("protocol", "mcp_response", direction="s2c",
                                     message={"jsonrpc": "2.0", "id": 1,
                                              "result": {"protocolVersion": "2024-11-05",
                                                         "capabilities": {},
                                                         "serverInfo": {"name": "drawio-mcp",
                                                                        "version": "1.0.0"}}}))
        info = await _extract_server_info(event_store.reader)
        assert info == {"name": "drawio-mcp", "version": "1.0.0"}

    async def test_extract_server_info_returns_empty_when_no_handshake(self, event_store) -> None:  # type: ignore[no-untyped-def]
        from mcp_dynamic_analyzer.orchestrator import _extract_server_info
        info = await _extract_server_info(event_store.reader)
        assert info == {}

    async def test_extract_server_info_skips_responses_without_serverinfo(self, event_store) -> None:  # type: ignore[no-untyped-def]
        """tools/list etc. don't carry serverInfo — must not match."""
        from mcp_dynamic_analyzer.orchestrator import _extract_server_info
        from tests.conftest import make_event
        async with event_store.writer as w:
            await w.write(make_event("protocol", "mcp_response", direction="s2c",
                                     message={"jsonrpc": "2.0", "id": 2,
                                              "result": {"tools": []}}))
            await w.write(make_event("protocol", "mcp_response", direction="s2c",
                                     message={"jsonrpc": "2.0", "id": 1,
                                              "result": {"serverInfo": {"name": "chrome_devtools",
                                                                        "version": "0.26.0"}}}))
        info = await _extract_server_info(event_store.reader)
        assert info["name"] == "chrome_devtools"
        assert info["version"] == "0.26.0"

    def test_reporter_shows_discovered_name_with_launcher_in_parens(self) -> None:
        from mcp_dynamic_analyzer.models import AnalysisOutput
        from mcp_dynamic_analyzer.output.reporter import Reporter
        from mcp_dynamic_analyzer.output.scorer import Scorer
        out = AnalysisOutput(
            session_id="s",
            server={"name": "drawio-mcp", "version": "1.0.0",
                    "command": "npx", "args": ["@drawio/mcp"]},
            findings=[], event_log_path="/dev/null",
            dynamic_risk_scores={"R6": 0.0}, metadata={},
        )
        text = Reporter("/tmp")._render(out, Scorer().score([]))
        srv_line = next(l for l in text.splitlines() if l.startswith("**Server"))
        assert "`drawio-mcp 1.0.0`" in srv_line
        assert "(via `npx @drawio/mcp`)" in srv_line

    def test_reporter_falls_back_to_launcher_when_handshake_missing(self) -> None:
        """No serverInfo discovered → ``name`` stays as the launcher command.
        Reporter must not show ``foo (via foo)`` redundancy."""
        from mcp_dynamic_analyzer.models import AnalysisOutput
        from mcp_dynamic_analyzer.output.reporter import Reporter
        from mcp_dynamic_analyzer.output.scorer import Scorer
        out = AnalysisOutput(
            session_id="s",
            server={"name": "docker", "version": "",
                    "command": "docker", "args": ["run", "ghcr.io/example/mcp"]},
            findings=[], event_log_path="/dev/null",
            dynamic_risk_scores={"R6": 0.0}, metadata={},
        )
        text = Reporter("/tmp")._render(out, Scorer().score([]))
        srv_line = next(l for l in text.splitlines() if l.startswith("**Server"))
        assert "docker run ghcr.io/example/mcp" in srv_line
        assert "(via" not in srv_line  # no redundancy
