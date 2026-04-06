"""Abstract base classes for the analysis-phase scanner and collection-phase test sequence."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

from mcp_dynamic_analyzer.models import AnalysisContext, Finding, RiskType

if TYPE_CHECKING:
    from mcp_dynamic_analyzer.correlation.event_store import EventWriter


# ---------------------------------------------------------------------------
# BaseScanner — analysis phase
# ---------------------------------------------------------------------------

class BaseScanner(ABC):
    """Analyses events that were already collected in the EventStore.

    Subclasses implement a single ``analyze`` method that receives an
    ``AnalysisContext`` (read-only access to events, tool metadata, config)
    and returns a list of ``Finding`` objects.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Scanner identifier, e.g. ``'r1_data_access'``."""

    @property
    @abstractmethod
    def risk_type(self) -> RiskType:
        """The primary risk category this scanner covers."""

    @abstractmethod
    async def analyze(self, ctx: AnalysisContext) -> list[Finding]:
        """Run post-hoc analysis on collected events.

        Args:
            ctx: Read-only analysis context containing the EventReader,
                 tool metadata, optional static-analysis context, and
                 the full YAML config.

        Returns:
            Findings discovered by this scanner.
        """


# ---------------------------------------------------------------------------
# TestSequence — collection phase
# ---------------------------------------------------------------------------

class TestSequence(ABC):
    """A scenario executed during the collection phase.

    The sequencer runs each ``TestSequence`` against the live MCP server
    via a test client.  Every request/response is automatically captured
    by the interceptor; the sequence may additionally write its own
    ``test`` events (e.g. payload metadata) via the ``EventWriter``.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Sequence identifier, e.g. ``'fuzz_path_traversal'``."""

    @property
    def timeout(self) -> float:
        """Per-sequence timeout in seconds.  Override for long-running tests."""
        return 30.0

    @abstractmethod
    async def execute(self, client: object, writer: EventWriter) -> None:
        """Execute the test scenario.

        Args:
            client: An ``McpClient`` connected through the interceptor.
                    Typed as ``object`` to avoid circular imports; cast
                    in concrete implementations.
            writer: EventWriter for recording test-specific events.
        """
