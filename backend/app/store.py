from __future__ import annotations

from collections import OrderedDict

from .schemas import SpanRecord, TraceSummary


class InMemorySpanStore:
    """Small bounded store for the first integration milestone.

    This lets us prove the OTLP -> FastAPI -> normalized-span path before
    introducing PostgreSQL. The interface is intentionally simple so it can
    be replaced by a PostgreSQL repository without changing the API layer.
    """

    def __init__(self, max_spans: int = 5000) -> None:
        self.max_spans = max_spans
        self._spans: OrderedDict[str, SpanRecord] = OrderedDict()

    def add(self, span: SpanRecord) -> None:
        self._spans[span.span_id] = span
        self._spans.move_to_end(span.span_id)

        while len(self._spans) > self.max_spans:
            self._spans.popitem(last=False)

    def count(self) -> int:
        return len(self._spans)

    def recent(self, limit: int = 100) -> list[SpanRecord]:
        limit = max(1, min(limit, self.max_spans))
        return list(self._spans.values())[-limit:]

    def trace(self, trace_id: str) -> list[SpanRecord]:
        return [
            span for span in self._spans.values()
            if span.trace_id == trace_id
        ]

    def trace_summaries(self) -> list[TraceSummary]:
        grouped: dict[str, list[SpanRecord]] = {}
        for span in self._spans.values():
            grouped.setdefault(span.trace_id, []).append(span)

        return [
            TraceSummary(
                trace_id=trace_id,
                span_count=len(spans),
                services=sorted(
                    {s.service_name for s in spans if s.service_name}
                ),
            )
            for trace_id, spans in grouped.items()
        ]
