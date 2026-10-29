from __future__ import annotations

from typing import Any

from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import (
    ExportTraceServiceRequest,
)
from google.protobuf.message import DecodeError

from .schemas import SpanRecord


class InvalidOTLPTracePayload(ValueError):
    """Raised when the request body is not a valid OTLP trace protobuf."""


def _hex_bytes(value: bytes) -> str:
    return value.hex() if value else ""


def _any_value(value: Any) -> Any:
    kind = value.WhichOneof("value")
    if kind is None:
        return None

    if kind == "string_value":
        return value.string_value
    if kind == "bool_value":
        return value.bool_value
    if kind == "int_value":
        return value.int_value
    if kind == "double_value":
        return value.double_value
    if kind == "bytes_value":
        return value.bytes_value.hex()
    if kind == "array_value":
        return [_any_value(v) for v in value.array_value.values]
    if kind == "kvlist_value":
        return {
            item.key: _any_value(item.value)
            for item in value.kvlist_value.values
        }

    return None


def attributes_to_dict(attributes) -> dict[str, Any]:
    return {
        item.key: _any_value(item.value)
        for item in attributes
    }


def _service_name(resource_attributes: dict[str, Any]) -> str | None:
    value = resource_attributes.get("service.name")
    return str(value) if value is not None else None


def normalize_traces(payload: bytes) -> tuple[int, list[SpanRecord]]:
    request = ExportTraceServiceRequest()
    try:
        request.ParseFromString(payload)
    except DecodeError as exc:
        raise InvalidOTLPTracePayload(
            "Invalid OTLP trace payload."
        ) from exc

    records: list[SpanRecord] = []

    for resource_spans in request.resource_spans:
        resource_attrs = attributes_to_dict(
            resource_spans.resource.attributes
        )
        service_name = _service_name(resource_attrs)

        for scope_spans in resource_spans.scope_spans:
            for span in scope_spans.spans:
                start_ns = int(span.start_time_unix_nano)
                end_ns = int(span.end_time_unix_nano)
                if len(span.trace_id) != 16 or not any(span.trace_id):
                    raise InvalidOTLPTracePayload(
                        "Invalid OTLP trace payload."
                    )
                if len(span.span_id) != 8 or not any(span.span_id):
                    raise InvalidOTLPTracePayload(
                        "Invalid OTLP trace payload."
                    )
                if span.parent_span_id and (
                    len(span.parent_span_id) != 8
                    or not any(span.parent_span_id)
                ):
                    raise InvalidOTLPTracePayload(
                        "Invalid OTLP trace payload."
                    )
                if end_ns < start_ns:
                    raise InvalidOTLPTracePayload(
                        "Invalid OTLP trace payload."
                    )

                records.append(
                    SpanRecord(
                        trace_id=_hex_bytes(span.trace_id),
                        span_id=_hex_bytes(span.span_id),
                        parent_span_id=_hex_bytes(span.parent_span_id) or None,
                        service_name=service_name,
                        span_name=span.name,
                        start_time_unix_nano=start_ns,
                        end_time_unix_nano=end_ns,
                        duration_ms=max(0, end_ns - start_ns) / 1_000_000,
                        span_kind=int(span.kind),
                        status_code=int(span.status.code),
                        attributes=attributes_to_dict(span.attributes),
                    )
                )

    return len(request.resource_spans), records
