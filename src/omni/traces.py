from __future__ import annotations

from collections import Counter
from collections.abc import Iterable


class TraceError(ValueError):
    pass


def normalize(event: object) -> tuple[object, str, str, str, tuple[str, ...]]:
    if not isinstance(event, dict):
        raise TraceError("event must be an object")
    raw_node = event.get("node") or {}
    if not isinstance(raw_node, dict):
        raise TraceError("event node must be an object")
    return (
        event.get("kind"),
        str(raw_node.get("role", "")).strip().lower(),
        " ".join(str(raw_node.get("name", "")).split()),
        " ".join(str(raw_node.get("value", "")).split()),
        tuple(sorted(str(x).lower() for x in raw_node.get("state", []))),
    )


def _normalize_trace(trace: Iterable[object]) -> list[tuple[object, str, str, str, tuple[str, ...]]]:
    return [normalize(event) for event in trace]


def diff(a: Iterable[object], b: Iterable[object]) -> dict[str, object]:
    try:
        aa = _normalize_trace(a)
        bb = _normalize_trace(b)
    except (TraceError, TypeError) as exc:
        return {
            "status": "FAIL",
            "reason": "INVALID_EVENT",
            "error": str(exc),
            "differences": [],
        }

    differences = []
    for index in range(max(len(aa), len(bb))):
        left = aa[index] if index < len(aa) else None
        right = bb[index] if index < len(bb) else None
        if left != right:
            differences.append({"index": index, "a": left, "b": right})

    return {
        "status": "PASS" if not differences else "DIVERGED",
        "a_events": len(aa),
        "b_events": len(bb),
        "differences": differences,
    }


def consensus(traces: Iterable[Iterable[object]]) -> dict[str, object]:
    trace_list = list(traces)
    if not trace_list:
        return {
            "status": "FAIL",
            "reason": "NO_TRACES",
            "events": 0,
            "disagreements": [],
        }
    if len(trace_list) < 2:
        return {
            "status": "FAIL",
            "reason": "INSUFFICIENT_TRACES",
            "traces": len(trace_list),
            "events": 0,
            "disagreements": [],
        }

    try:
        normalized = [_normalize_trace(trace) for trace in trace_list]
    except (TraceError, TypeError) as exc:
        return {
            "status": "FAIL",
            "reason": "INVALID_EVENT",
            "traces": len(trace_list),
            "events": 0,
            "error": str(exc),
            "disagreements": [],
        }

    empty = [index for index, trace in enumerate(normalized) if not trace]
    if empty:
        return {
            "status": "FAIL",
            "reason": "EMPTY_TRACE",
            "traces": len(normalized),
            "empty_trace_indexes": empty,
            "events": 0,
            "disagreements": [],
        }

    disagreements = []
    unanimous = 0
    count = max(len(trace) for trace in normalized)
    for index in range(count):
        values = [trace[index] if index < len(trace) else None for trace in normalized]
        _, votes = Counter(values).most_common(1)[0]
        if votes == len(values):
            unanimous += 1
        else:
            disagreements.append(
                {
                    "index": index,
                    "values": values,
                    "majority_count": votes,
                }
            )

    return {
        "status": "PASS" if not disagreements else "DIVERGED",
        "traces": len(normalized),
        "events": count,
        "unanimous": unanimous,
        "disagreements": disagreements,
    }
