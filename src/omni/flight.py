from __future__ import annotations
import hashlib, json
from typing import Iterable

GENESIS = "0" * 64

def canonical(event: dict[str, object]) -> bytes:
    return json.dumps(event, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()

def event_hash(previous: str, event: dict[str, object]) -> str:
    h = hashlib.sha256()
    h.update(bytes.fromhex(previous))
    h.update(canonical(event))
    return h.hexdigest().upper()

def build(events: Iterable[dict[str, object]]) -> list[dict[str, object]]:
    previous = GENESIS
    output = []
    for index, event in enumerate(events):
        digest = event_hash(previous, event)
        output.append({"index": index, "prev_hash": previous, "event": event, "hash": digest})
        previous = digest
    return output

def verify(records: Iterable[dict[str, object]]) -> tuple[bool, str]:
    previous = GENESIS
    for expected_index, record in enumerate(records):
        if int(record["index"]) != expected_index:
            return False, "INDEX"
        if str(record["prev_hash"]).upper() != previous:
            return False, "PREVIOUS_HASH"
        expected = event_hash(previous, dict(record["event"]))
        if str(record["hash"]).upper() != expected:
            return False, "HASH"
        previous = expected
    return True, previous
