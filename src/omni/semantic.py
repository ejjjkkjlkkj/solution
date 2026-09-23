from __future__ import annotations
from dataclasses import dataclass, field
from typing import Iterable

FOCUSABLE_ROLES = {"menuitem", "button", "checkbox", "radiobutton", "slider", "edit", "listitem", "tab", "bootentry"}

@dataclass(slots=True)
class Node:
    id: int
    role: str
    name: str
    parent_id: int | None = None
    value: str = ""
    state: set[str] = field(default_factory=set)

class SemanticModel:
    def __init__(self) -> None:
        self.nodes: dict[int, Node] = {}
        self.focus: int | None = None
        self.sequence = -1
        self.violations: list[dict[str, object]] = []

    def _violate(self, code: str, **detail: object) -> None:
        self.violations.append({"code": code, **detail})

    def _validate(self, node: Node) -> None:
        role = node.role.lower()
        state = {x.lower() for x in node.state}
        if role in FOCUSABLE_ROLES and not node.name.strip():
            self._violate("FOCUSABLE_WITHOUT_NAME", node=node.id)
        if "password" in state and node.value:
            self._violate("PASSWORD_VALUE_EXPOSED", node=node.id)
        if node.parent_id == node.id:
            self._violate("SELF_PARENT", node=node.id)

    def apply(self, event: dict[str, object]) -> None:
        sequence = int(event["sequence"])
        if sequence <= self.sequence:
            self._violate("NON_MONOTONIC_SEQUENCE", sequence=sequence, previous=self.sequence)
        self.sequence = max(self.sequence, sequence)
        kind = str(event["kind"])
        raw = dict(event.get("node") or {})
        node_id = int(raw.get("id", event.get("node_id", -1)))

        if kind in {"node_created", "node_updated", "focus_changed", "value_changed", "state_changed"}:
            node = Node(
                id=node_id,
                parent_id=raw.get("parent_id"),
                role=str(raw.get("role", "unknown")),
                name=str(raw.get("name", "")),
                value=str(raw.get("value", "")),
                state=set(raw.get("state", [])),
            )
            if kind == "node_created" and node_id in self.nodes:
                self._violate("DUPLICATE_NODE_CREATE", node=node_id)
            self.nodes[node_id] = node
            self._validate(node)

        if kind == "node_removed":
            self.nodes.pop(node_id, None)
            if self.focus == node_id:
                self.focus = None

        if kind == "focus_changed":
            if node_id not in self.nodes:
                self._violate("FOCUS_UNKNOWN_NODE", node=node_id)
            self.focus = node_id
            for current_id, node in self.nodes.items():
                if current_id == node_id:
                    node.state.add("focused")
                else:
                    node.state.discard("focused")

        focused = [n.id for n in self.nodes.values() if "focused" in {x.lower() for x in n.state}]
        if len(focused) > 1:
            self._violate("MULTIPLE_FOCUS", nodes=focused)

    def apply_all(self, events: Iterable[dict[str, object]]) -> None:
        for event in events:
            self.apply(event)

    @property
    def passed(self) -> bool:
        return not self.violations
