from __future__ import annotations
from dataclasses import dataclass, field
from typing import Iterable

FOCUSABLE_ROLES = {"menuitem", "button", "checkbox", "radiobutton", "slider", "edit", "listitem", "tab", "bootentry"}
SNAPSHOT_UPDATE_KINDS = {"node_updated", "value_changed", "state_changed"}
KNOWN_KINDS = {"node_created", *SNAPSHOT_UPDATE_KINDS, "focus_changed", "node_removed"}

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
        if not role or role == "unknown":
            self._violate("MISSING_ROLE", node=node.id)
        if role in FOCUSABLE_ROLES and not node.name.strip():
            self._violate("FOCUSABLE_WITHOUT_NAME", node=node.id)
        if "password" in state and node.value:
            self._violate("PASSWORD_VALUE_EXPOSED", node=node.id)
        if node.parent_id == node.id:
            self._violate("SELF_PARENT", node=node.id)

    @staticmethod
    def _merge_node(node_id: int, raw: dict[str, object], existing: Node | None) -> Node:
        def prior(name: str, default: object) -> object:
            if name in raw:
                return raw[name]
            if existing is None:
                return default
            return getattr(existing, name)

        parent_raw = prior("parent_id", None)
        parent_id = None if parent_raw is None else int(parent_raw)
        state_raw = prior("state", set())
        return Node(
            id=node_id,
            parent_id=parent_id,
            role=str(prior("role", "unknown")).strip().lower(),
            name=str(prior("name", "")),
            value=str(prior("value", "")),
            state={str(x).lower() for x in state_raw},
        )

    def apply(self, event: dict[str, object]) -> None:
        sequence = int(event["sequence"])
        if sequence <= self.sequence:
            self._violate("NON_MONOTONIC_SEQUENCE", sequence=sequence, previous=self.sequence)
        self.sequence = max(self.sequence, sequence)

        kind = str(event["kind"])
        if kind not in KNOWN_KINDS:
            self._violate("UNKNOWN_EVENT_KIND", kind=kind)
            return

        raw = dict(event.get("node") or {})
        node_id = int(raw.get("id", event.get("node_id", -1)))
        if node_id < 0:
            self._violate("INVALID_NODE_ID", node=node_id, kind=kind)
            return

        if kind == "node_created":
            if node_id in self.nodes:
                self._violate("DUPLICATE_NODE_CREATE", node=node_id)
                return
            node = self._merge_node(node_id, raw, None)
            self.nodes[node_id] = node
            self._validate(node)

        elif kind in SNAPSHOT_UPDATE_KINDS:
            existing = self.nodes.get(node_id)
            if existing is None:
                self._violate("UPDATE_UNKNOWN_NODE", node=node_id, kind=kind)
                return
            node = self._merge_node(node_id, raw, existing)
            self.nodes[node_id] = node
            self._validate(node)

        elif kind == "node_removed":
            if node_id not in self.nodes:
                self._violate("REMOVE_UNKNOWN_NODE", node=node_id)
                return
            self.nodes.pop(node_id)
            if self.focus == node_id:
                self.focus = None

        elif kind == "focus_changed":
            existing = self.nodes.get(node_id)
            if existing is None:
                self._violate("FOCUS_UNKNOWN_NODE", node=node_id)
                return
            if raw:
                node = self._merge_node(node_id, raw, existing)
                self.nodes[node_id] = node
                self._validate(node)
            self.focus = node_id
            for current_id, node in self.nodes.items():
                if current_id == node_id:
                    node.state.add("focused")
                else:
                    node.state.discard("focused")

        focused = [n.id for n in self.nodes.values() if "focused" in n.state]
        if len(focused) > 1:
            self._violate("MULTIPLE_FOCUS", nodes=focused)

    def apply_all(self, events: Iterable[dict[str, object]]) -> None:
        for event in events:
            self.apply(event)

    @property
    def passed(self) -> bool:
        return not self.violations
