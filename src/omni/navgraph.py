from __future__ import annotations
from collections import deque

def check_graph(graph: dict[str, object]) -> dict[str, object]:
    raw_nodes = list(graph.get("nodes", []))
    node_ids = [str(n["id"]) for n in raw_nodes]
    nodes = {str(n["id"]): n for n in raw_nodes}
    start = str(graph.get("start", ""))
    violations = []
    duplicate_ids = sorted({node_id for node_id in node_ids if node_ids.count(node_id) > 1})
    for node_id in duplicate_ids:
        violations.append({"code":"DUPLICATE_NODE_ID","node":node_id})
    if start not in nodes:
        return {"status":"FAIL","reachable":0,"nodes":len(nodes),"coverage_percent":0.0,
                "violations":[{"code":"MISSING_START","start":start}]}
    for node_id,node in nodes.items():
        seen={}
        for edge in node.get("edges", []):
            action,target=str(edge["action"]),str(edge["to"])
            if target not in nodes:
                violations.append({"code":"EDGE_TO_UNKNOWN","node":node_id,"action":action,"target":target})
            if action in seen and seen[action] != target:
                violations.append({"code":"NONDETERMINISTIC_ACTION","node":node_id,"action":action,"targets":[seen[action],target]})
            seen[action]=target
        if node.get("focusable",False) and not str(node.get("name","")).strip():
            violations.append({"code":"FOCUSABLE_WITHOUT_NAME","node":node_id})
        if node.get("password",False) and str(node.get("value","")):
            violations.append({"code":"PASSWORD_VALUE_EXPOSED","node":node_id})
    reachable={start}; q=deque([start])
    while q:
        current=q.popleft()
        for edge in nodes[current].get("edges",[]):
            target=str(edge["to"])
            if target in nodes and target not in reachable:
                reachable.add(target); q.append(target)
    for node_id in nodes:
        if node_id not in reachable:
            violations.append({"code":"UNREACHABLE_NODE","node":node_id})
    reverse={}
    for node_id,node in nodes.items():
        for edge in node.get("edges",[]):
            reverse.setdefault(str(edge["to"]),[]).append(node_id)
    can_return={start}; q=deque([start])
    while q:
        current=q.popleft()
        for previous in reverse.get(current,[]):
            if previous not in can_return:
                can_return.add(previous); q.append(previous)
    for node_id in sorted(reachable):
        node=nodes[node_id]
        if node.get("terminal",False):
            continue
        if node_id not in can_return:
            violations.append({"code":"NO_PATH_BACK_TO_START","node":node_id})
        if node.get("focusable",False) and not node.get("edges",[]):
            violations.append({"code":"FOCUS_DEAD_END","node":node_id})
    coverage=100.0*len(reachable)/len(nodes) if nodes else 100.0
    return {"status":"PASS" if not violations else "FAIL","nodes":len(nodes),
            "reachable":len(reachable),"coverage_percent":coverage,"violations":violations}
