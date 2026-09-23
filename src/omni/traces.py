from __future__ import annotations
from collections import Counter

def normalize(event):
    node=dict(event.get("node") or {})
    return (event.get("kind"),str(node.get("role","")).strip().lower(),
            " ".join(str(node.get("name","")).split()),
            " ".join(str(node.get("value","")).split()),
            tuple(sorted(str(x).lower() for x in node.get("state",[]))))

def diff(a,b):
    aa=[normalize(x) for x in a]; bb=[normalize(x) for x in b]; differences=[]
    if not aa or not bb:
        return {"status":"FAIL","reason":"EMPTY_TRACE","a_events":len(aa),
                "b_events":len(bb),"differences":[]}
    for index in range(max(len(aa),len(bb))):
        left=aa[index] if index<len(aa) else None
        right=bb[index] if index<len(bb) else None
        if left != right:
            differences.append({"index":index,"a":left,"b":right})
    return {"status":"PASS" if not differences else "DIVERGED","a_events":len(aa),
            "b_events":len(bb),"differences":differences}

def consensus(traces):
    normalized=[[normalize(x) for x in trace] for trace in traces]
    if len(normalized) < 2:
        return {"status":"FAIL","reason":"INSUFFICIENT_TRACES","traces":len(normalized),
                "events":len(normalized[0]) if normalized else 0,"disagreements":[]}
    if any(not trace for trace in normalized):
        return {"status":"FAIL","reason":"EMPTY_TRACE","traces":len(normalized),
                "events":max((len(t) for t in normalized), default=0),"disagreements":[]}
    disagreements=[]; unanimous=0; count=max(len(t) for t in normalized)
    for index in range(count):
        values=[trace[index] if index<len(trace) else None for trace in normalized]
        _,votes=Counter(values).most_common(1)[0]
        if votes == len(values): unanimous += 1
        else: disagreements.append({"index":index,"values":values,"majority_count":votes})
    return {"status":"PASS" if not disagreements else "DIVERGED","traces":len(normalized),
            "events":count,"unanimous":unanimous,"disagreements":disagreements}
