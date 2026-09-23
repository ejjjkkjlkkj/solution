from __future__ import annotations
import hashlib, pathlib

def merkle_root(paths):
    artifacts=[]; leaves=[]
    for item in sorted((pathlib.Path(x) for x in paths),key=lambda p:str(p)):
        data=item.read_bytes(); digest=hashlib.sha256(data).digest()
        artifacts.append({"path":str(item),"bytes":len(data),"sha256":digest.hex().upper()})
        leaves.append(digest)
    if not leaves: root=hashlib.sha256(b"").digest()
    else:
        level=leaves
        while len(level)>1:
            if len(level)%2: level=level+[level[-1]]
            level=[hashlib.sha256(level[i]+level[i+1]).digest() for i in range(0,len(level),2)]
        root=level[0]
    return {"algorithm":"SHA-256","root":root.hex().upper(),"artifacts":artifacts}
