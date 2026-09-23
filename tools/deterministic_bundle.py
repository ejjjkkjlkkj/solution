#!/usr/bin/env python3
import hashlib, pathlib, sys, zipfile
ROOT=pathlib.Path(__file__).resolve().parents[1]
def members():
    for p in sorted(ROOT.rglob("*")):
        if not p.is_file(): continue
        r=p.relative_to(ROOT)
        if ".git" in r.parts or "__pycache__" in r.parts or r.suffix==".pyc" or r.name=="software-bundle.zip": continue
        yield p,r
out=pathlib.Path(sys.argv[1]).resolve()
with zipfile.ZipFile(out,"w",zipfile.ZIP_DEFLATED,compresslevel=9) as z:
    for p,r in members():
        i=zipfile.ZipInfo(r.as_posix(),date_time=(1980,1,1,0,0,0)); i.compress_type=zipfile.ZIP_DEFLATED; i.external_attr=(0o100644&0xFFFF)<<16
        z.writestr(i,p.read_bytes(),compress_type=zipfile.ZIP_DEFLATED,compresslevel=9)
print(hashlib.sha256(out.read_bytes()).hexdigest().upper())
