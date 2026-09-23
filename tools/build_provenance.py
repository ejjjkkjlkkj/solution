#!/usr/bin/env python3
import hashlib,json,os,pathlib,sys
artifact=pathlib.Path(sys.argv[1]); out=pathlib.Path(sys.argv[2]); digest=hashlib.sha256(artifact.read_bytes()).hexdigest()
stmt={"_type":"https://in-toto.io/Statement/v1","subject":[{"name":artifact.name,"digest":{"sha256":digest}}],"predicateType":"https://slsa.dev/provenance/v1","predicate":{"buildDefinition":{"buildType":"https://github.com/ejjjkkjlkkj/solution/software-ceiling","externalParameters":{},"internalParameters":{},"resolvedDependencies":[]},"runDetails":{"builder":{"id":"https://github.com/actions/runner"},"metadata":{"invocationId":os.environ.get("GITHUB_RUN_ID","local")},"byproducts":[]}}}
out.write_text(json.dumps(stmt,sort_keys=True,indent=2)+"\n",encoding="utf-8")
