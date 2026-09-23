import unittest
from omni.navgraph import check_graph
from omni.traces import diff, consensus

class NavigationAndTraceTests(unittest.TestCase):
    def setUp(self):
        self.graph={"start":"root","nodes":[
          {"id":"root","name":"Setup","edges":[{"action":"enter","to":"boot"}]},
          {"id":"boot","name":"Boot","focusable":True,"edges":[{"action":"down","to":"secure"},{"action":"back","to":"root"}]},
          {"id":"secure","name":"Secure Boot","value":"Enabled","focusable":True,"edges":[{"action":"up","to":"boot"},{"action":"back","to":"root"}]}]}
        self.trace=[
          {"kind":"focus_changed","node":{"role":"checkbox","name":"Secure Boot","value":"Enabled","state":["focused","enabled"]}},
          {"kind":"value_changed","node":{"role":"checkbox","name":"Secure Boot","value":"Disabled","state":["focused","enabled"]}}]

    def test_graph_passes(self):
        r=check_graph(self.graph); self.assertEqual(r["status"],"PASS"); self.assertEqual(r["coverage_percent"],100.0)

    def test_graph_detects_nondeterminism(self):
        self.graph["nodes"][1]["edges"].append({"action":"down","to":"root"})
        r=check_graph(self.graph); self.assertEqual(r["status"],"FAIL")
        self.assertIn("NONDETERMINISTIC_ACTION",{x["code"] for x in r["violations"]})

    def test_graph_detects_duplicate_node_ids(self):
        self.graph["nodes"].append(
            {"id":"boot","name":"Duplicate","focusable":True,"edges":[]}
        )
        r=check_graph(self.graph)
        self.assertEqual(r["status"],"FAIL")
        self.assertIn("DUPLICATE_NODE_ID",{x["code"] for x in r["violations"]})

    def test_graph_detects_malformed_edge(self):
        self.graph["nodes"][0]["edges"].append({"to":"secure"})
        r=check_graph(self.graph)
        self.assertEqual(r["status"],"FAIL")
        self.assertIn("EDGE_MISSING_ACTION",{x["code"] for x in r["violations"]})

    def test_trace_consensus(self):
        other=[
          {"kind":"focus_changed","timestamp":999,"node":{"id":400,"role":"CHECKBOX","name":" Secure   Boot ","value":"Enabled","state":["enabled","focused"]}},
          {"kind":"value_changed","node":{"id":400,"role":"checkbox","name":"Secure Boot","value":"Disabled","state":["focused","enabled"]}}]
        self.assertEqual(diff(self.trace,other)["status"],"PASS")
        self.assertEqual(consensus([self.trace,other,self.trace])["status"],"PASS")

    def test_trace_consensus_requires_real_evidence(self):
        self.assertEqual(consensus([])["reason"],"NO_TRACES")
        self.assertEqual(consensus([self.trace])["reason"],"INSUFFICIENT_TRACES")
        self.assertEqual(consensus([[],[]])["reason"],"EMPTY_TRACE")

    def test_trace_consensus_rejects_malformed_event(self):
        r=consensus([[{"kind":"focus_changed","node":[]}], self.trace])
        self.assertEqual(r["status"],"FAIL")
        self.assertEqual(r["reason"],"INVALID_EVENT")
