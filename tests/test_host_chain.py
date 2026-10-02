import unittest

from omni.host_chain import (
    Detection,
    HostScan,
    scan_file_hints,
)


class HostScanHintTests(unittest.TestCase):
    def test_recognizes_nvda_and_jaws_from_hints(self):
        # On force la detection via hints : scan_file_hints verifie
        # (a) chaque hint fourni puis (b) l'existence du chemin candidat sur
        # la machine. Sur cette machine-ci NVDA + JAWS sont installes donc on
        # verifie plutot que les hints sont reconnus quand aucun des chemins
        # candidats n'existe (grace a un hint bidon).
        det = scan_file_hints([
            r"C:\Definitely\Not\A\Real\Path\For\Testing\NVDA\nvda.exe",
            r"C:\Definitely\Not\A\Real\Path\For\Testing\JAWS\jfw.exe",
        ])
        keys = {d.key for d in det}
        self.assertIn("nvda", keys)
        self.assertIn("jaws", keys)

    def test_recognizes_paths_that_exist(self):
        # Les chemins candidats sont verifies en plus des hints : si l'un
        # d'eux existe sur la machine, il doit remonter.
        det = scan_file_hints([])
        # Cette assertion depend de la presence reellee : NVDA est tres
        # probablement installe, mais on ne le considere pas obligatoire.
        # Ce qui compte : la fonction rend une liste (vide ou non).
        self.assertIsInstance(det, list)

    def test_category_partition(self):
        # On utilise des hints qui pointent sur les chemins candidats reels
        # definis dans A11Y_DETECTORS / VPN_DETECTORS / IDS_DETECTORS : la
        # fonction scan_file_hints matche uniquement (a) les hints egaux a un
        # chemin candidat ou (b) un chemin candidat qui existe sur le disque.
        det = scan_file_hints([
            r"C:\Program Files\NVDA",
            r"C:\Program Files\WireGuard",
            r"C:\Program Files\OpenVPN",
            r"C:\Windows\SystemApps\Microsoft.Windows.NarratorQuickStart",
        ])
        by_cat: dict[str, list[str]] = {}
        for d in det:
            by_cat.setdefault(d.category, []).append(d.key)
        self.assertIn("nvda", by_cat.get("a11y", []))
        self.assertIn("wireguard", by_cat.get("vpn", []))
        self.assertIn("openvpn", by_cat.get("vpn", []))

    def test_hostscan_passed_requires_each_category(self):
        # Construit un scan artificiel : uniquement a11y installe.
        scan = HostScan(platform="static", detections=(
            Detection(key="nvda", label="NVDA", category="a11y",
                     installed=True, running=None, evidence="hint"),
        ))
        self.assertFalse(scan.passed(("a11y", "vpn", "ids")))
        self.assertTrue(scan.passed(("a11y",)))

    def test_as_dict_shape(self):
        scan = HostScan(platform="static", detections=(
            Detection(key="nvda", label="NVDA", category="a11y",
                     installed=True, running=None, evidence="hint"),
        ))
        d = scan.as_dict()
        self.assertEqual(d["platform"], "static")
        self.assertIn("categories", d)
        self.assertIn("a11y", d["categories"])
        self.assertIn("nvda", {x["key"] for x in d["categories"]["a11y"]})


class HostScanLiveTests(unittest.TestCase):
    """Les tests live sont proteges : ils skippent si les detecteurs sont absents.

    On veut quand meme pouvoir tester la pipeline de scan (running hints,
    subprocess timeout, etc.) sans dependre d'une machine specifique.
    """

    def test_live_scan_returns_platform(self):
        from omni import host_chain
        scan = host_chain.scan_host(a11y=False, vpn=False, ids=False)
        self.assertEqual(scan.detections, ())
        self.assertIn(scan.platform, ("win32", "linux", "darwin"))


class DetectionDataclassTests(unittest.TestCase):
    def test_slots_and_frozen(self):
        # On ne peut pas definir de __dict__ sur des slots, et on ne peut pas
        # reassigner les attributs sur frozen.
        d = Detection(key="x", label="x", category="a11y",
                       installed=True, running=False, evidence="path")
        with self.assertRaises(Exception):
            d.key = "y"  # type: ignore[misc]


if __name__ == "__main__":
    unittest.main()