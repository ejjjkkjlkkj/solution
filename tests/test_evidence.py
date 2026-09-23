import hashlib
import tempfile
import unittest
from pathlib import Path
from tools.verify_uefi_evidence import EvidenceError, parse_evidence, verify

VALID="""OMNI_EVIDENCE_V1
OMNI_HII_HANDLES=2
OMNI_HII_FORM_PACKAGES=3
OMNI_HII_OPCODES=21
OMNI_HII_QUESTIONS=8
OMNI_HII_PASSWORDS=1
OMNI_HII_INVALID=0
OMNI_HII_PASS
OMNI_UEFI_PASS
"""

class PhysicalEvidenceTests(unittest.TestCase):
    def test_valid_evidence_is_bound_to_efi_hash(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            evidence=root/"OMNI-EVIDENCE.TXT"
            efi=root/"BOOTX64.EFI"
            evidence.write_text(VALID,encoding="ascii")
            efi.write_bytes(b"known-efi")
            expected=hashlib.sha256(b"known-efi").hexdigest()
            result=verify(evidence,efi,expected)
            self.assertEqual(result["status"],"PHYSICAL_EVIDENCE_SOFTWARE_VERIFY_PASS")

    def test_firmware_fail_marker_is_fatal(self):
        with self.assertRaises(EvidenceError):
            parse_evidence(VALID.replace("OMNI_HII_PASS","OMNI_HII_FAIL"))

    def test_nonzero_invalid_count_is_fatal(self):
        with self.assertRaises(EvidenceError):
            parse_evidence(VALID.replace("OMNI_HII_INVALID=0","OMNI_HII_INVALID=1"))

    def test_wrong_binary_hash_is_fatal(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            evidence=root/"OMNI-EVIDENCE.TXT"
            efi=root/"BOOTX64.EFI"
            evidence.write_text(VALID,encoding="ascii")
            efi.write_bytes(b"tampered")
            expected=hashlib.sha256(b"known-efi").hexdigest()
            with self.assertRaises(EvidenceError):
                verify(evidence,efi,expected)

if __name__=="__main__":
    unittest.main()
