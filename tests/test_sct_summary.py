import unittest
from tools.sct_summary import decode_summary_bytes, parse

class SctSummaryTests(unittest.TestCase):
    def test_pass_log(self):
        result=parse("Alpha -- PASS\nBeta -- WARNING\nErrors........... 0\n")
        self.assertEqual(result["status"],"PASS")
        self.assertEqual(result["passes_observed"],1)

    def test_failure_line_is_fatal(self):
        result=parse("Thing -- FAILURE\n")
        self.assertEqual(result["status"],"FAIL")

    def test_nonzero_error_count_is_fatal(self):
        result=parse("Errors........... 4\n")
        self.assertEqual(result["status"],"FAIL")

    def test_words_in_descriptions_do_not_false_positive(self):
        result=parse("This text discusses FAILURE handling but is not a result\nAlpha -- PASS\nErrors........... 0\n")
        self.assertEqual(result["status"],"PASS")

    def test_empty_or_inconclusive_log_is_fatal(self):
        self.assertEqual(parse("")["status"],"FAIL")
        self.assertEqual(parse("Errors........... 0\n")["status"],"FAIL")

    def test_official_utf16_summary_is_decoded(self):
        raw="Alpha -- PASS\nBeta -- WARNING\nErrors........... 0\n".encode("utf-16")
        result=parse(decode_summary_bytes(raw))
        self.assertEqual(result["status"],"PASS")
        self.assertEqual(result["passes_observed"],1)
        self.assertEqual(result["warnings_observed"],1)

    def test_utf16_failure_cannot_be_hidden_by_nul_bytes(self):
        raw="Alpha -- PASS\nBroken -- FAILURE\nErrors........... 1\n".encode("utf-16")
        result=parse(decode_summary_bytes(raw))
        self.assertEqual(result["status"],"FAIL")
        self.assertTrue(result["explicit_failure_lines"])
        self.assertTrue(result["nonzero_error_counts"])

    def test_bomless_utf16_le_is_detected_when_signature_is_strong(self):
        raw="Alpha -- PASS\nErrors........... 0\n".encode("utf-16-le")
        result=parse(decode_summary_bytes(raw))
        self.assertEqual(result["status"],"PASS")
