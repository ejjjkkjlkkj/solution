import unittest

from tools.sct_summary import parse


class SctSummaryTests(unittest.TestCase):
    def test_pass_log(self):
        result = parse("Alpha -- PASS\nBeta -- WARNING\nErrors........... 0\n")
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["passes_observed"], 1)
        self.assertEqual(result["blockers"], [])

    def test_empty_log_is_fatal(self):
        result = parse("")
        self.assertEqual(result["status"], "FAIL")
        self.assertIn("EMPTY_SUMMARY", result["blockers"])
        self.assertIn("NO_PASS_RESULT", result["blockers"])

    def test_resultless_log_is_fatal(self):
        result = parse("Errors........... 0\nInformational text only\n")
        self.assertEqual(result["status"], "FAIL")
        self.assertIn("NO_PASS_RESULT", result["blockers"])

    def test_warning_only_log_is_not_a_pass(self):
        result = parse("Alpha -- WARNING\nErrors........... 0\n")
        self.assertEqual(result["status"], "FAIL")
        self.assertIn("NO_PASS_RESULT", result["blockers"])

    def test_failure_line_is_fatal(self):
        result = parse("Alpha -- PASS\nThing -- FAILURE\n")
        self.assertEqual(result["status"], "FAIL")
        self.assertIn("FAILURES_OBSERVED", result["blockers"])

    def test_nonzero_error_count_is_fatal(self):
        result = parse("Alpha -- PASS\nErrors........... 4\n")
        self.assertEqual(result["status"], "FAIL")
        self.assertIn("FAILURES_OBSERVED", result["blockers"])

    def test_words_in_descriptions_do_not_false_positive(self):
        result = parse(
            "This text discusses FAILURE handling but is not a result\n"
            "RealCase -- PASS\n"
            "Errors........... 0\n"
        )
        self.assertEqual(result["status"], "PASS")

    def test_decode_replacement_is_fatal(self):
        result = parse("Alpha -- PASS\nBad encoding �\nErrors........... 0\n")
        self.assertEqual(result["status"], "FAIL")
        self.assertIn("DECODE_REPLACEMENT_OBSERVED", result["blockers"])


if __name__ == "__main__":
    unittest.main()
