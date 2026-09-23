import unittest
from tools.sct_summary import parse

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
        result=parse("This text discusses FAILURE handling but is not a result\nErrors........... 0\n")
        self.assertEqual(result["status"],"PASS")
