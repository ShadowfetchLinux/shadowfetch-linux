"""Bookkeeping tests only; these are not mission or stress execution evidence."""
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "qa_4_0_0"))
import unittest
from mission_stress import coverage_summary


class CoverageTests(unittest.TestCase):
    def test_three_completed_intervals_with_gaps(self):
        result=coverage_summary([{'started':0,'finished':850},{'started':851,'finished':1700},{'started':1701,'finished':2600}],2700)
        self.assertEqual(result,{'coverage_seconds':2598.0,'completed_within_load_window':3,'tail_cycles':0})

    def test_tail_clipped_and_not_counted_within_window(self):
        result=coverage_summary([{'started':2600,'finished':2900}],2700)
        self.assertEqual(result,{'coverage_seconds':100.0,'completed_within_load_window':0,'tail_cycles':1})

    def test_no_success_means_no_coverage(self):
        self.assertEqual(coverage_summary([],2700)['coverage_seconds'],0)

    def test_overlap_rejected(self):
        with self.assertRaises(ValueError):
            coverage_summary([{'started':1,'finished':200},{'started':199,'finished':250}],2700)

    def test_exact_end_is_within_window(self):
        self.assertEqual(coverage_summary([{'started':2600,'finished':2700}],2700)['completed_within_load_window'],1)

    def test_reversed_interval_rejected(self):
        with self.assertRaises(ValueError):
            coverage_summary([{'started':20,'finished':10}],2700)


if __name__=='__main__':
    unittest.main()
