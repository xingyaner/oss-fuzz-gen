# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
"""Unit tests for the deterministic pre-repair safety boundary."""

import datetime as dt
import tempfile
import unittest
from pathlib import Path

from experimental.build_fixer import pre_repair


class PreRepairSelectionTest(unittest.TestCase):

  def test_calendar_window_matches_requested_example(self):
    self.assertEqual(pre_repair.subtract_calendar_months(dt.date(2026, 9, 20)),
                     dt.date(2026, 6, 20))
    self.assertEqual(pre_repair.subtract_calendar_months(dt.date(2026, 5, 31)),
                     dt.date(2026, 2, 28))

  def test_continuous_error_keeps_earliest_and_success_keeps_boundaries(self):
    with tempfile.TemporaryDirectory() as temp_dir:
      root = Path(temp_dir)
      names = [
          '2026_6_20 success', '2026_6_21 success', '2026_6_22 error',
          '2026_6_23 error', '2026_6_24 success', '2026_6_25 success'
      ]
      logs = []
      for name in names:
        path = root / name
        path.touch()
        logs.append(pre_repair.parse_log_name(path))
      kept, collisions = pre_repair.select_boundary_logs(logs)
      self.assertEqual(collisions, [])
      self.assertEqual({path.name for path in kept}, {
          '2026_6_20 success', '2026_6_21 success', '2026_6_22 error',
          '2026_6_24 success', '2026_6_25 success'
      })

  def test_same_day_conflict_is_preserved(self):
    with tempfile.TemporaryDirectory() as temp_dir:
      root = Path(temp_dir)
      names = ['2026_6_20 error', '2026_6_20 success', '2026_6_21 error']
      logs = []
      for name in names:
        path = root / name
        path.touch()
        logs.append(pre_repair.parse_log_name(path))
      kept, collisions = pre_repair.select_boundary_logs(logs)
      self.assertEqual(collisions, ['2026-06-20'])
      self.assertEqual({path.name for path in kept}, set(names))

  def test_required_metadata_rejects_empty_values(self):
    entry = {field: 'set' for field in pre_repair.REQUIRED_METADATA}
    entry['engine'] = ''
    self.assertEqual(pre_repair._valid_entry(entry), ['engine'])

  def test_vertex_alias_matches_full_fixer_alias(self):
    self.assertEqual(pre_repair._vertex_model_name('vertex_ai_gemini-3-1-pro'),
                     'gemini-3.1-pro-preview')

  def test_commit_mapping_uses_latest_commit_strictly_before_error_date(self):
    mapping = [{
        'timestamp_utc': '2026-06-19T23:00:00+00:00',
        'sha': 'anchor'
    }, {
        'timestamp_utc': '2026-06-20T12:00:00+00:00',
        'sha': 'inside-window'
    }]
    self.assertEqual(
        pre_repair._checkout_for_date(mapping, dt.date(2026, 6, 20)), 'anchor')
    self.assertEqual(
        pre_repair._checkout_for_date(mapping, dt.date(2026, 6, 21)),
        'inside-window')


if __name__ == '__main__':
  unittest.main()
