# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Adapts fix-build results to the native OSS-Fuzz-Gen report layout."""

import argparse
import json
import shutil
from pathlib import Path
from typing import Any

import yaml

from report.fix_build import _find_project_dirs, _project_record


def _write_yaml(path: Path, data: dict[str, Any]) -> None:
  path.write_text(yaml.safe_dump(data, sort_keys=False), encoding='utf-8')


def _result(record: dict[str, Any]) -> dict[str, Any]:
  """Creates the native evaluator result for one repair project."""
  successful = record['status'].lower() in ('success', 'fixed')
  return {
      'finished': True,
      'compiles': successful,
      'crashes': False,
      'coverage': 0.0,
      'line_coverage_diff': 0.0,
      'compile_error': record['result_text'],
      'compile_log': record['run_log'],
  }


def adapt_results(results_dir: str, output_dir: str) -> int:
  """Writes a standard ``output-*`` tree and returns project count."""
  source = Path(results_dir)
  output = Path(output_dir)
  output.mkdir(parents=True, exist_ok=True)
  records = [_project_record(path) for path in _find_project_dirs(source)]

  source_report = source / 'report.json'
  if source_report.is_file():
    shutil.copyfile(source_report, output / 'report.json')
  else:
    (output / 'report.json').write_text('{}', encoding='utf-8')

  for record in records:
    project = str(record['project'])
    benchmark_id = f'output-{project}-build'
    benchmark_dir = output / benchmark_id
    status_dir = benchmark_dir / 'status' / '01'
    run_logs_dir = benchmark_dir / 'logs' / 'run'
    repair_dir = benchmark_dir / 'repair'
    status_dir.mkdir(parents=True, exist_ok=True)
    run_logs_dir.mkdir(parents=True, exist_ok=True)
    repair_dir.mkdir(parents=True, exist_ok=True)

    metadata = record['metadata'].copy()
    metadata.setdefault('project', project)
    metadata['functions'] = []
    _write_yaml(benchmark_dir / 'benchmark.yaml', metadata)
    (benchmark_dir / 'fuzz_targets').mkdir(exist_ok=True)
    (benchmark_dir / 'fuzz_targets' / '01.fuzz_target').write_text(
        f'// Fix-build validation target for {project}.\n', encoding='utf-8')
    (status_dir / 'result.json').write_text(json.dumps(_result(record),
                                                       indent=2),
                                            encoding='utf-8')
    (status_dir / 'log.txt').write_text(record['run_log'], encoding='utf-8')
    (run_logs_dir / '01.log').write_text(record['run_log'], encoding='utf-8')
    (repair_dir / 'result.txt').write_text(record['result_text'],
                                           encoding='utf-8')
    (repair_dir / 'repair-trace.json').write_text(json.dumps(record['trace'],
                                                             indent=2),
                                                  encoding='utf-8')

  return len(records)


def main() -> None:
  parser = argparse.ArgumentParser()
  parser.add_argument('-r', '--results-dir', required=True)
  parser.add_argument('-o', '--output-dir', required=True)
  args = parser.parse_args()
  adapt_results(args.results_dir, args.output_dir)


if __name__ == '__main__':
  main()
