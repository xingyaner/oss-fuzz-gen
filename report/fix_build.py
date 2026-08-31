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
"""Generates a self-contained report for OSS-Fuzz project build repairs."""

import argparse
import html
import json
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

import yaml


def _read_text(path: Path) -> str:
  """Reads a text file without allowing one bad artifact to stop reporting."""
  try:
    return path.read_text(encoding='utf-8', errors='replace')
  except OSError as error:
    return f'Unable to read {path}: {error}'


def _read_remote_log(url: str) -> str:
  """Reads the original OSS-Fuzz log referenced by project metadata."""
  if not url.startswith(('http://', 'https://')):
    return ''
  try:
    with urllib.request.urlopen(url, timeout=20) as response:
      content = response.read(128 * 1024)
    return content.decode('utf-8', errors='replace')
  except (OSError, urllib.error.URLError):
    return ''


def _load_input(path: Path) -> dict[str, Any]:
  """Loads the project metadata written by the repair agent."""
  try:
    data = yaml.safe_load(_read_text(path)) or {}
  except yaml.YAMLError:
    return {}
  if isinstance(data, list):
    data = data[0] if data else {}
  return data if isinstance(data, dict) else {}


def _find_project_dirs(results_dir: Path) -> list[Path]:
  """Finds project result directories and ignores nested agent folders."""
  if not results_dir.is_dir():
    return []

  candidates: set[Path] = set()
  markers = {'input.yaml', 'result.txt', 'repair-trace.json'}
  for marker in markers:
    for artifact in results_dir.rglob(marker):
      # Agent artifacts can be nested below the project directory. Walk up
      # through known implementation folders before registering the project.
      project_dir = artifact.parent
      while project_dir.parent != results_dir and project_dir.name in {
          'external-agent', 'fixed-files', 'process_fixed', 'process_unfixed'
      }:
        project_dir = project_dir.parent
      if project_dir != results_dir:
        candidates.add(project_dir)
  return sorted(candidates)


def _first_file(project_dir: Path, name: str) -> Path | None:
  """Returns the project-level artifact, falling back to agent artifacts."""
  direct = project_dir / name
  if direct.is_file():
    return direct
  matches = sorted(project_dir.rglob(name))
  return matches[0] if matches else None


def _project_record(project_dir: Path) -> dict[str, Any]:
  """Collects metadata and repair artifacts for one project."""
  input_path = project_dir / 'input.yaml'
  metadata = _load_input(input_path) if input_path.is_file() else {}
  trace_path = _first_file(project_dir, 'repair-trace.json')
  result_path = _first_file(project_dir, 'result.txt')
  run_log_path = _first_file(project_dir, 'run.log')

  trace: dict[str, Any] = {}
  if trace_path:
    try:
      value = json.loads(_read_text(trace_path))
      trace = value if isinstance(value, dict) else {}
    except json.JSONDecodeError:
      trace = {}

  nodes = trace.get('nodes', [])
  nodes = nodes if isinstance(nodes, list) else []
  patch_files = sorted(path for path in project_dir.rglob('*')
                       if path.is_file() and path.suffix == '.patch')
  fixed_files = sorted(path for path in project_dir.rglob('*')
                       if path.is_file() and 'fixed-files' in path.parts and
                       path.suffix != '.patch')

  result_text = _read_text(result_path) if result_path else ''
  status = str(
      metadata.get('fix_result') or
      ('Success' if 'SUCCESS' in result_text.upper() else 'Unknown'))
  return {
      'project':
          metadata.get('project') or project_dir.name,
      'status':
          status,
      'metadata':
          metadata,
      'rounds':
          len(nodes),
      'trace':
          trace,
      'result_text':
          result_text,
      'run_log':
          _read_text(run_log_path) if run_log_path else '',
      'original_build_log':
          _read_remote_log(str(metadata.get('fuzzing_build_error_log', ''))),
      'patches': [(str(path.relative_to(project_dir)), _read_text(path))
                  for path in patch_files],
      'fixed_files': [(str(path.relative_to(project_dir)), _read_text(path))
                      for path in fixed_files],
      'source_dir':
          str(project_dir),
  }


def _pre(value: str) -> str:
  """Escapes text for a report preformatted block."""
  return html.escape(value or '(none)')


def _section(title: str, content: str, open_by_default: bool = False) -> str:
  """Returns a collapsible report section."""
  opened = ' open' if open_by_default else ''
  return (f'<details{opened}><summary>{html.escape(title)}</summary>'
          f'<pre>{_pre(content)}</pre></details>')


def _project_html(record: dict[str, Any]) -> str:
  """Renders the details for one repaired project."""
  metadata = record['metadata']
  source_log = metadata.get('fuzzing_build_error_log', '')
  source_link = (f'<a href="{html.escape(source_log)}" target="_blank">'
                 'Original build log</a>' if source_log else 'Unavailable')
  sections = [_section('Repair result', record['result_text'], True)]
  sections.append(
      _section('Original OSS-Fuzz build log', record['original_build_log']))
  sections.append(
      _section('Repair trace (JSON)', json.dumps(record['trace'], indent=2)))
  sections.append(_section('Agent run log', record['run_log']))
  for name, content in record['patches']:
    sections.append(_section(f'Patch: {name}', content, True))
  for name, content in record['fixed_files']:
    sections.append(_section(f'Fixed file: {name}', content))
  details = ''.join(sections)
  return (
      f'<article><h2>{html.escape(record["project"])}: '
      f'<span class="status">{html.escape(record["status"])}</span></h2>'
      '<dl>'
      f'<dt>Repair rounds</dt><dd>{record["rounds"]}</dd>'
      f'<dt>Original build failure</dt><dd>{source_link}</dd>'
      f'<dt>Project revision</dt><dd><code>{_pre(str(metadata.get("software_sha", "")))}</code></dd>'
      f'<dt>OSS-Fuzz revision</dt><dd><code>{_pre(str(metadata.get("oss-fuzz_sha", "")))}</code></dd>'
      '</dl>' + details + '</article>')


def generate_report(results_dir: str, output_dir: str, model: str = '') -> None:
  """Generates index.html and index.json for a fix-build experiment."""
  root = Path(results_dir)
  records = [_project_record(path) for path in _find_project_dirs(root)]
  successful = sum(
      record['status'].lower() in ('success', 'fixed') for record in records)
  summary = {
      'total_projects': len(records),
      'successful_projects': successful,
      'projects': records,
  }
  output = Path(output_dir)
  output.mkdir(parents=True, exist_ok=True)
  (output / 'index.json').write_text(json.dumps(summary, indent=2),
                                     encoding='utf-8')
  cards = ''.join(_project_html(record) for record in records)
  if not records:
    cards = '<p>No fix-build results were found.</p>'
  document = f'''<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>OSS-Fuzz Build Repair Report</title>
<style>
body {{ font: 16px system-ui, sans-serif; margin: 2rem auto; max-width: 1100px; color: #202124; }}
article {{ border: 1px solid #dadce0; border-radius: 8px; margin: 1.5rem 0; padding: 1rem 1.25rem; }}
summary {{ cursor: pointer; font-weight: 600; margin: .75rem 0; }}
pre {{ background: #f8f9fa; border: 1px solid #e8eaed; overflow: auto; padding: 1rem; white-space: pre-wrap; }}
dl {{ display: grid; grid-template-columns: 180px 1fr; gap: .4rem 1rem; }} dt {{ font-weight: 600; }}
.status {{ color: #137333; font-size: .8em; }} code {{ overflow-wrap: anywhere; }}
</style></head><body>
<h1>OSS-Fuzz Build Repair Report</h1>
<p>Model: {_pre(model or 'unknown')} | Projects: {len(records)} | Successful: {successful}</p>{cards}
</body></html>'''
  (output / 'index.html').write_text(document, encoding='utf-8')


def main() -> None:
  """Parses command-line arguments and generates the report."""
  parser = argparse.ArgumentParser()
  parser.add_argument('-r', '--results-dir', required=True)
  parser.add_argument('-o', '--output-dir', default='results-report')
  parser.add_argument('-m', '--model', default='')
  args = parser.parse_args()
  generate_report(args.results_dir, args.output_dir, args.model)


if __name__ == '__main__':
  main()
