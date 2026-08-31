#!/bin/bash
# Copyright 2024 Google LLC
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


## Usage:
##   bash report/upload_report.sh results_dir [gcs_dir]
##
##   results_dir is the local directory with the experiment results.
##   gcs_dir is the name of the directory for the report in gs://oss-fuzz-gcb-experiment-run-logs/Result-reports/.
##     Defaults to '$(whoami)-%YY-%MM-%DD'.
##   additional_args are passed through to report.web (e.g., --with-csv)

# TODO(dongge): Re-write this script in Python as it gets more complex.

RESULTS_DIR=$1
GCS_DIR=$2
BENCHMARK_SET=$3
MODEL=$4
# All remaining arguments are additional args for report.web
shift 4
REPORT_ADDITIONAL_ARGS="$@"
DATE=$(date '+%Y-%m-%d')

if [[ $RESULTS_DIR = '' ]]
then
  echo 'This script takes the results directory as the first argument'
  exit 1
fi

if [[ $GCS_DIR = '' ]]
then
  echo "This script needs to take gcloud Bucket directory as the second argument. Consider using $(whoami)-${DATE:?}."
  exit 1
fi

# The LLM used to generate and fix fuzz targets.
if [[ $MODEL = '' ]]
then
  echo "This script needs to take LLM as the third argument."
  exit 1
fi

IS_FIX_BUILD=false
if [[ $RESULTS_DIR == *results-fix-build* ]]; then
  IS_FIX_BUILD=true
fi

REPORT_RESULTS_DIR="${RESULTS_DIR}"
if [[ "$IS_FIX_BUILD" == true ]]; then
  REPORT_RESULTS_DIR="results-fix-build-standard/${MODEL}"
fi

# Keep the original delay for normal experiments. Fix-build reports are
# generated from a different result layout and can be published immediately.
if [[ "$IS_FIX_BUILD" == true ]]; then
  sleep 30
else
  sleep 300
fi

echo "Report results directory: ${RESULTS_DIR}"
echo "Report GCS directory: ${GCS_DIR}"
echo "Fix-build report mode: ${IS_FIX_BUILD}"
mkdir -p results-report

update_report() {
  echo "Inspecting result files before report generation."
  if [[ -d "${RESULTS_DIR}" ]]; then
    find "${RESULTS_DIR}" -maxdepth 5 -type f | sort | head -200
  else
    echo "Result directory does not exist: ${RESULTS_DIR}"
  fi

  # Do not leave files from an earlier report generation in the upload set.
  rm -rf results-report
  mkdir -p results-report

  if [[ "$IS_FIX_BUILD" == true ]]; then
    rm -rf "${REPORT_RESULTS_DIR}"
    mkdir -p "${REPORT_RESULTS_DIR}"
    echo "Adapting fix-build results for the native report: ${REPORT_RESULTS_DIR}"
    $PYTHON -m report.fix_build_adapter -r "${RESULTS_DIR:?}" -o "${REPORT_RESULTS_DIR:?}" || return 1
  fi

  # Generate the report
  echo "Generating report."
  if [[ $GCS_DIR != '' ]]; then
    CLOUD_BASE_URL="https://llm-exp.oss-fuzz.com/Result-reports/${GCS_DIR}"
    if [[ "$IS_FIX_BUILD" == true ]]; then
      $PYTHON -m report.web -r "${REPORT_RESULTS_DIR:?}" -b "${BENCHMARK_SET:?}" -m "$MODEL" -o results-report --base-url "$CLOUD_BASE_URL" --gcs-dir "${GCS_DIR}" $REPORT_ADDITIONAL_ARGS
    else
      $PYTHON -m report.web -r "${RESULTS_DIR:?}" -b "${BENCHMARK_SET:?}" -m "$MODEL" -o results-report --base-url "$CLOUD_BASE_URL" --gcs-dir "${GCS_DIR}" $REPORT_ADDITIONAL_ARGS
    fi
  else
    if [[ "$IS_FIX_BUILD" == true ]]; then
      $PYTHON -m report.web -r "${REPORT_RESULTS_DIR:?}" -b "${BENCHMARK_SET:?}" -m "$MODEL" -o results-report $REPORT_ADDITIONAL_ARGS
    else
      $PYTHON -m report.web -r "${RESULTS_DIR:?}" -b "${BENCHMARK_SET:?}" -m "$MODEL" -o results-report $REPORT_ADDITIONAL_ARGS
    fi
  fi

  report_status=$?
  if [[ $report_status -ne 0 ]]; then
    echo "Report generation failed with exit code ${report_status}."
    return $report_status
  fi
  if [[ ! -f results-report/index.html ]]; then
    echo "Report generation did not create results-report/index.html."
    return 1
  fi

  cd results-report || exit 1

  # Upload the report to GCS.
  echo "Uploading the report."
  BUCKET_PATH="gs://oss-fuzz-gcb-experiment-run-logs/Result-reports/${GCS_DIR:?}"
  # Upload HTMLs.
  gcloud storage cp --recursive --content-type="text/html" \
         --cache-control="public, max-age=3600" \
         . "$BUCKET_PATH" || return 1
  # Find all JSON files and upload them, removing the leading './'
  find . -name '*json' | while read -r file; do
    file_path="${file#./}"  # Remove the leading "./".
    gcloud storage cp --content-type="application/json" \
        --cache-control="public, max-age=3600" "$file" "$BUCKET_PATH/$file_path" || return 1
  done

  cd ..

  # Upload the raw results into the same GCS directory.
  echo "Uploading the raw results."
  gcloud storage cp --recursive "${RESULTS_DIR:?}" \
         "gs://oss-fuzz-gcb-experiment-run-logs/Result-reports/${GCS_DIR:?}" || return 1

  echo "See the published report at https://llm-exp.oss-fuzz.com/Result-reports/${GCS_DIR:?}/"

  # Upload training data.
  echo "Uploading training data."
  rm -rf 'training_data'
  gcloud storage rm --recursive "gs://oss-fuzz-gcb-experiment-run-logs/Result-reports/${GCS_DIR:?}/training_data" || true

  # $PYTHON -m data_prep.parse_training_data \
  #  --experiment-dir "${RESULTS_DIR:?}" --save-dir 'training_data'
  #$PYTHON -m data_prep.parse_training_data --group \
  #  --experiment-dir "${RESULTS_DIR:?}" --save-dir 'training_data'
  #$PYTHON -m data_prep.parse_training_data --coverage \
  #  --experiment-dir "${RESULTS_DIR:?}" --save-dir 'training_data'
  #$PYTHON -m data_prep.parse_training_data --coverage --group \
  #  --experiment-dir "${RESULTS_DIR:?}" --save-dir 'training_data'
  #gsutil -q cp -r 'training_data' \
  #  "gs://oss-fuzz-gcb-experiment-run-logs/Result-reports/${GCS_DIR:?}"
}

while [[ ! -f /experiment_ended ]]; do
  update_report
  update_status=$?
  if [[ $update_status -ne 0 ]]; then
    echo "Report update failed with exit code ${update_status}; retrying."
  fi
  echo "Experiment is running..."
  sleep 600
done

echo "Experiment finished."
update_report
echo "Final report uploaded."
