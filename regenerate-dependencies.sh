#!/bin/bash

set -exo pipefail

pip-compile --generate-hashes --output-file=requirements/prod.txt "${@}"
pip-compile --constraint=requirements/prod.txt --extra=uvloop --generate-hashes --output-file=requirements/uvloop.txt "${@}"
pip-compile --constraint=requirements/prod.txt --extra=dev --generate-hashes --allow-unsafe --output-file=requirements/dev.txt "${@}"
pip-compile --constraint=requirements/prod.txt --extra=aiofiles --generate-hashes --output-file=requirements/aiofiles.txt "${@}"
pip-compile --constraint=requirements/prod.txt --extra=prometheus --generate-hashes --output-file=requirements/prometheus.txt "${@}"
