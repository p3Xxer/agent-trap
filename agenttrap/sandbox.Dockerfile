# The safe room the bait agent works in. Built once, with internet; containers then run on an
# internal network with no route out.
FROM python:3.11-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends curl wget git ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# Common dependencies baked in, since pip can't reach PyPI at scan time.
RUN pip install --no-cache-dir pytest setuptools wheel requests black

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 PYTHONDONTWRITEBYTECODE=1
WORKDIR /work
