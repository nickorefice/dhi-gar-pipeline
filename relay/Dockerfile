# Relay container for Cloud Run.
#
# python:3.13-alpine is used here only because this POC's org has no mirrored DHI
# python repo. A customer running this pipeline should build the relay FROM their own
# mirrored DHI python image -- the relay is the one internet-facing component in the
# whole system, and running it on an unhardened base while the pipeline exists to
# distribute hardened images would be an odd place to stop caring:
#
#   FROM us-central1-docker.pkg.dev/PROJECT/dhi-prod/dhi-python@sha256:...
#
# Pinned by digest, for the same reason everything else here is.
FROM python:3.13-alpine

# No dependencies: main.py is stdlib-only, so there is nothing to install, pin, or
# audit, and no supply chain beyond the base image.
WORKDIR /app
COPY main.py /app/main.py

# Cloud Run sends SIGTERM on shutdown; PID 1 under exec form receives it directly.
RUN adduser -D -u 10001 relay
USER 10001
EXPOSE 8080
ENTRYPOINT ["python3", "/app/main.py"]
