# syntax=docker/dockerfile:1
# mcp-confused-deputy — one image, three processes.
#
#   :8080  the lab walkthrough (static)
#   :8765  broker, vuln mode
#   :8766  broker, clean mode
#
# Both brokers must bind 0.0.0.0. The default is 127.0.0.1, which is
# unreachable from outside the container and is the classic silent break.

FROM python:3.11-slim-bookworm

LABEL org.opencontainers.image.title="mcp-confused-deputy" \
      org.opencontainers.image.description="A deliberately vulnerable MCP broker: confused deputy privilege escalation over the tool surface" \
      org.opencontainers.image.source="https://github.com/r00tb3/mcp-confused-deputy" \
      org.opencontainers.image.licenses="MIT"

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    VULN_PORT=8765 \
    CLEAN_PORT=8766 \
    UI_PORT=8080

WORKDIR /lab

# stdlib only, so there is nothing to pip install. Copy the tree, drop the
# git metadata and the local state file, and run.
COPY --chown=10001:10001 . /lab
RUN rm -rf /lab/.git /lab/__pycache__ \
    && find /lab -name '__pycache__' -type d -prune -exec rm -rf {} + \
    && rm -f /lab/lab/state/service-state.json \
    && mkdir -p /lab/run/vuln /lab/run/clean \
    && chown -R 10001:10001 /lab

USER 10001:10001

EXPOSE 8080 8765 8766

# Both brokers answer /health. The UI is a static file server, so a HEAD on /
# is enough to prove it is up.
HEALTHCHECK --interval=15s --timeout=3s --start-period=5s --retries=3 \
    CMD python3 /lab/docker/healthcheck.py

ENTRYPOINT ["/lab/docker/entrypoint.sh"]
