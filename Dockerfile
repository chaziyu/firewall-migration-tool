FROM node:24-bookworm-slim AS frontend

WORKDIR /build/src/frontend
COPY src/frontend/package.json src/frontend/package-lock.json ./
RUN npm ci
COPY src/frontend/ ./
RUN npm run build

FROM python:3.12-slim AS runtime

ENV HOME=/home/fwmigrate \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    FWMIGRATE_FRONTEND_DIST_DIR=/opt/fwmigrate/frontend-dist

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src/fwmigrate ./src/fwmigrate

RUN groupadd --system fwmigrate \
    && useradd --system --gid fwmigrate --home-dir /home/fwmigrate --create-home fwmigrate \
    && install -d --owner=fwmigrate --group=fwmigrate --mode=0700 /home/fwmigrate/.ssh \
    && python -m pip install --no-cache-dir '.[ai,collection,deployment]'

COPY --from=frontend /build/src/frontend/dist /opt/fwmigrate/frontend-dist

USER fwmigrate
EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5000/api/vendors', timeout=3)" || exit 1

# Keep one worker for transient per-target candidate locks and validated-session metadata.
# Supply FWMIGRATE_WORKSPACE_SIGNING_KEY through the runtime environment.
CMD ["gunicorn", "--bind=0.0.0.0:5000", "--workers=1", "--threads=4", "--timeout=120", "fwmigrate.web_live:create_app()"]
