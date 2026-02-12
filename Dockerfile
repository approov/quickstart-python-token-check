# syntax=docker/dockerfile:1
# Builds the quickstart backend container image with scripts/build.sh
# as the entrypoint used both locally and when deployed via Docker.
FROM python:3.12-slim

ENV APP_HOME=/workspace \
    RUN_MODE=container

WORKDIR /app

COPY . .

RUN pip install --no-cache-dir -r requirements.txt
# Provide APP_START_CMD via --env-file.
CMD ["bash", "scripts/build.sh"]
