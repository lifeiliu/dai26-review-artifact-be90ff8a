ARG PYTHON_BASE=python:3.12-alpine@sha256:aa679aa4eed6eb56c1dc6ad3f1b98b7d2d788fd961596779d188fdedad97fb38
FROM ${PYTHON_BASE}

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN addgroup -g 24024 -S e-b24 \
    && adduser -u 24024 -S -D -h /home/anonymous -s /sbin/nologin -G e-b24 e-b24

WORKDIR /opt/e-b24
COPY pyproject.toml README.md ./
COPY src ./src
RUN python -m pip install --no-cache-dir .

RUN mkdir -p /var/lib/e-b24 /var/log/e-b24 \
    && chown -R e-b24:e-b24 /var/lib/e-b24 /var/log/e-b24

USER e-b24
ENTRYPOINT ["python"]
CMD ["-m", "revocation_propagation.e_b24_receiver", "--help"]
