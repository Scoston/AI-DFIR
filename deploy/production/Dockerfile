# Production build intentionally requires an explicitly pinned base image digest.
ARG PYTHON_IMAGE
FROM ${PYTHON_IMAGE}

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN useradd --system --uid 10001 --home /nonexistent --shell /usr/sbin/nologin aidfir \
    && install -d -o 10001 -g 10001 /opt/ai-dfir

WORKDIR /opt/ai-dfir

# Production gateway dependencies are isolated from optional model/GPU runtimes.
# The lock file pins both package versions and artifact SHA-256 hashes.
COPY requirements-gateway.txt requirements-gateway.lock ./
RUN python -m pip install \
    --no-cache-dir \
    --require-hashes \
    -r requirements-gateway.lock

COPY --chown=10001:10001 . .

# CI rejects any production path that is group- or other-writable.
USER 10001:10001

EXPOSE 8890

ENTRYPOINT ["python","enterprise_gateway_v15.py"]