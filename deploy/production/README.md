# Production container

The production Dockerfile has **no default base image**. Supply a digest-pinned base:

```bash
docker build \
  --build-arg PYTHON_IMAGE='python:3.12-slim@sha256:<approved-digest>' \
  -f deploy/production/Dockerfile \
  -t ghcr.io/ORG/ai-dfir@<digest> .
```

Do not replace the digest with `latest`. Production admission policy should require immutable image digests and Sigstore/SLSA provenance.
