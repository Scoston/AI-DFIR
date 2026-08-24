# Production build intentionally requires an explicitly pinned base image digest.
ARG PYTHON_IMAGE
FROM ${PYTHON_IMAGE}
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_DISABLE_PIP_VERSION_CHECK=1
RUN useradd --system --uid 10001 --home /nonexistent --shell /usr/sbin/nologin aidfir
WORKDIR /opt/ai-dfir
COPY requirements-enterprise.txt requirements-model.txt requirements.txt ./
RUN python -m pip install --no-cache-dir --upgrade pip && pip install --no-cache-dir -r requirements-enterprise.txt
COPY . .
RUN chown -R 10001:10001 /opt/ai-dfir && chmod -R go-w /opt/ai-dfir
USER 10001:10001
EXPOSE 8890
ENTRYPOINT ["python","enterprise_gateway_v15.py"]
