# The same explicit Python base-image digest used by production CI is required.
ARG PYTHON_IMAGE
FROM ${PYTHON_IMAGE}

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 OMP_THREAD_LIMIT=1 OMP_NUM_THREADS=1

RUN apt-get update \
    && apt-get install --no-install-recommends -y poppler-utils tesseract-ocr tesseract-ocr-eng fonts-liberation2 \
    && rm -rf /var/lib/apt/lists/* \
    && install -d -m 0555 /opt/ai-dfir \
    && dpkg-query -W -f='${Package}\t${Version}\n' > /opt/ai-dfir/packages.txt \
    && if [ -f /usr/share/fonts/truetype/liberation2/LiberationSans-Regular.ttf ]; then \
         cp /usr/share/fonts/truetype/liberation2/LiberationSans-Regular.ttf /opt/ai-dfir/render-font.ttf; \
       else \
         cp /usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf /opt/ai-dfir/render-font.ttf; \
       fi

COPY deploy/render/worker.py /opt/ai-dfir/render_worker.py
RUN chmod 0444 /opt/ai-dfir/render_worker.py /opt/ai-dfir/packages.txt /opt/ai-dfir/render-font.ttf
LABEL org.ai-dfir.render-profile="pdf-raster-ocr-v1.7"
USER 65532:65532
WORKDIR /tmp
ENTRYPOINT ["python", "/opt/ai-dfir/render_worker.py"]
