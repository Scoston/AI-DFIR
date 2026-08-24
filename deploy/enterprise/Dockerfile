FROM python:3.12-slim
WORKDIR /opt/ai-dfir
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN useradd --system --uid 10001 ai-dfir && mkdir -p /var/lib/ai-dfir && chown -R ai-dfir:ai-dfir /var/lib/ai-dfir /opt/ai-dfir
USER ai-dfir
EXPOSE 8890 8891
CMD ["python","enterprise_api.py","--help"]
