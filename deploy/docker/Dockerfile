FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN useradd --create-home --uid 10001 aidfir
WORKDIR /opt/ai-dfir
COPY requirements.txt ./
RUN python -m pip install --no-cache-dir --upgrade pip && pip install --no-cache-dir -r requirements.txt
COPY . .
RUN chown -R aidfir:aidfir /opt/ai-dfir
USER aidfir
EXPOSE 8877
ENTRYPOINT ["python", "analyst_dashboard.py"]
CMD ["--case-root", "/cases", "--host", "0.0.0.0", "--port", "8877"]
