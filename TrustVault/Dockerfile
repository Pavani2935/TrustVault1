# Container image for any Docker host (Railway, Fly.io, Koyeb, Azure Container Apps, a VM...).
FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 PORT=8000
WORKDIR /app

COPY requirements.txt .
RUN pip install --upgrade pip && pip install -r requirements.txt

COPY trustvault ./trustvault
COPY wsgi.py ./

RUN useradd --create-home --uid 10001 trustvault && chown -R trustvault /app
USER trustvault

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s CMD python -c "import urllib.request,os; urllib.request.urlopen('http://127.0.0.1:%s/healthz' % os.environ.get('PORT','8000'))"
CMD ["sh", "-c", "python -m trustvault serve --port ${PORT}"]
