FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    CANARY_DATA=/data

WORKDIR /app
COPY server.py /app/server.py

RUN mkdir -p /data

EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/',timeout=2).status==200 else 1)"

CMD ["python", "/app/server.py", "--host", "0.0.0.0", "--port", "8080"]
