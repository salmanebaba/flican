# Intentionally vulnerable static scan fixture for Checkov.
FROM python:3.12-slim
WORKDIR /app
COPY app.py /app/app.py
EXPOSE 22
CMD ["python", "/app/app.py", "2 + 3"]
