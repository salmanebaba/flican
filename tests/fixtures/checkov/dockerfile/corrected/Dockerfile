# Synthetic static checks fixture; the health command is not a production probe.
FROM python:3.12-slim
USER 10001:10001
HEALTHCHECK CMD ["python", "-c", "raise SystemExit(0)"]
CMD ["python", "-V"]
