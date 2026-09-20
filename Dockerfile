FROM python:3.12-slim

WORKDIR /app

RUN pip install --no-cache-dir cryptography requests tzdata

COPY server.py ./
COPY static ./static

ENV PYTHONUNBUFFERED=1
ENV TZ=Asia/Shanghai

EXPOSE 8080
CMD ["python", "server.py"]
