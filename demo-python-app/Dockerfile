FROM python:3.12-slim
WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

COPY demo-python-app/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY sdk-python/ /sdk-python/
RUN pip install --no-cache-dir /sdk-python

COPY demo-python-app/server.py ./

EXPOSE 3002
ENV PORT=3002
CMD ["python", "server.py"]
