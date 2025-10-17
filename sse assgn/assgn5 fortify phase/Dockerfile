# syntax=docker/dockerfile:1
FROM python:3.9-slim-buster


RUN apt-get update && apt-get install -y gcc build-essential


COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt


WORKDIR /workspace


COPY . .

# Build steps
RUN gcc main.c -static -o safe_main -lpthread  && \
    python3 crypt.py 0xFF && \
    strip --strip-all safe_main

# Copy the final binary to /output (must be mounted by host)
CMD cp /workspace/safe_main /output/safe_main
