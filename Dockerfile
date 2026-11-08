# Lab Linux terisolasi untuk seluruh simulasi (data sintetis saja).
FROM python:3.12-slim-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap wpasupplicant eapoltest hostapd openssl e2fsprogs procps iproute2 \
    && pip install --no-cache-dir cryptography==43.0.3 \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /lab
