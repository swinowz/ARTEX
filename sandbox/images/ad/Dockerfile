# Minimal AD discovery image for authorized lab validation.
FROM python:3.12-slim@sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1
RUN apt-get update && apt-get install -y --no-install-recommends ldap-utils dnsutils ca-certificates && rm -rf /var/lib/apt/lists/*
RUN mkdir -p /work && chmod 0777 /work
WORKDIR /work
