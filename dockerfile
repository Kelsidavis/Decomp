# dockerfile — slim exporter-only image, entrypoint-driven (Java 21)
FROM eclipse-temurin:21-jdk-jammy

# ---- Ghidra version/asset ----
ARG GHIDRA_VERSION=11.4.1
ARG GHIDRA_DATE=20250731
ARG GHIDRA_ZIP=ghidra_${GHIDRA_VERSION}_PUBLIC_${GHIDRA_DATE}.zip
ARG GHIDRA_URL=https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/${GHIDRA_ZIP}

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
      curl ca-certificates unzip coreutils \
  && rm -rf /var/lib/apt/lists/*

# ---- Ghidra ----
RUN curl -fL "${GHIDRA_URL}" -o "/opt/${GHIDRA_ZIP}" \
 && test -s "/opt/${GHIDRA_ZIP}" \
 && unzip "/opt/${GHIDRA_ZIP}" -d /opt \
 && rm "/opt/${GHIDRA_ZIP}"

ENV GHIDRA_HOME=/opt/ghidra_${GHIDRA_VERSION}_PUBLIC
# Make sure Ghidra sees Java 21 without prompting
ENV JAVA_HOME=/opt/java/openjdk
ENV GHIDRA_JAVA_HOME=/opt/java/openjdk
ENV PATH="${GHIDRA_HOME}/support:${PATH}"
ENV PYTHONUNBUFFERED=1
ENV GHIDRA_MAXMEM=4G

WORKDIR /app
COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

# Entrypoint reads: BINARY_PATH, OUT_JSON, GHIDRA_SCRIPT(_DIR), GHIDRA_TIMEOUT, GHIDRA_PROJECT_*.
ENTRYPOINT ["/app/entrypoint.sh"]

