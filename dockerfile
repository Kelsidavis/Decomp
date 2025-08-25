# Dockerfile — Ghidra + helpers for headless export
FROM eclipse-temurin:21-jdk-jammy

# ---- Ghidra version/asset ----
ARG GHIDRA_VERSION=11.4.1
ARG GHIDRA_DATE=20250731
ARG GHIDRA_ZIP=ghidra_${GHIDRA_VERSION}_PUBLIC_${GHIDRA_DATE}.zip
ARG GHIDRA_URL=https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/${GHIDRA_ZIP}

# ---- Base dependencies ----
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    curl ca-certificates unzip git \
    python3 python3-pip python3-venv \
    build-essential make cmake pkg-config \
    mingw-w64 \
    p7zip-full upx-ucl \
    gawk \
    && rm -rf /var/lib/apt/lists/*

# ---- Python deps usable by helper scripts ----
RUN python3 -m pip install --no-cache-dir \
      requests PyYAML tqdm rich \
      yara-python flare-floss pycparser pefile capa

# ---- Ghidra ----
RUN curl -fL "${GHIDRA_URL}" -o "/opt/${GHIDRA_ZIP}" && \
    test -s "/opt/${GHIDRA_ZIP}" && \
    unzip "/opt/${GHIDRA_ZIP}" -d /opt && \
    rm "/opt/${GHIDRA_ZIP}"

ENV GHIDRA_HOME=/opt/ghidra_${GHIDRA_VERSION}_PUBLIC
ENV PATH="${GHIDRA_HOME}/support:${PATH}"

# ---- Script staging ----
# Expect these to be present in build context (repo)
RUN mkdir -p /app/ghidra_scripts
COPY tools/ghidra_scripts/simple_export.py /app/ghidra_scripts/simple_export.py

# Helpful defaults; overridable at run time
ENV GHIDRA_SCRIPT=simple_export.py
ENV PYTHONUNBUFFERED=1

WORKDIR /app
CMD ["/bin/bash", "-lc", "echo 'Ghidra image ready. Use analyzeHeadless with -scriptPath /app/ghidra_scripts'"]

