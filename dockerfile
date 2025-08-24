FROM eclipse-temurin:21-jdk-jammy

# ---- Ghidra version/asset ----
ARG GHIDRA_VERSION=11.4.1
ARG GHIDRA_DATE=20250731
ARG GHIDRA_ZIP=ghidra_${GHIDRA_VERSION}_PUBLIC_${GHIDRA_DATE}.zip
ARG GHIDRA_URL=https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/${GHIDRA_ZIP}

# ---- Base + build deps ----
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    curl ca-certificates unzip git \
    python3 python3-pip python3-venv python3-yaml \
    build-essential make cmake pkg-config \
    mingw-w64 \
    binutils \
    yara libyara-dev \
    libzip-dev \
 && rm -rf /var/lib/apt/lists/*

# ---- Python packages ----
RUN python3 -m pip install --no-cache-dir requests capa yara-python

# ---- Build & install radare2 from source (latest) ----
# Installs into /usr/local by default via sys/install.sh
RUN git clone --depth=1 https://github.com/radareorg/radare2 /tmp/radare2 \
 && cd /tmp/radare2 \
 && sys/install.sh \
 && cd / && rm -rf /tmp/radare2

# ---- Ghidra ----
RUN curl -fL "${GHIDRA_URL}" -o "/opt/${GHIDRA_ZIP}" \
 && test -s "/opt/${GHIDRA_ZIP}" \
 && unzip "/opt/${GHIDRA_ZIP}" -d /opt \
 && rm "/opt/${GHIDRA_ZIP}"

ENV GHIDRA_HOME=/opt/ghidra_${GHIDRA_VERSION}_PUBLIC
ENV PATH=${GHIDRA_HOME}/support:/usr/local/bin:$PATH
ENV GHIDRA_JAVA_HOME=${JAVA_HOME}
ENV PYTHONUNBUFFERED=1
ENV GHIDRA_MAXMEM=4G
ENV JAVA_TOOL_OPTIONS="-XX:ActiveProcessorCount=24 -XX:ParallelGCThreads=12 -XX:CICompilerCount=6"

# ---- Non-root workspace ----
RUN useradd -ms /bin/bash app
WORKDIR /app

# ---- Ensure script dir ----
RUN mkdir -p /app/ghidra_scripts

# ---- Scripts used by entrypoint ----
COPY --chown=app:app ghidra_scripts/dump_functions.py     /app/ghidra_scripts/dump_functions.py
COPY --chown=app:app ghidra_scripts/dump_pe_resources.py  /app/ghidra_scripts/dump_pe_resources.py
COPY --chown=app:app ghidra_scripts/dump_imports.py       /app/ghidra_scripts/dump_imports.py
COPY --chown=app:app explain_with_llm.py                  /app/explain_with_llm.py
COPY --chown=app:app report_to_code.py                    /app/report_to_code.py
COPY --chown=app:app carve_assets.py                      /app/carve_assets.py
COPY --chown=app:app fix_pe_resources.py                  /app/fix_pe_resources.py
COPY --chown=app:app embed_assets.py                      /app/embed_assets.py
COPY --chown=app:app humanize_project.py                  /app/humanize_project.py
COPY --chown=app:app generate_windows_build.py            /app/generate_windows_build.py
COPY --chown=app:app entrypoint.sh                        /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

# ---- Defaults ----
USER app
ENV LLM_ENDPOINT=http://127.0.0.1:8080/v1/chat/completions
ENV LLM_MODEL=qwen3coder30b
ENV MAX_FUNC_TOKENS=8000
ENV GHIDRA_PROJECT_DIR=/tmp/ghidra_proj
ENV GHIDRA_PROJECT_NAME=autoproj
ENV BINARY_PATH=/work/target_binary
ENV OUT_JSON=/work/out.json
ENV REPORT_MD=/work/report.md
ENV THREAD_COUNT=24

ENTRYPOINT ["/app/entrypoint.sh"]

