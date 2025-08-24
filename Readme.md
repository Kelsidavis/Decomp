# 🔎 Ghidra-LLM Reverse Engineering Pipeline

This project bundles **Ghidra (headless mode)**, a set of custom Python scripts, and a connected **LLM endpoint** (e.g. Qwen3, GPT-style models) into a single Docker workflow for semi-automated reverse engineering.

The pipeline takes a Windows PE binary (`.exe`), decompiles it, generates human-readable stubs, extracts embedded assets, and scaffolds a compilable project (`C` or `C++`) that you can iterate on.

---

## 📦 Features

* **Headless Ghidra analysis**
  Dumps functions, imports, and PE resources.

* **Function Hunt & Humanization**
  Analyzes functions, filters/dedupes, and calls an LLM to label them.
  Produces `functions.labeled.jsonl`, rewrites source tree with human-readable names, and writes a `report.md`.

* **LLM explanation**
  Calls your configured model endpoint to annotate functions with JSON labels, progress %, elapsed time, and ETA in logs.

* **Code scaffolding**
  Converts the report into compilable stubs (`.c` or `.cpp`).

* **Asset extraction**

  * PE resources (icons, bitmaps).
  * Magic-based carving from binary.
  * Embeds assets directly into C code for buildability.

* **Windows build generator**
  Creates `recovered_project_win/` with CMake files.
  Links system DLLs, generates dynamic wrappers for vendor DLLs, and builds with MinGW.

* **Enhanced logging**
  Both `run.sh` and `humanize.sh` now prefix logs with timestamps, show live progress %, elapsed time, and estimated time remaining. Logs are written to `work/logs/` and `work/run.<timestamp>.log`.

---

## 🚀 Usage

### 1. Build the image

```bash
docker build -t ghidra-llm:latest .
```

### 2. Place your binary

```
work/target.exe
```

### 3. Run the full pipeline

```bash
./run.sh --exe work/target.exe
```

This will:

* Launch the Docker container.
* Run headless Ghidra.
* Extract functions, imports, and resources.
* Call the LLM to label and humanize.
* Generate a compilable project under `work/recovered_project/`.

### 4. Humanize only (optional re-run)

```bash
./humanize.sh --topn 500 --min-size 16
```

---

## ⚙️ Environment Variables

* `BINARY_PATH` – input binary (`.exe`).
* `OUT_JSON` – path to dump functions JSON.
* `REPORT_MD` – path for human-readable LLM explanation.
* `CODE_LANG` – `c`, `cpp`, or `auto` (default).
* `HUMANIZE_MODE` – `off`, `suggest`, or `apply`.
* `BUILD_RECOVERED` – `1` to attempt a `make` build of the applied project.
* `LLM_ENDPOINT` – model API URL (defaults to localhost:8080).
* `LLM_MODEL` – model name (e.g. `Qwen3-14B-UD-Q5_K_XL.gguf`).
* `HUNT_TOPN` – number of functions to keep by size.
* `HUNT_LIMIT` – hard cap on number of functions.
* `HUNT_MIN_SIZE` – drop functions below N bytes.
* `HUNT_CAPA`, `HUNT_YARA` – enable/disable enrichment.
* `HUNT_LLM_CONCURRENCY` – number of concurrent LLM requests.
* `HUNT_LLM_MAX_TOKENS` – max tokens per function label (increase for more detail, at cost of speed).

---

## 📂 Output Layout

* `recovered_project/`

  * `include/` – headers (`recovered.h`, `resources.h`)
  * `src/` – function stubs + `resources_embedded.c`
  * `assets/` – extracted icons, bitmaps, carved files
  * `report.md` – annotated function descriptions

* `work/hunt/`

  * `functions.enriched.jsonl` – enriched with capa/yara.
  * `functions.labeled.jsonl` – LLM labels (names, tags, inputs/outputs).
  * `report.md` – human-readable explanations.

* `recovered_project_human/`
  Humanized project (if enabled).

* `recovered_project_win/`
  Windows build scaffold with CMake + vendor shims.

* `run.<timestamp>.log` and `work/logs/pipeline.<timestamp>.log`
  Full logs with timestamps, % complete, and ETA.

---

## 🛠 Building for Windows

```bash
cd work/recovered_project_win/build
cmake ..
make
```

---

## ⚠️ Notes

* Many stubs will be placeholders until you refine them.
* Assets may be incomplete if the binary didn’t contain resources.
* Vendor DLLs (FMOD, DivX, etc.) are stubbed dynamically; you’ll need the SDK for full functionality.
* Expect to iterate: the goal is a **compilable baseline** close to original source, not a 1:1 decompile.

---

## 🧡 Next Steps

* Replace vendor stubs with real SDK headers/libs.
* Use the LLM-generated docs (`report.md`) and `functions.labeled.jsonl` to re-implement function logic.
* Refactor and test: compile → run under Wine/Windows → fix.

