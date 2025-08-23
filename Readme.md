# 🔎 Ghidra-LLM Reverse Engineering Pipeline

This project bundles **Ghidra (headless mode)**, a set of custom Python scripts, and a connected **LLM endpoint** (e.g. Qwen3, GPT-style models) into a single Docker workflow for semi-automated reverse engineering.

The pipeline takes a Windows PE binary (`.exe`), decompiles it, generates human-readable stubs, extracts embedded assets, and scaffolds a compilable project (`C` or `C++`) that you can iterate on.

---

## 📦 Features

* **Headless Ghidra analysis**
  Dumps functions, imports, and PE resources.

* **LLM explanation**
  Calls your configured model endpoint to annotate functions into `report.md`.

* **Code scaffolding**
  Converts the report into compilable stubs (`.c` or `.cpp`).

* **Asset extraction**

  * PE resources (icons, bitmaps).
  * Magic-based carving from binary.
  * Embeds assets directly into C code for buildability.

* **Humanization**
  Optionally renames functions and buckets files into modules.

* **Windows build generator**
  Creates `recovered_project_win/` with CMake files.
  Links system DLLs, generates dynamic wrappers for vendor DLLs, and builds with MinGW.

---

## 🚀 Usage

### 1. Build the image

```bash
docker build -t ghidra-llm:latest .
```

### 2. Prepare your binary

Place your target binary into the `work/` directory:

```
work/target.exe
```

### 3. Run

```bash
docker run --rm -it \
  --add-host=host.docker.internal:host-gateway \
  -v $PWD/work:/work \
  -e BINARY_PATH=/work/target.exe \
  -e OUT_JSON=/work/target_out.json \
  -e REPORT_MD=/work/target_report.md \
  -e LLM_ENDPOINT="http://host.docker.internal:8080/v1/chat/completions" \
  -e LLM_MODEL="qwen3-14b-q5" \
  ghidra-llm:latest
```

---

## ⚙️ Environment Variables

* `BINARY_PATH` – input binary (`.exe`).
* `OUT_JSON` – path to dump functions JSON.
* `REPORT_MD` – path for human-readable LLM explanation.
* `CODE_LANG` – `c`, `cpp`, or `auto` (default).
  Auto-detects based on mangled symbols / STL use.
* `HUMANIZE_MODE` – `off`, `suggest`, or `apply`.
  Controls function renaming/module organization.
* `BUILD_RECOVERED` – `1` to attempt a `make` build of the applied project.
* `LLM_ENDPOINT` – model API URL (defaults to localhost:8080).
* `LLM_MODEL` – model name (e.g. `qwen3-14b-q5`).

---

## 📂 Output Layout

After a successful run you will have:

* `recovered_project/`

  * `include/` – headers (`recovered.h`, `resources.h`)
  * `src/` – function stubs + `resources_embedded.c`
  * `assets/` – extracted icons, bitmaps, carved files
  * `report.md` – annotated function descriptions

* `recovered_project_human_applied/`
  Humanized project (if enabled).

* `imports.json`
  DLL imports and functions.

* `recovered_project_win/`
  Windows build scaffold with CMake + vendor shims.

* `run.<timestamp>.log`
  Full log of the run.

---

## 🛠 Building for Windows

Inside the container, CMake+MinGW is included.
A Windows project is generated automatically:

```bash
cd work/recovered_project_win/build
file recovered.exe   # should be PE32+
```

You can also cross-compile on the host with MinGW.

---

## ⚠️ Notes

* Many stubs will be placeholders until you refine them.
* Assets may be incomplete if the binary didn’t contain resources.
* Vendor DLLs (FMOD, DivX, etc.) are stubbed dynamically; you’ll need the SDK for full functionality.
* Expect to iterate: the goal is a **compilable baseline** close to original source, not a 1:1 decompile.

---

## 🤍 Next Steps

* Replace vendor stubs with real SDK headers/libs.
* Use the LLM-generated docs (`report.md`) to re-implement function logic.
* Refactor and test: compile → run under Wine/Windows → fix.

---

## 📜 License

This project is a scaffold for reverse engineering research and educational purposes.
Please ensure you have the legal right to analyze any binaries you run through it.

