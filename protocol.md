# Phlegethon High-Performance Inter-Process Data Exchange Specification

## 👥 Development & Author
*   **0xSorrow** 
*   **0xSolitude** 
*   **0xBlaze** 

---

This document details the communication rules, string formatting protocols, and system pipeline interfaces used for moving data between the native C++ engine (`Analyzer/`) and the high-level Python orchestration layer (`Analysis/`).

## 1. Stream Interoperability Mode

To maintain maximum portability and keep execution completely isolated from common language interface bottlenecks, data exchange occurs entirely through standard I/O pipes. 

```text
  [ Target File Ingestion ]
             │
             ▼
   [ Analyzer Subsystem ] ──── (Stdout Pipe Stream: Minified JSON object) ────► [ Analysis Pipeline ]
    (C++ File Deserializer)                                                       (Python Engine / Loader)
```

## 2. Native Output Specification

The C++ executable parses structural metrics, creates a single-line minified JSON payload, and outputs it to `stdout`. The string output must adhere to the following formatting requirements:

*   **Minification Requirement:** The output cannot contain newline (`\n`) formatting breaks or indentation spacing. It must present as one contiguous, continuous data string.
*   **Numerical Standardizations:** Pointer fields and relative address bounds must be explicitly output as lowercase hexadecimal values prefixed with `0x`.
*   **Module Name Normalization:** Library dependencies and export function names must be converted completely to lowercase text arrays before printing.

### Verified Stdout JSON Schema Layout

```json
{"status_code":200,"payload":{"entry_point_rva":"0x00041a20","image_base_va":"0x140000000","subsystem":3,"sections":[{"name":".text","raw_size":4096,"virtual_size":4100,"characteristics":"0x60000020"}],"imports":[{"module":"kernel32.dll","function":"virtualallocex"}]}}
```

## 3. Python Component Error Trapping Lifecycle

The Python pipeline is required to scan the stream output for these explicit structural status declarations to protect the automation loop from parsing failures:

*   **`200` (SUCCESS_VALIDATION_MATCH):** The file was mapped completely, passed integrity verification loops, and holds actionable metadata targets.
*   **`400` (STRUCTURE_MALFORMED_EXCEPTION):** Target lacks valid PE structural signatures, or contains data corruption causing out-of-bounds mapping threats.
*   **`403` (OS_ACCESS_DENIED):** Target cannot be accessed by the framework due to missing runtime administrative privileges.
