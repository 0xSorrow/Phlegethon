# Phlegethon Framework Data Exchange Protocol

This document defines the formal communication contract, data serialization schemas, and interoperability standards used for exchanging data between the native C++ engine (`Analyzer/`) and the high-level Python pipeline (`Analysis/`).

## 1. Data Exchange Architecture

The framework relies on a decoupled, pipeline-driven architecture. To prevent language-specific memory management conflicts, component synchronization is maintained via structured data channels:

```text
  [ Target Binary ]
         │
         ▼
  [ Analyzer Engine ]  ──(Stdout Pipe / Structured JSON String)──► [ Python Pipeline ]
  (C++ Header Parser)                                              (Orchestration / Math)
                                                                            │
                                                                            ▼
                                                                   [ Unified Report ]
                                                                   (Schema-Valid JSON)
```

## 2. Low-Level Component Pipeline Signature

When the native C++ engine analyzes a binary, it prints a single-line, standardized JSON data object directly to the standard output (`stdout`) stream. This allows the Python pipeline to safely trap, decode, and use the telemetry without needing a shared memory map.

### Required Telemetry Schema Fields

```json
{
  "status_code": 200,
  "file_metadata": {
    "entry_point_rva": "0x00041A20",
    "image_base": "0x140000000",
    "subsystem": 3
  },
  "sections": [
    {
      "name": "string",
      "raw_size": 0,
      "virtual_size": 0,
      "characteristics": "0x60000020"
    }
  ],
  "imports": [
    {
      "library": "string",
      "function": "string"
    }
  ]
}
```

### Component Status Specification Codes
*   **`200` (SUCCESS_VALID_PE):** The binary was read successfully and matches standard Windows PE structural rules.
*   **`400` (MALFORMED_STRUCTURE):** The target file is corrupt, lacks valid magic byte signatures (`MZ`/`PE`), or triggers an out-of-bounds safety boundary exception.
*   **`403` (ACCESS_DENIED):** The platform runtime toolchain lacks the security privileges required to open or map the physical target disk asset.

## 3. Serialization Rules & Data Formatting

To guarantee fast data validation and parsing across different systems, all data strings passing through the Phlegethon framework must adhere to these structural rules:

*   **Memory Addresses:** Every pointer offset value, including the execution Entry Point and virtual Image Base address, must be passed as a hexadecimal string prefixed with a lowercase `0x`.
*   **Segment Character Constraints:** Section names extracted from the binary must be passed as raw ASCII character strings. Any trailing space allocation or non-printable character block must be trimmed off completely before serialization.
*   **Casing Rules:** To prevent casing mismatches from breaking automated threat rules, imported module names (DLLs) and specific API function strings must be converted completely to lowercase before being evaluated against signatures.
