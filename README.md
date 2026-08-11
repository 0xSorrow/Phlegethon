# Phlegethon Static Analysis Framework

Phlegethon is a high-performance, decoupled static analysis and binary triage framework designed to streamline initial asset assessment for security operations centers (SOC), incident response teams, and threat intelligence pipelines. By isolating low-level data parsing from high-level orchestration, the platform delivers high-speed inspection of Windows Portable Executable (PE) structures without executing the untrusted binary.

## 1. System Architecture & Component Mapping

The framework is architected using a decoupled, multi-language paradigm to balance memory-safe execution speeds with rapid logical processing:

*   **Core Parser Subsystem (C++):** Executes low-level file I/O operations to map and validate physical binary schemas directly against defined structural alignments (`IMAGE_DOS_HEADER`, `IMAGE_NT_HEADERS`).
*   **Orchestration Engine (Python):** Manages asynchronous file workflows, implements mathematical algorithms, and handles data consolidation.
*   **Data Exchange Layer (JSON):** Serves as the universal serialization format, standardizing structural observations into schema-validated outputs compatible with SIEM, SOAR, and central threat databases.

## 2. Technical Specifications & Functional Vectors

### Structural Integrity Verification
*   Validates physical file magic signatures (`MZ` / `PE`) and verifies offset references.
*   Inspects section alignments, header distribution ratios, and base relocation tables.
*   Flags anomalies such as abnormal entry point configurations or unbacked executable sections.

### Mathematical Entropy Analysis
*   Implements block-by-block Shannon Entropy calculations across discrete file offsets.
*   Evaluates byte-distribution randomness scores (bounded from 0.0 to 8.0).
*   Establishes predictive baselines to distinguish uncompressed native code from encrypted shellcode arrays, heavily packed regions, or obfuscated assets.

### Automated Telemetry Ingestion
*   Translates native binary struct representations into structured JSON schema primitives.
*   Normalizes disparate technical metrics into uniform indicators of compromise (IoC).
*   Enables frictionless integrations with internal analytics platforms via machine-readable JSON dumps.

## 3. Development & Deployment Requirements

*   **Compiler Toolchain:** MSVC / GCC conforming to standard C++17 or higher.
*   **Runtime Environment:** Python 3.10+ (Standard deployment utilizes core mathematical packages with zero external dependencies).
*   **Target Architectures:** Windows / Linux (Cross-platform compatibility for static data analysis).

## 4. License & Operational Notice
This software is intended exclusively for authorized system monitoring, defensive security research, academic study, and administrative triage workflows.
