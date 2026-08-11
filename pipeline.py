#!/usr/bin/env python3
import os
import sys
import json
from entropy import calculate_block_entropy

class PhlegethonPipeline:
    def __init__(self, config_path="config.json"):
        # Look for config in root directory if run from Analysis/ folder
        if not os.path.exists(config_path) and os.path.exists("../config.json"):
            config_path = "../config.json"
            
        with open(config_path, "r") as f:
            self.config = json.load(f)
            
        # Extract operational limits from config blocks
        heuristics = self.config["static_analysis_heuristics"]["entropy_triage"]
        output_cfg = self.config["telemetry_output"]
        
        self.suspicious_limit = heuristics["suspicious_threshold"]
        self.critical_limit = heuristics["critical_packed_threshold"]
        self.output_dir = output_cfg["target_destination_directory"]
        self.extensions = tuple(self.config["ingestion_pipeline"]["supported_extensions"])

    def process_file(self, file_path: str):
        if not file_path.endswith(self.extensions):
            print(f"[-] Skipping: Unsupported file extension -> {os.path.basename(file_path)}")
            return

        print(f"[*] Analyzing target asset: {os.path.basename(file_path)}")
        try:
            with open(file_path, "rb") as f:
                file_bytes = f.read()
        except Exception as error:
            print(f"[-] Error: Failed to open targeted asset: {error}")
            return

        file_size = len(file_bytes)
        entropy_score = calculate_block_entropy(file_bytes)

        # Apply triage heuristic decision framework
        if entropy_score >= self.critical_limit:
            verdict = "CRITICAL_PACKED_OR_OBFUSCATED"
        elif entropy_score >= self.suspicious_limit:
            verdict = "SUSPICIOUS_HIGH_ENTROPY"
        else:
            verdict = "CLEAN_OR_UNPACKED"

        # Build clean, normalized JSON report payload
        report_data = {
            "target_info": {
                "filename": os.path.basename(file_path),
                "size_bytes": file_size,
                "shannon_entropy": entropy_score
            },
            "analysis_results": {
                "triage_verdict": verdict,
                "flags": {
                    "exceeds_suspicious_threshold": entropy_score >= self.suspicious_limit,
                    "exceeds_critical_threshold": entropy_score >= self.critical_limit
                }
            }
        }

        # Export report file out to destination target
        os.makedirs(self.output_dir, exist_ok=True)
        report_name = f"triage_{os.path.basename(file_path)}.json"
        destination = os.path.join(self.output_dir, report_name)
        
        with open(destination, "w") as out:
            json.dump(report_data, out, indent=4)
        print(f"[+] Stored triage log: {destination}\n")

    def scan_directory(self, target_directory: str):
        if not os.path.isdir(target_directory):
            print(f"[-] Error: Target is not a valid directory: {target_directory}")
            return

        print(f"[*] Starting batch intake across target: {target_directory}")
        for root, _, files in os.walk(target_directory):
            for file in files:
                full_path = os.path.join(root, file)
                self.process_file(full_path)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python pipeline.py <path_to_target_file_or_directory>")
        sys.exit(1)

    input_target = sys.argv[1]
    engine = PhlegethonPipeline()

    if os.path.isdir(input_target):
        engine.scan_directory(input_target)
    else:
        engine.process_file(input_target)
