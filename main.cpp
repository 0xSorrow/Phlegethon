#include "HeaderParser.h"
#include <fstream>
#include <iostream>
#include <vector>
#include <string>
#include <algorithm>

struct HeuristicAlert {
    std::string category;
    std::string indicator;
    int severity_score; // 1 = Low, 2 = Medium, 3 = Critical
};

std::vector<uint8_t> ReadBinaryFile(const std::string& path) {
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        std::cerr << "[-] Error: Access denied or file path invalid: " << path << std::endl;
        return {};
    }
    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);
    std::vector<uint8_t> buffer(static_cast<size_t>(size));
    file.read(reinterpret_cast<char*>(buffer.data()), size);
    return buffer;
}

std::vector<HeuristicAlert> EvaluateImportSignatures(const std::vector<Phlegethon::Core::ImportedSymbol>& imports) {
    std::vector<HeuristicAlert> alerts;

    for (const auto& imp : imports) {
        std::string func = imp.symbol_name;
        // Normalize casing to prevent trivial signature bypasses
        std::transform(func.begin(), func.end(), func.begin(), ::tolower);

        if (func == "virtualallocex" || func == "writeprocessmemory" || func == "createremotethread") {
            alerts.push_back({"PROCESS_INJECTION", imp.symbol_name + " found in " + imp.module_name, 3});
        }
        else if (func == "ntsetcontextthread" || func == "ntresumethread" || func == "ntunmapviewofsection") {
            alerts.push_back({"PROCESS_HOLLOWING", imp.symbol_name + " found in " + imp.module_name, 3});
        }
        else if (func == "isdebuggerpresent" || func == "checkremotedebuggerpresent" || func == "ntqueryinformationprocess") {
            alerts.push_back({"ANTI_DEBUGGING", imp.symbol_name, 1});
        }
        else if (func == "ntdelayexecution" || func == "sleepex") {
            alerts.push_back({"SANDBOX_DELAY_EVASION", imp.symbol_name, 1});
        }
        else if (func == "cryptdecrypt" || func == "cryptencrypt" || func == "bcrypthashdata") {
            alerts.push_back({"CRYPTOGRAPHY_OR_RANSOMWARE", imp.symbol_name, 2});
        }
        else if (func == "regsetvalueexw" || func == "regsetvalueexa" || func == "createservicea") {
            alerts.push_back({"PERSISTENCE_MECHANISM", imp.symbol_name, 2});
        }
    }
    return alerts;
}

void RunAdvancedTriage(const std::string& path) {
    std::vector<uint8_t> fileBuffer = ReadBinaryFile(path);
    if (fileBuffer.empty()) return;

    auto result = Phlegethon::Core::ParseTargetBinary(fileBuffer);
    if (!result.integrity_validated) {
        std::cerr << "[-] Error: Target failed structural PE validation metrics." << std::endl;
        return;
    }

    // 1. Core Header Metrics
    std::cout << "[+] Entry Point: 0x" << std::hex << result.address_of_entry_point << std::dec << std::endl;
    std::cout << "[+] Image Base:  0x" << std::hex << result.image_base_address << std::dec << std::endl;
    
    // 2. Structural Anomaly Detections
    std::cout << "[*] Inspecting section layout mappings..." << std::endl;
    bool suspiciousSections = false;
    for (const auto& sec : result.structural_sections) {
        std::cout << "  -> Section: " << sec << std::endl;
        if (sec == ".upx0" || sec == ".upx1" || sec == ".vmp0" || sec == ".themida") {
            std::cout << "    [!] Warning: Known packer/protector signature detected via section header name." << std::endl;
            suspiciousSections = true;
        }
    }

    // 3. Heuristic Signature Rule Engine Processing
    std::cout << "[*] Running API sequence threat heuristics..." << std::endl;
    auto alerts = EvaluateImportSignatures(result.resolved_imports);
    
    int totalRiskScore = (suspiciousSections ? 15 : 0);
    int criticalAlertCount = 0;

    for (const auto& alert : alerts) {
        totalRiskScore += (alert.severity_score == 3) ? 10 : (alert.severity_score == 2) ? 5 : 2;
        if (alert.severity_score == 3) criticalAlertCount++;

        std::cout << "  [!] Alert [" << alert.category << "] -> " << alert.indicator 
                  << " (Severity: " << ((alert.severity_score == 3) ? "CRITICAL" : (alert.severity_score == 2) ? "MEDIUM" : "LOW") << ")" << std::endl;
    }

    // 4. Final Advanced Structural Evaluation Output
    std::cout << "=========================================================" << std::endl;
    std::cout << "[*] TRIAGE ANALYSIS :" << std::endl;
    std::cout << "    Total Imports Resolved: " << result.resolved_imports.size() << std::endl;
    std::cout << "    Total Suspicious Indicators Flagged: " << alerts.size() << std::endl;
    std::cout << "    Calculated Risk Vector Score: " << totalRiskScore << std::endl;
    
    if (totalRiskScore > 25 || criticalAlertCount > 0) {
        std::cout << "    [VERDICT] HIGHLY SUSPICIOUS: File exhibits malware behavioral traits." << std::endl;
    } else if (totalRiskScore > 5) {
        std::cout << "    [VERDICT] SUSPICIOUS: Requires deeper validation or sandboxing." << std::endl;
    } else {
        std::cout << "    [VERDICT] CLEAN: No immediate malicious anomalies mapped." << std::endl;
    }
    std::cout << "=========================================================" << std::endl;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: .\\CoreAnalyzer.exe <target_pe_file>" << std::endl;
        return 1;
    }
    RunAdvancedTriage(argv[1]);
    return 0;
}
