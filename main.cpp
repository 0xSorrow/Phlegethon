#include "HeaderParser.h"
#include <fstream>
#include <iostream>
#include <vector>
#include <string>
#include <algorithm>

struct ThreatSignature {
    std::string api_name;
    std::string category;
    int weight; // 1 = Low, 2 = Medium, 3 = Critical
};

// Expanded list of critical APIs often targeted for inspection
const std::vector<ThreatSignature> API_WATCHLIST = {
    {"virtualallocex", "PROCESS_INJECTION", 3},
    {"writeprocessmemory", "PROCESS_INJECTION", 3},
    {"createremotethread", "PROCESS_INJECTION", 3},
    {"ntsetcontextthread", "PROCESS_HOLLOWING", 3},
    {"ntresumethread", "PROCESS_HOLLOWING", 3},
    {"ntunmapviewofsection", "PROCESS_HOLLOWING", 3},
    {"queueuserapc", "APC_INJECTION", 3},
    {"isdebuggerpresent", "ANTI_DEBUGGING", 1},
    {"checkremotedebuggerpresent", "ANTI_DEBUGGING", 1},
    {"ntqueryinformationprocess", "ANTI_DEBUGGING", 2},
    {"ntdelayexecution", "SANDBOX_DELAY", 1},
    {"sleepex", "SANDBOX_DELAY", 1},
    {"cryptdecrypt", "CRYPTOGRAPHY", 2},
    {"cryptencrypt", "CRYPTOGRAPHY", 2},
    {"bcrypthashdata", "CRYPTOGRAPHY", 1},
    {"regsetvalueexw", "PERSISTENCE", 2},
    {"regsetvalueexa", "PERSISTENCE", 2},
    {"createservicea", "PERSISTENCE", 3},
    {"urldownloadtofilea", "NETWORK_INGESTION", 3},
    {"internetopenw", "NETWORK_INGESTION", 2},
    {"winhttprequest", "NETWORK_INGESTION", 2}
};

std::vector<uint8_t> MapBinaryBuffer(const std::string& target_path) {
    std::ifstream stream(target_path, std::ios::binary | std::ios::ate);
    if (!stream.is_open()) {
        std::cerr << "[-] Error: Failed to open targeted file path: " << target_path << std::endl;
        return {};
    }

    std::streamsize physical_size = stream.tellg();
    stream.seekg(0, std::ios::beg);

    std::vector<uint8_t> allocation_buffer(static_cast<size_t>(physical_size));
    if (!stream.read(reinterpret_cast<char*>(allocation_buffer.data()), physical_size)) {
        std::cerr << "[-] Error: Failed reading stream into continuous memory block." << std::endl;
        return {};
    }

    return allocation_buffer;
}

void EvaluateImportSignatures(const std::vector<Phlegethon::Core::ImportedSymbol>& resolved_imports, int& cumulative_score, int& flag_count) {
    std::cout << "[*] Running API mutation and sequence threat parsing loops..." << std::endl;
    
    for (const auto& found_import : resolved_imports) {
        std::string normalized_import = found_import.symbol_name;
        std::transform(normalized_import.begin(), normalized_import.end(), normalized_import.begin(), ::tolower);

        for (const auto& watch_target : API_WATCHLIST) {
            if (normalized_import == watch_target.api_name) {
                flag_count++;
                cumulative_score += (watch_target.weight == 3) ? 12 : (watch_target.weight == 2) ? 6 : 2;
                
                std::string severity = (watch_target.weight == 3) ? "CRITICAL" : (watch_target.weight == 2) ? "MEDIUM" : "LOW";
                std::cout << "  [!] MATCH: Symbol -> " << found_import.symbol_name 
                          << " [" << watch_target.category << "] | Severity: " << severity << std::endl;
            }
        }
    }
}

void ProcessTargetAsset(const std::string& binary_path) {
    std::vector<uint8_t> raw_buffer = MapBinaryBuffer(binary_path);
    if (raw_buffer.empty()) return;

    auto evaluation = Phlegethon::Core::ParseTargetBinary(raw_buffer);
    if (!evaluation.integrity_validated) {
        std::cerr << "[-] Error: Core validation failed. Executable format signatures are invalid or corrupted." << std::endl;
        return;
    }

    std::cout << "[+] Architectural Alignment Verified." << std::endl;
    std::cout << "  |-- Entry Point RVA:  0x" << std::hex << evaluation.address_of_entry_point << std::dec << std::endl;
    std::cout << "  |-- Target Image Base: 0x" << std::hex << evaluation.image_base_address << std::dec << std::endl;
    std::cout << "  |-- Target Subsystem: " << evaluation.subsystem_type << std::endl;

    std::cout << "[*] Validating physical segment names..." << std::endl;
    int structural_risk_weight = 0;
    for (const auto& current_section : evaluation.structural_sections) {
        std::cout << "  -> Directory Section: " << current_section << std::endl;
        
        std::string continuous_name = current_section;
        std::transform(continuous_name.begin(), continuous_name.end(), continuous_name.begin(), ::tolower);
        
        if (continuous_name.find("upx") != std::string::npos || 
            continuous_name.find("vmp") != std::string::npos || 
            continuous_name.find("themida") != std::string::npos ||
            continuous_name.find(".aspack") != std::string::npos) {
            std::cout << "    [!] High Risk: Packing layer signature matched: " << current_section << std::endl;
            structural_risk_weight += 20;
        }
    }

    int heuristic_score = structural_risk_weight;
    int triggered_signatures = 0;

    EvaluateImportSignatures(evaluation.resolved_imports, heuristic_score, triggered_signatures);

    std::cout << "\n=========================================================" << std::endl;
    std::cout << "PHLEGETHON STATIC ANALYSIS MATRIX VERDICT" << std::endl;
    std::cout << "=========================================================" << std::endl;
    std::cout << "  Resolved Import Elements : " << evaluation.resolved_imports.size() << std::endl;
    std::cout << "  Triggered Rules Matches  : " << triggered_signatures << std::endl;
    std::cout << "  Calculated Risk Matrix Score  : " << heuristic_score << std::endl;
    std::cout << "---------------------------------------------------------" << std::endl;

    if (heuristic_score >= 35) {
        std::cout << "  [VERDICT] MALICIOUS_ANOMALIES_DETECTED (High structural risk score)" << std::endl;
    } else if (heuristic_score >= 15) {
        std::cout << "  [VERDICT] SUSPICIOUS_ASSET (Requires containment isolation sandboxing)" << std::endl;
    } else {
        std::cout << "  [VERDICT] STRUCTURE_CLEAN (No heuristic baseline signatures matched)" << std::endl;
    }
    std::cout << "=========================================================" << std::endl;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage Error. Syntax: .\\CoreAnalyzer.exe <target_file_path>" << std::endl;
        return 1;
    }
    ProcessTargetAsset(argv[1]);
    return 0;
}

    return 0;
}
