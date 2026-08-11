#include "HeaderParser.h"
#include <fstream>
#include <iostream>
#include <vector>
#include <string>
#include <algorithm>
#include <iomanip>

struct ThreatSignature {
    std::string api_name;
    std::string category;
    int weight; // 1 = Low risk anomaly, 2 = Medium capability, 3 = High risk/Malicious primitive
};

// Advanced comprehensive watchlist mapping critical Windows API combinations
const std::vector<ThreatSignature> EXTENDED_WATCHLIST = {
    // Process Injection / Memory Manipulation primitives
    {"virtualallocex", "INJECTION_ALLOCATION", 3},
    {"writeprocessmemory", "INJECTION_WRITING", 3},
    {"createremotethread", "INJECTION_EXECUTION", 3},
    {"queueuserapc", "APC_INJECTION", 3},
    {"ntqueueapcthread", "APC_INJECTION", 3},
    {"virtualprotectex", "MEMORY_PERMISSION_FLIP", 2},
    
    // Process Hollowing & Thread Hijacking
    {"ntsetcontextthread", "THREAD_HIJACKING", 3},
    {"setthreadcontext", "THREAD_HIJACKING", 3},
    {"ntresumethread", "THREAD_HIJACKING", 3},
    {"ntunmapviewofsection", "PROCESS_HOLLOWING", 3},
    {"zwunmapviewofsection", "PROCESS_HOLLOWING", 3},
    
    // Evasion, Anti-Analysis, and Anti-Debugging
    {"isdebuggerpresent", "ANTI_DEBUGGING", 1},
    {"checkremotedebuggerpresent", "ANTI_DEBUGGING", 1},
    {"ntqueryinformationprocess", "ANTI_DEBUG_OR_INFO_GATHER", 2},
    {"ntdelayexecution", "SANDBOX_TIMING_DELAY", 1},
    {"sleepex", "SANDBOX_TIMING_DELAY", 1},
    {"outputdebugstringa", "ANTI_ANALYSIS", 1},
    
    // Credential Dumping, Token Manipulation & Privilege Escalation
    {"openprocesstoken", "PRIVILEGE_ESCALATION", 2},
    {"adjusttokenprivileges", "PRIVILEGE_ESCALATION", 3},
    {"lookupprivilegevaluea", "PRIVILEGE_ESCALATION", 2},
    {"samopenhandle", "CREDENTIAL_STEALING", 3},
    {"samigetprivatedata", "CREDENTIAL_STEALING", 3},
    
    // Persistence Mechanisms
    {"regsetvalueexw", "REGISTRY_PERSISTENCE", 2},
    {"regsetvalueexa", "REGISTRY_PERSISTENCE", 2},
    {"createservicea", "SERVICE_PERSISTENCE", 3},
    {"createservicew", "SERVICE_PERSISTENCE", 3},
    
    // C2 Infrastructure Communication / Network Ingestion
    {"urldownloadtofilea", "NETWORK_DOWNLOADER", 3},
    {"internetopenw", "NETWORK_C2", 2},
    {"internetconnectw", "NETWORK_C2", 2},
    {"httpopensendrequestw", "NETWORK_C2", 3},
    {"wsastartup", "NETWORK_SOCKET_INIT", 1}
};

std::vector<uint8_t> IngestPhysicalFile(const std::string& path) {
    std::ifstream stream(path, std::ios::binary | std::ios::ate);
    if (!stream.is_open()) {
        std::cerr << "[-] Error: Failed to open path: " << path << std::endl;
        return {};
    }
    std::streamsize size = stream.tellg();
    stream.seekg(0, std::ios::beg);
    std::vector<uint8_t> buffer(static_cast<size_t>(size));
    stream.read(reinterpret_cast<char*>(buffer.data()), size);
    return buffer;
}

void ParseWatchlistHeuristics(const std::vector<Phlegethon::Core::ImportedSymbol>& imports, int& risk_score, int& match_count) {
    for (const auto& imp : imports) {
        std::string normalized = imp.symbol_name;
        std::transform(normalized.begin(), normalized.end(), normalized.begin(), ::tolower);

        for (const auto& sig : EXTENDED_WATCHLIST) {
            if (normalized == sig.api_name) {
                match_count++;
                // Advanced algorithmic weighting multiplier for critical clusters
                risk_score += (sig.weight == 3) ? 15 : (sig.weight == 2) ? 7 : 2;
                
                std::string lvl = (sig.weight == 3) ? "CRITICAL" : (sig.weight == 2) ? "MEDIUM" : "LOW";
                std::cout << "  [!] MATCH -> " << std::left << std::setw(25) << imp.symbol_name 
                          << " | Vector: " << std::setw(25) << sig.category 
                          << " | Risk: " << lvl << std::endl;
            }
        }
    }
}

void ExecuteAdvancedTriagePipeline(const std::string& path) {
    std::vector<uint8_t> raw_bytes = IngestPhysicalFile(path);
    if (raw_bytes.empty()) return;

    auto pe_data = Phlegethon::Core::ParseTargetBinary(raw_bytes);
    if (!pe_data.integrity_validated) {
        std::cerr << "[-] Error: Asset structural checks failed. Target is corrupted or non-PE." << std::endl;
        return;
    }

    std::cout << "[+] Header Structural Integrity Verified." << std::endl;
    std::cout << "  |-- Entry Point Address: 0x" << std::hex << pe_data.address_of_entry_point << std::dec << std::endl;
    std::cout << "  |-- Image Base Virtual Address: 0x" << std::hex << pe_data.image_base_address << std::dec << std::endl;

    // Advanced Section Obfuscation Scan
    int accumulated_score = 0;
    std::cout << "[*] Parsing physical segment identifiers..." << std::endl;
    for (const auto& section : pe_data.structural_sections) {
        std::string lower_sec = section;
        std::transform(lower_sec.begin(), lower_sec.end(), lower_sec.begin(), ::tolower);
        
        // Flag common packing/protector signatures
        if (lower_sec.find("upx") != std::string::npos || lower_sec.find("vmp") != std::string::npos || 
            lower_sec.find("themida") != std::string::npos || lower_sec.find("aspack") != std::string::npos) {
            std::cout << "    [!] Alert: Obfuscation packing signature matched in section: " << section << std::endl;
            accumulated_score += 25; 
        }
    }

    int matched_signatures_count = 0;
    ParseWatchlistHeuristics(pe_data.resolved_imports, accumulated_score, matched_signatures_count);

    // Advanced Operational Metrics Density Check
    // High file size combined with suspiciously few resolved imports indicates a packed or stripped binary
    if (raw_bytes.size() > 500000 && pe_data.resolved_imports.size() < 15) {
        std::cout << "  [!] Anomaly: Low import density detected for file size. High probability of an encrypted payload stub." << std::endl;
        accumulated_score += 20;
    }

    std::cout << "\n=========================================================" << std::endl;
    std::cout << "PHLEGETHON RISK ASSESSMENT" << std::endl;
    std::cout << "=========================================================" << std::endl;
    std::cout << "  Total Extracted Imports       : " << pe_data.resolved_imports.size() << std::endl;
    std::cout << "  Heuristic Pattern Matches     : " << matched_signatures_count << std::endl;
    std::cout << "  Calculated Aggregated Threat Vector Score : " << accumulated_score << std::endl;
    std::cout << "---------------------------------------------------------" << std::endl;

    if (accumulated_score >= 45) {
        std::cout << "  [VERDICT] STATUS_MALICIOUS_INDICATORS_ENCOUNTERED" << std::endl;
    } else if (accumulated_score >= 20) {
        std::cout << "  [VERDICT] STATUS_SUSPICIOUS_ASSET_REQUIRES_CONTAINMENT" << std::endl;
    } else {
        std::cout << "  [VERDICT] STATUS_ASSET_STRUCTURE_CLEAN" << std::endl;
    }
    std::cout << "=========================================================" << std::endl;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage Error. Syntax: .\\CoreAnalyzer.exe <target_file_path>" << std::endl;
        return 1;
    }
    ExecuteAdvancedTriagePipeline(argv[1]);
    return 0;
}

