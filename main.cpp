#include <Windows.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <cstdio>
#include <vector>
#include <string>
#include <sstream>
#include <fstream>
#include <chrono>
#include <iomanip>

// Structure to represent a memory signature
struct Signature {
    std::string pattern;
    uint32_t offset;
    uint32_t extra;

    Signature(const std::string& pat, uint32_t off, uint32_t ext)
        : pattern(pat), offset(off), extra(ext) {
    }

    // Parse the signature pattern into a byte array with wildcards
    std::vector<std::pair<uint8_t, bool>> parse_pattern() const {
        std::vector<std::pair<uint8_t, bool>> bytes;
        std::istringstream patternStream(pattern);
        std::string byteStr;

        while (patternStream >> byteStr) {
            if (byteStr == "?" || byteStr == "??") {
                bytes.emplace_back(0, true); // Wildcard byte
            }
            else {
                bytes.emplace_back(static_cast<uint8_t>(strtol(byteStr.c_str(), nullptr, 16)), false);
            }
        }
        return bytes;
    }

    // Search for the pattern in memory
    void find(const std::vector<uint8_t>& memory, HANDLE processHandle, uintptr_t moduleBase, std::ofstream& logFile) const {
        auto parsedPattern = parse_pattern();
        size_t patternSize = parsedPattern.size();
        size_t memorySize = memory.size();
        std::vector<uintptr_t> results; // Store unique results

        for (size_t i = 0; i <= memorySize - patternSize; ++i) {
            bool found = true;

            for (size_t j = 0; j < patternSize; ++j) {
                if (!parsedPattern[j].second && memory[i + j] != parsedPattern[j].first) {
                    found = false;
                    break;
                }
            }

            if (found) {
                uintptr_t patternAddress = moduleBase + i;
                int32_t displacement;

                if (ReadProcessMemory(processHandle, reinterpret_cast<LPCVOID>(patternAddress + offset), &displacement, sizeof(displacement), nullptr)) {
                    uintptr_t result = patternAddress + displacement + extra;

                    // Avoid duplicate results
                    if (std::find(results.begin(), results.end(), result) == results.end()) {
                        results.push_back(result);
                        printf("  [+] Found pattern: +0x%08X\n", static_cast<uint32_t>(result - moduleBase));
                        logFile << "  [+] Found pattern: +0x" << std::hex << (result - moduleBase) << std::endl;
                    }
                }
                else {
                    printf("  [!] Failed to read memory at address: 0x%08X\n", static_cast<uint32_t>(patternAddress + offset));
                    logFile << "  [!] Failed to read memory at address: 0x" << std::hex << (patternAddress + offset) << std::endl;
                }
            }
        }

        if (results.empty()) {
            printf("  [!] No matches found for pattern: %s\n", pattern.c_str());
            logFile << "  [!] No matches found for pattern: " << pattern << std::endl;
        }
        else {
            printf("  [*] Total matches for pattern \"%s\": %zu\n", pattern.c_str(), results.size());
            logFile << "  [*] Total matches for pattern \"" << pattern << "\": " << results.size() << std::endl;
        }
    }
};

// Retrieve a handle to a process by name
HANDLE getProcessHandle(const std::string& processName) {
    PROCESSENTRY32 processEntry = { sizeof(PROCESSENTRY32) };
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (snapshot == INVALID_HANDLE_VALUE) {
        printf("[!] Error: Unable to create process snapshot.\n");
        return nullptr;
    }

    HANDLE processHandle = nullptr;

    if (Process32First(snapshot, &processEntry)) {
        do {
            std::wstring exeFileName(processEntry.szExeFile);
            if (processName == std::string(exeFileName.begin(), exeFileName.end())) {
                processHandle = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, processEntry.th32ProcessID);
                break;
            }
        } while (Process32Next(snapshot, &processEntry));
    }

    CloseHandle(snapshot);
    return processHandle;
}

// Retrieve information about a specific module in a process
MODULEINFO getModuleInfo(HANDLE processHandle, const std::string& moduleName) {
    HMODULE hModules[1024];
    DWORD cbNeeded;
    MODULEINFO modInfo = { 0 };

    if (EnumProcessModules(processHandle, hModules, sizeof(hModules), &cbNeeded)) {
        for (size_t i = 0; i < (cbNeeded / sizeof(HMODULE)); ++i) {
            char szModuleName[MAX_PATH];
            if (GetModuleBaseNameA(processHandle, hModules[i], szModuleName, sizeof(szModuleName))) {
                if (moduleName == szModuleName) {
                    GetModuleInformation(processHandle, hModules[i], &modInfo, sizeof(modInfo));
                    break;
                }
            }
        }
    }
    else {
        printf("[!] Error: Unable to enumerate process modules.\n");
    }
    return modInfo;
}

// Read memory from a process into a buffer
std::vector<uint8_t> readMemoryBytes(HANDLE processHandle, uintptr_t address, size_t size) {
    std::vector<uint8_t> buffer(size);

    if (!ReadProcessMemory(processHandle, reinterpret_cast<LPCVOID>(address), buffer.data(), size, nullptr)) {
        printf("[!] Error: Failed to read memory at address: 0x%08X\n", static_cast<uint32_t>(address));
    }
    return buffer;
}

int main() {
    printf("Signature Finder by vcpu (Enhanced Version)\n\n");

    std::ofstream logFile("SignatureFinderOutput.txt");
    if (!logFile.is_open()) {
        printf("[!] Error: Unable to create output log file.\n");
        return EXIT_FAILURE;
    }

    // Define signature patterns
    std::vector<Signature> signatures = {
        {"48 8B 0D ? ? ? ? 48 85 C9 74 65 83 FF FF", 3, 7},
        {"48 8D ? ? ? ? ? 48 C1 E0 06 48 03 C1 C3", 3, 7},
        {"48 8B 0D ? ? ? ? 8B C5 48 C1 E8", 3, 7},
        {"48 8D 3D ? ? ? ? 8B D9", 3, 7},
        {"48 8B 1D ? ? ? ? 48 89 1D", 3, 7},
        {"48 89 05 ? ? ? ? 48 8B C8 48 85 C0", 3, 7},
        {"48 8B 0D ? ? ? ? 48 8D 45 ? 48 89 44 24 ? 4C 8D 44 24 ? 4C 8B CF", 3, 7}
    };

    // Specify process and modules
    std::string processName = "project8.exe";
    std::vector<std::string> modules = { "client.dll", "engine2.dll" };

    HANDLE processHandle = getProcessHandle(processName);
    if (!processHandle) {
        printf("[!] Error: Process \"%s\" not found.\n", processName.c_str());
        logFile << "[!] Error: Process \"" << processName << "\" not found." << std::endl;
        return EXIT_FAILURE;
    }

    auto start = std::chrono::high_resolution_clock::now();

    for (const auto& moduleName : modules) {
        MODULEINFO moduleInfo = getModuleInfo(processHandle, moduleName);
        if (!moduleInfo.lpBaseOfDll) {
            printf("[!] Error: Module \"%s\" not found.\n", moduleName.c_str());
            logFile << "[!] Error: Module \"" << moduleName << "\" not found." << std::endl;
            continue;
        }

        uintptr_t moduleBase = reinterpret_cast<uintptr_t>(moduleInfo.lpBaseOfDll);
        size_t moduleSize = moduleInfo.SizeOfImage;

        printf("\n[*] Scanning module: %s (Base: 0x%08X, Size: 0x%08X)\n", moduleName.c_str(), static_cast<uint32_t>(moduleBase), static_cast<uint32_t>(moduleSize));
        logFile << "\n[*] Scanning module: " << moduleName << " (Base: 0x" << std::hex << moduleBase << ", Size: 0x" << std::hex << moduleSize << ")" << std::endl;

        std::vector<uint8_t> memory = readMemoryBytes(processHandle, moduleBase, moduleSize);

        for (const auto& sig : signatures) {
            printf("[*] Searching for pattern: %s\n", sig.pattern.c_str());
            logFile << "[*] Searching for pattern: " << sig.pattern << std::endl;

            auto patternStart = std::chrono::high_resolution_clock::now();
            sig.find(memory, processHandle, moduleBase, logFile);
            auto patternEnd = std::chrono::high_resolution_clock::now();

            std::chrono::duration<double> patternDuration = patternEnd - patternStart;
            printf("    Time taken: %.4f seconds\n", patternDuration.count());
            logFile << "    Time taken: " << patternDuration.count() << " seconds" << std::endl;
        }
    }

    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> totalDuration = end - start;

    printf("\n[+] Total time taken: %.4f seconds\n", totalDuration.count());
    logFile << "\n[+] Total time taken: " << totalDuration.count() << " seconds" << std::endl;

    logFile.close();
    CloseHandle(processHandle);
    printf("[+] Results have been saved to SignatureFinderOutput.txt\n");
    return EXIT_SUCCESS;
}
