#include <iostream>
#include <string>
#include <vector>
#include <filesystem>
#include <thread>
#include <chrono>
#include <Windows.h>

namespace fs = std::filesystem;

bool deleteFileOrDirectory(const fs::path& path) {
    try {
        if (fs::exists(path)) {
            if (fs::is_regular_file(path)) {
                fs::remove(path);
            } else if (fs::is_directory(path)) {
                fs::remove_all(path);
            }
            return true;
        }
    } catch (const std::exception& e) {
        std::cerr << "Error deleting " << path << ": " << e.what() << std::endl;
    }
    return false;
}

std::string readRegistryValue(HKEY key, const std::wstring& subkey, const std::wstring& valueName) {
    HKEY subkeyHandle;
    DWORD dataSize;
    DWORD dataType;
    if (RegOpenKeyExW(key, subkey.c_str(), 0, KEY_READ, &subkeyHandle) == ERROR_SUCCESS) {
        if (RegQueryValueExW(subkeyHandle, valueName.c_str(), NULL, &dataType, NULL, &dataSize) == ERROR_SUCCESS) {
            if (dataType == REG_SZ) {
                std::vector<wchar_t> data(dataSize / sizeof(wchar_t));
                if (RegQueryValueExW(subkeyHandle, valueName.c_str(), NULL, &dataType, reinterpret_cast<LPBYTE>(data.data()), &dataSize) == ERROR_SUCCESS) {
                    RegCloseKey(subkeyHandle);
                    return std::wstring(data.begin(), data.end() - 1); // Remove null terminator
                }
            }
        }
        RegCloseKey(subkeyHandle);
    }
    return "";
}

void deleteRegistryKey(HKEY key, const std::wstring& subkey) {
    HKEY subkeyHandle;
    if (RegOpenKeyExW(key, subkey.c_str(), 0, KEY_ALL_ACCESS, &subkeyHandle) == ERROR_SUCCESS) {
        RegDeleteTreeW(subkeyHandle, nullptr);
        RegCloseKey(subkeyHandle);
    }
}

void patchOverwatch() {
    const std::wstring userProfile = std::wstring(_wgetenv(L"USERPROFILE"));
    const std::wstring appData = std::wstring(_wgetenv(L"APPDATA"));
    const std::wstring programData = std::wstring(_wgetenv(L"ProgramData"));

    std::vector<fs::path> overwatchPaths = {
        fs::path(userProfile) / L"AppData\\Local\\Battle.net",
        fs::path(userProfile) / L"AppData\\Local\\Blizzard",
        fs::path(userProfile) / L"AppData\\Local\\Blizzard Entertainment",
        fs::path(userProfile) / L"AppData\\Roaming\\Battle.net",
        fs::path(userProfile) / L"Documents\\Overwatch\\Logs",
        fs::path(programData) / L"Battle.net\\Setup",
        fs::path(programData) / L"Battle.net\\Agent\\data",
        fs::path(programData) / L"Battle.net\\Agent\\Logs",
        fs::path(programData) / L"Blizzard Entertainment"
    };

    std::wcout << L"Deleting Overwatch-related paths..." << std::endl;

    for (const auto& path : overwatchPaths) {
        deleteFileOrDirectory(path);
    }

    const std::wstring installLocation = readRegistryValue(HKEY_LOCAL_MACHINE, L"SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Overwatch", L"InstallLocation");

    if (!installLocation.empty()) {
        std::vector<fs::path> cacheDirs = {
            fs::path(installLocation) / L"_retail_\\cache",
            fs::path(installLocation) / L"_retail_\\GPUCache"
        };

        std::wcout << L"Deleting Overwatch cache directories..." << std::endl;

        for (const auto& cacheDir : cacheDirs) {
            deleteFileOrDirectory(cacheDir);
        }
    }

    const fs::path agentsPath = fs::path(programData) / L"Battle.net\\Agent";
    if (fs::exists(agentsPath)) {
        std::vector<fs::path> agents;
        for (const auto& entry : fs::directory_iterator(agentsPath)) {
            if (entry.path().stem().string().starts_with("Agent")) {
                agents.push_back(entry.path());
            }
        }

        if (!agents.empty()) {
            const auto latestAgent = *std::max_element(agents.begin(), agents.end(), [](const fs::path& p1, const fs::path& p2) {
                return fs::last_write_time(p1) < fs::last_write_time(p2);
            });

            for (const auto& agent : agents) {
                if (agent != latestAgent) {
                    deleteFileOrDirectory(agent);
                }
            }
        }
    }

    const std::vector<std::wstring> registryKeys = {
        L"SOFTWARE\\WOW6432Node\\Blizzard Entertainment",
        L"SOFTWARE\\Blizzard Entertainment",
        L"SOFTWARE\\Activision",
        L"HKEY_CLASSES_ROOT\\Applications\\Overwatch.exe",
        L"HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\microphone\\NonPackaged\\C:#Program Files (x86)#Overwatch#_retail_#Overwatch.exe",
        L"HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\RADAR\\HeapLeakDetection\\DiagnosedApplications\\Overwatch.exe",
        L"HKEY_CURRENT_USER\\VirtualStore\\MACHINE\\SOFTWARE\\WOW6432Node\\Activision",
        L"HKEY_CURRENT_USER\\SOFTWARE\\Classes\\VirtualStore\\MACHINE\\SOFTWARE\\WOW6432Node\\Activision"
    };

    std::wcout << L"Deleting Overwatch registry keys..." << std::endl;

    for (const auto& key : registryKeys) {
        const std::wstring baseKey = key.substr(0, key.find('\\'));
        const std::wstring subkey = key.substr(key.find('\\') + 1);

        if (baseKey == L"HKEY_CLASSES_ROOT") {
            deleteRegistryKey(HKEY_CLASSES_ROOT, subkey);
        } else if (baseKey == L"HKEY_CURRENT_USER") {
            deleteRegistryKey(HKEY_CURRENT_USER, subkey);
        } else if (baseKey == L"HKEY_LOCAL_MACHINE") {
            deleteRegistryKey(HKEY_LOCAL_MACHINE, subkey);
        } else if (baseKey == L"HKEY_USERS") {
            deleteRegistryKey(HKEY_USERS, subkey);
        } else if (baseKey == L"HKEY_CURRENT_CONFIG") {
            deleteRegistryKey(HKEY_CURRENT_CONFIG, subkey);
        }
    }
}

void patchCookies() {
    const std::wstring userProfile = std::wstring(_wgetenv(L"USERPROFILE"));
    const std::wstring appData = std::wstring(_wgetenv(L"APPDATA"));

    std::vector<fs::path> browserCookiePaths = {
        fs::path(userProfile) / L"AppData\\Local\\BraveSoftware\\Brave-Browser\\User Data\\Default\\Cookies",
        fs::path(appData) / L"Google\\Chrome\\User Data\\Default\\Cookies",
        fs::path(appData) / L"Opera Software\\Opera Stable\\Cookies"
    };

    std::wcout << L"Deleting browser cookie files..." << std::endl;

    for (const auto& path : browserCookiePaths) {
        deleteFileOrDirectory(path);
    }

    const fs::path firefoxProfilesPath = fs::path(appData) / L"Mozilla\\Firefox\\Profiles";
    if (fs::exists(firefoxProfilesPath)) {
        for (const auto& entry : fs::directory_iterator(firefoxProfilesPath)) {
            const fs::path cookiesPath = entry.path() / L"cookies.sqlite";
            deleteFileOrDirectory(cookiesPath);
        }
    }
}

void flushNetworkAndExit() {
    std::cout << "Flushing network..." << std::endl;
    system("ipconfig /flushdns"); // Flush DNS cache
    std::cout << "Network flushed." << std::endl;
    std::exit(0);
}

int main() {
    std::cout << "Starting patching process..." << std::endl;

    std::thread overwatchThread(patchOverwatch);
    std::thread cookiesThread(patchCookies);

    overwatchThread.join();
    cookiesThread.join();

    std::cout << "Patching completed successfully." << std::endl;

    flushNetworkAndExit();

    return 0;
}
