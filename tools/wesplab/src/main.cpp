#include <windows.h>
#include <bcrypt.h>
#include <objbase.h>
#include <winsvc.h>

#include <wesplab/abi_0_1_0_156346177.hpp>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <mutex>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

namespace {

using namespace wesplab::abi_0_1_0_156346177;
#include <expected_exports.inc>

constexpr wchar_t kLabMarker[] = L"C:\\ProgramData\\wesplab\\LAB_MACHINE";
constexpr wchar_t kClientName[] = L"wesplab research client";
constexpr wchar_t kClientAltitude[] = L"385000.54321";
constexpr wchar_t kMonitorAltitude[] = L"385000.54322";
constexpr std::uint32_t kMaxCapturedPayload = 4u * 1024u * 1024u;

std::mutex g_output;
std::atomic_bool g_stop{false};

void Line(std::wstring_view value) {
    const std::scoped_lock lock(g_output);
    std::wcout << value << L'\n';
}

std::wstring HresultText(HRESULT hr) {
    DWORD code = HRESULT_FACILITY(hr) == FACILITY_WIN32 ? HRESULT_CODE(hr)
                                                        : static_cast<DWORD>(hr);
    std::array<wchar_t, 512> buffer{};
    DWORD length = FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                                  nullptr, code, 0, buffer.data(),
                                  static_cast<DWORD>(buffer.size()), nullptr);
    std::wstring text = length ? std::wstring(buffer.data(), length) : L"unknown error";
    while (!text.empty() && (text.back() == L'\r' || text.back() == L'\n' || text.back() == L' ')) {
        text.pop_back();
    }
    return text;
}

void Failure(std::wstring_view operation, HRESULT hr) {
    std::wostringstream out;
    out << L"[-] " << operation << L": 0x" << std::hex << std::uppercase
        << std::setw(8) << std::setfill(L'0') << static_cast<std::uint32_t>(hr)
        << L" (" << HresultText(hr) << L")";
    Line(out.str());
}

std::wstring GuidString(const GUID& id) {
    std::array<wchar_t, 40> buffer{};
    StringFromGUID2(id, buffer.data(), static_cast<int>(buffer.size()));
    return buffer.data();
}

std::string NarrowAscii(std::wstring_view value) {
    std::string result;
    result.reserve(value.size());
    for (wchar_t ch : value) result.push_back(ch <= 0x7f ? static_cast<char>(ch) : '?');
    return result;
}

std::string Hex(const void* data, std::size_t size) {
    static constexpr char digits[] = "0123456789abcdef";
    const auto* bytes = static_cast<const unsigned char*>(data);
    std::string result(size * 2, '0');
    for (std::size_t i = 0; i < size; ++i) {
        result[i * 2] = digits[bytes[i] >> 4];
        result[i * 2 + 1] = digits[bytes[i] & 0x0f];
    }
    return result;
}

std::string UtcNow() {
    SYSTEMTIME time{};
    GetSystemTime(&time);
    std::ostringstream out;
    out << std::setfill('0') << std::setw(4) << time.wYear << '-'
        << std::setw(2) << time.wMonth << '-' << std::setw(2) << time.wDay << 'T'
        << std::setw(2) << time.wHour << ':' << std::setw(2) << time.wMinute << ':'
        << std::setw(2) << time.wSecond << '.' << std::setw(3) << time.wMilliseconds << 'Z';
    return out.str();
}

bool ParseGuid(std::wstring_view text, GUID& id) {
    std::wstring owned(text);
    return SUCCEEDED(CLSIDFromString(owned.c_str(), &id));
}

std::wstring JsonEscape(std::wstring_view input) {
    std::wostringstream out;
    for (wchar_t ch : input) {
        switch (ch) {
        case L'"': out << L"\\\""; break;
        case L'\\': out << L"\\\\"; break;
        case L'\b': out << L"\\b"; break;
        case L'\f': out << L"\\f"; break;
        case L'\n': out << L"\\n"; break;
        case L'\r': out << L"\\r"; break;
        case L'\t': out << L"\\t"; break;
        default:
            if (ch < 0x20) {
                out << L"\\u" << std::hex << std::setw(4) << std::setfill(L'0')
                    << static_cast<unsigned>(ch);
            } else {
                out << ch;
            }
        }
    }
    return out.str();
}

bool IsElevated() {
    HANDLE raw = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw)) return false;
    TOKEN_ELEVATION elevation{};
    DWORD returned = 0;
    const BOOL ok = GetTokenInformation(raw, TokenElevation, &elevation,
                                        sizeof(elevation), &returned);
    CloseHandle(raw);
    return ok && elevation.TokenIsElevated;
}

bool LabMarkerPresent() {
    return GetFileAttributesW(kLabMarker) != INVALID_FILE_ATTRIBUTES;
}

std::wstring FileVersionString(const std::filesystem::path& path) {
    DWORD ignored = 0;
    DWORD size = GetFileVersionInfoSizeW(path.c_str(), &ignored);
    if (!size) return L"";
    std::vector<std::byte> bytes(size);
    if (!GetFileVersionInfoW(path.c_str(), 0, size, bytes.data())) return L"";
    struct Translation { WORD language; WORD codepage; };
    Translation* translations = nullptr;
    UINT translation_bytes = 0;
    if (VerQueryValueW(bytes.data(), L"\\VarFileInfo\\Translation",
                       reinterpret_cast<void**>(&translations), &translation_bytes) &&
        translation_bytes >= sizeof(Translation)) {
        for (UINT index = 0; index < translation_bytes / sizeof(Translation); ++index) {
            std::wostringstream key;
            key << L"\\StringFileInfo\\" << std::hex << std::setw(4) << std::setfill(L'0')
                << translations[index].language << std::setw(4) << translations[index].codepage
                << L"\\FileVersion";
            wchar_t* value = nullptr;
            UINT chars = 0;
            if (VerQueryValueW(bytes.data(), key.str().c_str(),
                               reinterpret_cast<void**>(&value), &chars) && chars && value) {
                return value;
            }
        }
    }
    VS_FIXEDFILEINFO* fixed = nullptr;
    UINT fixed_size = 0;
    if (!VerQueryValueW(bytes.data(), L"\\", reinterpret_cast<void**>(&fixed), &fixed_size) ||
        fixed_size < sizeof(VS_FIXEDFILEINFO)) return L"";
    std::wostringstream value;
    value << HIWORD(fixed->dwFileVersionMS) << L'.' << LOWORD(fixed->dwFileVersionMS)
          << L'.' << HIWORD(fixed->dwFileVersionLS) << L'.' << LOWORD(fixed->dwFileVersionLS);
    return value.str();
}

std::wstring Sha256(const std::filesystem::path& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file) return L"";
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    DWORD object_size = 0, result_size = 0;
    if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0 ||
        BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH,
                          reinterpret_cast<PUCHAR>(&object_size), sizeof(object_size),
                          &result_size, 0) < 0) {
        if (algorithm) BCryptCloseAlgorithmProvider(algorithm, 0);
        return L"";
    }
    std::vector<UCHAR> object(object_size);
    std::array<UCHAR, 32> digest{};
    if (BCryptCreateHash(algorithm, &hash, object.data(), object_size, nullptr, 0, 0) < 0) {
        BCryptCloseAlgorithmProvider(algorithm, 0);
        return L"";
    }
    std::array<char, 1024 * 1024> block{};
    while (file) {
        file.read(block.data(), static_cast<std::streamsize>(block.size()));
        const auto count = file.gcount();
        if (count > 0) BCryptHashData(hash, reinterpret_cast<PUCHAR>(block.data()),
                                      static_cast<ULONG>(count), 0);
    }
    if (BCryptFinishHash(hash, digest.data(), static_cast<ULONG>(digest.size()), 0) < 0) {
        BCryptDestroyHash(hash);
        BCryptCloseAlgorithmProvider(algorithm, 0);
        return L"";
    }
    BCryptDestroyHash(hash);
    BCryptCloseAlgorithmProvider(algorithm, 0);
    std::wostringstream out;
    for (UCHAR byte : digest) out << std::hex << std::setw(2) << std::setfill(L'0') << unsigned(byte);
    return out.str();
}

struct Api {
    using Register = HRESULT(WINAPI*)(const ClientDescriptor*);
    using Unregister = HRESULT(WINAPI*)(const GUID*);
    using Enumerate = HRESULT(WINAPI*)(std::uint32_t*, GUID**);
    using Free = void(WINAPI*)(void*);
    using Connect = HRESULT(WINAPI*)(const GUID*, OpaqueHandle*);
    using Disconnect = HRESULT(WINAPI*)(OpaqueHandle);
    using Capabilities = HRESULT(WINAPI*)(OpaqueHandle, std::uint32_t, std::uint32_t*);
    using EnumerateIds = HRESULT(WINAPI*)(OpaqueHandle, std::uint32_t, std::uint32_t*, GUID**);
    using IsPropertySupported = HRESULT(WINAPI*)(OpaqueHandle, std::uint32_t, int*);
    using CreateQueue = HRESULT(WINAPI*)(OpaqueHandle, const EventQueueDescriptor*, OpaqueHandle*);
    using CloseQueue = HRESULT(WINAPI*)(OpaqueHandle);
    using ConnectQueue = HRESULT(WINAPI*)(OpaqueHandle, std::uint32_t, NotificationCallback, void*);
    using DisconnectQueue = HRESULT(WINAPI*)(OpaqueHandle);
    using CreateRule = HRESULT(WINAPI*)(const RuleDescriptor*, OpaqueHandle*);
    using CloseRule = HRESULT(WINAPI*)(OpaqueHandle);
    using UpdateRules = HRESULT(WINAPI*)(OpaqueHandle, std::uint32_t, std::uint32_t, const RuleUpdate*);
    using AllocateNotification = void*(WINAPI*)();
    using ArmNotification = HRESULT(WINAPI*)(OpaqueHandle, void*);
    using CompleteNotification = HRESULT(WINAPI*)(void*);
    using FreeNotification = void(WINAPI*)(void*);

    HMODULE module = nullptr;
    Register register_client{};
    Unregister unregister_client{};
    Enumerate registered_clients{};
    Enumerate connected_clients{};
    Free free_memory{};
    Connect connect_client{};
    Disconnect disconnect_client{};
    Capabilities get_capabilities{};
    EnumerateIds enumerate_rule_ids{};
    EnumerateIds enumerate_queue_ids{};
    EnumerateIds enumerate_collection_ids{};
    CreateQueue create_queue{};
    CloseQueue close_queue{};
    ConnectQueue connect_queue{};
    DisconnectQueue disconnect_queue{};
    CreateRule create_rule{};
    CloseRule close_rule{};
    UpdateRules update_rules{};
    AllocateNotification allocate_notification{};
    ArmNotification arm_notification{};
    CompleteNotification complete_notification{};
    FreeNotification free_notification{};

    ~Api() { if (module) FreeLibrary(module); }
    Api(const Api&) = delete;
    Api& operator=(const Api&) = delete;
    Api() = default;

    template<typename T> void Get(const char* name, T& target) {
        static_assert(sizeof(T) == sizeof(FARPROC));
        FARPROC address = GetProcAddress(module, name);
        std::memcpy(&target, &address, sizeof(target));
    }

    bool Load() {
        module = LoadLibraryExW(L"espclient.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
        if (!module) return false;
        Get("EspRegisterClient", register_client);
        Get("EspUnregisterClient", unregister_client);
        Get("EspEnumerateRegisteredClients", registered_clients);
        Get("EspEnumerateConnectedClients", connected_clients);
        Get("EspFreeMemory", free_memory);
        Get("EspConnectClient", connect_client);
        Get("EspDisconnectClient", disconnect_client);
        Get("EspGetEventCapabilities", get_capabilities);
        Get("EspEnumerateRuleIds", enumerate_rule_ids);
        Get("EspEnumerateEventQueueIds", enumerate_queue_ids);
        Get("EspEnumerateCollectionIds", enumerate_collection_ids);
        Get("EspCreateEventQueue", create_queue);
        Get("EspCloseEventQueue", close_queue);
        Get("EspConnectEventQueueWithCallback", connect_queue);
        Get("EspDisconnectEventQueue", disconnect_queue);
        Get("EspCreateRule", create_rule);
        Get("EspCloseRule", close_rule);
        Get("EspUpdateRules", update_rules);
        Get("EspAllocateEventNotification", allocate_notification);
        Get("EspArmEventNotification", arm_notification);
        Get("EspCompleteEventNotification", complete_notification);
        Get("EspFreeEventNotification", free_notification);
        return true;
    }

    std::vector<std::string> MissingExports() const {
        std::vector<std::string> missing;
        for (const char* name : kExpectedExports) {
            if (!GetProcAddress(module, name)) missing.emplace_back(name);
        }
        return missing;
    }
};

std::filesystem::path SystemFile(std::wstring_view suffix) {
    std::array<wchar_t, MAX_PATH> root{};
    UINT length = GetWindowsDirectoryW(root.data(), static_cast<UINT>(root.size()));
    if (!length || length >= root.size()) return {};
    return std::filesystem::path(root.data()) / suffix;
}

bool ServiceRunning(std::wstring_view name) {
    SC_HANDLE manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!manager) return false;
    std::wstring owned(name);
    SC_HANDLE service = OpenServiceW(manager, owned.c_str(), SERVICE_QUERY_STATUS);
    SERVICE_STATUS_PROCESS status{};
    DWORD needed = 0;
    bool running = service && QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO,
        reinterpret_cast<LPBYTE>(&status), sizeof(status), &needed) &&
        status.dwCurrentState == SERVICE_RUNNING;
    if (service) CloseServiceHandle(service);
    CloseServiceHandle(manager);
    return running;
}

int Doctor(bool json) {
    const auto dll = SystemFile(L"System32\\espclient.dll");
    const auto driver = SystemFile(L"System32\\drivers\\wesp.sys");
    const bool dll_exists = std::filesystem::exists(dll);
    const bool driver_exists = std::filesystem::exists(driver);
    const std::wstring dll_version = dll_exists ? FileVersionString(dll) : L"";
    const std::wstring driver_version = driver_exists ? FileVersionString(driver) : L"";
    const bool version_match = dll_version.find(kExpectedVersion) != std::wstring::npos &&
                               driver_version.find(kExpectedVersion) != std::wstring::npos;
    Api api;
    const bool loaded = api.Load();
    const auto missing = loaded ? api.MissingExports() : std::vector<std::string>{};
    const std::size_t missing_count = loaded ? missing.size() : std::size(kExpectedExports);
    const std::size_t available_count = loaded ? std::size(kExpectedExports) - missing.size() : 0;
    if (json) {
        std::wcout << L"{\n"
                   << L"  \"schema\": \"wesplab.doctor.v1\",\n"
                   << L"  \"elevated\": " << (IsElevated() ? L"true" : L"false") << L",\n"
                   << L"  \"lab_marker\": " << (LabMarkerPresent() ? L"true" : L"false") << L",\n"
                   << L"  \"espclient\": {\"present\": " << (dll_exists ? L"true" : L"false")
                   << L", \"version\": \"" << JsonEscape(dll_version)
                   << L"\", \"sha256\": \"" << Sha256(dll) << L"\"},\n"
                   << L"  \"driver\": {\"present\": " << (driver_exists ? L"true" : L"false")
                   << L", \"version\": \"" << JsonEscape(driver_version)
                   << L"\", \"sha256\": \"" << Sha256(driver) << L"\"},\n"
                   << L"  \"target_version_match\": " << (version_match ? L"true" : L"false") << L",\n"
                   << L"  \"driver_service_running\": " << (ServiceRunning(L"wesp") ? L"true" : L"false") << L",\n"
                   << L"  \"expected_exports\": " << std::size(kExpectedExports) << L",\n"
                   << L"  \"missing_export_count\": " << missing_count << L"\n}\n";
    } else {
        Line(L"WESP lab preflight");
        Line(L"  elevated       : " + std::wstring(IsElevated() ? L"yes" : L"no"));
        Line(L"  lab marker     : " + std::wstring(LabMarkerPresent() ? L"present" : L"absent"));
        Line(L"  espclient.dll  : " + std::wstring(dll_exists ? L"present" : L"missing"));
        if (dll_exists) {
            Line(L"    version      : " + dll_version);
            Line(L"    sha256       : " + Sha256(dll));
        }
        Line(L"  wesp.sys       : " + std::wstring(driver_exists ? L"present" : L"missing"));
        if (driver_exists) Line(L"    version      : " + driver_version);
        Line(L"  target version  : " + std::wstring(version_match ? L"exact" : L"mismatch"));
        Line(L"  service        : " + std::wstring(ServiceRunning(L"wesp") ? L"running" : L"not running"));
        Line(L"  ABI exports    : " + std::to_wstring(available_count) +
             L"/" + std::to_wstring(std::size(kExpectedExports)));
        for (const auto& name : missing) Line(L"    missing: " + std::wstring(name.begin(), name.end()));
    }
    return dll_exists && driver_exists && loaded && missing.empty() && version_match ? 0 : 1;
}

struct GuidList {
    Api* api{};
    GUID* values{};
    std::uint32_t count{};
    ~GuidList() { if (values && api && api->free_memory) api->free_memory(values); }
};

HRESULT Enumerate(Api& api, bool connected, GuidList& result) {
    auto function = connected ? api.connected_clients : api.registered_clients;
    if (!function || !api.free_memory) return HRESULT_FROM_WIN32(ERROR_PROC_NOT_FOUND);
    result.api = &api;
    return function(&result.count, &result.values);
}

int Clients(bool connected, bool json) {
    Api api;
    if (!api.Load()) return Failure(L"LoadLibraryExW(espclient.dll)", HRESULT_FROM_WIN32(GetLastError())), 1;
    GuidList list;
    HRESULT hr = Enumerate(api, connected, list);
    if (FAILED(hr)) return Failure(connected ? L"EspEnumerateConnectedClients" : L"EspEnumerateRegisteredClients", hr), 1;
    if (list.count && !list.values) return Line(L"[-] invalid null list returned"), 1;
    if (json) {
        std::wcout << L"{\"schema\":\"wesplab.clients.v1\",\"kind\":\""
                   << (connected ? L"connected" : L"registered") << L"\",\"clients\":[";
        for (std::uint32_t index = 0; index < list.count; ++index) {
            if (index) std::wcout << L',';
            std::wcout << L"\"" << GuidString(list.values[index]) << L"\"";
        }
        std::wcout << L"]}\n";
    } else {
        Line(std::wstring(connected ? L"Connected" : L"Registered") + L" clients: " + std::to_wstring(list.count));
        for (std::uint32_t index = 0; index < list.count; ++index) Line(L"  " + GuidString(list.values[index]));
    }
    return 0;
}

bool RequireWrite(bool write, bool require_lab = false) {
    if (!write) {
        Line(L"[-] mutation refused: repeat with --write after reviewing the target");
        return false;
    }
    const auto dll = SystemFile(L"System32\\espclient.dll");
    const auto driver = SystemFile(L"System32\\drivers\\wesp.sys");
    const bool exact = std::filesystem::exists(dll) && std::filesystem::exists(driver) &&
        FileVersionString(dll).find(kExpectedVersion) != std::wstring::npos &&
        FileVersionString(driver).find(kExpectedVersion) != std::wstring::npos;
    if (!exact) {
        Line(L"[-] mutation refused: inbox DLL/driver do not match ABI 0.1.0.156346177");
        return false;
    }
    if (require_lab && !LabMarkerPresent()) {
        Line(L"[-] lab operation refused: create C:\\ProgramData\\wesplab\\LAB_MACHINE in a disposable VM");
        return false;
    }
    return true;
}

int RegisterClient(std::wstring_view supplied, bool write,
                   std::wstring_view supplied_name, std::wstring_view supplied_altitude) {
    if (!RequireWrite(write)) return 2;
    if (supplied_name.empty() || supplied_altitude.empty() ||
        supplied_name.size() > 256 || supplied_altitude.size() > 64) {
        return Line(L"[-] client name/altitude is empty or too long"), 2;
    }
    GUID id{};
    HRESULT hr = supplied.empty() ? CoCreateGuid(&id) : (ParseGuid(supplied, id) ? S_OK : E_INVALIDARG);
    if (FAILED(hr)) return Failure(L"client GUID", hr), 2;
    Line(L"[*] target client: " + GuidString(id));
    Api api;
    if (!api.Load() || !api.register_client) return Failure(L"resolve EspRegisterClient", HRESULT_FROM_WIN32(ERROR_PROC_NOT_FOUND)), 1;
    const std::wstring name(supplied_name);
    const std::wstring altitude(supplied_altitude);
    ClientDescriptor descriptor{id, name.c_str(), altitude.c_str()};
    hr = api.register_client(&descriptor);
    if (FAILED(hr)) return Failure(L"EspRegisterClient", hr), 1;
    Line(L"[+] registered " + GuidString(id));
    return 0;
}

int RemoveClient(std::wstring_view supplied, bool write, bool cross_client) {
    if (!RequireWrite(write, cross_client)) return 2;
    GUID id{};
    if (!ParseGuid(supplied, id)) return Line(L"[-] invalid GUID"), 2;
    if (cross_client) Line(L"[!] cross-client authorization test enabled");
    Line(L"[*] unregister target: " + GuidString(id));
    Api api;
    if (!api.Load() || !api.unregister_client) return 1;
    HRESULT hr = api.unregister_client(&id);
    if (FAILED(hr)) return Failure(L"EspUnregisterClient", hr), 1;
    Line(L"[+] unregistered " + GuidString(id));
    return 0;
}

struct ConnectedClient {
    Api* api{};
    OpaqueHandle handle{};
    ~ConnectedClient() { if (handle && api && api->disconnect_client) api->disconnect_client(handle); }
};

int Capabilities(std::wstring_view supplied, std::uint32_t first, std::uint32_t last, bool json) {
    GUID id{};
    if (!ParseGuid(supplied, id) || first > last || last - first > 100000) return 2;
    Api api;
    if (!api.Load() || !api.connect_client || !api.get_capabilities) return 1;
    ConnectedClient client{&api};
    HRESULT hr = api.connect_client(&id, &client.handle);
    if (FAILED(hr)) return Failure(L"EspConnectClient", hr), 1;
    if (json) std::wcout << L"{\"schema\":\"wesplab.capabilities.v1\",\"client\":\"" << GuidString(id) << L"\",\"events\":[";
    bool comma = false;
    for (std::uint32_t event = first; event <= last; ++event) {
        std::uint32_t flags = 0;
        hr = api.get_capabilities(client.handle, event, &flags);
        if (SUCCEEDED(hr) && flags) {
            if (json) {
                if (comma) std::wcout << L',';
                std::wcout << L"{\"event\":" << event << L",\"flags\":" << flags << L'}';
                comma = true;
            } else {
                Line(L"  event " + std::to_wstring(event) + L" flags=0x" + [&] {
                    std::wostringstream value; value << std::hex << flags; return value.str(); }());
            }
        }
        if (event == std::numeric_limits<std::uint32_t>::max()) break;
    }
    if (json) std::wcout << L"]}\n";
    return 0;
}

int OwnedIds(std::wstring_view supplied, std::wstring_view family,
             std::uint32_t selector, bool json) {
    GUID id{};
    if (!ParseGuid(supplied, id)) return 2;
    Api api;
    if (!api.Load() || !api.connect_client || !api.free_memory) return 1;
    Api::EnumerateIds enumerate = nullptr;
    if (family == L"rules") enumerate = api.enumerate_rule_ids;
    else if (family == L"queues") enumerate = api.enumerate_queue_ids;
    else if (family == L"collections") enumerate = api.enumerate_collection_ids;
    else return Line(L"[-] family must be rules, queues, or collections"), 2;
    if (!enumerate) return Failure(L"resolve enumeration export", HRESULT_FROM_WIN32(ERROR_PROC_NOT_FOUND)), 1;
    ConnectedClient client{&api};
    HRESULT hr = api.connect_client(&id, &client.handle);
    if (FAILED(hr)) return Failure(L"EspConnectClient", hr), 1;
    GuidList list;
    list.api = &api;
    hr = enumerate(client.handle, selector, &list.count, &list.values);
    if (FAILED(hr)) return Failure(L"EspEnumerate*Ids", hr), 1;
    if (json) {
        std::wcout << L"{\"schema\":\"wesplab.ids.v1\",\"family\":\"" << family
                   << L"\",\"selector\":" << selector << L",\"ids\":[";
        for (std::uint32_t index = 0; index < list.count; ++index) {
            if (index) std::wcout << L',';
            std::wcout << L"\"" << GuidString(list.values[index]) << L"\"";
        }
        std::wcout << L"]}\n";
    } else {
        Line(std::wstring(family) + L": " + std::to_wstring(list.count));
        for (std::uint32_t index = 0; index < list.count; ++index) Line(L"  " + GuidString(list.values[index]));
    }
    return 0;
}

int PropertySupport(std::wstring_view supplied, std::wstring_view family,
                    std::uint32_t first, std::uint32_t last, bool json) {
    GUID id{};
    if (!ParseGuid(supplied, id) || first > last || last - first > 100000) return 2;
    static constexpr std::pair<std::wstring_view, const char*> families[] = {
        {L"client", "EspIsClientPropertySupported"}, {L"event", "EspIsEventPropertySupported"},
        {L"token", "EspIsTokenPropertySupported"}, {L"mailslot", "EspIsMailslotPropertySupported"},
        {L"pipe", "EspIsPipePropertySupported"}, {L"ktm", "EspIsKtmTransactionPropertySupported"},
        {L"desktop", "EspIsDesktopPropertySupported"}, {L"registry-object", "EspIsRegistryKeyObjectPropertySupported"},
        {L"registry", "EspIsRegistryKeyPropertySupported"}, {L"disk", "EspIsDiskPropertySupported"},
        {L"volume", "EspIsVolumePropertySupported"}, {L"file-object", "EspIsFileObjectPropertySupported"},
        {L"file", "EspIsFilePropertySupported"}, {L"stream", "EspIsFileStreamPropertySupported"},
        {L"process", "EspIsProcessPropertySupported"}, {L"thread", "EspIsThreadPropertySupported"},
    };
    const char* export_name = nullptr;
    for (const auto& entry : families) if (entry.first == family) export_name = entry.second;
    if (!export_name) return Line(L"[-] unknown property family"), 2;
    Api api;
    if (!api.Load() || !api.connect_client) return 1;
    Api::IsPropertySupported function = nullptr;
    api.Get(export_name, function);
    if (!function) return 1;
    ConnectedClient client{&api};
    HRESULT hr = api.connect_client(&id, &client.handle);
    if (FAILED(hr)) return Failure(L"EspConnectClient", hr), 1;
    if (json) std::wcout << L"{\"schema\":\"wesplab.properties.v1\",\"family\":\"" << family << L"\",\"supported\":[";
    bool comma = false;
    for (std::uint32_t property = first; property <= last; ++property) {
        int supported = 0;
        hr = function(client.handle, property, &supported);
        if (SUCCEEDED(hr) && supported) {
            if (json) { if (comma) std::wcout << L','; std::wcout << property; comma = true; }
            else Line(L"  property " + std::to_wstring(property));
        }
        if (property == std::numeric_limits<std::uint32_t>::max()) break;
    }
    if (json) std::wcout << L"]}\n";
    return 0;
}

int AuthzProbe(std::wstring_view supplied) {
    GUID id{};
    if (!ParseGuid(supplied, id)) return 2;
    Api api;
    if (!api.Load()) return 1;
    GuidList registered, connected;
    HRESULT management_registered = Enumerate(api, false, registered);
    HRESULT management_connected = Enumerate(api, true, connected);
    OpaqueHandle handle = nullptr;
    HRESULT connect = api.connect_client ? api.connect_client(&id, &handle)
                                         : HRESULT_FROM_WIN32(ERROR_PROC_NOT_FOUND);
    HRESULT rules = E_HANDLE, queues = E_HANDLE, collections = E_HANDLE, capabilities = E_HANDLE;
    auto enumerate_ids = [&](Api::EnumerateIds function, HRESULT& result) {
        if (!function || !api.free_memory) {
            result = HRESULT_FROM_WIN32(ERROR_PROC_NOT_FOUND);
            return;
        }
        std::uint32_t count = 0;
        GUID* values = nullptr;
        result = function(handle, 1, &count, &values);
        if (values) api.free_memory(values);
    };
    if (SUCCEEDED(connect) && handle) {
        enumerate_ids(api.enumerate_rule_ids, rules);
        enumerate_ids(api.enumerate_queue_ids, queues);
        enumerate_ids(api.enumerate_collection_ids, collections);
        std::uint32_t flags = 0;
        capabilities = api.get_capabilities
            ? api.get_capabilities(handle, kProcessCreateEvent, &flags)
            : HRESULT_FROM_WIN32(ERROR_PROC_NOT_FOUND);
        api.disconnect_client(handle);
    }
    std::wcout << L"{\"schema\":\"wesplab.authz-probe.v2\",\"target\":\"" << GuidString(id)
               << L"\",\"enumerate_registered_hresult\":" << static_cast<std::int32_t>(management_registered)
               << L",\"enumerate_connected_hresult\":" << static_cast<std::int32_t>(management_connected)
               << L",\"connect_hresult\":" << static_cast<std::int32_t>(connect)
               << L",\"enumerate_rules_hresult\":" << static_cast<std::int32_t>(rules)
               << L",\"enumerate_queues_hresult\":" << static_cast<std::int32_t>(queues)
               << L",\"enumerate_collections_hresult\":" << static_cast<std::int32_t>(collections)
               << L",\"process_create_capabilities_hresult\":" << static_cast<std::int32_t>(capabilities)
               << L"}\n";
    return 0;
}

int Snapshot() {
    Api api;
    if (!api.Load()) return 1;
    GuidList registered, connected;
    HRESULT hr1 = Enumerate(api, false, registered);
    HRESULT hr2 = Enumerate(api, true, connected);
    std::wcout << L"{\n  \"schema\": \"wesplab.live-snapshot.v1\",\n"
               << L"  \"registered_hresult\": " << static_cast<std::int32_t>(hr1) << L",\n"
               << L"  \"connected_hresult\": " << static_cast<std::int32_t>(hr2) << L",\n"
               << L"  \"registered\": [";
    for (std::uint32_t i = 0; SUCCEEDED(hr1) && i < registered.count; ++i) {
        if (i) std::wcout << L',';
        std::wcout << L"\"" << GuidString(registered.values[i]) << L"\"";
    }
    std::wcout << L"],\n  \"connected\": [";
    for (std::uint32_t i = 0; SUCCEEDED(hr2) && i < connected.count; ++i) {
        if (i) std::wcout << L',';
        std::wcout << L"\"" << GuidString(connected.values[i]) << L"\"";
    }
    std::wcout << L"]\n}\n";
    return FAILED(hr1) || FAILED(hr2) ? 1 : 0;
}

int WatchClients(std::uint32_t seconds) {
    Api api;
    if (!api.Load()) return 1;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(seconds);
    std::uint64_t samples = 0;
    do {
        GuidList registered, connected;
        const HRESULT hr1 = Enumerate(api, false, registered);
        const HRESULT hr2 = Enumerate(api, true, connected);
        if (FAILED(hr1) || FAILED(hr2)) return 1;
        ++samples;
        std::this_thread::sleep_for(std::chrono::milliseconds(250));
    } while (std::chrono::steady_clock::now() < deadline);
    Line(L"[+] read-only client-state samples: " + std::to_wstring(samples));
    return 0;
}

struct MonitorState {
    Api* api{};
    OpaqueHandle queue{};
    GUID queue_id{};
    GUID rule_id{};
    std::mutex gate;
    bool stopping{};
    std::atomic_uint64_t count{};
    std::atomic<HRESULT> error{S_OK};
    std::ofstream capture;
};

bool Readable(const void* address, std::size_t length) {
    if (!address || !length) return false;
    auto cursor = reinterpret_cast<std::uintptr_t>(address);
    if (cursor + length < cursor) return false;
    const auto end = cursor + length;
    while (cursor < end) {
        MEMORY_BASIC_INFORMATION info{};
        if (VirtualQuery(reinterpret_cast<void*>(cursor), &info, sizeof(info)) != sizeof(info) ||
            info.State != MEM_COMMIT || (info.Protect & (PAGE_GUARD | PAGE_NOACCESS))) return false;
        auto next = reinterpret_cast<std::uintptr_t>(info.BaseAddress) + info.RegionSize;
        if (next <= cursor) return false;
        cursor = std::min(next, end);
    }
    return true;
}

void WINAPI EventCallback(void* notification, void* raw_state) noexcept {
    auto& state = *static_cast<MonitorState*>(raw_state);
    const std::scoped_lock lock(state.gate);
    if (!notification || state.stopping) return;
    try {
        auto* bytes = static_cast<std::byte*>(notification);
        NotificationHeader header{};
        if (Readable(bytes, sizeof(header))) {
            std::memcpy(&header, bytes, sizeof(header));
            if (IsEqualGUID(header.queue_id, state.queue_id) && Readable(header.data, sizeof(EventDataPrefix))) {
                EventDataPrefix event{};
                std::memcpy(&event, header.data, sizeof(event));
                const std::string timestamp = UtcNow();
                Line(L"{\"timestamp_utc\":\"" + std::wstring(timestamp.begin(), timestamp.end()) +
                     L"\",\"event_type\":" + std::to_wstring(event.event_type) +
                     L",\"instance_id\":" + std::to_wstring(event.instance_id) +
                     L",\"rule_id\":\"" + GuidString(event.rule_id) + L"\"}");
                if (state.capture) {
                    const std::uint32_t wanted = std::min(header.external_size, kMaxCapturedPayload);
                    const bool payload_readable = wanted == 0 || Readable(header.external_payload, wanted);
                    state.capture << "{\"schema\":\"wesplab.notification-capture.v1\","
                                  << "\"timestamp_utc\":\"" << timestamp << "\","
                                  << "\"queue_id\":\"" << NarrowAscii(GuidString(header.queue_id)) << "\","
                                  << "\"event_type\":" << event.event_type << ','
                                  << "\"event_data_hex\":\"" << Hex(&event, sizeof(event)) << "\","
                                  << "\"external_payload_hex\":\""
                                  << (payload_readable && wanted ? Hex(header.external_payload, wanted) : "") << "\","
                                  << "\"external_size\":" << header.external_size << ','
                                  << "\"truncated\":" << (wanted != header.external_size ? "true" : "false") << ','
                                  << "\"payload_readable\":" << (payload_readable ? "true" : "false") << "}\n";
                    state.capture.flush();
                }
                ++state.count;
            }
        }
        HRESULT hr = state.api->complete_notification(notification);
        if (SUCCEEDED(hr)) hr = state.api->arm_notification(state.queue, notification);
        if (FAILED(hr)) { state.error.store(hr); g_stop.store(true); }
    } catch (...) {
        state.error.store(E_FAIL);
        g_stop.store(true);
    }
}

BOOL WINAPI CtrlHandler(DWORD type) {
    if (type == CTRL_C_EVENT || type == CTRL_BREAK_EVENT || type == CTRL_CLOSE_EVENT) {
        g_stop.store(true);
        return TRUE;
    }
    return FALSE;
}

int MonitorProcess(std::uint32_t seconds, bool write, std::wstring_view capture_path) {
    if (!RequireWrite(write, true)) return 2;
    Api api;
    if (!api.Load() || !api.register_client || !api.unregister_client || !api.connect_client ||
        !api.create_queue || !api.connect_queue || !api.create_rule || !api.update_rules ||
        !api.allocate_notification || !api.arm_notification) return 1;
    GUID client_id{}, queue_id{}, rule_id{};
    if (FAILED(CoCreateGuid(&client_id)) || FAILED(CoCreateGuid(&queue_id)) || FAILED(CoCreateGuid(&rule_id))) return 1;
    Line(L"[*] temporary client: " + GuidString(client_id));
    ClientDescriptor descriptor{client_id, kClientName, kMonitorAltitude};
    HRESULT hr = api.register_client(&descriptor);
    if (FAILED(hr)) return Failure(L"EspRegisterClient", hr), 1;
    OpaqueHandle client = nullptr, queue = nullptr, rule = nullptr;
    void* notification = nullptr;
    bool delivery = false;
    auto cleanup = [&] {
        if (delivery && queue) {
            HRESULT disconnect = api.disconnect_queue(queue);
            if (FAILED(disconnect)) {
                Failure(L"cleanup EspDisconnectEventQueue", disconnect);
                HRESULT close = api.close_queue(queue);
                if (FAILED(close)) {
                    Failure(L"cleanup EspCloseEventQueue", close);
                    Line(L"[-] callbacks could not be drained; refusing to free callback-owned state");
                    std::quick_exit(1);
                }
                queue = nullptr;
            }
            delivery = false;
        }
        if (rule) api.close_rule(rule);
        if (notification) api.free_notification(notification);
        if (queue) api.close_queue(queue);
        if (client) api.disconnect_client(client);
        HRESULT remove = api.unregister_client(&client_id);
        if (FAILED(remove)) Failure(L"cleanup EspUnregisterClient", remove);
    };
    hr = api.connect_client(&client_id, &client);
    if (FAILED(hr)) { Failure(L"EspConnectClient", hr); cleanup(); return 1; }
    EventQueueDescriptor queue_descriptor{queue_id, 1, 1, 64u * 1024u * 1024u, 1};
    hr = api.create_queue(client, &queue_descriptor, &queue);
    if (FAILED(hr)) { Failure(L"EspCreateEventQueue", hr); cleanup(); return 1; }
    MonitorState state;
    state.api = &api;
    state.queue = queue;
    state.queue_id = queue_id;
    state.rule_id = rule_id;
    if (!capture_path.empty()) {
        state.capture.open(std::filesystem::path(capture_path), std::ios::binary | std::ios::app);
        if (!state.capture) {
            Line(L"[-] could not open notification capture output");
            cleanup();
            return 1;
        }
    }
    hr = api.connect_queue(queue, 1, EventCallback, &state);
    if (FAILED(hr)) { Failure(L"EspConnectEventQueueWithCallback", hr); cleanup(); return 1; }
    delivery = true;
    notification = api.allocate_notification();
    hr = notification ? api.arm_notification(queue, notification) : E_OUTOFMEMORY;
    if (FAILED(hr)) { Failure(L"EspArmEventNotification", hr); cleanup(); return 1; }
    std::array<std::uint32_t, 3> properties{kProcessId, kProcessImagePath, kProcessCommandLine};
    ProcessCreateConfig config{};
    config.mask = 0x08;
    config.property_count = static_cast<std::uint32_t>(properties.size());
    config.property_ids = properties.data();
    RuleDescriptor rule_descriptor{};
    rule_descriptor.id = rule_id;
    rule_descriptor.order_group = 100;
    rule_descriptor.lifetime = 1;
    rule_descriptor.event_type = kProcessCreateEvent;
    rule_descriptor.event_config = &config;
    rule_descriptor.action = 1;
    rule_descriptor.action_object = queue;
    hr = api.create_rule(&rule_descriptor, &rule);
    if (FAILED(hr)) { Failure(L"EspCreateRule", hr); cleanup(); return 1; }
    RuleUpdate update{1, 0, rule, 0};
    hr = api.update_rules(client, 0, 1, &update);
    if (FAILED(hr)) { Failure(L"EspUpdateRules", hr); cleanup(); return 1; }
    Line(L"[+] monitoring ProcessCreate; Ctrl+C stops safely");
    g_stop.store(false);
    SetConsoleCtrlHandler(CtrlHandler, TRUE);
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(seconds);
    while (!g_stop.load() && (!seconds || std::chrono::steady_clock::now() < deadline)) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    {
        const std::scoped_lock lock(state.gate);
        state.stopping = true;
    }
    SetConsoleCtrlHandler(CtrlHandler, FALSE);
    cleanup();
    Line(L"[+] events: " + std::to_wstring(state.count.load()));
    if (FAILED(state.error.load())) { Failure(L"notification loop", state.error.load()); return 1; }
    return 0;
}

void Usage() {
    std::wcout <<
        L"wesplab-runtime 0.2.0 (ABI 0.1.0.156346177)\n\n"
        L"Read-only:\n"
        L"  wesplab-runtime doctor [--json]\n"
        L"  wesplab-runtime clients [registered|connected] [--json]\n"
        L"  wesplab-runtime watch-clients [seconds]\n"
        L"  wesplab-runtime snapshot\n"
        L"  wesplab-runtime capabilities <client-guid> <first-event> <last-event> [--json]\n\n"
        L"  wesplab-runtime ids <client-guid> <rules|queues|collections> [selector] [--json]\n"
        L"  wesplab-runtime properties <client-guid> <family> <first> <last> [--json]\n"
        L"  wesplab-runtime authz-probe <client-guid>\n\n"
        L"Mutating (explicit consent):\n"
        L"  wesplab-runtime register [guid] --write [--name TEXT] [--altitude TEXT]\n"
        L"  wesplab-runtime remove <guid> --write [--cross-client-test]\n"
        L"  wesplab-runtime monitor-process [seconds] --write [--capture FILE.jsonl]\n\n"
        L"monitor-process and cross-client tests additionally require " << kLabMarker << L".\n"
        L"Use wesplab.py for inspect, build diff, protocol lookup, and corpus generation.\n";
}

bool Has(int argc, wchar_t** argv, std::wstring_view option) {
    for (int i = 2; i < argc; ++i) if (std::wstring_view(argv[i]) == option) return true;
    return false;
}

std::wstring_view OptionValue(int argc, wchar_t** argv, std::wstring_view option) {
    for (int i = 2; i + 1 < argc; ++i) {
        if (std::wstring_view(argv[i]) == option) return argv[i + 1];
    }
    return {};
}

bool Number(std::wstring_view text, std::uint32_t& value) {
    if (text.empty()) return false;
    std::uint64_t wide = 0;
    for (wchar_t ch : text) {
        if (ch < L'0' || ch > L'9') return false;
        wide = wide * 10 + static_cast<unsigned>(ch - L'0');
        if (wide > std::numeric_limits<std::uint32_t>::max()) return false;
    }
    value = static_cast<std::uint32_t>(wide);
    return true;
}

int Run(int argc, wchar_t** argv) {
    if (argc < 2 || std::wstring_view(argv[1]) == L"--help") { Usage(); return 0; }
    const std::wstring_view command(argv[1]);
    const bool json = Has(argc, argv, L"--json");
    const bool write = Has(argc, argv, L"--write");
    if (command == L"doctor") return Doctor(json);
    if (command == L"clients") {
        const bool connected = argc > 2 && std::wstring_view(argv[2]) == L"connected";
        return Clients(connected, json);
    }
    if (command == L"watch-clients") {
        std::uint32_t seconds = 30;
        if (argc > 2 && argv[2][0] != L'-' && !Number(argv[2], seconds)) return 2;
        return WatchClients(seconds);
    }
    if (command == L"snapshot") return Snapshot();
    if (command == L"register") {
        std::wstring_view guid = argc > 2 && argv[2][0] != L'-' ? argv[2] : L"";
        auto name = OptionValue(argc, argv, L"--name");
        auto altitude = OptionValue(argc, argv, L"--altitude");
        if (name.empty()) name = kClientName;
        if (altitude.empty()) altitude = kClientAltitude;
        return RegisterClient(guid, write, name, altitude);
    }
    if (command == L"remove" && argc >= 3) return RemoveClient(argv[2], write, Has(argc, argv, L"--cross-client-test"));
    if (command == L"capabilities" && argc >= 5) {
        std::uint32_t first = 0, last = 0;
        if (!Number(argv[3], first) || !Number(argv[4], last)) return 2;
        return Capabilities(argv[2], first, last, json);
    }
    if (command == L"ids" && argc >= 4) {
        std::uint32_t selector = 1;
        if (argc >= 5 && argv[4][0] != L'-' && !Number(argv[4], selector)) return 2;
        return OwnedIds(argv[2], argv[3], selector, json);
    }
    if (command == L"properties" && argc >= 6) {
        std::uint32_t first = 0, last = 0;
        if (!Number(argv[4], first) || !Number(argv[5], last)) return 2;
        return PropertySupport(argv[2], argv[3], first, last, json);
    }
    if (command == L"authz-probe" && argc >= 3) return AuthzProbe(argv[2]);
    if (command == L"monitor-process") {
        std::uint32_t seconds = 60;
        if (argc > 2 && argv[2][0] != L'-' && !Number(argv[2], seconds)) return 2;
        const auto capture = OptionValue(argc, argv, L"--capture");
        if (Has(argc, argv, L"--capture") && capture.empty()) {
            Line(L"[-] --capture requires an output path");
            return 2;
        }
        return MonitorProcess(seconds, write, capture);
    }
    Usage();
    return 2;
}

}  // namespace

int wmain(int argc, wchar_t** argv) {
    try {
        return Run(argc, argv);
    } catch (const std::exception& error) {
        std::cerr << "wesplab: " << error.what() << '\n';
        return 1;
    }
}
