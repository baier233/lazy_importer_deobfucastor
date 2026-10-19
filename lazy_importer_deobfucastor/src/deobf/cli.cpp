#include "cli.h"
#include "deobfuscator.h"
#include <fstream>
#include <iostream>
#include <set>

namespace deobf {
namespace {
std::string ascii(const std::wstring& text) {
    std::string result;
    for (const auto c : text) {
        if (c < 1 || c > 127) throw pe::error("DLL/symbol identifiers must be ASCII");
        result += static_cast<char>(c);
    }
    return result;
}

std::string utf8(const std::filesystem::path& path) {
    const auto text = path.u8string();
    return std::string(text.begin(), text.end());
}

std::string lowercase(std::string value) {
    for (auto& c : value) if (c >= 'A' && c <= 'Z') c += 'a' - 'A';
    return value;
}

std::uint32_t number(const std::wstring& value) {
    if (value.empty() || value[0] < L'0' || value[0] > L'9') throw pe::error("Invalid unsigned RVA");
    std::size_t used = 0;
    const auto n = std::stoull(value, &used, value.size() > 2 && value[0] == L'0' && (value[1] == L'x' || value[1] == L'X') ? 16 : 10);
    if (used != value.size() || n > UINT32_MAX) throw pe::error("RVA exceeds 32 bits");
    return static_cast<std::uint32_t>(n);
}

void require_new(const std::filesystem::path& path) {
    if (std::filesystem::exists(path)) throw pe::error("Output/report already exists: " + utf8(path));
    const auto parent = path.parent_path();
    if (!parent.empty() && !std::filesystem::is_directory(parent)) throw pe::error("Output/report directory does not exist");
}

void report(const analysis& plan, const std::filesystem::path& path) {
    require_new(path);
    std::ofstream stream(path, std::ios::binary | std::ios::trunc);
    const auto json = to_json(plan);
    if (!stream || !stream.write(json.data(), json.size())) throw pe::error("Cannot write analysis report");
    stream.close();
    if (!stream) throw pe::error("Cannot finish analysis report");
}

void summarize(const analysis& plan) {
    for (const auto& c : plan.candidates) {
        std::cout << "RVA 0x" << std::hex << c.entry_rva << " [" << status_name(c.state) << ']';
        if (c.has_hash) std::cout << " seed=0x" << c.seed << " prime=0x" << c.prime << " hash=0x" << c.hash;
        if (c.api) std::cout << " -> " << c.api->module << '!' << c.api->name;
        if (c.iat_rva) std::cout << " IAT=0x" << *c.iat_rva;
        if (!c.reason.empty()) std::cout << " (" << c.reason << ')';
        std::cout << '\n';
    }
    std::cout << std::dec << "Candidates: " << plan.candidates.size() << ", ready: " << plan.count(status::ready)
        << ", patched: " << plan.count(status::patched) << ", unresolved: " << plan.count(status::unresolved)
        << ", ambiguous: " << plan.count(status::ambiguous) << ", unsupported: " << plan.count(status::unsupported) << '\n';
    for (const auto& note : plan.diagnostics) std::cerr << "Note: " << note << '\n';
}
void print_usage() {
    std::cout << "AMD64 lazy_importer deobfuscation and PE rebuilding\n"
        "  lazy_importer_deobfucastor rebuild <input> <output> [options]\n"
        "    --dll <name-or-path>       Add an offline export provider (repeatable)\n"
        "    --dll-dir <directory>      Search custom DLLs here (repeatable)\n"
        "    --no-default-dlls          Omit kernel32/ntdll/user32 defaults\n"
        "    --map <rva>=<dll>!<name>   Explicit resolution for a detected entry\n"
        "    --strict                  Require every candidate to be repairable\n"
        "    --report <path>           JSON report (default: <output>.json)\n";
}

} // namespace

int run_cli(int argc, wchar_t** argv) {
    if (argc == 1 || (argc == 2 && std::wstring(argv[1]) == L"--help")) {
        print_usage(); return 0;
    }
    if (argc < 4 || std::wstring(argv[1]) != L"rebuild") { print_usage(); return 2; }
    const std::filesystem::path input = argv[2];
    const std::filesystem::path output = argv[3];
    std::filesystem::path report_path = output.wstring() + L".json";
    options config;
    bool defaults = true;
    std::vector<std::filesystem::path> explicit_dlls, directories;
    for (int n = 4; n < argc; ++n) {
        const std::wstring option = argv[n];
        if (option == L"--strict") config.strict = true;
        else if (option == L"--no-default-dlls") defaults = false;
        else if (option == L"--dll" || option == L"--dll-dir" || option == L"--report" || option == L"--map") {
            if (++n == argc) throw pe::error("Missing option value");
            if (option == L"--dll") explicit_dlls.emplace_back(argv[n]);
            else if (option == L"--dll-dir") {
                if (!std::filesystem::is_directory(argv[n])) throw pe::error("DLL search directory does not exist");
                directories.emplace_back(argv[n]);
            } else if (option == L"--report") report_path = argv[n];
            else {
                const std::wstring value = argv[n];
                const auto equals = value.find(L'=');
                const auto bang = value.find(L'!');
                if (equals == std::wstring::npos || bang == std::wstring::npos || bang <= equals + 1 || bang + 1 == value.size())
                    throw pe::error("Expected --map <entry-rva>=<dll>!<name>");
                api_symbol api{ascii(value.substr(equals + 1, bang - equals - 1)), ascii(value.substr(bang + 1)), {}};
                if (!config.overrides.emplace(number(value.substr(0, equals)), std::move(api)).second)
                    throw pe::error("Duplicate manual entry mapping");
            }
        } else { print_usage(); return 2; }
    }
    require_new(output);
    require_new(report_path);
    const auto report_absolute = std::filesystem::absolute(report_path).lexically_normal().wstring();
    const auto output_absolute = std::filesystem::absolute(output).lexically_normal().wstring();
    if (CompareStringOrdinal(report_absolute.c_str(), -1, output_absolute.c_str(), -1, TRUE) == CSTR_EQUAL)
        throw pe::error("PE output and JSON report must use different paths");
    auto image = pe::image::load(input);
    const auto imports = image.imports();
    directories.push_back(std::filesystem::absolute(input).parent_path());
    wchar_t system[MAX_PATH]{};
    const auto system_length = GetSystemDirectoryW(system, MAX_PATH);
    if (system_length && system_length < MAX_PATH) directories.emplace_back(system);
    export_database database;
    std::set<std::string> loaded;
    std::vector<std::string> diagnostics;
    auto load = [&](const std::filesystem::path& requested, bool required) {
        const auto identity = lowercase(utf8(requested.filename()));
        if (loaded.count(identity)) return;
        std::filesystem::path found;
        if (requested.has_parent_path()) {
            if (std::filesystem::is_regular_file(requested)) found = requested;
        } else {
            for (const auto& dir : directories)
                if (std::filesystem::is_regular_file(dir / requested)) { found = dir / requested; break; }
        }
        try {
            if (found.empty()) throw pe::error("DLL not found: " + utf8(requested));
            database.add_file(found);
            loaded.insert(identity);
        } catch (const pe::error& e) {
            if (required) throw;
            diagnostics.push_back(utf8(requested) + ": " + e.what());
            loaded.insert(identity);
        }
    };
    for (const auto& dll : explicit_dlls) load(dll, true);
    if (defaults) for (const auto* dll : {L"KERNEL32.dll", L"NTDLL.dll", L"USER32.dll"}) load(dll, false);
    for (const auto& imported : imports) load(std::filesystem::path(imported.module), false);
    // Existing named imports remain useful even when an offline DLL is unavailable.
    for (const auto& imported : imports)
        if (!imported.symbol.ordinal) database.add(imported.module, {{imported.symbol.name, 0, 1, {}}});
    auto plan = analyze(image, database, config);
    plan.diagnostics = std::move(diagnostics);
    if (!plan.count(status::ready) || (config.strict && plan.count(status::ready) != plan.candidates.size())) {
        summarize(plan); report(plan, report_path);
        std::cerr << "No PE written: no repairable candidates, or strict analysis was incomplete.\n";
        return 3;
    }
    const auto patched = apply(image, plan, config);
    image.save(output);
    report(plan, report_path);
    summarize(plan);
    std::cout << "Saved " << patched << " repaired call sites to " << utf8(output) << '\n';
    return 0;
}
} // namespace deobf
