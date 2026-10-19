#pragma once

#include "../disasm/disassembler.h"
#include <map>
#include <string_view>
#include <unordered_map>

namespace deobf {

std::uint32_t hash_name(std::string_view name, std::uint32_t seed, std::uint32_t prime);

struct api_symbol {
    std::string module;
    std::string name;
    std::string forwarder;
};

// Offline export catalog. No LoadLibrary/GetProcAddress or target execution.
class export_database {
public:
    void add(const std::string& module, const std::vector<pe::exported_function>& exports);
    void add_file(const std::filesystem::path& path);
    const std::vector<api_symbol>& symbols() const noexcept { return symbols_; }
    std::vector<api_symbol> match(std::uint32_t seed, std::uint32_t prime, std::uint32_t hash) const;
    std::string canonical(const api_symbol& symbol) const;
private:
    std::vector<api_symbol> symbols_;
    std::unordered_map<std::string, std::size_t> index_;
};

struct options {
    std::size_t max_resolver_bytes = 2048;
    std::size_t max_liveness_instructions = 4096;
    bool strict = false; // No edits if any detected candidate is not ready.
    std::map<std::uint32_t, api_symbol> overrides; // Entry RVA -> explicit DLL!name.
};

enum class status { unsupported, unresolved, ambiguous, ready, patched };
const char* status_name(status value) noexcept;

struct candidate {
    std::uint32_t entry_rva = 0;
    std::uint32_t end_rva = 0; // Exclusive; original call return address.
    std::uint32_t call_rva = 0;
    std::uint32_t seed = 0, prime = 0, hash = 0;
    bool has_hash = false;
    status state = status::unsupported;
    std::string reason;
    std::vector<api_symbol> matches;
    std::optional<api_symbol> api;
    std::optional<std::uint32_t> iat_rva;
    std::vector<disasm::instruction> parameters;
    pe::bytes original_bytes;
};

struct analysis {
    std::vector<candidate> candidates;
    std::vector<std::string> diagnostics;
    std::uint64_t source_fingerprint = 0;
    std::uint64_t image_base = 0;
    std::size_t source_size = 0;
    std::size_t count(status value) const noexcept;
};

// Scans all executable sections for the MSVC inline pattern used by the reference
// PoC. Unsupported PEB resolver shapes are reported, never force-patched.
analysis analyze(const pe::image& image, const export_database& exports, const options& config = {});

// Transactional: appends only required imports and replaces ready candidates.
// Relocates retained parameter instructions and preserves the original return RVA.
std::size_t apply(pe::image& image, analysis& plan, const options& config = {});
std::string to_json(const analysis& plan);

} // namespace deobf
