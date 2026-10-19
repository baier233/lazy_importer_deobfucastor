#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

namespace pe {

using bytes = std::vector<std::uint8_t>;

class error : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

struct section {
    std::string name;
    IMAGE_SECTION_HEADER header{};
    bool executable() const noexcept { return (header.Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0; }
};

struct import_symbol {
    std::string name;                       // Empty for ordinal imports.
    std::optional<std::uint16_t> ordinal;
    std::uint16_t hint = 0;
};

struct import_module {
    std::string name;
    std::vector<import_symbol> symbols;
};

struct imported_function {
    std::string module;
    import_symbol symbol;
    std::uint32_t iat_rva = 0;
};

struct exported_function {
    std::string name;                       // Empty for ordinal-only exports.
    std::uint32_t ordinal = 0;
    std::uint32_t rva = 0;
    std::string forwarder;                  // e.g. KERNELBASE.CreateFileW
};

// Owns an on-disk PE image; never loads or executes the target.
// PE validation/I/O failures throw pe::error (allocation failures may throw std::bad_alloc).
// Mutation invalidates references into data()/sections().
class image {
public:
    static image load(const std::filesystem::path& path);
    static image from_bytes(bytes data);

    const bytes& data() const noexcept { return data_; }
    const std::vector<section>& sections() const noexcept { return sections_; }
    std::uint64_t image_base() const noexcept { return optional_.ImageBase; }
    std::uint32_t entry_point() const noexcept { return optional_.AddressOfEntryPoint; }
    std::uint32_t image_size() const noexcept { return optional_.SizeOfImage; }
    IMAGE_DATA_DIRECTORY directory(std::size_t index) const;

    // A range must be contiguous and backed by file bytes (not .bss or an RVA gap).
    std::optional<std::size_t> rva_to_offset(std::uint32_t rva, std::size_t size = 1) const;
    std::optional<std::uint32_t> va_to_rva(std::uint64_t va) const;
    std::uint64_t rva_to_va(std::uint32_t rva) const;
    bytes read_rva(std::uint32_t rva, std::size_t size) const;
    void patch_rva(std::uint32_t rva, const bytes& patch);
    // Validate a raw-backed executable region with no overlapping base relocations.
    void validate_code_patch(std::uint32_t rva, std::size_t size) const;

    std::vector<imported_function> imports() const;
    std::vector<exported_function> exports() const;

    // Appends imports while preserving existing IAT slot RVAs. Returned entries refer
    // to the new slots; the caller must explicitly patch resolved lazy_importer call sites.
    std::vector<imported_function> rebuild_imports(const std::vector<import_module>& modules,
        const std::string& section_name = ".liimp");

    // Recomputes size fields and PE checksum; invalidates the Authenticode directory.
    bytes rebuild() const;
    void save(const std::filesystem::path& path) const;

private:
    image() = default;
    bytes data_;
    IMAGE_FILE_HEADER file_{};
    IMAGE_OPTIONAL_HEADER64 optional_{};
    std::vector<section> sections_;
    std::size_t nt_offset_ = 0;
    std::size_t optional_offset_ = 0;
    std::size_t section_offset_ = 0;

    void parse();
    void write_headers();
    void invalidate_signature();
    void insert_file_space(std::size_t offset, std::size_t count);
    std::uint32_t add_section_impl(const std::string&, const bytes&, std::uint32_t);
    std::vector<IMAGE_IMPORT_DESCRIPTOR> import_descriptors() const;
    std::string string_at(std::uint32_t rva) const;
};

} // namespace pe
