#include "image.h"

#include <algorithm>
#include <cstring>
#include <fstream>
#include <limits>
#include <utility>

namespace pe {
namespace {
bool fits(std::size_t offset, std::size_t size, std::size_t limit) {
    return offset <= limit && size <= limit - offset;
}

template<class T> T read(const bytes& data, std::size_t offset) {
    if (!fits(offset, sizeof(T), data.size())) throw error("Truncated PE structure");
    T value{};
    std::memcpy(&value, data.data() + offset, sizeof(T));
    return value;
}

template<class T> void write(bytes& data, std::size_t offset, const T& value) {
    if (!fits(offset, sizeof(T), data.size())) throw error("PE write outside file");
    std::memcpy(data.data() + offset, &value, sizeof(T));
}

std::uint32_t u32(std::uint64_t value) {
    if (value > UINT32_MAX) throw error("PE size or RVA exceeds 32 bits");
    return static_cast<std::uint32_t>(value);
}

std::uint32_t align_up(std::uint64_t value, std::uint32_t alignment) {
    if (!alignment || (alignment & (alignment - 1))) throw error("Invalid PE alignment");
    return u32((value + alignment - 1) & ~static_cast<std::uint64_t>(alignment - 1));
}

std::uint32_t extent(const IMAGE_SECTION_HEADER& s) {
    return std::max(s.Misc.VirtualSize, s.SizeOfRawData);
}

bool overlaps(std::uint64_t a, std::uint64_t as, std::uint64_t b, std::uint64_t bs) {
    return as && bs && a < b + bs && b < a + as;
}

void valid_name(const std::string& value) {
    if (value.empty() || value.find('\0') != std::string::npos)
        throw error("Import names must be non-empty and contain no NUL bytes");
}
} // namespace

image image::load(const std::filesystem::path& path) {
    std::ifstream stream(path, std::ios::binary | std::ios::ate);
    if (!stream) throw error("Cannot open input file");
    const auto size = stream.tellg();
    if (size < 0 || static_cast<std::uint64_t>(size) > UINT32_MAX)
        throw error("Invalid or unsupported file size");
    bytes data(static_cast<std::size_t>(size));
    stream.seekg(0);
    if (!data.empty() && !stream.read(reinterpret_cast<char*>(data.data()), data.size()))
        throw error("Cannot read input file");
    return from_bytes(std::move(data));
}

image image::from_bytes(bytes data) {
    if (data.size() > UINT32_MAX) throw error("PE file exceeds 4 GiB");
    image result;
    result.data_ = std::move(data);
    result.parse();
    return result;
}

void image::parse() {
    const auto dos = read<IMAGE_DOS_HEADER>(data_, 0);
    if (dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew < sizeof(IMAGE_DOS_HEADER))
        throw error("Invalid DOS header");
    nt_offset_ = static_cast<std::size_t>(dos.e_lfanew);
    if (read<DWORD>(data_, nt_offset_) != IMAGE_NT_SIGNATURE) throw error("Invalid PE signature");
    file_ = read<IMAGE_FILE_HEADER>(data_, nt_offset_ + sizeof(DWORD));
    optional_offset_ = nt_offset_ + sizeof(DWORD) + sizeof(file_);
    if (file_.SizeOfOptionalHeader < sizeof(optional_)) throw error("Truncated PE32+ optional header");
    optional_ = read<IMAGE_OPTIONAL_HEADER64>(data_, optional_offset_);
    if (file_.Machine != IMAGE_FILE_MACHINE_AMD64 || optional_.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        throw error("Only AMD64 PE32+ images are supported");
    if (!file_.NumberOfSections || file_.NumberOfSections > 96 || optional_.NumberOfRvaAndSizes > 16)
        throw error("Invalid section or directory count");
    const auto fa = optional_.FileAlignment;
    const auto sa = optional_.SectionAlignment;
    align_up(0, fa);
    align_up(0, sa);
    if (sa < fa || (sa < 0x1000 ? fa != sa : fa < 0x200 || fa > 0x10000))
        throw error("Unsupported PE alignment");
    section_offset_ = optional_offset_ + file_.SizeOfOptionalHeader;
    if (!fits(section_offset_, file_.NumberOfSections * sizeof(IMAGE_SECTION_HEADER), optional_.SizeOfHeaders)
        || optional_.SizeOfHeaders > data_.size() || optional_.SizeOfHeaders % fa
        || optional_.SizeOfImage < optional_.SizeOfHeaders || optional_.SizeOfImage % sa
        || optional_.ImageBase > UINT64_MAX - optional_.SizeOfImage)
        throw error("Invalid header or image size");
    if (optional_.AddressOfEntryPoint && optional_.AddressOfEntryPoint >= optional_.SizeOfImage)
        throw error("Entry point outside image");
    sections_.clear();
    for (std::size_t i = 0; i < file_.NumberOfSections; ++i) {
        section s;
        s.header = read<IMAGE_SECTION_HEADER>(data_, section_offset_ + i * sizeof(IMAGE_SECTION_HEADER));
        const auto& h = s.header;
        for (auto ch : h.Name) { if (!ch) break; s.name.push_back(static_cast<char>(ch)); }
        if (extent(h) && (h.VirtualAddress % sa || h.VirtualAddress < optional_.SizeOfHeaders
            || !fits(h.VirtualAddress, extent(h), optional_.SizeOfImage)))
            throw error("Section virtual range outside image or misaligned");
        if (h.SizeOfRawData && (h.PointerToRawData < optional_.SizeOfHeaders
            || h.PointerToRawData % fa || h.SizeOfRawData % fa
            || !fits(h.PointerToRawData, h.SizeOfRawData, data_.size())
            || (sa < 0x1000 && h.PointerToRawData != h.VirtualAddress)))
            throw error("Section raw range outside file or misaligned");
        for (const auto& other : sections_) {
            const auto& o = other.header;
            if (overlaps(h.VirtualAddress, extent(h), o.VirtualAddress, extent(o))
                || overlaps(h.PointerToRawData, h.SizeOfRawData, o.PointerToRawData, o.SizeOfRawData))
                throw error("Overlapping PE sections");
        }
        sections_.push_back(std::move(s));
    }
}

void image::write_headers() {
    write(data_, nt_offset_ + sizeof(DWORD), file_);
    write(data_, optional_offset_, optional_);
    for (std::size_t i = 0; i < sections_.size(); ++i)
        write(data_, section_offset_ + i * sizeof(IMAGE_SECTION_HEADER), sections_[i].header);
}

IMAGE_DATA_DIRECTORY image::directory(std::size_t index) const {
    if (index >= IMAGE_NUMBEROF_DIRECTORY_ENTRIES) throw error("Invalid directory index");
    return index < optional_.NumberOfRvaAndSizes ? optional_.DataDirectory[index] : IMAGE_DATA_DIRECTORY{};
}

std::optional<std::size_t> image::rva_to_offset(std::uint32_t rva, std::size_t size) const {
    if (rva < optional_.SizeOfHeaders && fits(rva, size, optional_.SizeOfHeaders)) return rva;
    for (const auto& s : sections_) {
        const auto& h = s.header;
        if (rva >= h.VirtualAddress) {
            const auto delta = rva - h.VirtualAddress;
            if (delta < h.SizeOfRawData && fits(delta, size, h.SizeOfRawData))
                return static_cast<std::size_t>(h.PointerToRawData) + delta;
        }
    }
    return std::nullopt;
}

std::optional<std::uint32_t> image::va_to_rva(std::uint64_t va) const {
    if (va < image_base() || va - image_base() >= image_size()) return std::nullopt;
    return static_cast<std::uint32_t>(va - image_base());
}

std::uint64_t image::rva_to_va(std::uint32_t rva) const {
    if (rva >= image_size()) throw error("RVA outside image");
    return image_base() + rva;
}

bytes image::read_rva(std::uint32_t rva, std::size_t size) const {
    const auto offset = rva_to_offset(rva, size);
    if (!offset) throw error("RVA range is not backed by contiguous file bytes");
    return bytes(data_.begin() + *offset, data_.begin() + *offset + size);
}

void image::invalidate_signature() {
    optional_.CheckSum = 0;
    optional_.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY] = {};
}

void image::patch_rva(std::uint32_t rva, const bytes& patch) {
    if (patch.empty()) return;
    const auto offset = rva_to_offset(rva, patch.size());
    if (!offset) throw error("Patch range is not backed by file bytes");
    // Use dedicated APIs for structural header changes.
    if (rva < optional_.SizeOfHeaders) throw error("Patching PE headers is not supported");
    std::copy(patch.begin(), patch.end(), data_.begin() + *offset);
    invalidate_signature();
    write_headers();
}

std::string image::string_at(std::uint32_t rva) const {
    const auto offset = rva_to_offset(rva);
    if (!offset) throw error("String RVA outside raw data");
    std::size_t limit = optional_.SizeOfHeaders;
    for (const auto& s : sections_)
        if (rva >= s.header.VirtualAddress && rva - s.header.VirtualAddress < s.header.SizeOfRawData)
            limit = static_cast<std::size_t>(s.header.PointerToRawData) + s.header.SizeOfRawData;
    auto end = std::find(data_.begin() + *offset, data_.begin() + limit, 0);
    if (end == data_.begin() + limit) throw error("Unterminated PE string");
    return std::string(data_.begin() + *offset, end);
}

std::vector<IMAGE_IMPORT_DESCRIPTOR> image::import_descriptors() const {
    const auto dir = directory(IMAGE_DIRECTORY_ENTRY_IMPORT);
    if (!dir.VirtualAddress && !dir.Size) return {};
    const auto offset = rva_to_offset(dir.VirtualAddress, dir.Size);
    if (!dir.VirtualAddress || dir.Size < sizeof(IMAGE_IMPORT_DESCRIPTOR) || !offset)
        throw error("Invalid import directory");
    std::vector<IMAGE_IMPORT_DESCRIPTOR> result;
    for (std::size_t pos = 0; fits(pos, sizeof(IMAGE_IMPORT_DESCRIPTOR), dir.Size); pos += sizeof(IMAGE_IMPORT_DESCRIPTOR)) {
        const auto d = read<IMAGE_IMPORT_DESCRIPTOR>(data_, *offset + pos);
        if (!d.OriginalFirstThunk && !d.TimeDateStamp && !d.ForwarderChain && !d.Name && !d.FirstThunk)
            return result;
        if (!d.Name || !d.FirstThunk) throw error("Invalid import descriptor");
        result.push_back(d);
    }
    throw error("Import directory has no null descriptor");
}

std::vector<imported_function> image::imports() const {
    std::vector<imported_function> result;
    for (const auto& d : import_descriptors()) {
        const auto module = string_at(d.Name);
        valid_name(module);
        const auto lookup = d.OriginalFirstThunk ? d.OriginalFirstThunk : d.FirstThunk;
        for (std::uint64_t index = 0; ; ++index) {
            const auto entry = u32(static_cast<std::uint64_t>(lookup) + index * 8);
            const auto pos = rva_to_offset(entry, 8);
            if (!pos) throw error("Import lookup table has no terminator");
            const auto value = read<std::uint64_t>(data_, *pos);
            const auto slot = u32(static_cast<std::uint64_t>(d.FirstThunk) + index * 8);
            if (!rva_to_offset(slot, 8)) throw error("Import IAT outside raw data");
            if (!value) break;
            import_symbol symbol;
            if (value & IMAGE_ORDINAL_FLAG64) {
                if (value & ~(IMAGE_ORDINAL_FLAG64 | 0xffffull)) throw error("Invalid import ordinal");
                symbol.ordinal = static_cast<std::uint16_t>(value);
            } else {
                if (value > UINT32_MAX) throw error("Resolved/bound IAT without a usable lookup table");
                const auto hint_pos = rva_to_offset(static_cast<std::uint32_t>(value), 2);
                if (!hint_pos) throw error("Invalid import name RVA");
                symbol.hint = read<std::uint16_t>(data_, *hint_pos);
                symbol.name = string_at(u32(value + 2));
                valid_name(symbol.name);
            }
            result.push_back({module, std::move(symbol), slot});
        }
    }
    return result;
}

std::vector<exported_function> image::exports() const {
    const auto dir = directory(IMAGE_DIRECTORY_ENTRY_EXPORT);
    if (!dir.VirtualAddress && !dir.Size) return {};
    const auto pos = rva_to_offset(dir.VirtualAddress, dir.Size);
    if (!dir.VirtualAddress || dir.Size < sizeof(IMAGE_EXPORT_DIRECTORY) || !pos)
        throw error("Invalid export directory");
    const auto e = read<IMAGE_EXPORT_DIRECTORY>(data_, *pos);
    if (!e.NumberOfFunctions) {
        if (e.NumberOfNames) throw error("Export names without functions");
        return {};
    }
    const auto funcs = rva_to_offset(e.AddressOfFunctions, static_cast<std::size_t>(e.NumberOfFunctions) * 4);
    if (!e.AddressOfFunctions || !funcs) throw error("Invalid export address table");
    std::vector<std::vector<std::string>> names(e.NumberOfFunctions);
    if (e.NumberOfNames) {
        const auto name_ptrs = rva_to_offset(e.AddressOfNames, static_cast<std::size_t>(e.NumberOfNames) * 4);
        const auto ordinals = rva_to_offset(e.AddressOfNameOrdinals, static_cast<std::size_t>(e.NumberOfNames) * 2);
        if (!e.AddressOfNames || !e.AddressOfNameOrdinals || !name_ptrs || !ordinals)
            throw error("Invalid export name tables");
        for (std::size_t i = 0; i < e.NumberOfNames; ++i) {
            const auto index = read<std::uint16_t>(data_, *ordinals + i * 2);
            if (index >= e.NumberOfFunctions) throw error("Export ordinal index outside function table");
            names[index].push_back(string_at(read<DWORD>(data_, *name_ptrs + i * 4)));
        }
    }
    std::vector<exported_function> result;
    for (std::size_t i = 0; i < e.NumberOfFunctions; ++i) {
        const auto rva = read<DWORD>(data_, *funcs + i * 4);
        if (!rva) continue;
        if (rva >= image_size()) throw error("Export RVA outside image");
        std::string forwarder;
        if (rva >= dir.VirtualAddress && static_cast<std::uint64_t>(rva) < static_cast<std::uint64_t>(dir.VirtualAddress) + dir.Size) {
            forwarder = string_at(rva);
            if (forwarder.empty() || static_cast<std::uint64_t>(rva) + forwarder.size() + 1 > static_cast<std::uint64_t>(dir.VirtualAddress) + dir.Size)
                throw error("Invalid export forwarder");
        }
        if (names[i].empty()) names[i].push_back({});
        for (const auto& name : names[i]) result.push_back({name, u32(static_cast<std::uint64_t>(e.Base) + i), rva, forwarder});
    }
    return result;
}

void image::insert_file_space(std::size_t offset, std::size_t count) {
    if (!count) return;
    if (offset > data_.size()) throw error("Invalid insertion offset");
    u32(static_cast<std::uint64_t>(data_.size()) + count);
    const auto debug = directory(IMAGE_DIRECTORY_ENTRY_DEBUG);
    std::optional<std::size_t> debug_offset;
    if (debug.Size) {
        debug_offset = rva_to_offset(debug.VirtualAddress, debug.Size);
        if (!debug_offset || debug.Size % sizeof(IMAGE_DEBUG_DIRECTORY))
            throw error("Invalid debug directory");
        if (*debug_offset < offset && *debug_offset + debug.Size > offset)
            throw error("Insertion would split the debug directory");
    }
    auto shift = [offset, count](DWORD& value) {
        if (value && value >= offset) value = u32(static_cast<std::uint64_t>(value) + count);
    };
    data_.insert(data_.begin() + offset, count, 0);
    for (auto& s : sections_) {
        shift(s.header.PointerToRawData);
        shift(s.header.PointerToRelocations);
        shift(s.header.PointerToLinenumbers);
    }
    shift(file_.PointerToSymbolTable);
    // Security directory uses a file offset, not an RVA. It is cleared on mutation.
    if (debug_offset) {
        auto base = *debug_offset + (*debug_offset >= offset ? count : 0);
        for (std::size_t pos = 0; pos < debug.Size; pos += sizeof(IMAGE_DEBUG_DIRECTORY)) {
            auto d = read<IMAGE_DEBUG_DIRECTORY>(data_, base + pos);
            shift(d.PointerToRawData);
            write(data_, base + pos, d);
        }
    }
    invalidate_signature();
}

std::uint32_t image::add_section_impl(const std::string& name, const bytes& contents, std::uint32_t characteristics) {
    if (name.empty() || name.size() > IMAGE_SIZEOF_SHORT_NAME || name.find('\0') != std::string::npos)
        throw error("Section name must contain 1 to 8 non-NUL bytes");
    if (contents.empty()) throw error("A new section must contain data");
    if (sections_.size() >= 96) throw error("Maximum PE section count reached");
    if (optional_.SectionAlignment < 0x1000)
        throw error("Adding sections to low-alignment images is not supported");
    for (const auto& s : sections_) if (s.name == name) throw error("Section name already exists");
    const auto needed = align_up(section_offset_ + (sections_.size() + 1) * sizeof(IMAGE_SECTION_HEADER), optional_.FileAlignment);
    if (needed > optional_.SizeOfHeaders) {
        for (const auto& s : sections_)
            if (extent(s.header) && needed > s.header.VirtualAddress)
                throw error("No virtual address space for expanded PE headers");
        insert_file_space(optional_.SizeOfHeaders, needed - optional_.SizeOfHeaders);
        optional_.SizeOfHeaders = needed;
        write_headers();
    }
    // Do not overwrite non-padding header data when claiming the next section slot.
    const auto slot = section_offset_ + sections_.size() * sizeof(IMAGE_SECTION_HEADER);
    for (std::size_t i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; ++i) {
        const auto dir = directory(i);
        if (i != IMAGE_DIRECTORY_ENTRY_SECURITY && overlaps(slot, sizeof(IMAGE_SECTION_HEADER), dir.VirtualAddress, dir.Size))
            throw error("New section header would overwrite a data directory");
    }
    if (std::any_of(data_.begin() + slot, data_.begin() + slot + sizeof(IMAGE_SECTION_HEADER),
        [](std::uint8_t b) { return b != 0; }))
        throw error("New section header would overwrite non-padding header data");
    std::uint32_t raw_end = optional_.SizeOfHeaders;
    std::uint32_t virtual_end = optional_.SizeOfHeaders;
    for (const auto& s : sections_) {
        const auto& h = s.header;
        if (h.SizeOfRawData) raw_end = std::max(raw_end, u32(static_cast<std::uint64_t>(h.PointerToRawData) + h.SizeOfRawData));
        if (extent(h)) virtual_end = std::max(virtual_end, u32(static_cast<std::uint64_t>(h.VirtualAddress) + extent(h)));
    }
    section added;
    added.name = name;
    auto& h = added.header;
    std::memcpy(h.Name, name.data(), name.size());
    h.Misc.VirtualSize = u32(contents.size());
    h.VirtualAddress = align_up(virtual_end, optional_.SectionAlignment);
    h.SizeOfRawData = align_up(contents.size(), optional_.FileAlignment);
    h.PointerToRawData = align_up(raw_end, optional_.FileAlignment);
    h.Characteristics = characteristics;
    optional_.SizeOfImage = align_up(static_cast<std::uint64_t>(h.VirtualAddress) + extent(h), optional_.SectionAlignment);
    insert_file_space(raw_end, static_cast<std::size_t>(h.PointerToRawData - raw_end) + h.SizeOfRawData);
    std::copy(contents.begin(), contents.end(), data_.begin() + h.PointerToRawData);
    const auto rva = h.VirtualAddress;
    sections_.push_back(std::move(added));
    file_.NumberOfSections = static_cast<WORD>(sections_.size());
    invalidate_signature();
    write_headers();
    parse();
    return rva;
}

std::vector<imported_function> image::rebuild_imports(const std::vector<import_module>& modules, const std::string& section_name) {
    if (modules.empty()) return {};
    auto next = *this;
    const auto old = next.import_descriptors();
    const auto old_imports = next.imports(); // Reject resolved IATs that have lost their lookup table.
    auto retained_iat = next.directory(IMAGE_DIRECTORY_ENTRY_IAT);
    if ((retained_iat.VirtualAddress == 0) != (retained_iat.Size == 0))
        throw error("Invalid existing IAT directory");
    // The loader uses the IAT directory to make original read-only slots writable.
    // Moving the import descriptors and dropping that directory breaks loading.
    // For IAT-directory-less inputs, infer a range within one read-only section.
    std::optional<std::size_t> inferred_section;
    std::uint32_t inferred_begin = UINT32_MAX, inferred_end = 0;
    for (const auto& entry : old_imports) {
        if (retained_iat.VirtualAddress && entry.iat_rva >= retained_iat.VirtualAddress
            && fits(entry.iat_rva - retained_iat.VirtualAddress, 8, retained_iat.Size)) continue;
        bool writable = false;
        std::optional<std::size_t> slot_section;
        for (std::size_t i = 0; i < next.sections_.size(); ++i) {
            const auto& h = next.sections_[i].header;
            if (entry.iat_rva >= h.VirtualAddress && fits(entry.iat_rva - h.VirtualAddress, 8, h.SizeOfRawData)) {
                writable = (h.Characteristics & IMAGE_SCN_MEM_WRITE) != 0;
                slot_section = i;
                break;
            }
        }
        if (writable) continue;
        if (retained_iat.VirtualAddress || !slot_section || (inferred_section && inferred_section != slot_section))
            throw error("Read-only IAT slots are not covered by a usable IAT directory");
        inferred_section = slot_section;
        inferred_begin = std::min(inferred_begin, entry.iat_rva);
        inferred_end = std::max(inferred_end, u32(static_cast<std::uint64_t>(entry.iat_rva) + 8));
    }
    if (inferred_section) retained_iat = {inferred_begin, inferred_end - inferred_begin};
    const auto descriptor_size = u32((static_cast<std::uint64_t>(old.size()) + modules.size() + 1) * sizeof(IMAGE_IMPORT_DESCRIPTOR));
    bytes blob(descriptor_size, 0);
    struct module_offsets {
        std::uint32_t name = 0, lookup = 0, iat = 0;
        std::vector<std::uint64_t> values;
    };
    std::vector<module_offsets> offsets;
    auto reserve = [&blob](std::uint64_t size, std::uint32_t alignment) {
        const auto pos = align_up(blob.size(), alignment);
        blob.resize(u32(static_cast<std::uint64_t>(pos) + size), 0);
        return pos;
    };
    auto put_string = [&blob, &reserve](const std::string& name, bool hint, std::uint16_t hint_value) {
        const auto pos = reserve(name.size() + 1 + (hint ? 2 : 0), hint ? 2 : 1);
        if (hint) write(blob, pos, hint_value);
        std::copy(name.begin(), name.end(), blob.begin() + pos + (hint ? 2 : 0));
        return pos;
    };
    for (const auto& module : modules) {
        valid_name(module.name);
        if (module.symbols.empty()) throw error("An import module must contain at least one symbol");
        module_offsets o;
        o.name = put_string(module.name, false, 0);
        o.lookup = reserve((static_cast<std::uint64_t>(module.symbols.size()) + 1) * 8, 8);
        for (const auto& symbol : module.symbols) {
            if (symbol.ordinal) {
                if (!symbol.name.empty()) throw error("Specify an import by either name or ordinal");
                o.values.push_back(IMAGE_ORDINAL_FLAG64 | *symbol.ordinal);
            } else {
                valid_name(symbol.name);
                o.values.push_back(put_string(symbol.name, true, symbol.hint));
            }
        }
        offsets.push_back(std::move(o));
    }
    const auto iat_begin = align_up(blob.size(), 8);
    for (auto& o : offsets) o.iat = reserve((static_cast<std::uint64_t>(o.values.size()) + 1) * 8, 8);
    const auto iat_size = u32(blob.size() - iat_begin);
    const auto base = next.add_section_impl(section_name, blob,
        IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE);
    for (std::size_t i = 0; i < old.size(); ++i) {
        auto descriptor = old[i];
        descriptor.TimeDateStamp = 0;
        descriptor.ForwarderChain = 0;
        write(blob, i * sizeof(descriptor), descriptor);
    }
    std::vector<imported_function> bindings;
    for (std::size_t i = 0; i < modules.size(); ++i) {
        const auto& o = offsets[i];
        IMAGE_IMPORT_DESCRIPTOR descriptor{};
        descriptor.Name = u32(static_cast<std::uint64_t>(base) + o.name);
        descriptor.OriginalFirstThunk = u32(static_cast<std::uint64_t>(base) + o.lookup);
        descriptor.FirstThunk = u32(static_cast<std::uint64_t>(base) + o.iat);
        write(blob, (old.size() + i) * sizeof(descriptor), descriptor);
        for (std::size_t j = 0; j < o.values.size(); ++j) {
            const std::uint64_t value = (o.values[j] & IMAGE_ORDINAL_FLAG64) ? o.values[j] : u32(static_cast<std::uint64_t>(base) + o.values[j]);
            write(blob, o.lookup + j * 8, value);
            write(blob, o.iat + j * 8, value);
            bindings.push_back({modules[i].name, modules[i].symbols[j], u32(static_cast<std::uint64_t>(base) + o.iat + j * 8)});
        }
    }
    next.patch_rva(base, blob);
    // Newly exposed directories must not inherit bytes that were previously unused.
    for (std::size_t i = next.optional_.NumberOfRvaAndSizes; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; ++i)
        next.optional_.DataDirectory[i] = {};
    next.optional_.NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
    next.optional_.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT] = {base, descriptor_size};
    next.optional_.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT] = {};
    // Keep the original protection range. Additional IATs live in our writable
    // section and are resolved through their own import descriptors.
    next.optional_.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT] = retained_iat.VirtualAddress
        ? retained_iat : IMAGE_DATA_DIRECTORY{u32(static_cast<std::uint64_t>(base) + iat_begin), iat_size};
    next.write_headers();
    (void)next.imports();
    *this = std::move(next);
    return bindings;
}

void image::validate_code_patch(std::uint32_t site_rva, std::size_t overwrite_size) const {
    if (!overwrite_size || !rva_to_offset(site_rva, overwrite_size))
        throw error("Code patch outside raw data");
    bool executable = false;
    for (const auto& s : sections_)
        if (site_rva >= s.header.VirtualAddress && site_rva - s.header.VirtualAddress < s.header.SizeOfRawData)
            executable = s.executable();
    if (!executable) throw error("Branch patch must be in an executable section");
    // A stale relocation would cause the loader to rewrite our new instruction
    // after ASLR. Refuse the patch until the caller has dealt with that relocation.
    const auto reloc = directory(IMAGE_DIRECTORY_ENTRY_BASERELOC);
    if (reloc.VirtualAddress || reloc.Size) {
        const auto reloc_offset = rva_to_offset(reloc.VirtualAddress, reloc.Size);
        if (!reloc.VirtualAddress || !reloc.Size || !reloc_offset) throw error("Invalid base relocation directory");
        for (std::size_t pos = 0; pos < reloc.Size;) {
            if (!fits(pos, sizeof(IMAGE_BASE_RELOCATION), reloc.Size)) throw error("Truncated relocation block");
            const auto block = read<IMAGE_BASE_RELOCATION>(data_, *reloc_offset + pos);
            if (block.SizeOfBlock < sizeof(block) || block.SizeOfBlock % 4 || !fits(pos, block.SizeOfBlock, reloc.Size))
                throw error("Invalid relocation block size");
            for (std::size_t entry = sizeof(block); entry < block.SizeOfBlock; entry += sizeof(WORD)) {
                const auto value = read<WORD>(data_, *reloc_offset + pos + entry);
                const auto type = value >> 12;
                if (type == IMAGE_REL_BASED_ABSOLUTE) continue;
                if (type != IMAGE_REL_BASED_DIR64) throw error("Unsupported AMD64 base relocation type");
                const auto target = u32(static_cast<std::uint64_t>(block.VirtualAddress) + (value & 0xfff));
                if (overlaps(site_rva, overwrite_size, target, 8))
                    throw error("Branch patch overlaps an existing base relocation");
            }
            pos += block.SizeOfBlock;
        }
    }
}

bytes image::rebuild() const {
    auto result = *this;
    auto& opt = result.optional_;
    opt.SizeOfCode = opt.SizeOfInitializedData = opt.SizeOfUninitializedData = 0;
    std::uint32_t image_end = opt.SizeOfHeaders;
    opt.BaseOfCode = 0;
    for (const auto& s : result.sections_) {
        const auto& h = s.header;
        if (extent(h)) image_end = std::max(image_end, u32(static_cast<std::uint64_t>(h.VirtualAddress) + extent(h)));
        if (h.Characteristics & IMAGE_SCN_CNT_CODE) {
            opt.SizeOfCode = u32(static_cast<std::uint64_t>(opt.SizeOfCode) + h.SizeOfRawData);
            if (!opt.BaseOfCode || h.VirtualAddress < opt.BaseOfCode) opt.BaseOfCode = h.VirtualAddress;
        }
        if (h.Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA)
            opt.SizeOfInitializedData = u32(static_cast<std::uint64_t>(opt.SizeOfInitializedData) + h.SizeOfRawData);
        if (h.Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA)
            opt.SizeOfUninitializedData = u32(static_cast<std::uint64_t>(opt.SizeOfUninitializedData) + h.Misc.VirtualSize);
    }
    opt.SizeOfImage = align_up(image_end, opt.SectionAlignment);
    result.invalidate_signature();
    result.write_headers();
    const auto checksum_offset = result.optional_offset_ + offsetof(IMAGE_OPTIONAL_HEADER64, CheckSum);
    std::uint64_t sum = 0;
    for (std::size_t i = 0; i < result.data_.size(); i += 2) {
        // Zero the checksum bytes individually, even for an unaligned NT header.
        auto byte = [&result, checksum_offset](std::size_t index) -> std::uint16_t {
            return index >= result.data_.size() || (index >= checksum_offset && index < checksum_offset + 4)
                ? 0 : result.data_[index];
        };
        sum += byte(i) | (byte(i + 1) << 8);
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum = (sum & 0xffff) + (sum >> 16);
    opt.CheckSum = static_cast<DWORD>((sum & 0xffff) + result.data_.size());
    result.write_headers();
    result.parse();
    return result.data_;
}

void image::save(const std::filesystem::path& path) const {
    const auto rebuilt = rebuild();
    std::ofstream stream(path, std::ios::binary | std::ios::trunc);
    if (!stream || !stream.write(reinterpret_cast<const char*>(rebuilt.data()), rebuilt.size()))
        throw error("Cannot write output file");
    stream.close();
    if (!stream) throw error("Cannot finish writing output file");
}

} // namespace pe
