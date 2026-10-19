#include "deobfuscator.h"

#include <algorithm>
#include <cstring>
#include <deque>
#include <iomanip>
#include <set>
#include <sstream>
#include <unordered_set>

namespace deobf {
namespace {
using insn = disasm::instruction;
using reg = ZydisRegister;

std::string lower(std::string value) {
    for (auto& c : value) if (c >= 'A' && c <= 'Z') c += 'a' - 'A';
    return value;
}

std::string module_name(std::string value) {
    value = lower(value);
    if (value.find('.') == std::string::npos) value += ".dll";
    return value;
}

std::string key(const api_symbol& api) { return module_name(api.module) + "!" + api.name; }

reg full(reg value) { return ZydisRegisterGetLargestEnclosing(ZYDIS_MACHINE_MODE_LONG_64, value); }
reg operand_reg(const ZydisDecodedOperand& op) { return op.type == ZYDIS_OPERAND_TYPE_REGISTER ? full(op.reg.value) : ZYDIS_REGISTER_NONE; }
bool is_gpr(reg value) { return value >= ZYDIS_REGISTER_RAX && value <= ZYDIS_REGISTER_R15; }
bool nonvolatile(reg value) {
    return value == ZYDIS_REGISTER_RBX || value == ZYDIS_REGISTER_RBP || value == ZYDIS_REGISTER_RSI
        || value == ZYDIS_REGISTER_RDI || (value >= ZYDIS_REGISTER_R12 && value <= ZYDIS_REGISTER_R15);
}

std::set<reg> reads(const insn& i) {
    std::set<reg> result;
    // Zeroing idioms do not depend on their old register value.
    if ((i.decoded.mnemonic == ZYDIS_MNEMONIC_XOR || i.decoded.mnemonic == ZYDIS_MNEMONIC_SUB)
        && i.decoded.operand_count_visible == 2 && operand_reg(i.operands[0]) != ZYDIS_REGISTER_NONE
        && i.operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER
        && i.operands[0].reg.value == i.operands[1].reg.value) return result;
    if (i.decoded.mnemonic == ZYDIS_MNEMONIC_NOP) return result;
    for (std::size_t n = 0; n < i.decoded.operand_count; ++n) {
        const auto& op = i.operands[n];
        if (op.type == ZYDIS_OPERAND_TYPE_REGISTER && (op.actions & ZYDIS_OPERAND_ACTION_MASK_READ))
            result.insert(full(op.reg.value));
        if (op.type == ZYDIS_OPERAND_TYPE_MEMORY) {
            if (op.mem.base != ZYDIS_REGISTER_NONE) result.insert(full(op.mem.base));
            if (op.mem.index != ZYDIS_REGISTER_NONE) result.insert(full(op.mem.index));
        }
    }
    return result;
}

std::set<reg> writes(const insn& i, bool complete_only = false) {
    std::set<reg> result;
    for (std::size_t n = 0; n < i.decoded.operand_count; ++n) {
        const auto& op = i.operands[n];
        if (op.type == ZYDIS_OPERAND_TYPE_REGISTER && (op.actions & ZYDIS_OPERAND_ACTION_MASK_WRITE)
            && (!complete_only || (op.size >= 32 && (op.actions & ZYDIS_OPERAND_ACTION_WRITE))))
            result.insert(full(op.reg.value));
    }
    return result;
}

bool mov_load(const insn& i, reg base, std::int64_t displacement, unsigned size = 0) {
    return i.decoded.mnemonic == ZYDIS_MNEMONIC_MOV && i.decoded.operand_count_visible == 2
        && i.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER && i.operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY
        && full(i.operands[1].mem.base) == base && i.operands[1].mem.index == ZYDIS_REGISTER_NONE
        && i.operands[1].mem.disp.value == displacement && (!size || i.operands[0].size == size);
}

bool peb_start(const insn& i) {
    return mov_load(i, ZYDIS_REGISTER_NONE, 0x60, 64)
        && i.operands[1].mem.segment == ZYDIS_REGISTER_GS;
}

std::size_t next_real(const std::vector<insn>& code, std::size_t pos) {
    while (pos < code.size() && code[pos].decoded.mnemonic == ZYDIS_MNEMONIC_NOP) ++pos;
    return pos;
}

std::uint64_t fingerprint(const pe::bytes& data) {
    std::uint64_t value = 14695981039346656037ull;
    for (const auto b : data) value = (value ^ b) * 1099511628211ull;
    return value;
}

insn at(const pe::image& image, const disasm::disassembler& decoder, std::uint32_t rva) {
    for (const auto& s : image.sections()) {
        const auto& h = s.header;
        if (s.executable() && rva >= h.VirtualAddress && rva - h.VirtualAddress < h.SizeOfRawData) {
            const auto delta = rva - h.VirtualAddress;
            return decoder.decode(image.data().data() + h.PointerToRawData + delta,
                std::min<std::size_t>(15, h.SizeOfRawData - delta), image.rva_to_va(rva));
        }
    }
    throw pe::error("Control flow leaves executable raw data");
}

bool dead_after(const pe::image& image, std::uint32_t start, reg value, std::size_t budget) {
    disasm::disassembler decoder;
    std::deque<std::uint32_t> queue{start};
    std::unordered_set<std::uint32_t> seen;
    while (!queue.empty()) {
        const auto rva = queue.front(); queue.pop_front();
        if (!seen.insert(rva).second) continue;
        if (seen.size() > budget) return false;
        insn i;
        try { i = at(image, decoder, rva); } catch (const pe::error&) { return false; }
        if (reads(i).count(value)) return false;
        if (writes(i, true).count(value)) continue;
        // At a return/tail call, a nonvolatile register remains observable by the caller.
        if (i.is_return()) return false;
        if (i.is_branch() && !i.is_call()) {
            if (!i.branch_target) return false;
            const auto target = image.va_to_rva(*i.branch_target);
            if (!target) return false;
            queue.push_back(*target);
            if (i.decoded.meta.category == ZYDIS_CATEGORY_UNCOND_BR) continue;
        }
        if (static_cast<std::uint64_t>(rva) + i.length >= image.image_size()) return false;
        queue.push_back(rva + i.length);
    }
    return true;
}

bool prefix_instruction(const insn& i) {
    switch (i.decoded.mnemonic) {
    case ZYDIS_MNEMONIC_MOV: case ZYDIS_MNEMONIC_MOVZX: case ZYDIS_MNEMONIC_MOVSX:
    case ZYDIS_MNEMONIC_MOVSXD: case ZYDIS_MNEMONIC_ADD: case ZYDIS_MNEMONIC_LEA:
    case ZYDIS_MNEMONIC_XOR: case ZYDIS_MNEMONIC_TEST: case ZYDIS_MNEMONIC_CMP:
    case ZYDIS_MNEMONIC_DEC: case ZYDIS_MNEMONIC_INC: case ZYDIS_MNEMONIC_IMUL:
    case ZYDIS_MNEMONIC_NOP: break;
    default: if (!i.is_branch() || i.is_call()) return false;
    }
    if (writes(i).count(ZYDIS_REGISTER_RSP) || writes(i).count(ZYDIS_REGISTER_RBP)) return false;
    for (std::size_t n = 0; n < i.decoded.operand_count; ++n)
        if (i.operands[n].type == ZYDIS_OPERAND_TYPE_MEMORY
            && (i.operands[n].actions & ZYDIS_OPERAND_ACTION_MASK_WRITE)) return false;
    return true;
}

bool parameter_instruction(const insn& i) {
    if (writes(i).count(ZYDIS_REGISTER_RSP) || writes(i).count(ZYDIS_REGISTER_RBP)) return false;
    switch (i.decoded.mnemonic) {
    case ZYDIS_MNEMONIC_MOV: case ZYDIS_MNEMONIC_MOVZX: case ZYDIS_MNEMONIC_MOVSX:
    case ZYDIS_MNEMONIC_MOVSXD: case ZYDIS_MNEMONIC_LEA: case ZYDIS_MNEMONIC_XOR:
    case ZYDIS_MNEMONIC_ADD: case ZYDIS_MNEMONIC_SUB: case ZYDIS_MNEMONIC_AND:
    case ZYDIS_MNEMONIC_OR: case ZYDIS_MNEMONIC_MOVSS: case ZYDIS_MNEMONIC_MOVSD:
    case ZYDIS_MNEMONIC_MOVAPS: case ZYDIS_MNEMONIC_MOVUPS: case ZYDIS_MNEMONIC_MOVDQA:
    case ZYDIS_MNEMONIC_MOVDQU: case ZYDIS_MNEMONIC_MOVQ: case ZYDIS_MNEMONIC_MOVD:
    case ZYDIS_MNEMONIC_XORPS: case ZYDIS_MNEMONIC_XORPD: case ZYDIS_MNEMONIC_PXOR:
    case ZYDIS_MNEMONIC_NOP: return true;
    default: return false;
    }
}

enum class symbolic { unknown, module, exports, name_index, eat_rva, eat, ord_rva, ords, ordinal, function_rva, function };

// MSVC can schedule the string-pointer increment or next-byte load between
// MOVSX, XOR and IMUL. Accept only independent string-loop operations; never
// skip a write/read involving the live hash or byte-mixing register.
bool hash_schedule_instruction(const insn& i, reg hash, reg work) {
    if (i.decoded.mnemonic == ZYDIS_MNEMONIC_NOP) return true;
    const auto used = reads(i);
    const auto changed = writes(i);
    if (used.count(hash) || used.count(work) || changed.count(hash) || changed.count(work)) return false;
    const auto& dst = i.operands[0];
    const auto& src = i.operands[1];
    if (i.decoded.mnemonic == ZYDIS_MNEMONIC_LEA && dst.type == ZYDIS_OPERAND_TYPE_REGISTER && dst.size == 64
        && src.type == ZYDIS_OPERAND_TYPE_MEMORY && full(src.mem.base) == operand_reg(dst)
        && src.mem.index == ZYDIS_REGISTER_NONE && src.mem.disp.value == 1) return true;
    if (i.decoded.mnemonic == ZYDIS_MNEMONIC_INC && dst.type == ZYDIS_OPERAND_TYPE_REGISTER && dst.size == 64) return true;
    return i.decoded.mnemonic == ZYDIS_MNEMONIC_MOVZX && dst.type == ZYDIS_OPERAND_TYPE_REGISTER && dst.size == 32
        && src.type == ZYDIS_OPERAND_TYPE_MEMORY && src.size == 8 && is_gpr(full(src.mem.base))
        && src.mem.index == ZYDIS_REGISTER_NONE && src.mem.segment != ZYDIS_REGISTER_GS && src.mem.segment != ZYDIS_REGISTER_FS;
}

void recognize(candidate& c, const pe::image& image, const std::vector<insn>& code, const options& config) {
    auto reject = [&c](const char* reason) { c.reason = reason; };
    if (code.size() < 15) { reject("Truncated resolver window"); return; }
    const auto list_reg = operand_reg(code[0].operands[0]);
    auto pos = next_real(code, 1);
    if (pos == code.size() || !mov_load(code[pos], list_reg, 0x18, 64)
        || operand_reg(code[pos].operands[0]) != list_reg) { reject("Unsupported PEB->Ldr traversal"); return; }
    pos = next_real(code, pos + 1);
    if (pos == code.size() || !mov_load(code[pos], list_reg, 0x10, 64)
        || operand_reg(code[pos].operands[0]) != list_reg) { reject("Unsupported loader module list traversal"); return; }
    pos = next_real(code, pos + 1);
    if (pos == code.size() || !mov_load(code[pos], list_reg, 0x30, 64)) { reject("Missing module DllBase load"); return; }
    const auto module_reg = operand_reg(code[pos].operands[0]);
    const auto module_pos = pos;
    reg export_reg = ZYDIS_REGISTER_NONE, index_reg = ZYDIS_REGISTER_NONE;
    bool nt_offset = false, export_rva = false;
    for (++pos; pos < code.size(); ++pos) {
        const auto& i = code[pos];
        if (i.decoded.mnemonic == ZYDIS_MNEMONIC_MOVSXD && i.operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY
            && full(i.operands[1].mem.base) == module_reg && i.operands[1].mem.disp.value == 0x3c) nt_offset = true;
        if (nt_offset && i.decoded.mnemonic == ZYDIS_MNEMONIC_MOV && i.operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY
            && i.operands[1].mem.disp.value == 0x88 && i.operands[0].size == 32
            && (full(i.operands[1].mem.base) == module_reg || full(i.operands[1].mem.index) == module_reg)) {
            export_reg = operand_reg(i.operands[0]); export_rva = true;
        }
        if (export_rva && mov_load(i, export_reg, 0x18, 32)) { index_reg = operand_reg(i.operands[0]); break; }
    }
    if (index_reg == ZYDIS_REGISTER_NONE) { reject("Missing export directory/NumberOfNames traversal"); return; }

    std::size_t multiply = code.size(), compare = code.size(), seed_pos = 0;
    reg calc_reg = ZYDIS_REGISTER_NONE;
    for (std::size_t n = pos + 1; n < code.size(); ++n) {
        const auto& i = code[n];
        if (i.decoded.mnemonic != ZYDIS_MNEMONIC_IMUL || i.decoded.operand_count_visible != 3
            || i.operands[0].size != 32 || i.operands[2].type != ZYDIS_OPERAND_TYPE_IMMEDIATE) continue;
        calc_reg = operand_reg(i.operands[0]);
        for (std::size_t k = n; k-- > pos;) {
            if (code[k].decoded.mnemonic == ZYDIS_MNEMONIC_MOV && operand_reg(code[k].operands[0]) == calc_reg
                && code[k].operands[0].size == 32 && code[k].operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
                seed_pos = k; break;
            }
        }
        if (seed_pos) { multiply = n; break; }
    }
    if (multiply == code.size()) { reject("No seeded 32-bit FNV multiply"); return; }
    c.seed = static_cast<std::uint32_t>(code[seed_pos].operands[1].imm.value.u);
    c.prime = static_cast<std::uint32_t>(code[multiply].operands[2].imm.value.u);
    for (std::size_t n = multiply + 1; n < code.size(); ++n)
        if (code[n].decoded.mnemonic == ZYDIS_MNEMONIC_CMP && operand_reg(code[n].operands[0]) == calc_reg
            && code[n].operands[0].size == 32 && code[n].operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) { compare = n; break; }
    if (compare == code.size()) { reject("Missing FNV hash comparison"); return; }
    c.hash = static_cast<std::uint32_t>(code[compare].operands[1].imm.value.u);
    c.has_hash = true;
    if (!(c.prime & 1) || c.prime <= 1) { reject("Unsupported hash multiplier"); return; }
    const auto work_reg = operand_reg(code[multiply].operands[1]);
    auto xor_pos = multiply;
    while (xor_pos > seed_pos + 1 && hash_schedule_instruction(code[xor_pos - 1], calc_reg, work_reg)) --xor_pos;
    if (xor_pos == 0) { reject("Missing FNV XOR"); return; }
    --xor_pos;
    auto extend_pos = xor_pos;
    while (extend_pos > seed_pos + 1 && hash_schedule_instruction(code[extend_pos - 1], calc_reg, work_reg)) --extend_pos;
    if (extend_pos == 0) { reject("Missing FNV byte extension"); return; }
    --extend_pos;
    if (code[xor_pos].decoded.mnemonic != ZYDIS_MNEMONIC_XOR
        || operand_reg(code[xor_pos].operands[0]) != work_reg || code[xor_pos].operands[0].size != 32
        || operand_reg(code[xor_pos].operands[1]) != calc_reg || code[xor_pos].operands[1].size != 32
        || (code[extend_pos].decoded.mnemonic != ZYDIS_MNEMONIC_MOVSX && code[extend_pos].decoded.mnemonic != ZYDIS_MNEMONIC_MOVZX)
        || operand_reg(code[extend_pos].operands[0]) != work_reg || code[extend_pos].operands[0].size != 32
        || code[extend_pos].operands[1].type != ZYDIS_OPERAND_TYPE_REGISTER || code[extend_pos].operands[1].size != 8) {
        reject("Unsupported FNV byte-mixing sequence (case folding/custom hash needs another profile)"); return;
    }
    bool loop_back = false;
    for (auto n = multiply + 1; n < compare; ++n)
        if (code[n].decoded.mnemonic == ZYDIS_MNEMONIC_JNZ && code[n].branch_target == code[extend_pos].address) loop_back = true;
    if (!loop_back) { reject("Missing bounded FNV byte loop"); return; }
    const auto conditional = next_real(code, compare + 1);
    if (conditional == code.size() || code[conditional].decoded.mnemonic != ZYDIS_MNEMONIC_JZ || !code[conditional].branch_target) {
        reject("Unsupported hash success branch"); return;
    }
    std::size_t success = code.size();
    for (std::size_t n = conditional + 1; n < code.size(); ++n)
        if (code[n].address == *code[conditional].branch_target) { success = n; break; }
    if (success == code.size()) { reject("Hash success target outside resolver window"); return; }
    bool module_loop = false;
    std::set<reg> tainted;
    for (std::size_t n = 0; n < success; ++n) {
        const auto& i = code[n];
        if (!prefix_instruction(i)) { reject("Resolver prefix has unsupported instructions or side effects"); return; }
        if (i.is_branch()) {
            if (!i.branch_target || *i.branch_target < code[0].address || *i.branch_target > code[success].address) {
                reject("Resolver branch escapes replacement region"); return;
            }
            if (i.decoded.mnemonic == ZYDIS_MNEMONIC_JMP && *i.branch_target == code[module_pos].address) module_loop = true;
        }
        for (auto r : writes(i)) if (is_gpr(r)) tainted.insert(r);
    }
    if (!module_loop) { reject("Missing module traversal back edge"); return; }
    std::map<reg, symbolic> values;
    values[module_reg] = symbolic::module;
    values[export_reg] = symbolic::exports;
    values[index_reg] = symbolic::name_index;
    bool found_call = false;
    for (std::size_t n = success; n < code.size(); ++n) {
        const auto& i = code[n];
        const auto dst = operand_reg(i.operands[0]);
        if (i.is_call()) {
            if (i.decoded.operand_count_visible != 1 || i.operands[0].type != ZYDIS_OPERAND_TYPE_REGISTER
                || values[dst] != symbolic::function) { reject("Call target is not the resolved export address"); return; }
            c.call_rva = static_cast<std::uint32_t>(i.address - image.image_base());
            c.end_rva = c.call_rva + i.length;
            found_call = true;
            break;
        }
        if (i.decoded.mnemonic == ZYDIS_MNEMONIC_NOP) continue;
        symbolic produced = symbolic::unknown;
        const auto& src = i.operands[1];
        if (src.type == ZYDIS_OPERAND_TYPE_MEMORY && dst != ZYDIS_REGISTER_NONE) {
            const auto base = values[full(src.mem.base)];
            const auto index = values[full(src.mem.index)];
            if (i.decoded.mnemonic == ZYDIS_MNEMONIC_MOV && i.operands[0].size == 32
                && base == symbolic::exports && src.mem.index == ZYDIS_REGISTER_NONE) {
                if (src.mem.disp.value == 0x1c) produced = symbolic::eat_rva;
                if (src.mem.disp.value == 0x24) produced = symbolic::ord_rva;
            }
            if (i.decoded.mnemonic == ZYDIS_MNEMONIC_MOVZX && i.operands[0].size == 32 && src.size == 16
                && base == symbolic::ords && index == symbolic::name_index && src.mem.scale == 2 && !src.mem.disp.value)
                produced = symbolic::ordinal;
            if (i.decoded.mnemonic == ZYDIS_MNEMONIC_MOV && i.operands[0].size == 32 && src.size == 32
                && base == symbolic::eat && index == symbolic::ordinal && src.mem.scale == 4 && !src.mem.disp.value)
                produced = symbolic::function_rva;
        }
        if (i.decoded.mnemonic == ZYDIS_MNEMONIC_ADD && i.operands[0].size == 64
            && operand_reg(src) != ZYDIS_REGISTER_NONE && values[operand_reg(src)] == symbolic::module) {
            if (values[dst] == symbolic::eat_rva) produced = symbolic::eat;
            if (values[dst] == symbolic::ord_rva) produced = symbolic::ords;
            if (values[dst] == symbolic::function_rva) produced = symbolic::function;
        }
        if (produced != symbolic::unknown) {
            values[dst] = produced;
            tainted.insert(dst);
            continue;
        }
        if (!parameter_instruction(i)) { reject("Unsupported instruction in argument preparation"); return; }
        for (auto r : reads(i)) if (tainted.count(r)) { reject("Argument preparation depends on removed resolver state"); return; }
        for (auto r : writes(i)) values[r] = symbolic::unknown;
        for (auto r : writes(i, true)) tainted.erase(r);
        c.parameters.push_back(i);
    }
    if (!found_call) { reject("No indirect API call in bounded resolver window"); return; }
    for (auto r : tainted) {
        if (nonvolatile(r) && !dead_after(image, c.end_rva, r, config.max_liveness_instructions)) {
            c.reason = std::string("Nonvolatile resolver register is live after call: ") + ZydisRegisterGetString(r);
            return;
        }
    }
    c.original_bytes = image.read_rva(c.entry_rva, c.end_rva - c.entry_rva);
    std::size_t required = 11;
    for (const auto& i : c.parameters) required += i.length;
    if (required > c.original_bytes.size()) { reject("Insufficient room for arguments, jump and IAT call"); return; }
    c.state = status::unresolved;
    c.reason = "No export matches the recovered hash";
}

std::string section_name(const pe::image& image) {
    for (unsigned n = 0; n < 10000; ++n) {
        const auto name = n ? ".li" + std::to_string(n) : ".liimp";
        bool exists = false;
        for (const auto& s : image.sections()) if (s.name == name) exists = true;
        if (!exists) return name;
    }
    throw pe::error("Cannot allocate an import section name");
}

template<class T> void put(pe::bytes& data, std::size_t offset, T value) {
    if (offset > data.size() || sizeof(T) > data.size() - offset) throw pe::error("Generated patch exceeds replacement region");
    std::memcpy(data.data() + offset, &value, sizeof(value));
}

pe::bytes make_patch(const pe::image& image, const candidate& c, std::uint32_t slot) {
    pe::bytes patch(c.end_rva - c.entry_rva, 0x90);
    std::size_t pos = 0;
    for (const auto& i : c.parameters) {
        std::copy_n(i.bytes.begin(), i.length, patch.begin() + pos);
        bool rip = false;
        for (std::size_t n = 0; n < i.decoded.operand_count_visible; ++n) {
            const auto& op = i.operands[n];
            if (op.type == ZYDIS_OPERAND_TYPE_IMMEDIATE && op.imm.is_relative) throw pe::error("Cannot relocate a relative argument branch");
            if (op.type == ZYDIS_OPERAND_TYPE_MEMORY && (op.mem.base == ZYDIS_REGISTER_RIP || op.mem.base == ZYDIS_REGISTER_EIP)) {
                if (op.mem.base != ZYDIS_REGISTER_RIP || i.decoded.raw.disp.size != 32 || rip)
                    throw pe::error("Unsupported argument displacement encoding");
                rip = true;
                const auto delta = i.decoded.raw.disp.value + static_cast<std::int64_t>(i.address - image.image_base())
                    - (static_cast<std::int64_t>(c.entry_rva) + static_cast<std::int64_t>(pos));
                if (delta < INT32_MIN || delta > INT32_MAX) throw pe::error("Relocated argument is out of RIP-relative range");
                put(patch, pos + i.decoded.raw.disp.offset, static_cast<std::int32_t>(delta));
            }
        }
        pos += i.length;
    }
    const auto call_pos = patch.size() - 6;
    if (pos + 5 > call_pos) throw pe::error("Insufficient space for replacement call");
    patch[pos] = 0xe9;
    put(patch, pos + 1, static_cast<std::int32_t>(call_pos - pos - 5));
    patch[call_pos] = 0xff; patch[call_pos + 1] = 0x15;
    const auto delta = static_cast<std::int64_t>(slot) - c.end_rva;
    if (delta < INT32_MIN || delta > INT32_MAX) throw pe::error("New IAT is out of RIP-relative range");
    put(patch, call_pos + 2, static_cast<std::int32_t>(delta));
    return patch;
}

std::string quote(const std::string& value) {
    std::ostringstream out;
    out << '"';
    for (unsigned char c : value) {
        if (c == '"' || c == '\\') out << '\\' << c;
        else if (c < 32) out << "\\u00" << std::hex << std::setw(2) << std::setfill('0') << static_cast<unsigned>(c);
        else out << c;
    }
    out << '"';
    return out.str();
}
} // namespace

std::uint32_t hash_name(std::string_view name, std::uint32_t seed, std::uint32_t prime) {
    // Windows export names are ASCII. Match the signed-char extension used by MSVC's profile.
    for (unsigned char c : name) seed = (seed ^ static_cast<std::uint32_t>(static_cast<std::int32_t>(static_cast<std::int8_t>(c)))) * prime;
    return seed;
}

void export_database::add(const std::string& module, const std::vector<pe::exported_function>& exports) {
    if (module.empty() || module.find_first_of("/\\!\r\n") != std::string::npos || module.find('\0') != std::string::npos)
        throw pe::error("Invalid export module name");
    for (const auto& e : exports) {
        if (e.name.empty()) continue;
        api_symbol api{module_name(module), e.name, e.forwarder};
        if (index_.emplace(key(api), symbols_.size()).second) symbols_.push_back(std::move(api));
    }
}

void export_database::add_file(const std::filesystem::path& path) {
    const auto name = path.filename().u8string();
    add(std::string(name.begin(), name.end()), pe::image::load(path).exports());
}

std::vector<api_symbol> export_database::match(std::uint32_t seed, std::uint32_t prime, std::uint32_t hash) const {
    std::vector<api_symbol> result;
    for (const auto& symbol : symbols_) if (hash_name(symbol.name, seed, prime) == hash) result.push_back(symbol);
    return result;
}

std::string export_database::canonical(const api_symbol& symbol) const {
    auto current = symbol;
    std::set<std::string> visited;
    for (unsigned n = 0; n < 32; ++n) {
        const auto identity = key(current);
        if (!visited.insert(identity).second) return key(symbol); // Cyclic forwarder is not an equivalence proof.
        if (current.forwarder.empty()) return identity;
        const auto dot = current.forwarder.rfind('.');
        if (dot == std::string::npos) return identity;
        current = {current.forwarder.substr(0, dot), current.forwarder.substr(dot + 1), {}};
        const auto target_key = key(current);
        const auto target = index_.find(target_key);
        if (target == index_.end()) return target_key;
        current = symbols_[target->second];
    }
    return key(symbol);
}

const char* status_name(status value) noexcept {
    switch (value) {
    case status::unsupported: return "unsupported";
    case status::unresolved: return "unresolved";
    case status::ambiguous: return "ambiguous";
    case status::ready: return "ready";
    case status::patched: return "patched";
    }
    return "unknown";
}

std::size_t analysis::count(status value) const noexcept {
    return static_cast<std::size_t>(std::count_if(candidates.begin(), candidates.end(), [value](const candidate& c) { return c.state == value; }));
}

analysis analyze(const pe::image& image, const export_database& exports, const options& config) {
    if (config.max_resolver_bytes < 32 || config.max_resolver_bytes > 65536 || !config.max_liveness_instructions)
        throw pe::error("Invalid analysis limits");
    analysis result;
    result.source_size = image.data().size(); result.source_fingerprint = fingerprint(image.data());
    result.image_base = image.image_base();
    disasm::disassembler decoder;
    std::vector<std::uint32_t> starts;
    std::vector<std::pair<std::uint32_t, std::uint32_t>> references;
    decoder.executable_sections(image, [&](const insn& i) {
        const auto source = static_cast<std::uint32_t>(i.address - image.image_base());
        if (peb_start(i)) starts.push_back(source);
        auto add_ref = [&](std::uint64_t address) {
            if (const auto target = image.va_to_rva(address)) references.emplace_back(source, *target);
        };
        if (i.branch_target) add_ref(*i.branch_target);
        for (auto address : i.memory_addresses) add_ref(address);
        return true;
    });
    // Runtime function entries are also externally reachable, independent of direct xrefs.
    const auto exception = image.directory(IMAGE_DIRECTORY_ENTRY_EXCEPTION);
    if (exception.Size) {
        const auto data = image.read_rva(exception.VirtualAddress, exception.Size);
        if (data.size() % sizeof(RUNTIME_FUNCTION)) throw pe::error("Malformed runtime function table");
        for (std::size_t pos = 0; pos < data.size(); pos += sizeof(RUNTIME_FUNCTION)) {
            RUNTIME_FUNCTION f{}; std::memcpy(&f, data.data() + pos, sizeof(f));
            references.emplace_back(UINT32_MAX, f.BeginAddress);
        }
    }
    std::sort(starts.begin(), starts.end());
    for (const auto start : starts) {
        candidate c; c.entry_rva = start;
        std::vector<insn> code;
        try {
            auto rva = start;
            while (rva - start < config.max_resolver_bytes) {
                auto i = at(image, decoder, rva);
                if (!code.empty() && peb_start(i)) break;
                rva += i.length;
                const bool stop = i.is_call() || i.is_return();
                code.push_back(std::move(i));
                if (stop) break;
            }
            recognize(c, image, code, config);
            if (c.state != status::unsupported) {
                for (const auto& ref : references) {
                    if (ref.second > c.entry_rva && ref.second < c.end_rva && (ref.first < c.entry_rva || ref.first >= c.end_rva)) {
                        c.state = status::unsupported; c.reason = "External control-flow/address reference enters the replacement region"; break;
                    }
                }
            }
            if (c.state != status::unsupported) {
                image.validate_code_patch(c.entry_rva, c.end_rva - c.entry_rva);
                (void)make_patch(image, c, c.end_rva); // Check argument relocation before import-table mutation.
                c.matches = exports.match(c.seed, c.prime, c.hash);
                const auto manual = config.overrides.find(c.entry_rva);
                if (manual != config.overrides.end()) {
                    if (manual->second.name.empty() || manual->second.name.find('\0') != std::string::npos
                        || manual->second.module.empty() || manual->second.module.find_first_of("/\\!\r\n") != std::string::npos)
                        throw pe::error("Invalid manual DLL!name mapping");
                    c.api = manual->second; c.state = status::ready; c.reason = "Explicit mapping";
                } else if (!c.matches.empty()) {
                    const auto canonical = exports.canonical(c.matches.front());
                    const bool equivalent = std::all_of(c.matches.begin(), c.matches.end(), [&](const api_symbol& api) {
                        return api.name == c.matches.front().name && exports.canonical(api) == canonical;
                    });
                    if (equivalent) { c.api = c.matches.front(); c.state = status::ready; c.reason.clear(); }
                    else { c.state = status::ambiguous; c.reason = "Hash matches multiple non-equivalent exports; use an explicit mapping"; }
                }
            }
        } catch (const pe::error& e) { c.state = status::unsupported; c.reason = e.what(); }
        result.candidates.push_back(std::move(c));
    }
    for (const auto& mapping : config.overrides)
        if (std::none_of(result.candidates.begin(), result.candidates.end(), [&](const candidate& c) { return c.entry_rva == mapping.first; }))
            throw pe::error("Manual mapping does not identify a detected PEB resolver");
    return result;
}

std::size_t apply(pe::image& image, analysis& plan, const options& config) {
    if (plan.source_size != image.data().size() || plan.source_fingerprint != fingerprint(image.data()))
        throw pe::error("Analysis is stale: source image changed");
    if (config.strict && plan.count(status::ready) != plan.candidates.size())
        throw pe::error("Strict mode: some resolver candidates are not ready");
    if (!plan.count(status::ready)) return 0;
    auto next = image;
    auto updated = plan;
    std::map<std::string, std::uint32_t> slots;
    for (const auto& imported : image.imports())
        if (!imported.symbol.ordinal) slots.emplace(key({imported.module, imported.symbol.name, {}}), imported.iat_rva);
    std::vector<pe::import_module> modules;
    std::set<std::string> required;
    for (const auto& c : updated.candidates) {
        if (c.state != status::ready || !c.api || slots.count(key(*c.api)) || !required.insert(key(*c.api)).second) continue;
        const auto module = module_name(c.api->module);
        auto found = std::find_if(modules.begin(), modules.end(), [&](const pe::import_module& m) { return m.name == module; });
        if (found == modules.end()) { modules.push_back({module, {}}); found = modules.end() - 1; }
        found->symbols.push_back({c.api->name, {}, 0});
    }
    for (const auto& binding : next.rebuild_imports(modules, section_name(next)))
        slots[key({binding.module, binding.symbol.name, {}})] = binding.iat_rva;
    std::uint32_t previous_end = 0;
    for (auto& c : updated.candidates) {
        if (c.state != status::ready || !c.api) continue;
        if (c.entry_rva < previous_end) throw pe::error("Overlapping replacement candidates");
        previous_end = c.end_rva;
        if (next.read_rva(c.entry_rva, c.end_rva - c.entry_rva) != c.original_bytes)
            throw pe::error("Candidate bytes no longer match analysis");
        const auto slot = slots.at(key(*c.api));
        if (static_cast<std::uint64_t>(slot) + 8 > c.entry_rva && slot < c.end_rva)
            throw pe::error("Replacement region overlaps the selected IAT slot");
        const auto patch = make_patch(next, c, slot);
        next.validate_code_patch(c.entry_rva, patch.size());
        next.patch_rva(c.entry_rva, patch);
        c.iat_rva = slot; c.state = status::patched;
    }
    const auto count = updated.count(status::patched);
    image = std::move(next); plan = std::move(updated);
    return count;
}

std::string to_json(const analysis& plan) {
    std::ostringstream out;
    out << "{\n  \"schema_version\": 1,\n  \"architecture\": \"amd64\",\n  \"profile\": \"msvc-inline-fnv1a\",\n  \"image_base\": " << plan.image_base << ",\n  \"summary\": {\"candidates\": " << plan.candidates.size();
    for (auto value : {status::ready, status::patched, status::unresolved, status::ambiguous, status::unsupported})
        out << ", " << quote(status_name(value)) << ": " << plan.count(value);
    out << "},\n  \"diagnostics\": [";
    for (std::size_t n = 0; n < plan.diagnostics.size(); ++n) { if (n) out << ','; out << quote(plan.diagnostics[n]); }
    out << "],\n  \"candidates\": [";
    for (std::size_t n = 0; n < plan.candidates.size(); ++n) {
        const auto& c = plan.candidates[n];
        if (n) out << ',';
        out << "\n    {\"entry_rva\": " << c.entry_rva << ", \"end_rva\": " << c.end_rva << ", \"call_rva\": " << c.call_rva
            << ", \"status\": " << quote(status_name(c.state)) << ", \"reason\": " << quote(c.reason)
            << ", \"has_hash\": " << (c.has_hash ? "true" : "false") << ", \"seed\": " << c.seed << ", \"prime\": " << c.prime << ", \"hash\": " << c.hash
            << ", \"module\": " << (c.api ? quote(c.api->module) : "null") << ", \"name\": " << (c.api ? quote(c.api->name) : "null")
            << ", \"iat_rva\": " << (c.iat_rva ? std::to_string(*c.iat_rva) : "null") << ", \"parameter_rvas\": [";
        for (std::size_t p = 0; p < c.parameters.size(); ++p) {
            if (p) out << ',';
            out << c.parameters[p].address - plan.image_base;
        }
        out << "], \"matches\": [";
        for (std::size_t m = 0; m < c.matches.size(); ++m) { if (m) out << ','; out << quote(key(c.matches[m])); }
        out << "]}";
    }
    out << "\n  ]\n}\n";
    return out.str();
}

} // namespace deobf
