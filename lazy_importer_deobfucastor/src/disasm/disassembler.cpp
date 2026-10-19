#include "disassembler.h"
#include <algorithm>

namespace disasm {

bool instruction::is_call() const noexcept {
    return valid && decoded.meta.category == ZYDIS_CATEGORY_CALL;
}

bool instruction::is_branch() const noexcept {
    return valid && (is_call() || decoded.meta.category == ZYDIS_CATEGORY_COND_BR
        || decoded.meta.category == ZYDIS_CATEGORY_UNCOND_BR);
}

bool instruction::is_return() const noexcept {
    return valid && decoded.meta.category == ZYDIS_CATEGORY_RET;
}

disassembler::disassembler() {
    if (!ZYAN_SUCCESS(ZydisDecoderInit(&decoder_, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64)))
        throw pe::error("Cannot initialize Zydis");
}

instruction disassembler::decode(const std::uint8_t* data, std::size_t size, std::uint64_t address) const {
    if (!data || !size) throw pe::error("Empty instruction buffer");
    instruction result;
    result.address = address;
    if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder_, data, size, &result.decoded, result.operands.data())))
        throw pe::error("Cannot decode instruction at VA " + std::to_string(address));
    result.valid = true;
    result.length = result.decoded.length;
    if (address > UINT64_MAX - result.length) throw pe::error("Instruction address overflow");
    std::copy_n(data, result.length, result.bytes.begin());
    for (std::size_t i = 0; i < result.decoded.operand_count_visible; ++i) {
        const auto& operand = result.operands[i];
        ZyanU64 absolute = 0;
        if (operand.type == ZYDIS_OPERAND_TYPE_IMMEDIATE && operand.imm.is_relative && result.is_branch()
            && ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&result.decoded, &operand, address, &absolute)))
            result.branch_target = absolute;
        if (operand.type == ZYDIS_OPERAND_TYPE_MEMORY && operand.mem.segment != ZYDIS_REGISTER_FS
            && operand.mem.segment != ZYDIS_REGISTER_GS
            && ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&result.decoded, &operand, address, &absolute)))
            result.memory_addresses.push_back(absolute);
    }
    return result;
}

void disassembler::walk(const std::uint8_t* data, std::size_t size, std::uint64_t address,
    const std::function<bool(const instruction&)>& visitor, invalid_policy policy) const {
    if ((!data && size) || !visitor || size > UINT64_MAX - address) throw pe::error("Invalid disassembly range");
    for (std::size_t offset = 0; offset < size;) {
        instruction current;
        try {
            current = decode(data + offset, size - offset, address + offset);
        } catch (const pe::error&) {
            if (policy == invalid_policy::fail) throw;
            current.address = address + offset;
            current.length = 1;
            current.bytes[0] = data[offset];
        }
        if (!visitor(current)) return;
        offset += current.length;
    }
}

std::vector<instruction> disassembler::range(const pe::image& image, std::uint32_t rva, std::size_t size,
    invalid_policy policy, std::size_t max_instructions) const {
    const auto offset = image.rva_to_offset(rva, size);
    if (!offset) throw pe::error("Disassembly range is not backed by file bytes");
    std::vector<instruction> result;
    walk(image.data().data() + *offset, size, image.rva_to_va(rva), [&](const instruction& insn) {
        result.push_back(insn);
        return !max_instructions || result.size() < max_instructions;
    }, policy);
    return result;
}

void disassembler::executable_sections(const pe::image& image,
    const std::function<bool(const instruction&)>& visitor, invalid_policy policy) const {
    if (!visitor) throw pe::error("Missing instruction visitor");
    bool keep_going = true;
    for (const auto& section : image.sections()) {
        const auto& h = section.header;
        if (!section.executable() || !h.SizeOfRawData) continue;
        // Omit alignment padding where VirtualSize specifies a shorter extent.
        const auto size = h.Misc.VirtualSize ? std::min(h.Misc.VirtualSize, h.SizeOfRawData) : h.SizeOfRawData;
        walk(image.data().data() + h.PointerToRawData, size, image.rva_to_va(h.VirtualAddress),
            [&](const instruction& insn) { keep_going = visitor(insn); return keep_going; }, policy);
        if (!keep_going) return;
    }
}

} // namespace disasm
