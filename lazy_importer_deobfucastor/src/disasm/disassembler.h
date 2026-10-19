#pragma once

#include "../pe/image.h"
#include <Zydis/Zydis.h>
#include <array>
#include <functional>

namespace disasm {

enum class invalid_policy { fail, skip_byte };

struct instruction {
    std::uint64_t address = 0;
    std::uint8_t length = 0;
    bool valid = false;
    std::array<std::uint8_t, ZYDIS_MAX_INSTRUCTION_LENGTH> bytes{};
    ZydisDecodedInstruction decoded{};
    std::array<ZydisDecodedOperand, ZYDIS_MAX_OPERAND_COUNT> operands{};
    std::optional<std::uint64_t> branch_target;  // Direct relative call/jump only.
    std::vector<std::uint64_t> memory_addresses; // Static RIP-relative/absolute addresses, not dereferenced.

    bool is_call() const noexcept;
    bool is_branch() const noexcept;
    bool is_return() const noexcept;
};

class disassembler {
public:
    disassembler();
    instruction decode(const std::uint8_t* data, std::size_t size, std::uint64_t address) const;

    // Visitor returns false to stop. Invalid bytes have valid=false and length=1.
    // Linear sweep does not distinguish embedded data from code or recover a CFG.
    void walk(const std::uint8_t* data, std::size_t size, std::uint64_t address,
        const std::function<bool(const instruction&)>& visitor,
        invalid_policy policy = invalid_policy::fail) const;

    std::vector<instruction> range(const pe::image& image, std::uint32_t rva, std::size_t size,
        invalid_policy policy = invalid_policy::fail, std::size_t max_instructions = 0) const;

    void executable_sections(const pe::image& image,
        const std::function<bool(const instruction&)>& visitor,
        invalid_policy policy = invalid_policy::skip_byte) const;

private:
    ZydisDecoder decoder_{};
};

} // namespace disasm
