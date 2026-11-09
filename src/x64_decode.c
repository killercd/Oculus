#include "internal.h"

/*
 * Conservative x86-64 length decoder for hook prologues.  It intentionally
 * rejects VEX/EVEX and unknown encodings.  The hook layer also rejects every
 * RIP-relative or relative-control-flow instruction, so copied instructions
 * never need semantic rewriting.  This small decoder is derived from the
 * encoding rules in Intel SDM vol. 2, not from a runtime dependency.
 */
bool oculus_x64_decode(const uint8_t *p, size_t n, OculusX64Instruction *out) {
    size_t i = 0; bool rex_w = false, op16 = false, addr32 = false;
    if (!p || !out || !n) return false;
    for (;;) {
        if (i >= n || i >= 15) return false;
        uint8_t b = p[i];
        if (b == 0x66) op16 = true;
        else if (b == 0x67) addr32 = true;
        else if (b == 0xF0 || b == 0xF2 || b == 0xF3 || b == 0x2E || b == 0x36 ||
                 b == 0x3E || b == 0x26 || b == 0x64 || b == 0x65) { }
        else if ((b & 0xF0) == 0x40) rex_w = (b & 8) != 0;
        else break;
        ++i;
    }
    uint8_t op = p[i++]; bool modrm = false, relative = false; size_t imm = 0;
    if ((op >= 0x50 && op <= 0x5F) || op == 0x90 || op == 0x98 || op == 0x99 ||
        op == 0x9C || op == 0x9D || op == 0xC3 || op == 0xCB || op == 0xCC ||
        op == 0xF8 || op == 0xF9 || op == 0xFC || op == 0xFD) {
    } else if (op >= 0xB0 && op <= 0xB7) imm = 1;
    else if (op >= 0xB8 && op <= 0xBF) imm = rex_w ? 8 : (op16 ? 2 : 4);
    else if (op == 0x6A || op == 0xCD || op == 0xEB || (op >= 0x70 && op <= 0x7F)) {
        imm = 1; relative = (op == 0xEB || op >= 0x70);
    } else if (op == 0x68) imm = op16 ? 2 : 4;
    else if (op == 0xE8 || op == 0xE9) { imm = 4; relative = true; }
    else if (op == 0xC2 || op == 0xCA) imm = 2;
    else if (op == 0xA8) imm = 1;
    else if (op == 0xA9) imm = op16 ? 2 : 4;
    else if (op == 0x0F) {
        if (i >= n) return false;
        uint8_t op2 = p[i++];
        if (op2 >= 0x80 && op2 <= 0x8F) { imm = 4; relative = true; }
        else if (op2 == 0x05 || op2 == 0x31 || op2 == 0xA2) { }
        else if (op2 == 0x1F || op2 == 0xAF || op2 == 0xB6 || op2 == 0xB7 ||
                 op2 == 0xBE || op2 == 0xBF || (op2 >= 0x40 && op2 <= 0x4F) ||
                 (op2 >= 0x90 && op2 <= 0x9F) || (op2 >= 0x10 && op2 <= 0x17) ||
                 (op2 >= 0x28 && op2 <= 0x2F) || op2 == 0x6E || op2 == 0x6F ||
                 op2 == 0x7E || op2 == 0x7F) modrm = true;
        else return false;
    } else {
        switch (op) {
        case 0x00: case 0x01: case 0x02: case 0x03: case 0x08: case 0x09:
        case 0x0A: case 0x0B: case 0x10: case 0x11: case 0x12: case 0x13:
        case 0x18: case 0x19: case 0x1A: case 0x1B: case 0x20: case 0x21:
        case 0x22: case 0x23: case 0x28: case 0x29: case 0x2A: case 0x2B:
        case 0x30: case 0x31: case 0x32: case 0x33: case 0x38: case 0x39:
        case 0x3A: case 0x3B: case 0x62: case 0x63: case 0x84: case 0x85:
        case 0x86: case 0x87: case 0x88: case 0x89: case 0x8A: case 0x8B:
        case 0x8D: case 0x8F: case 0xD0: case 0xD1: case 0xD2: case 0xD3:
        case 0xF6: case 0xF7: case 0xFE: case 0xFF: modrm = true; break;
        case 0x69: modrm = true; imm = op16 ? 2 : 4; break;
        case 0x6B: modrm = true; imm = 1; break;
        case 0x80: case 0x82: case 0x83: modrm = true; imm = 1; break;
        case 0x81: modrm = true; imm = op16 ? 2 : 4; break;
        case 0xC0: case 0xC1: case 0xC6: modrm = true; imm = 1; break;
        case 0xC7: modrm = true; imm = op16 ? 2 : 4; break;
        default: return false;
        }
    }
    bool rip = false;
    if (modrm) {
        if (i >= n) return false;
        uint8_t mr = p[i++], mod = mr >> 6, rm = mr & 7;
        if (!addr32 && mod == 0 && rm == 5) rip = true;
        if (mod != 3 && rm == 4) {
            if (i >= n) return false;
            uint8_t sib = p[i++];
            if (mod == 0 && (sib & 7) == 5) i += 4;
        }
        if (mod == 1) i += 1;
        else if (mod == 2 || (mod == 0 && rm == 5)) i += 4;
        if ((op == 0xF6 && ((mr >> 3) & 7) <= 1)) imm = 1;
        if ((op == 0xF7 && ((mr >> 3) & 7) <= 1)) imm = op16 ? 2 : 4;
    }
    if (i > 15 || imm > 15 - i || i + imm > n) return false;
    out->length = (uint8_t)(i + imm); out->rip_relative = rip; out->relative_branch = relative;
    return true;
}
