/*
 * wkdm_arm64.S
 * PURE ARM64 ASSEMBLY CORE for WKdm-LZ4/HC V45
 * Target: Cortex-A75/A55 (Helio G85) - AArch64
 */

.arch armv8-a
.text
.align 4

/* 
 * 128-Byte Unrolled XZR Zero Bomber (4KB) 
 * C Prototype: void fast_arm64_zero_4k(u8 *dst);
 */
.global fast_arm64_zero_4k
.type fast_arm64_zero_4k, %function
fast_arm64_zero_4k:
    mov w1, #4096
1:  stp xzr, xzr, [x0], #16
    stp xzr, xzr, [x0], #16
    stp xzr, xzr, [x0], #16
    stp xzr, xzr, [x0], #16
    stp xzr, xzr, [x0], #16
    stp xzr, xzr, [x0], #16
    stp xzr, xzr, [x0], #16
    stp xzr, xzr, [x0], #16
    subs w1, w1, #128
    b.gt 1b
    ret

/* 
 * 128-Byte Unrolled XZR Zero Bomber (Dictionary 2KB)
 * C Prototype: void fast_arm64_zero_dict(u32 *dict);
 */
.global fast_arm64_zero_dict
.type fast_arm64_zero_dict, %function
fast_arm64_zero_dict:
    mov w1, #2048
1:  stp xzr, xzr, [x0], #16
    stp xzr, xzr, [x0], #16
    stp xzr, xzr, [x0], #16
    stp xzr, xzr, [x0], #16
    stp xzr, xzr, [x0], #16
    stp xzr, xzr, [x0], #16
    stp xzr, xzr, [x0], #16
    stp xzr, xzr, [x0], #16
    subs w1, w1, #128
    b.gt 1b
    ret

/* 
 * 128-Byte Unrolled STNP Copy (Cache Bypass Engine)
 * C Prototype: void fast_arm64_memcpy_nt(u8 *dst, const u8 *src, unsigned int len);
 */
.global fast_arm64_memcpy_nt
.type fast_arm64_memcpy_nt, %function
fast_arm64_memcpy_nt:
    cbz w2, 6f
    cmp w2, #128
    b.lt 2f
1:  ldp x3, x4, [x1], #16
    ldp x5, x6, [x1], #16
    ldp x7, x8, [x1], #16
    ldp x9, x10, [x1], #16
    stnp x3, x4, [x0]
    add x0, x0, #16
    stnp x5, x6, [x0]
    add x0, x0, #16
    stnp x7, x8, [x0]
    add x0, x0, #16
    stnp x9, x10, [x0]
    add x0, x0, #16
    
    ldp x3, x4, [x1], #16
    ldp x5, x6, [x1], #16
    ldp x7, x8, [x1], #16
    ldp x9, x10, [x1], #16
    stnp x3, x4, [x0]
    add x0, x0, #16
    stnp x5, x6, [x0]
    add x0, x0, #16
    stnp x7, x8, [x0]
    add x0, x0, #16
    stnp x9, x10, [x0]
    add x0, x0, #16
    
    subs w2, w2, #128
    cmp w2, #128
    b.ge 1b
2:  cmp w2, #16
    b.lt 4f
3:  ldp x3, x4, [x1], #16
    stnp x3, x4, [x0]
    add x0, x0, #16
    subs w2, w2, #16
    cmp w2, #16
    b.ge 3b
4:  cbz w2, 6f
5:  ldrb w3, [x1], #1
    strb w3, [x0], #1
    subs w2, w2, #1
    cbnz w2, 5b
6:  ret
