/*
 * wkdm_lz4hc_arm64.S
 * PURE ARM64 ASSEMBLY CORE for WKdm-LZ4/HC V46 ETERNITY
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

/* 
 * EXTR Fusion Delta Encode + Copy 
 * Memanfaatkan instruksi 'extr' (Extract) AArch64 untuk operasi 1-Cycle
 * C Prototype: void fast_arm64_fusion_delta_nt(u8 *dst, const u8 *src, unsigned int len);
 */
.global fast_arm64_fusion_delta_nt
.type fast_arm64_fusion_delta_nt, %function
fast_arm64_fusion_delta_nt:
    cbz w2, 4f                  
    cmp w2, #1
    b.eq 5f                     
    
    ldrb w3, [x1], #1           
    strb w3, [x0], #1           
    sub w2, w2, #1              
1:  cmp w2, #8
    b.lt 3f                     
    ldr x4, [x1], #8            
    extr x5, x4, x3, #56        // SAKTI: 1 Cycle Bit-Shift & ORR lewat Hardware
    eor x6, x4, x5              
    str x6, [x0], #8            // Tulis aman 8-byte
    lsr x3, x4, #56             
    sub w2, w2, #8
    b 1b
3:  cbz w2, 4f                  
2:  ldrb w4, [x1], #1           
    eor w5, w4, w3              
    strb w5, [x0], #1           
    mov w3, w4                  
    subs w2, w2, #1
    b.gt 2b
4:  ret
5:  ldrb w3, [x1]
    strb w3, [x0]
    ret
