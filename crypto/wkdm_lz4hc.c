/* SPDX-License-Identifier: GPL-2.0 */
/*
 * WKdm-LZ4/HC V58 SILICON INCARNATE (C89 Strict Fix)
 * Pure LDP Inline ASM + Explicit CRC32W + V57 Explicit Framing
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/crypto.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/lz4.h>
#include <linux/jiffies.h>
#include <linux/cache.h>
#include <linux/compiler.h>
#include <linux/string.h>
#include <linux/percpu.h>
#include <crypto/internal/scompress.h>
#include <asm/unaligned.h>

#define WKDM_PAGE_SIZE 4096
#define WKDM_WORDS 1024
#define WKDM_DICT_BITS 8
#define WKDM_DICT_BUCKETS (1U << WKDM_DICT_BITS)
#define WKDM_DICT_WAYS 2
#define WKDM_VALID_BYTES WKDM_DICT_BUCKETS
#define WKDM_TAG_BYTES (WKDM_WORDS/4)
#define WKDM_MAX_INDEX_BYTES WKDM_WORDS
#define WKDM_MAX_MISS WKDM_WORDS
#define WKDM_RAW_PLANE_SIZE WKDM_MAX_MISS
#define WKDM_TOTAL_RAW_BYTES (WKDM_RAW_PLANE_SIZE*4)
#define WKDM_TOTAL_INDEX_BYTES (WKDM_MAX_INDEX_BYTES*2)
#define WKDM_HEADER_SIZE 6
#define WKDM_MAX_CAPACITY (WKDM_HEADER_SIZE + WKDM_TAG_BYTES + WKDM_TOTAL_INDEX_BYTES + WKDM_TOTAL_RAW_BYTES)

/* 1-Byte Explicit Framing Protocol */
#define TYPE_ZERO 0x00
#define TYPE_WKDM 0x01
#define TYPE_RAW  0x02

/* Tags */
#define TAG_ZERO 0x00
#define TAG_DICT_0 0x01
#define TAG_DICT_1 0x02
#define TAG_MISS 0x03
#define ZERO_MARKER_U16 0x4B57

#define WKDM_MODE_FAST 0
#define WKDM_MODE_BALANCED 1
#define WKDM_MODE_EXTREME 2

#define WKDM_BURST_FAST_THRESHOLD 25
#define WKDM_DECAY_MAX_SHIFT 4
#define WKDM_SAMPLE_STEP 64
#define WKDM_SAMPLE_COUNT 16

#define WKDM_PREFETCH_READ(a) asm volatile("prfm pldl1strm, [%0]" :: "r"(a) : "memory")
#define WKDM_PREFETCH_WRITE(a) asm volatile("prfm pstl1strm, [%0]" :: "r"(a) : "memory")

#if defined(__ARM_FEATURE_CRC32)
static __always_inline u32 hw_hash_32_asm(u32 val) {
    u32 res;
    asm volatile("crc32w %w0, wzr, %w1" : "=r"(res) : "r"(val));
    return res & (WKDM_DICT_BUCKETS - 1);
}
#else
static __always_inline u32 hw_hash_32_asm(u32 val) {
    return (val * 2654435761U) >> (32 - WKDM_DICT_BITS);
}
#endif

extern void fast_arm64_zero_4k_dczva(u8 *dst);
extern void fast_arm64_zero_dict_dczva(u32 *dict);
extern void fast_arm64_zero_valid_dczva(u8 *bitmap);
extern void fast_arm64_delta_copy(u8 *dst, const u8 *src, unsigned int len);
extern void fast_arm64_copy_256_stnp(u8 *dst, const u8 *src);

__asm__(
".text\n.align 4\n"
".global fast_arm64_zero_4k_dczva\n.type fast_arm64_zero_4k_dczva, %function\n"
"fast_arm64_zero_4k_dczva:\n mov w1, #64\n1: dc zva, x0\n add x0, x0, #64\n subs w1, w1, #1\n b.gt 1b\n ret\n"
".global fast_arm64_zero_dict_dczva\n.type fast_arm64_zero_dict_dczva, %function\n"
"fast_arm64_zero_dict_dczva:\n mov w1, #32\n1: dc zva, x0\n add x0, x0, #64\n subs w1, w1, #1\n b.gt 1b\n ret\n"
".global fast_arm64_zero_valid_dczva\n.type fast_arm64_zero_valid_dczva, %function\n"
"fast_arm64_zero_valid_dczva:\n mov w1, #4\n1: dc zva, x0\n add x0, x0, #64\n subs w1, w1, #1\n b.gt 1b\n ret\n"
".global fast_arm64_copy_256_stnp\n.type fast_arm64_copy_256_stnp, %function\n"
"fast_arm64_copy_256_stnp:\n mov w2, #256\n1: ldp x3, x4, [x1], #16\n stnp x3, x4, [x0]\n add x0, x0, #16\n ldp x5, x6, [x1], #16\n stnp x5, x6, [x0]\n add x0, x0, #16\n subs w2, w2, #32\n b.gt 1b\n ret\n"
".global fast_arm64_delta_copy\n.type fast_arm64_delta_copy, %function\n"
"fast_arm64_delta_copy:\n cbz w2,9f\n cmp w2,#1\n b.eq 8f\n ldrb w3,[x1],#1\n strb w3,[x0],#1\n subs w2,w2,#1\n lsl x3,x3,#56\n1: cmp w2,#8\n b.lt 6f\n ldr x4,[x1],#8\n extr x5,x4,x3,#56\n eor x6,x4,x5\n str x6,[x0],#8\n mov x3,x4\n subs w2,w2,#8\n b.ne 1b\n6: cbz w2,9f\n lsr x3,x3,#56\n7: ldrb w4,[x1],#1\n eor w5,w4,w3\n strb w5,[x0],#1\n mov w3,w4\n subs w2,w2,#1\n b.gt 7b\n9: ret\n8: ldrb w3,[x1]\n strb w3,[x0]\n ret\n"
);

static __always_inline bool wkdm_way_valid(const u8 *v, u32 b, int way){ return v[b] & (1<<way); }

struct wkdm_memory_pool {
    u32 dict[WKDM_DICT_BUCKETS*WKDM_DICT_WAYS] __aligned(64);
    u8 valid[WKDM_VALID_BYTES] __aligned(64);
    u8 index_buffer[WKDM_TOTAL_INDEX_BYTES] __aligned(64);
    u8 raw_buffer[WKDM_TOTAL_RAW_BYTES] __aligned(64);
    u8 tags_buffer[WKDM_TAG_BYTES] __aligned(64);
} ____cacheline_aligned;

static DEFINE_PER_CPU(struct wkdm_memory_pool, wkdm_percpu_pool);

struct hybrid_ctx {
    void *lz4_workspace; 
    void *lz4hc_workspace; 
    u8 *wkdm_buffer;
    unsigned long last_jiffy; 
    u16 burst_count;
} ____cacheline_aligned;

struct wkdm_metrics {
    u16 miss; 
    u16 wkdm_len; 
    u16 burst; 
    u8 score;
};

static __always_inline u8 wkdm_select_mode(struct wkdm_metrics *m){
    u32 miss_ratio = (m->miss * 100) / 1024;
    if(miss_ratio > 85 && m->wkdm_len > 3481) return WKDM_MODE_FAST;
    if(m->wkdm_len < 512) return WKDM_MODE_EXTREME;
    if(m->burst >= 25) return WKDM_MODE_FAST;
    if(m->wkdm_len < 1500 && m->score >= 18) return WKDM_MODE_EXTREME;
    if(m->wkdm_len < 2800) return WKDM_MODE_BALANCED;
    return WKDM_MODE_FAST;
}

static __always_inline void wkdm_write_header(u8 *d,u16 a,u16 b,u16 c){ 
    put_unaligned_le16(a,d); 
    put_unaligned_le16(b,d+2); 
    put_unaligned_le16(c,d+4); 
}

static __always_inline void wkdm_update_burst(struct hybrid_ctx *c, unsigned long now){ 
    unsigned long d = now - c->last_jiffy; 
    if(d){ 
        if(d >= WKDM_DECAY_MAX_SHIFT) c->burst_count = 0; 
        else c->burst_count >>= d; 
        c->last_jiffy = now; 
    } 
    if(c->burst_count < 0xffff) c->burst_count++; 
}

static __always_inline unsigned int wkdm_sample_score(const u8 *src){
    unsigned int s = 0; 
    u32 p = 0;
    unsigned int i;
    for(i = 0; i < WKDM_SAMPLE_COUNT; i++){
        u32 v = get_unaligned_le32(src + (i * WKDM_SAMPLE_STEP * sizeof(u32)));
        if(v == 0) s += 4;
        if(i && v == p) s += 3;
        p = v;
    }
    return s;
}

/* Macro telah dipindahkan di bawah definisi TAG_* agar aman */
#define PROCESS_WORD(v_idx, shift_val) do { \
    u32 val = v##v_idx; \
    if (unlikely(val == 0)) { tp |= TAG_ZERO << shift_val; } \
    else { \
        u32 b = hw_hash_32_asm(val); \
        u32 *e = &dict[b << 1]; \
        WKDM_PREFETCH_READ(e); \
        if (wkdm_way_valid(valid, b, 0) && e[0] == val) { \
            if (unlikely(l0 >= WKDM_MAX_INDEX_BYTES)) return -ENOSPC; \
            tp |= TAG_DICT_0 << shift_val; i0[l0++] = (u8)b; \
        } else if (!is_gaming && wkdm_way_valid(valid, b, 1) && e[1] == val) { \
            if (unlikely(l1 >= WKDM_MAX_INDEX_BYTES)) return -ENOSPC; \
            tp |= TAG_DICT_1 << shift_val; i1[l1++] = (u8)b; \
            e[1] = e[0]; e[0] = val; \
        } else { \
            if (unlikely(miss >= WKDM_MAX_MISS)) return -ENOSPC; \
            tp |= TAG_MISS << shift_val; \
            r0[miss] = (u8)val; r1[miss] = (u8)(val >> 8); \
            r2[miss] = (u8)(val >> 16); r3[miss] = (u8)(val >> 24); \
            miss++; e[1] = e[0]; e[0] = val; valid[b] = (valid[b] << 1) | 1; \
        } \
    } \
} while(0)

static int wkdm_pack_split(const u8 *src, u8 *out, struct hybrid_ctx *ctx, struct wkdm_memory_pool *pool, struct wkdm_metrics *met){
    u32 *dict = pool->dict; 
    u8 *valid = pool->valid; 
    u8 *tags = pool->tags_buffer;
    u8 *i0 = pool->index_buffer, *i1 = i0 + WKDM_MAX_INDEX_BYTES;
    u8 *r0 = pool->raw_buffer, *r1 = r0 + WKDM_RAW_PLANE_SIZE;
    u8 *r2 = r1 + WKDM_RAW_PLANE_SIZE, *r3 = r2 + WKDM_RAW_PLANE_SIZE;
    u16 l0 = 0, l1 = 0, miss = 0; 
    u32 page_or = 0;
    bool is_gaming = ctx->burst_count >= WKDM_BURST_FAST_THRESHOLD;
    const u8 *src_ptr = src;
    u16 w;
    unsigned int off = 0;
    
    fast_arm64_zero_dict_dczva(dict); 
    fast_arm64_zero_valid_dczva(valid);
    
    for(w = 0; w < WKDM_WORDS; w += 4){
        register u64 d0_1, d2_3;
        u32 v0, v1, v2, v3;
        u8 tp = 0;
        
        WKDM_PREFETCH_READ(src_ptr + 128);
        
        asm volatile("ldp %0, %1, [%2], #16" : "=r"(d0_1), "=r"(d2_3), "+r"(src_ptr));
        
        v0 = (u32)d0_1; v1 = (u32)(d0_1 >> 32);
        v2 = (u32)d2_3; v3 = (u32)(d2_3 >> 32);
        
        page_or |= v0 | v1 | v2 | v3;
        
        PROCESS_WORD(0, 0);
        PROCESS_WORD(1, 2);
        PROCESS_WORD(2, 4);
        PROCESS_WORD(3, 6);
        
        tags[w >> 2] = tp;
    }
    
    if(unlikely(page_or == 0)) return 0;
    
    wkdm_write_header(out, l0, l1, miss); 
    off += 6; 
    fast_arm64_copy_256_stnp(out + off, tags); 
    off += WKDM_TAG_BYTES;
    
    fast_arm64_delta_copy(out + off, i0, l0); off += l0; 
    fast_arm64_delta_copy(out + off, i1, l1); off += l1;
    fast_arm64_delta_copy(out + off, r3, miss); off += miss; 
    fast_arm64_delta_copy(out + off, r2, miss); off += miss;
    fast_arm64_delta_copy(out + off, r1, miss); off += miss; 
    fast_arm64_delta_copy(out + off, r0, miss); off += miss;
    
    met->miss = miss; 
    met->wkdm_len = off; 
    met->burst = ctx->burst_count; 
    met->score = 0;
    
    if (unlikely(off >= 4096)) return -ENOSPC; 
    return off;
}

static int wkdm_unpack_linear(const u8 *src, unsigned int slen, u8 *dst, struct wkdm_memory_pool *pool){
    u16 l0, l1, miss;
    const u8 *tags, *i0, *i1, *r3, *r2, *r1, *r0;
    u32 *dict = pool->dict; 
    u8 *valid = pool->valid; 
    u16 c0 = 0, c1 = 0, cm = 0; 
    u8 p0 = 0, p1 = 0, p2 = 0, p3 = 0, pi0 = 0, pi1 = 0;
    u16 w;
    int k;

    if(slen < 6) return -EINVAL; 
    
    l0 = get_unaligned_le16(src); 
    l1 = get_unaligned_le16(src + 2); 
    miss = get_unaligned_le16(src + 4);
    
    if(l0 > 1024 || l1 > 1024 || miss > 1024 || 6 + 256 + l0 + l1 + miss * 4 != slen || slen > WKDM_MAX_CAPACITY) 
        return -EINVAL;
        
    tags = src + 6; 
    i0 = tags + 256; 
    i1 = i0 + l0; 
    r3 = i1 + l1; 
    r2 = r3 + miss; 
    r1 = r2 + miss; 
    r0 = r1 + miss;
    
    fast_arm64_zero_dict_dczva(dict); 
    fast_arm64_zero_valid_dczva(valid);
    
    for(w = 0; w < 1024; w += 4){ 
        u8 pk = tags[w >> 2]; 
        for(k = 0; k < 4; k++){ 
            u8 tag = (pk >> (k * 2)) & 0x03; 
            u8 *o = dst + ((w + k) << 2);
            
            if(tag == 0){ 
                put_unaligned_le32(0, o); 
            } 
            else if(tag == 3){ 
                u32 v, b, *e;
                if(unlikely(cm >= miss)) return -EINVAL; 
                p3 ^= r3[cm]; p2 ^= r2[cm]; p1 ^= r1[cm]; p0 ^= r0[cm]; cm++; 
                v = ((u32)p0) | ((u32)p1 << 8) | ((u32)p2 << 16) | ((u32)p3 << 24); 
                b = hw_hash_32_asm(v); 
                e = &dict[b << 1]; 
                e[1] = e[0]; e[0] = v; 
                valid[b] = (valid[b] << 1) | 1; 
                put_unaligned_le32(v, o); 
            }
            else if(tag == 1){ 
                u32 b;
                if(unlikely(c0 >= l0)) return -EINVAL; 
                pi0 ^= i0[c0++]; 
                b = pi0; 
                if(unlikely(!wkdm_way_valid(valid, b, 0))) return -EINVAL; 
                put_unaligned_le32(dict[b << 1], o); 
            }
            else{ 
                u32 b, *e, v;
                if(unlikely(c1 >= l1)) return -EINVAL; 
                pi1 ^= i1[c1++]; 
                b = pi1; 
                if(unlikely(!wkdm_way_valid(valid, b, 1))) return -EINVAL; 
                e = &dict[b << 1]; 
                v = e[1]; e[1] = e[0]; e[0] = v; 
                put_unaligned_le32(v, o); 
            } 
        } 
    }
    if(c0 != l0 || c1 != l1 || cm != miss) return -EINVAL; 
    return 0;
}

static void *hybrid_alloc_ctx(struct crypto_scomp *tfm){ 
    struct hybrid_ctx *c = kzalloc(sizeof(*c), GFP_KERNEL); 
    if(!c) return ERR_PTR(-ENOMEM); 
    
    c->lz4_workspace = kmalloc(LZ4_sizeofState(), GFP_KERNEL); 
    c->lz4hc_workspace = vmalloc(LZ4_sizeofStateHC()); 
    c->wkdm_buffer = kmalloc(WKDM_MAX_CAPACITY, GFP_KERNEL); 
    
    if(!c->lz4_workspace || !c->lz4hc_workspace || !c->wkdm_buffer){ 
        kfree(c->wkdm_buffer); 
        kfree(c->lz4_workspace); 
        vfree(c->lz4hc_workspace); 
        kfree(c); 
        return ERR_PTR(-ENOMEM);
    } 
    c->last_jiffy = jiffies; 
    return c; 
}

static void hybrid_free_ctx(struct crypto_scomp *tfm, void *p){ 
    struct hybrid_ctx *c = p; 
    if(!c) return; 
    kfree(c->wkdm_buffer); 
    kfree(c->lz4_workspace); 
    vfree(c->lz4hc_workspace); 
    kfree(c); 
}

static int hybrid_scompress(struct crypto_scomp *tfm, const u8 *src, unsigned int slen, u8 *dst, unsigned int *dlen, void *ctx_ptr){
    struct hybrid_ctx *c = ctx_ptr; 
    struct wkdm_metrics met;
    struct wkdm_memory_pool *pool;
    int wl, ll;
    u8 mode;

    if(!dlen || slen != 4096 || *dlen < 4096) return -EINVAL; 
    
    wkdm_update_burst(c, jiffies);
    
    pool = get_cpu_ptr(&wkdm_percpu_pool);
    wl = wkdm_pack_split(src, c->wkdm_buffer, c, pool, &met);
    put_cpu_ptr(&wkdm_percpu_pool);

    if (wl == 0) { 
        dst[0] = TYPE_ZERO; 
        *dlen = 1; 
        return 0; 
    }
    
    met.score = wkdm_sample_score(src);
    mode = wkdm_select_mode(&met);

    WKDM_PREFETCH_WRITE(dst);

    if (wl < 0) { 
        mode = (met.burst >= WKDM_BURST_FAST_THRESHOLD) ? WKDM_MODE_FAST : WKDM_MODE_BALANCED;
        if (mode == WKDM_MODE_FAST) {
            ll = LZ4_compress_default(src, dst + 1, 4096, *dlen - 1, c->lz4_workspace);
        } else {
            ll = LZ4_compress_HC(src, dst + 1, 4096, *dlen - 1, 9, c->lz4hc_workspace);
        }
        
        if (ll <= 0 || ll >= 4095) return -ENOSPC;
        dst[0] = TYPE_RAW; 
        *dlen = ll + 1; 
        return 0;
    } else {
        if (mode == WKDM_MODE_FAST) {
            ll = LZ4_compress_default(c->wkdm_buffer, dst + 1, wl, *dlen - 1, c->lz4_workspace); 
        } else if (mode == WKDM_MODE_BALANCED) {
            ll = LZ4_compress_HC(c->wkdm_buffer, dst + 1, wl, *dlen - 1, 9, c->lz4hc_workspace); 
        } else {
            ll = LZ4_compress_HC(c->wkdm_buffer, dst + 1, wl, *dlen - 1, 12, c->lz4hc_workspace); 
        }
        
        if (ll <= 0 || ll >= 4095) return -ENOSPC;
        dst[0] = TYPE_WKDM; 
        *dlen = ll + 1; 
        return 0;
    }
}

static int hybrid_sdecompress(struct crypto_scomp *tfm, const u8 *src, unsigned int slen, u8 *dst, unsigned int *dlen, void *ctx_ptr){
    struct hybrid_ctx *c = ctx_ptr; 
    u8 type;
    int ret;
    struct wkdm_memory_pool *pool;

    if(!dlen || slen < 1) return -EINVAL; 
    
    type = src[0];
    if (type == TYPE_ZERO) { 
        fast_arm64_zero_4k_dczva(dst); 
        *dlen = 4096; 
        return 0; 
    }
    
    if (type == TYPE_RAW) {
        ret = LZ4_decompress_safe(src + 1, dst, slen - 1, 4096);
        if (ret != 4096) return -EINVAL;
        *dlen = 4096; 
        return 0;
    }
    
    if (type == TYPE_WKDM) {
        ret = LZ4_decompress_safe(src + 1, c->wkdm_buffer, slen - 1, WKDM_MAX_CAPACITY); 
        if (ret < 6) return -EINVAL;
        
        pool = get_cpu_ptr(&wkdm_percpu_pool);
        ret = wkdm_unpack_linear(c->wkdm_buffer, ret, dst, pool); 
        put_cpu_ptr(&wkdm_percpu_pool);
        
        if (ret < 0) return ret; 
        *dlen = 4096; 
        return 0;
    }
    return -EINVAL;
}

static struct scomp_alg scomp={
    .alloc_ctx=hybrid_alloc_ctx, 
    .free_ctx=hybrid_free_ctx, 
    .compress=hybrid_scompress, 
    .decompress=hybrid_sdecompress,
    .base={.cra_name="wkdm_lz4hc",.cra_driver_name="wkdm_lz4hc-v58",.cra_module=THIS_MODULE,},
};

static int __init mod_init(void){ return crypto_register_scomp(&scomp); }
static void __exit mod_fini(void){ crypto_unregister_scomp(&scomp); }
module_init(mod_init); module_exit(mod_fini);
MODULE_LICENSE("GPL"); MODULE_AUTHOR("Purdianto Efendi"); MODULE_DESCRIPTION("WKdm-LZ4/HC V58 SILICON INCARNATE (C89 Strict Fix)"); MODULE_ALIAS_CRYPTO("wkdm_lz4hc");
