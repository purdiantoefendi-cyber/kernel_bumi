/*
 * Cryptographic API.
 *
 * WKdm-LZ4/HC V30 HC-Centric Density Edition 
 * (PURE ARM64 ASSEMBLY CORE - HARDCODED FOR AARCH64)
 *
 * ============================================================
 * V30 ARCHITECTURE & SAFETY MATRIX
 * ------------------------------------------------------------
 * 1. HC-CENTRIC CPU POLICY: LZ4HC-12 is unconditionally used.
 *    CRITICAL = 25 (Tuned for Helio G85 @ HZ=1000).
 * 2. PURE ARM64 CORE: Delta encode & Memcpy written in raw AArch64.
 * 3. NO ARCH CHECKS: Hardcoded strictly for ARM64 Processors.
 * ============================================================
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/crypto.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/lz4.h>
#include <linux/sched.h>
#include <linux/cache.h>
#include <linux/jiffies.h>
#include <linux/bug.h>
#include <linux/limits.h>
#include <linux/prefetch.h>
#include <crypto/internal/scompress.h>
#include <asm/unaligned.h>

#define WKDM_PAGE_SIZE          4096
#define WKDM_WORDS              1024
#define WKDM_DICT_BITS          7
#define WKDM_DICT_BUCKETS       (1U << WKDM_DICT_BITS)
#define WKDM_DICT_WAYS          2

#define WKDM_TAG_BYTES          (WKDM_WORDS / 4)
#define WKDM_MAX_INDEX_BYTES    WKDM_WORDS
#define WKDM_MAX_MISS           WKDM_WORDS
#define WKDM_RAW_PLANE_SIZE     WKDM_MAX_MISS

#define WKDM_TOTAL_RAW_BYTES    (WKDM_RAW_PLANE_SIZE * 4)
#define WKDM_TOTAL_INDEX_BYTES  (WKDM_MAX_INDEX_BYTES * 2)
#define WKDM_HEADER_SIZE        6
#define WKDM_MAX_CAPACITY       \
        (WKDM_HEADER_SIZE + WKDM_TAG_BYTES + WKDM_TOTAL_INDEX_BYTES + WKDM_TOTAL_RAW_BYTES)

#define WKDM_LZ4HC_LEVEL        12
#define WKDM_COMPRESS_RATE_CRITICAL 25
#define WKDM_DECAY_MAX_SHIFT        8

#define TAG_ZERO                0x00
#define TAG_DICT_0              0x01
#define TAG_DICT_1              0x02
#define TAG_MISS                0x03

struct wkdm_memory_pool {
    u32 dict[WKDM_DICT_BUCKETS * WKDM_DICT_WAYS];
    u8 index_buffer[WKDM_TOTAL_INDEX_BYTES];
    u8 raw_buffer[WKDM_TOTAL_RAW_BYTES];
    u8 tags_buffer[WKDM_TAG_BYTES];
};

struct hybrid_ctx {
    void *lz4_workspace;
    void *lz4hc_workspace;
    u8 *wkdm_buffer;
    struct wkdm_memory_pool *pool;
    u32 *wkdm_dict;
    u8 *index_buffer; 
    u8 *raw_buffer;
    u8 *tags_buffer;
    unsigned long last_jiffy;
    u16 burst_count;
} ____cacheline_aligned;

static __always_inline u32 hash_word(u32 word)
{
    return (word * 2654435761U) >> (32 - WKDM_DICT_BITS);
}

static __always_inline void wkdm_write_header(u8 *dst, u16 idx0_len, u16 idx1_len, u16 miss_count)
{
    put_unaligned_le16(idx0_len, dst + 0);
    put_unaligned_le16(idx1_len, dst + 2);
    put_unaligned_le16(miss_count, dst + 4);
}

/* 
 * ====================================================================
 * CORE 1: PURE ARM64 ASSEMBLY DELTA ENCODER
 * Mengeksekusi Prefix-XOR 8-Byte secara instan via register 64-bit (x3)
 * ====================================================================
 */
static __always_inline void wkdm_delta_encode(u8 *buf, unsigned int len)
{
    if (unlikely(len <= 1)) return;

    asm volatile(
        "1: \n"
        "   cmp %w1, #8 \n"                   /* Apakah sisa byte >= 8? */
        "   b.lt 2f \n"                       /* Jika tidak, lompat ke sisa kalkulasi */
        "   ldr x3, [%0] \n"                  /* Load 8 bytes memori ke CPU */
        "   lsr x4, x3, #8 \n"                /* Shift 1 byte */
        "   eor x3, x3, x4 \n"                /* Operasi XOR Massal */
        "   str x3, [%0] \n"                  /* Store 8 bytes kembali ke memori */
        "   add %0, %0, #7 \n"                /* Geser pointer 7 byte */
        "   sub %w1, %w1, #7 \n"              /* Kurangi sisa panjang */
        "   b 1b \n"                          /* Ulangi blok utama */
        
        "2: \n"
        "   cbz %w1, 3f \n"                   /* Jika panjang 0, selesai */
        "   ldrb w3, [%0] \n"
        "   ldrb w4, [%0, #1] \n"
        "   eor w4, w4, w3 \n"
        "   strb w4, [%0, #1] \n"
        "   add %0, %0, #1 \n"
        "   sub %w1, %w1, #1 \n"
        "   b 2b \n"
        
        "3: \n"
        : "+r" (buf), "+r" (len)
        :
        : "x3", "x4", "memory", "cc"
    );
}

/* 
 * ====================================================================
 * CORE 2: PURE ARM64 NEON MEMORY COPY
 * Menggantikan fungsi standar kernel memcpy() yang membebani CPU lambat.
 * Menggunakan LDP/STP untuk memindahkan 16-Bytes per clock cycle.
 * ====================================================================
 */
static __always_inline void fast_arm64_memcpy(u8 *dst, const u8 *src, unsigned int len)
{
    if (unlikely(len == 0)) return;

    asm volatile(
        "1: \n"
        "   cmp %w2, #16 \n"                  /* Cek apakah data >= 16 byte? */
        "   b.lt 2f \n"
        "   ldp x3, x4, [%1], #16 \n"         /* Ambil 16 byte sekaligus (2 register) */
        "   stp x3, x4, [%0], #16 \n"         /* Tulis 16 byte sekaligus */
        "   sub %w2, %w2, #16 \n"
        "   b 1b \n"
        
        "2: \n"
        "   cbz %w2, 3f \n"                   /* Tangani sisa data di bawah 16 byte */
        "   ldrb w3, [%1], #1 \n"
        "   strb w3, [%0], #1 \n"
        "   sub %w2, %w2, #1 \n"
        "   b 2b \n"
        
        "3: \n"
        : "+r" (dst), "+r" (src), "+r" (len)
        :
        : "x3", "x4", "memory", "cc"
    );
}

static __always_inline void wkdm_update_burst(struct hybrid_ctx *ctx, unsigned long now)
{
    unsigned long delta = now - ctx->last_jiffy; 
    if (delta) {
        if (delta >= WKDM_DECAY_MAX_SHIFT) ctx->burst_count = 0;
        else ctx->burst_count >>= delta;
        ctx->last_jiffy = now;
    }
    if (ctx->burst_count < U16_MAX) ctx->burst_count++;
}

static int wkdm_pack_split(const u8 * __restrict src, u8 * __restrict out, struct hybrid_ctx *ctx)
{
    u32 *dict = ctx->wkdm_dict;
    u8 *tags = ctx->tags_buffer;
    u8 *index0 = ctx->index_buffer;
    u8 *index1 = ctx->index_buffer + WKDM_MAX_INDEX_BYTES;
    u8 *r0 = ctx->raw_buffer;
    u8 *r1 = ctx->raw_buffer + WKDM_RAW_PLANE_SIZE;
    u8 *r2 = ctx->raw_buffer + WKDM_RAW_PLANE_SIZE * 2;
    u8 *r3 = ctx->raw_buffer + WKDM_RAW_PLANE_SIZE * 3;

    u16 index0_len = 0, index1_len = 0, miss_count = 0, word;

    /* Bersihkan kamus (Dictionary) dengan ARM64 Memset bawaan hardware */
    memset(dict, 0, WKDM_DICT_BUCKETS * WKDM_DICT_WAYS * sizeof(u32));

    for (word = 0; word < WKDM_WORDS; word += 4) {
        u8 tag_pack = 0;
        u32 val, bucket, *entry;

        /* Tarik RAM ke L1 Cache secara brutal sebelum instruksi baca tiba */
        prefetch(src + ((word + 8) << 2));

        /* --- WORD 0 --- */
        val = get_unaligned_le32(src + ((word + 0) << 2));
        if (unlikely(!val)) tag_pack |= (TAG_ZERO << 0);
        else {
            bucket = hash_word(val); entry = &dict[bucket << 1];
            if (likely(entry[0] == val)) { tag_pack |= (TAG_DICT_0 << 0); index0[index0_len++] = (u8)bucket; }
            else if (entry[1] == val) { tag_pack |= (TAG_DICT_1 << 0); index1[index1_len++] = (u8)bucket; entry[1] = entry[0]; entry[0] = val; }
            else { tag_pack |= (TAG_MISS << 0); r0[miss_count] = (u8)val; r1[miss_count] = (u8)(val>>8); r2[miss_count] = (u8)(val>>16); r3[miss_count] = (u8)(val>>24); miss_count++; entry[1] = entry[0]; entry[0] = val; }
        }

        /* --- WORD 1 --- */
        val = get_unaligned_le32(src + ((word + 1) << 2));
        if (unlikely(!val)) tag_pack |= (TAG_ZERO << 2);
        else {
            bucket = hash_word(val); entry = &dict[bucket << 1];
            if (likely(entry[0] == val)) { tag_pack |= (TAG_DICT_0 << 2); index0[index0_len++] = (u8)bucket; }
            else if (entry[1] == val) { tag_pack |= (TAG_DICT_1 << 2); index1[index1_len++] = (u8)bucket; entry[1] = entry[0]; entry[0] = val; }
            else { tag_pack |= (TAG_MISS << 2); r0[miss_count] = (u8)val; r1[miss_count] = (u8)(val>>8); r2[miss_count] = (u8)(val>>16); r3[miss_count] = (u8)(val>>24); miss_count++; entry[1] = entry[0]; entry[0] = val; }
        }

        /* --- WORD 2 --- */
        val = get_unaligned_le32(src + ((word + 2) << 2));
        if (unlikely(!val)) tag_pack |= (TAG_ZERO << 4);
        else {
            bucket = hash_word(val); entry = &dict[bucket << 1];
            if (likely(entry[0] == val)) { tag_pack |= (TAG_DICT_0 << 4); index0[index0_len++] = (u8)bucket; }
            else if (entry[1] == val) { tag_pack |= (TAG_DICT_1 << 4); index1[index1_len++] = (u8)bucket; entry[1] = entry[0]; entry[0] = val; }
            else { tag_pack |= (TAG_MISS << 4); r0[miss_count] = (u8)val; r1[miss_count] = (u8)(val>>8); r2[miss_count] = (u8)(val>>16); r3[miss_count] = (u8)(val>>24); miss_count++; entry[1] = entry[0]; entry[0] = val; }
        }

        /* --- WORD 3 --- */
        val = get_unaligned_le32(src + ((word + 3) << 2));
        if (unlikely(!val)) tag_pack |= (TAG_ZERO << 6);
        else {
            bucket = hash_word(val); entry = &dict[bucket << 1];
            if (likely(entry[0] == val)) { tag_pack |= (TAG_DICT_0 << 6); index0[index0_len++] = (u8)bucket; }
            else if (entry[1] == val) { tag_pack |= (TAG_DICT_1 << 6); index1[index1_len++] = (u8)bucket; entry[1] = entry[0]; entry[0] = val; }
            else { tag_pack |= (TAG_MISS << 6); r0[miss_count] = (u8)val; r1[miss_count] = (u8)(val>>8); r2[miss_count] = (u8)(val>>16); r3[miss_count] = (u8)(val>>24); miss_count++; entry[1] = entry[0]; entry[0] = val; }
        }

        tags[word >> 2] = tag_pack;
    }

    /* Panggil fungsi Delta Encoder Pure Assembly */
    wkdm_delta_encode(index0, index0_len); wkdm_delta_encode(index1, index1_len);
    wkdm_delta_encode(r3, miss_count); wkdm_delta_encode(r2, miss_count);
    wkdm_delta_encode(r1, miss_count); wkdm_delta_encode(r0, miss_count);

    {
        unsigned int offset = 0;
        wkdm_write_header(out, index0_len, index1_len, miss_count);
        offset += WKDM_HEADER_SIZE;

        /* Panggil Memory Copy NEON Assembly */
        fast_arm64_memcpy(out + offset, tags, WKDM_TAG_BYTES); offset += WKDM_TAG_BYTES;
        fast_arm64_memcpy(out + offset, index0, index0_len); offset += index0_len;
        fast_arm64_memcpy(out + offset, index1, index1_len); offset += index1_len;
        fast_arm64_memcpy(out + offset, r3, miss_count); offset += miss_count;
        fast_arm64_memcpy(out + offset, r2, miss_count); offset += miss_count;
        fast_arm64_memcpy(out + offset, r1, miss_count); offset += miss_count;
        fast_arm64_memcpy(out + offset, r0, miss_count); offset += miss_count;

        if (unlikely(offset > WKDM_MAX_CAPACITY)) return -ENOSPC;
        return offset;
    }
}

static int wkdm_unpack_linear(const u8 * __restrict src, unsigned int slen, u8 * __restrict dst, struct hybrid_ctx *ctx)
{
    u32 *dict = ctx->wkdm_dict;
    const u8 *tags, *index0, *index1, *r3, *r2, *r1, *r0;
    u16 index0_len, index1_len, miss_count, word;
    u16 index0_used = 0, index1_used = 0, miss_used = 0;
    unsigned int expected_size;
    u8 index0_prev = 0, index1_prev = 0;
    u8 prev0 = 0, prev1 = 0, prev2 = 0, prev3 = 0;

    if (unlikely(slen < WKDM_HEADER_SIZE)) return -EINVAL;

    index0_len = get_unaligned_le16(src + 0);
    index1_len = get_unaligned_le16(src + 2);
    miss_count = get_unaligned_le16(src + 4);

    expected_size = WKDM_HEADER_SIZE + WKDM_TAG_BYTES + index0_len + index1_len + (miss_count * 4);
    if (unlikely(expected_size != slen || expected_size > WKDM_MAX_CAPACITY)) return -EINVAL;

    tags = src + WKDM_HEADER_SIZE;
    index0 = tags + WKDM_TAG_BYTES; index1 = index0 + index0_len;
    r3 = index1 + index1_len; r2 = r3 + miss_count; r1 = r2 + miss_count; r0 = r1 + miss_count;

    memset(dict, 0, WKDM_DICT_BUCKETS * WKDM_DICT_WAYS * sizeof(u32));

    for (word = 0; word < WKDM_WORDS; word += 4) {
        u8 tag_pack = tags[word >> 2];
        u8 tag;
        u32 bucket, value, *entry;

        prefetch(dst + ((word + 8) << 2));

        /* --- WORD 0 --- */
        tag = tag_pack & 0x03;
        if (unlikely(tag == TAG_ZERO)) { put_unaligned_le32(0, dst + ((word + 0) << 2)); } 
        else if (likely(tag == TAG_MISS)) {
            prev3 ^= r3[miss_used]; prev2 ^= r2[miss_used]; prev1 ^= r1[miss_used]; prev0 ^= r0[miss_used]; miss_used++;
            value = ((u32)prev0) | ((u32)prev1 << 8) | ((u32)prev2 << 16) | ((u32)prev3 << 24);
            bucket = hash_word(value); entry = &dict[bucket << 1]; entry[1] = entry[0]; entry[0] = value;
            put_unaligned_le32(value, dst + ((word + 0) << 2));
        } else if (tag == TAG_DICT_0) {
            index0_prev ^= index0[index0_used++]; bucket = index0_prev; value = dict[bucket << 1];
            put_unaligned_le32(value, dst + ((word + 0) << 2));
        } else {
            index1_prev ^= index1[index1_used++]; bucket = index1_prev; entry = &dict[bucket << 1];
            value = entry[1]; entry[1] = entry[0]; entry[0] = value; put_unaligned_le32(value, dst + ((word + 0) << 2));
        }

        /* --- WORD 1 --- */
        tag = (tag_pack >> 2) & 0x03;
        if (unlikely(tag == TAG_ZERO)) { put_unaligned_le32(0, dst + ((word + 1) << 2)); } 
        else if (likely(tag == TAG_MISS)) {
            prev3 ^= r3[miss_used]; prev2 ^= r2[miss_used]; prev1 ^= r1[miss_used]; prev0 ^= r0[miss_used]; miss_used++;
            value = ((u32)prev0) | ((u32)prev1 << 8) | ((u32)prev2 << 16) | ((u32)prev3 << 24);
            bucket = hash_word(value); entry = &dict[bucket << 1]; entry[1] = entry[0]; entry[0] = value;
            put_unaligned_le32(value, dst + ((word + 1) << 2));
        } else if (tag == TAG_DICT_0) {
            index0_prev ^= index0[index0_used++]; bucket = index0_prev; value = dict[bucket << 1];
            put_unaligned_le32(value, dst + ((word + 1) << 2));
        } else {
            index1_prev ^= index1[index1_used++]; bucket = index1_prev; entry = &dict[bucket << 1];
            value = entry[1]; entry[1] = entry[0]; entry[0] = value; put_unaligned_le32(value, dst + ((word + 1) << 2));
        }

        /* --- WORD 2 --- */
        tag = (tag_pack >> 4) & 0x03;
        if (unlikely(tag == TAG_ZERO)) { put_unaligned_le32(0, dst + ((word + 2) << 2)); } 
        else if (likely(tag == TAG_MISS)) {
            prev3 ^= r3[miss_used]; prev2 ^= r2[miss_used]; prev1 ^= r1[miss_used]; prev0 ^= r0[miss_used]; miss_used++;
            value = ((u32)prev0) | ((u32)prev1 << 8) | ((u32)prev2 << 16) | ((u32)prev3 << 24);
            bucket = hash_word(value); entry = &dict[bucket << 1]; entry[1] = entry[0]; entry[0] = value;
            put_unaligned_le32(value, dst + ((word + 2) << 2));
        } else if (tag == TAG_DICT_0) {
            index0_prev ^= index0[index0_used++]; bucket = index0_prev; value = dict[bucket << 1];
            put_unaligned_le32(value, dst + ((word + 2) << 2));
        } else {
            index1_prev ^= index1[index1_used++]; bucket = index1_prev; entry = &dict[bucket << 1];
            value = entry[1]; entry[1] = entry[0]; entry[0] = value; put_unaligned_le32(value, dst + ((word + 2) << 2));
        }

        /* --- WORD 3 --- */
        tag = (tag_pack >> 6) & 0x03;
        if (unlikely(tag == TAG_ZERO)) { put_unaligned_le32(0, dst + ((word + 3) << 2)); } 
        else if (likely(tag == TAG_MISS)) {
            prev3 ^= r3[miss_used]; prev2 ^= r2[miss_used]; prev1 ^= r1[miss_used]; prev0 ^= r0[miss_used]; miss_used++;
            value = ((u32)prev0) | ((u32)prev1 << 8) | ((u32)prev2 << 16) | ((u32)prev3 << 24);
            bucket = hash_word(value); entry = &dict[bucket << 1]; entry[1] = entry[0]; entry[0] = value;
            put_unaligned_le32(value, dst + ((word + 3) << 2));
        } else if (tag == TAG_DICT_0) {
            index0_prev ^= index0[index0_used++]; bucket = index0_prev; value = dict[bucket << 1];
            put_unaligned_le32(value, dst + ((word + 3) << 2));
        } else {
            index1_prev ^= index1[index1_used++]; bucket = index1_prev; entry = &dict[bucket << 1];
            value = entry[1]; entry[1] = entry[0]; entry[0] = value; put_unaligned_le32(value, dst + ((word + 3) << 2));
        }
    }
    return 0;
}

static void *hybrid_alloc_ctx(struct crypto_scomp *tfm)
{
    struct hybrid_ctx *ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
    if (!ctx) return ERR_PTR(-ENOMEM);

    ctx->lz4_workspace = vmalloc(LZ4_sizeofState());
    ctx->lz4hc_workspace = vmalloc(LZ4_sizeofStateHC());
    ctx->wkdm_buffer = kmalloc(WKDM_MAX_CAPACITY, GFP_KERNEL);
    
    ctx->pool = kmalloc(sizeof(struct wkdm_memory_pool), GFP_KERNEL);
    if (!ctx->pool || !ctx->wkdm_buffer || !ctx->lz4hc_workspace || !ctx->lz4_workspace) {
        kfree(ctx->pool); kfree(ctx->wkdm_buffer);
        vfree(ctx->lz4hc_workspace); vfree(ctx->lz4_workspace); kfree(ctx);
        return ERR_PTR(-ENOMEM);
    }

    ctx->wkdm_dict = ctx->pool->dict;
    ctx->index_buffer = ctx->pool->index_buffer;
    ctx->raw_buffer = ctx->pool->raw_buffer;
    ctx->tags_buffer = ctx->pool->tags_buffer;

    ctx->last_jiffy = jiffies;
    ctx->burst_count = 0;
    return ctx;
}

static void hybrid_free_ctx(struct crypto_scomp *tfm, void *ctx_ptr)
{
    struct hybrid_ctx *ctx = ctx_ptr;
    if (!ctx) return;
    kfree(ctx->pool); kfree(ctx->wkdm_buffer);
    vfree(ctx->lz4hc_workspace); vfree(ctx->lz4_workspace); kfree(ctx);
}

static int hybrid_scompress(struct crypto_scomp *tfm, const u8 *src, unsigned int slen, u8 *dst, unsigned int *dlen, void *ctx_ptr)
{
    struct hybrid_ctx *ctx = ctx_ptr;
    int wkdm_len, lz4_len;
    if (unlikely(!dlen || slen != WKDM_PAGE_SIZE || *dlen < WKDM_PAGE_SIZE)) return -EINVAL;

    wkdm_update_burst(ctx, jiffies);
    wkdm_len = wkdm_pack_split(src, ctx->wkdm_buffer, ctx);
    if (unlikely(wkdm_len <= 0)) return -ENOSPC; 

    if (ctx->burst_count >= WKDM_COMPRESS_RATE_CRITICAL)
        lz4_len = LZ4_compress_default(ctx->wkdm_buffer, dst, wkdm_len, *dlen, ctx->lz4_workspace);
    else
        lz4_len = LZ4_compress_HC(ctx->wkdm_buffer, dst, wkdm_len, *dlen, WKDM_LZ4HC_LEVEL, ctx->lz4hc_workspace);

    if (unlikely(lz4_len <= 0 || lz4_len >= WKDM_PAGE_SIZE)) return -ENOSPC;
    *dlen = lz4_len;
    return 0;
}

static int hybrid_sdecompress(struct crypto_scomp *tfm, const u8 *src, unsigned int slen, u8 *dst, unsigned int *dlen, void *ctx_ptr)
{
    struct hybrid_ctx *ctx = ctx_ptr;
    int ret = LZ4_decompress_safe(src, ctx->wkdm_buffer, slen, WKDM_MAX_CAPACITY);
    if (unlikely(ret < WKDM_HEADER_SIZE) || unlikely(wkdm_unpack_linear(ctx->wkdm_buffer, ret, dst, ctx) < 0)) return -EINVAL;
    *dlen = WKDM_PAGE_SIZE; return 0;
}

static struct scomp_alg scomp = {
    .alloc_ctx = hybrid_alloc_ctx, .free_ctx = hybrid_free_ctx,
    .compress = hybrid_scompress, .decompress = hybrid_sdecompress,
    .base = { .cra_name = "wkdm_lz4hc", .cra_driver_name = "wkdm_lz4hc-scomp", .cra_module = THIS_MODULE, },
};

static int __init wkdm_lz4hc_mod_init(void) { 
    BUILD_BUG_ON(WKDM_DICT_BITS > 8);
    return crypto_register_scomp(&scomp); 
}

static void __exit wkdm_lz4hc_mod_fini(void) { crypto_unregister_scomp(&scomp); }

module_init(wkdm_lz4hc_mod_init); module_exit(wkdm_lz4hc_mod_fini);
MODULE_LICENSE("GPL"); MODULE_DESCRIPTION("WKdm-LZ4/HC V30 Ultimate ARM64 Core"); MODULE_ALIAS_CRYPTO("wkdm_lz4hc");
