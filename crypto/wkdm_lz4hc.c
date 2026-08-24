/*
 * Cryptographic API.
 *
 * WKdm-LZ4/HC V25.1 The Invariant Architecture (Pure WKdm)
 *
 * ============================================================
 * V25.1 ARCHITECTURE & CONSCIOUS TRADE-OFFS
 * ------------------------------------------------------------
 * 1. PURE INVARIANT PIPELINE: Every page strictly follows the 
 *    Page -> WKdm -> LZ4 -> Output path. No RAW bypass, no 
 *    ambiguous framing bytes. The decoder assumes absolute 
 *    LZ4(WKdm(Page)) invariant format.
 * 
 * 2. EARLY ABORT: Incompressible data (>896 MISS) returns -ENOSPC 
 *    before LZ4 is called, saving massive CPU cycles gracefully.
 * 
 * 3. SMART KSWAPD: kswapd uses LZ4HC-12, but yields to Fast during 
 *    critical memory burst traffic to prevent allocator stalls.
 * 
 * 4. [FIXED] BURST SENSOR & PARITY TRAP:
 *    Uses an exponential-decay counter (halving per jiffy elapsed).
 *    Thresholds (37/17) represent steady-state calls/jiffy. Actual 
 *    wall-clock translation depends strictly on kernel HZ configuration. 
 *    Zero-reset applied for long idles to clear residual loads.
 * 
 * 5. DICT SAFETY: Hash shift decoupled via log2(buckets).
 *    Strict BUILD_BUG_ON ensures WKDM_DICT_BITS <= 8 to prevent 
 *    silent (u8) cast overflows during dictionary indexing.
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

#define WKDM_EARLY_ABORT_MISS   896 

#define WKDM_TOTAL_RAW_BYTES    (WKDM_RAW_PLANE_SIZE * 4)
#define WKDM_TOTAL_INDEX_BYTES  (WKDM_MAX_INDEX_BYTES * 2)

#define WKDM_HEADER_SIZE        12
#define WKDM_MAX_CAPACITY       \
        (WKDM_HEADER_SIZE +     \
         WKDM_TAG_BYTES +       \
         WKDM_TOTAL_INDEX_BYTES + \
         WKDM_TOTAL_RAW_BYTES)

#define WKDM_LZ4HC_LEVEL        12
#define WKDM_MAGIC              0x3157
#define WKDM_STREAM_VERSION     251

/* Decay-domain steady-state thresholds */
#define WKDM_COMPRESS_RATE_CRITICAL 37
#define WKDM_COMPRESS_RATE_HIGH     17
#define WKDM_DECAY_MAX_SHIFT        8

#define TAG_ZERO                0x00
#define TAG_DICT_0              0x01
#define TAG_DICT_1              0x02
#define TAG_MISS                0x03

/*
 * Per-stream/context mutable state.
 * Concurrency isolation is provided by the caller's 
 * crypto_scomp context lifecycle (e.g., ZRAM per-CPU streams).
 */
struct hybrid_ctx {
    void *lz4_workspace;
    void *lz4hc_workspace;
    
    u8 *wkdm_buffer;
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

#define WKDM_FLAGS_V251 \
        ((1U << 0) | (1U << 1) | (1U << 2) | \
         (1U << 3) | (1U << 4) | (1U << 5))

static __always_inline void wkdm_write_header(u8 *dst, u16 idx0_len, u16 idx1_len, u16 miss_count)
{
    u32 version_flags = (WKDM_STREAM_VERSION << 16) | WKDM_FLAGS_V251;
    put_unaligned_le16(WKDM_MAGIC, dst + 0);
    put_unaligned_le16(idx0_len, dst + 2);
    put_unaligned_le16(idx1_len, dst + 4);
    put_unaligned_le16(miss_count, dst + 6);
    put_unaligned_le32(version_flags, dst + 8);
}

static __always_inline int wkdm_read_header(const u8 *src, unsigned int slen, 
                                            u16 *idx0_len, u16 *idx1_len, u16 *miss_count)
{
    u32 version_flags;
    u32 expected_flags = (WKDM_STREAM_VERSION << 16) | WKDM_FLAGS_V251;

    if (unlikely(slen < WKDM_HEADER_SIZE)) return -EINVAL;
    if (unlikely(get_unaligned_le16(src + 0) != WKDM_MAGIC)) return -EINVAL;

    *idx0_len = get_unaligned_le16(src + 2);
    *idx1_len = get_unaligned_le16(src + 4);
    *miss_count = get_unaligned_le16(src + 6);
    version_flags = get_unaligned_le32(src + 8);

    if (unlikely(version_flags != expected_flags)) return -EINVAL;
    if (unlikely(*idx0_len > WKDM_MAX_INDEX_BYTES || 
                 *idx1_len > WKDM_MAX_INDEX_BYTES || 
                 *miss_count > WKDM_MAX_MISS))
        return -EINVAL;

    return 0;
}

static __always_inline void wkdm_delta_encode(u8 *buf, unsigned int len)
{
    unsigned int i;
    u8 prev;

    if (unlikely(len <= 1)) return;

    prev = buf[0];
    for (i = 1; i < len; i++) {
        u8 cur = buf[i];
        buf[i] = cur ^ prev;
        prev = cur;
    }
}

static __always_inline void wkdm_update_burst(struct hybrid_ctx *ctx, unsigned long now)
{
    unsigned long delta = now - ctx->last_jiffy; 

    if (delta) {
        if (delta >= WKDM_DECAY_MAX_SHIFT)
            ctx->burst_count = 0;
        else
            ctx->burst_count >>= delta;

        ctx->last_jiffy = now;
    }

    if (ctx->burst_count < U16_MAX)
        ctx->burst_count++;
}

static int wkdm_pack_split(const u8 *src, u8 *out, struct hybrid_ctx *ctx)
{
    u32 *dict = ctx->wkdm_dict;
    u8 *tags = ctx->tags_buffer;
    
    u8 *index0 = ctx->index_buffer;
    u8 *index1 = ctx->index_buffer + WKDM_MAX_INDEX_BYTES;
    u8 *r0 = ctx->raw_buffer;
    u8 *r1 = ctx->raw_buffer + WKDM_RAW_PLANE_SIZE;
    u8 *r2 = ctx->raw_buffer + WKDM_RAW_PLANE_SIZE * 2;
    u8 *r3 = ctx->raw_buffer + WKDM_RAW_PLANE_SIZE * 3;

    unsigned int index0_len = 0, index1_len = 0, miss_count = 0, word;
    u8 tag_pack = 0;

    memset(dict, 0, WKDM_DICT_BUCKETS * WKDM_DICT_WAYS * sizeof(u32));

    for (word = 0; word < WKDM_WORDS; word++) {
        u32 value = get_unaligned_le32(src + (word << 2));
        u32 bucket;
        u32 *entry;
        u8 tag;

        if (unlikely(value == 0)) {
            tag = TAG_ZERO;
        } else {
            bucket = hash_word(value);
            entry = &dict[bucket << 1];
            
            u32 way0 = entry[0];
            u32 way1 = entry[1];
            
            if (likely(way0 == value)) {
                tag = TAG_DICT_0;
                index0[index0_len++] = (u8)bucket;
            } else if (way1 == value) {
                tag = TAG_DICT_1;
                index1[index1_len++] = (u8)bucket;
                entry[1] = way0;
                entry[0] = value;
            } else {
                tag = TAG_MISS;
                r0[miss_count] = (u8)value;
                r1[miss_count] = (u8)(value >> 8);
                r2[miss_count] = (u8)(value >> 16);
                r3[miss_count] = (u8)(value >> 24);
                miss_count++;
                
                entry[1] = way0;
                entry[0] = value;
            }
        }
        
        tag_pack |= tag << ((word & 3) << 1);
        if ((word & 3) == 3) {
            /* EARLY ABORT: Incompressible data guard */
            if (unlikely(miss_count > WKDM_EARLY_ABORT_MISS))
                return -ENOSPC;

            tags[word >> 2] = tag_pack;
            tag_pack = 0;
        }
    }

    wkdm_delta_encode(index0, index0_len);
    wkdm_delta_encode(index1, index1_len);
    wkdm_delta_encode(r3, miss_count);
    wkdm_delta_encode(r2, miss_count);
    wkdm_delta_encode(r1, miss_count);
    wkdm_delta_encode(r0, miss_count);

    {
        unsigned int offset = 0;

        wkdm_write_header(out, (u16)index0_len, (u16)index1_len, (u16)miss_count);
        offset += WKDM_HEADER_SIZE;

        memcpy(out + offset, tags, WKDM_TAG_BYTES);
        offset += WKDM_TAG_BYTES;

        memcpy(out + offset, index0, index0_len);
        offset += index0_len;

        memcpy(out + offset, index1, index1_len);
        offset += index1_len;

        memcpy(out + offset, r3, miss_count);
        offset += miss_count;

        memcpy(out + offset, r2, miss_count);
        offset += miss_count;

        memcpy(out + offset, r1, miss_count);
        offset += miss_count;

        memcpy(out + offset, r0, miss_count);
        offset += miss_count;
        
        if (unlikely(offset > WKDM_MAX_CAPACITY))
            return -ENOSPC;

        return offset;
    }
}

static int wkdm_unpack_linear(const u8 *src, unsigned int slen, u8 *dst, struct hybrid_ctx *ctx)
{
    u32 *dict = ctx->wkdm_dict;
    const u8 *tags, *index0, *index1, *r3, *r2, *r1, *r0;
    
    u16 index0_len, index1_len, miss_count;
    unsigned int index0_used = 0, index1_used = 0, miss_used = 0;
    unsigned int expected_size, word;
    
    u8 index0_prev = 0, index1_prev = 0;
    u8 prev0 = 0, prev1 = 0, prev2 = 0, prev3 = 0;

    if (unlikely(wkdm_read_header(src, slen, &index0_len, &index1_len, &miss_count)))
        return -EINVAL;

    expected_size = WKDM_HEADER_SIZE + WKDM_TAG_BYTES + index0_len + index1_len + (miss_count * 4);
    if (unlikely(expected_size != slen || expected_size > WKDM_MAX_CAPACITY)) 
        return -EINVAL;

    tags = src + WKDM_HEADER_SIZE;
    index0 = tags + WKDM_TAG_BYTES;
    index1 = index0 + index0_len;
    r3 = index1 + index1_len;
    r2 = r3 + miss_count;
    r1 = r2 + miss_count;
    r0 = r1 + miss_count;

    memset(dict, 0, WKDM_DICT_BUCKETS * WKDM_DICT_WAYS * sizeof(u32));

    for (word = 0; word < WKDM_WORDS; word++) {
        u8 tag = (tags[word >> 2] >> ((word & 3) << 1)) & 0x03;
        u32 bucket, value, *entry;

        switch (tag) {
        case TAG_ZERO:
            put_unaligned_le32(0, dst + (word << 2));
            break;

        case TAG_DICT_0:
            if (unlikely(index0_used >= index0_len)) return -EINVAL;
            index0_prev ^= index0[index0_used++];
            bucket = index0_prev;
            
            if (unlikely(bucket >= WKDM_DICT_BUCKETS)) return -EINVAL;
            value = dict[bucket << 1];
            put_unaligned_le32(value, dst + (word << 2));
            break;

        case TAG_DICT_1:
            if (unlikely(index1_used >= index1_len)) return -EINVAL;
            index1_prev ^= index1[index1_used++];
            bucket = index1_prev;
            
            if (unlikely(bucket >= WKDM_DICT_BUCKETS)) return -EINVAL;
            entry = &dict[bucket << 1];
            value = entry[1];
            
            entry[1] = entry[0];
            entry[0] = value;
            put_unaligned_le32(value, dst + (word << 2));
            break;

        case TAG_MISS:
            if (unlikely(miss_used >= miss_count)) return -EINVAL;
            prev3 ^= r3[miss_used];
            prev2 ^= r2[miss_used];
            prev1 ^= r1[miss_used];
            prev0 ^= r0[miss_used];
            miss_used++;

            value = ((u32)prev0) | ((u32)prev1 << 8) | ((u32)prev2 << 16) | ((u32)prev3 << 24);
            bucket = hash_word(value);
            entry = &dict[bucket << 1];
            
            entry[1] = entry[0];
            entry[0] = value;
            put_unaligned_le32(value, dst + (word << 2));
            break;

        default:
            return -EINVAL;
        }
    }

    if (unlikely(index0_used != index0_len || index1_used != index1_len || miss_used != miss_count))
        return -EINVAL;

    return 0;
}

static void *hybrid_alloc_ctx(struct crypto_scomp *tfm)
{
    struct hybrid_ctx *ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
    if (!ctx) return ERR_PTR(-ENOMEM);

    ctx->lz4_workspace = vmalloc(LZ4_sizeofState());
    if (!ctx->lz4_workspace) goto err_ctx;

    ctx->lz4hc_workspace = vmalloc(LZ4_sizeofStateHC());
    if (!ctx->lz4hc_workspace) goto err_lz4;

    ctx->wkdm_buffer = kmalloc(WKDM_MAX_CAPACITY, GFP_KERNEL);
    if (!ctx->wkdm_buffer) goto err_lz4hc;

    ctx->wkdm_dict = kmalloc(WKDM_DICT_BUCKETS * WKDM_DICT_WAYS * sizeof(u32), GFP_KERNEL);
    if (!ctx->wkdm_dict) goto err_wkdm;

    ctx->index_buffer = kmalloc(WKDM_TOTAL_INDEX_BYTES, GFP_KERNEL);
    if (!ctx->index_buffer) goto err_dict;

    ctx->raw_buffer = kmalloc(WKDM_TOTAL_RAW_BYTES, GFP_KERNEL);
    if (!ctx->raw_buffer) goto err_idx;

    ctx->tags_buffer = kmalloc(WKDM_TAG_BYTES, GFP_KERNEL);
    if (!ctx->tags_buffer) goto err_raw;

    ctx->last_jiffy = jiffies;
    ctx->burst_count = 0;

    return ctx;

err_raw:
    kfree(ctx->raw_buffer);
err_idx:
    kfree(ctx->index_buffer);
err_dict:
    kfree(ctx->wkdm_dict);
err_wkdm:
    kfree(ctx->wkdm_buffer);
err_lz4hc:
    vfree(ctx->lz4hc_workspace);
err_lz4:
    vfree(ctx->lz4_workspace);
err_ctx:
    kfree(ctx);
    return ERR_PTR(-ENOMEM);
}

static void hybrid_free_ctx(struct crypto_scomp *tfm, void *ctx_ptr)
{
    struct hybrid_ctx *ctx = ctx_ptr;
    if (!ctx) return;
    
    kfree(ctx->tags_buffer);
    kfree(ctx->raw_buffer); 
    kfree(ctx->index_buffer); 
    kfree(ctx->wkdm_dict); 
    kfree(ctx->wkdm_buffer);
    vfree(ctx->lz4hc_workspace);
    vfree(ctx->lz4_workspace);
    kfree(ctx);
}

static int hybrid_scompress(struct crypto_scomp *tfm, const u8 *src, unsigned int slen,
                            u8 *dst, unsigned int *dlen, void *ctx_ptr)
{
    struct hybrid_ctx *ctx = ctx_ptr;
    int wkdm_len, lz4_len;
    unsigned long now = jiffies;
    
    bool is_kswapd;
    bool is_memalloc; 
    bool use_hc;

    if (unlikely(!dlen || slen != WKDM_PAGE_SIZE || *dlen < WKDM_PAGE_SIZE))
        return -EINVAL;

    wkdm_update_burst(ctx, now);

    is_kswapd = !!(current->flags & PF_KSWAPD);
    is_memalloc = !!(current->flags & PF_MEMALLOC);

    /* WKdm is ALWAYS mandatory */
    wkdm_len = wkdm_pack_split(src, ctx->wkdm_buffer, ctx);
    
    if (unlikely(wkdm_len <= 0))
        return -ENOSPC; 

    /* Decision engine only controls LZ4 stage */
    if (ctx->burst_count >= WKDM_COMPRESS_RATE_CRITICAL) {
        use_hc = false;
    } else if (is_kswapd) {
        use_hc = true;
    } else if (is_memalloc && ctx->burst_count >= WKDM_COMPRESS_RATE_HIGH) {
        use_hc = false;
    } else {
        use_hc = true;
    }

    if (use_hc) {
        lz4_len = LZ4_compress_HC(ctx->wkdm_buffer, dst, wkdm_len, *dlen, 
                                  WKDM_LZ4HC_LEVEL, ctx->lz4hc_workspace);
    } else {
        lz4_len = LZ4_compress_default(ctx->wkdm_buffer, dst, wkdm_len, *dlen, 
                                       ctx->lz4_workspace);
    }

    if (unlikely(lz4_len <= 0 || lz4_len >= WKDM_PAGE_SIZE))
        return -ENOSPC;

    *dlen = lz4_len;
    return 0;
}

static int hybrid_sdecompress(struct crypto_scomp *tfm, const u8 *src, unsigned int slen,
                              u8 *dst, unsigned int *dlen, void *ctx_ptr)
{
    struct hybrid_ctx *ctx = ctx_ptr;
    int ret;

    if (unlikely(!dlen || slen == 0)) return -EINVAL;

    ret = LZ4_decompress_safe(src, ctx->wkdm_buffer, slen, WKDM_MAX_CAPACITY);
    
    if (unlikely(ret < WKDM_HEADER_SIZE))
        return -EINVAL;

    if (unlikely(wkdm_unpack_linear(ctx->wkdm_buffer, ret, dst, ctx) < 0))
        return -EINVAL;

    *dlen = WKDM_PAGE_SIZE;
    return 0;
}

static struct scomp_alg scomp = {
    .alloc_ctx  = hybrid_alloc_ctx,
    .free_ctx   = hybrid_free_ctx,
    .compress   = hybrid_scompress,
    .decompress = hybrid_sdecompress,
    .base = {
        .cra_name        = "wkdm_lz4hc", 
        .cra_driver_name = "wkdm_lz4hc-scomp",
        .cra_module      = THIS_MODULE,
    },
};

static int __init wkdm_lz4hc_mod_init(void) 
{ 
    BUILD_BUG_ON(WKDM_DICT_BITS > 8);
    return crypto_register_scomp(&scomp); 
}

static void __exit wkdm_lz4hc_mod_fini(void) { crypto_unregister_scomp(&scomp); }

module_init(wkdm_lz4hc_mod_init);
module_exit(wkdm_lz4hc_mod_fini);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("WKdm-LZ4/HC V25.1 The Invariant Architecture (Pure WKdm)");
MODULE_ALIAS_CRYPTO("wkdm_lz4hc");
