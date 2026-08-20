/*
 * Cryptographic API.
 *
 * WKdm-LZ4HC Absolute Linear Compressor V20.1 (Final Optimized)
 *
 * SUPER-DENSE STRUCTURAL PRE-COMPRESSOR
 *
 * Pipeline:
 *
 *      4096 BYTE PAGE
 *            |
 *            v
 *       WKdm 1-PASS
 *            |
 *            +--> ZERO TAG
 *            |
 *            +--> DICT0 INDEX
 *            |
 *            +--> DICT1 INDEX
 *            |
 *            +--> RAW BYTE PLANES (MSB -> B2 -> B1 -> LSB)
 *            |
 *            +--> XOR DELTA PER PLANE
 *            |
 *            v
 *       LZ4HC LEVEL 12
 *            |
 *            v
 *           ZRAM
 *
 * Properties:
 *  - Absolute Linear
 *  - Single WKdm pass & LZ4HC pass
 *  - No analyzer, No trial compression, No padding
 *  - Kernel Stack Safe (No large local arrays)
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/crypto.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/lz4.h>
#include <crypto/internal/scompress.h>
#include <asm/unaligned.h>

/* ============================================================
 * 1. CORE CONSTANTS
 * ============================================================ */
#define WKDM_PAGE_SIZE          4096
#define WKDM_WORDS              1024

#define WKDM_DICT_BUCKETS       128
#define WKDM_DICT_WAYS          2

#define WKDM_TAG_BYTES          256

#define WKDM_MAX_INDEX_BYTES    1024
#define WKDM_MAX_MISS           1024

#define WKDM_RAW_PLANE_SIZE     WKDM_MAX_MISS
#define WKDM_RAW_BUFFER_SIZE    (WKDM_RAW_PLANE_SIZE * 4)

/* Header (12 bytes) */
#define WKDM_HEADER_SIZE        12

#define WKDM_MAX_CAPACITY       \
        (WKDM_HEADER_SIZE +     \
         WKDM_TAG_BYTES +       \
         WKDM_MAX_INDEX_BYTES + \
         WKDM_MAX_INDEX_BYTES + \
         WKDM_RAW_BUFFER_SIZE)

#define WKDM_LZ4HC_LEVEL        12
#define WKDM_MAGIC              0x3157

/* ============================================================
 * 2. TAG FORMAT
 * ============================================================ */
#define TAG_ZERO                0x00
#define TAG_DICT_0              0x01
#define TAG_DICT_1              0x02
#define TAG_MISS                0x03

/* ============================================================
 * 3. CONTEXT
 * ============================================================ */
struct hybrid_ctx {
    void *lz4hc_workspace;
    u8 *wkdm_buffer;
    u32 *wkdm_dict;
    u8 *index0_buffer;
    u8 *index1_buffer;
    u8 *raw_b0;
    u8 *raw_b1;
    u8 *raw_b2;
    u8 *raw_b3;
};

/* ============================================================
 * 4. FAST HASH
 * ============================================================ */
static __always_inline u32 hash_word(u32 word)
{
    return (word * 2654435761U) >> 25;
}

/* ============================================================
 * 5. HEADER
 * ============================================================ */
static __always_inline void
wkdm_write_header(u8 *dst, u16 index0_len, u16 index1_len, u16 miss_count)
{
    put_unaligned_le16(WKDM_MAGIC, dst + 0);
    put_unaligned_le16(index0_len, dst + 2);
    put_unaligned_le16(index1_len, dst + 4);
    put_unaligned_le16(miss_count, dst + 6);
    put_unaligned_le32(0, dst + 8);
}

static __always_inline int
wkdm_read_header(const u8 *src, unsigned int slen,
                 u16 *index0_len, u16 *index1_len, u16 *miss_count)
{
    if (unlikely(slen < WKDM_HEADER_SIZE)) return -EINVAL;
    if (unlikely(get_unaligned_le16(src) != WKDM_MAGIC)) return -EINVAL;

    *index0_len = get_unaligned_le16(src + 2);
    *index1_len = get_unaligned_le16(src + 4);
    *miss_count = get_unaligned_le16(src + 6);

    if (unlikely(*index0_len > WKDM_MAX_INDEX_BYTES || 
                 *index1_len > WKDM_MAX_INDEX_BYTES || 
                 *miss_count > WKDM_MAX_MISS))
        return -EINVAL;

    return 0;
}

/* ============================================================
 * 6. XOR DELTA ENCODING
 * ============================================================ */
static __always_inline void
wkdm_delta_encode(u8 *buf, unsigned int len)
{
    unsigned int i;
    u8 prev;

    if (len <= 1) return;

    prev = buf[0];
    for (i = 1; i < len; i++) {
        u8 cur = buf[i];
        buf[i] = cur ^ prev;
        prev = cur;
    }
}

/* ============================================================
 * 7. WKDM PACK
 * ============================================================ */
static int
wkdm_pack_split(const u8 *src, u8 *out, struct hybrid_ctx *ctx)
{
    u32 *dict = ctx->wkdm_dict;
    u8 *index0 = ctx->index0_buffer;
    u8 *index1 = ctx->index1_buffer;
    u8 *r0 = ctx->raw_b0, *r1 = ctx->raw_b1, *r2 = ctx->raw_b2, *r3 = ctx->raw_b3;
    u8 tags[WKDM_TAG_BYTES] = { 0 };

    unsigned int index0_len = 0, index1_len = 0, miss_count = 0, word;

    memset(dict, 0, WKDM_DICT_BUCKETS * WKDM_DICT_WAYS * sizeof(u32));

    for (word = 0; word < WKDM_WORDS; word++) {
        u32 value = get_unaligned_le32(src + (word << 2));
        u32 bucket, *entry;
        u8 tag;

        if (unlikely(value == 0)) {
            tag = TAG_ZERO;
        } else {
            bucket = hash_word(value);
            entry = &dict[bucket << 1];

            if (likely(entry[0] == value)) {
                tag = TAG_DICT_0;
                index0[index0_len++] = (u8)bucket;
            } else if (entry[1] == value) {
                tag = TAG_DICT_1;
                index1[index1_len++] = (u8)bucket;
                entry[1] = entry[0];
                entry[0] = value;
            } else {
                tag = TAG_MISS;
                r0[miss_count] = (u8)value;
                r1[miss_count] = (u8)(value >> 8);
                r2[miss_count] = (u8)(value >> 16);
                r3[miss_count] = (u8)(value >> 24);
                miss_count++;
                
                entry[1] = entry[0];
                entry[0] = value;
            }
        }
        tags[word >> 2] |= tag << ((word & 3) << 1);
    }

    /* Transform to Delta */
    wkdm_delta_encode(r3, miss_count);
    wkdm_delta_encode(r2, miss_count);
    wkdm_delta_encode(r1, miss_count);
    wkdm_delta_encode(r0, miss_count);

    /* Assemble Stream */
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

        return offset;
    }
}

/* ============================================================
 * 8. WKDM UNPACK WITH STREAMING DELTA PLANES
 * ============================================================ */
static int
wkdm_unpack_linear(const u8 *src, unsigned int slen, u8 *dst, struct hybrid_ctx *ctx)
{
    /* KERNEL SAFETY FIX: Use heap-allocated dict instead of stack */
    u32 *dict = ctx->wkdm_dict;
    const u8 *tags, *index0, *index1, *r3, *r2, *r1, *r0;
    
    u16 index0_len, index1_len, miss_count;
    unsigned int index0_used = 0, index1_used = 0, miss_used = 0;
    unsigned int expected_size, word;

    u8 prev0 = 0, prev1 = 0, prev2 = 0, prev3 = 0;

    if (unlikely(wkdm_read_header(src, slen, &index0_len, &index1_len, &miss_count)))
        return -EINVAL;

    expected_size = WKDM_HEADER_SIZE + WKDM_TAG_BYTES + index0_len + index1_len + (miss_count * 4);
    if (unlikely(expected_size != slen)) return -EINVAL;

    tags = src + WKDM_HEADER_SIZE;
    index0 = tags + WKDM_TAG_BYTES;
    index1 = index0 + index0_len;
    r3 = index1 + index1_len;
    r2 = r3 + miss_count;
    r1 = r2 + miss_count;
    r0 = r1 + miss_count;

    /* Reset dictionary state for decompression */
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
            bucket = index0[index0_used++];
            if (unlikely(bucket >= WKDM_DICT_BUCKETS)) return -EINVAL;
            
            entry = &dict[bucket << 1];
            value = entry[0];
            put_unaligned_le32(value, dst + (word << 2));
            break;

        case TAG_DICT_1:
            if (unlikely(index1_used >= index1_len)) return -EINVAL;
            bucket = index1[index1_used++];
            if (unlikely(bucket >= WKDM_DICT_BUCKETS)) return -EINVAL;
            
            entry = &dict[bucket << 1];
            value = entry[1];
            
            entry[1] = entry[0];
            entry[0] = value;
            
            put_unaligned_le32(value, dst + (word << 2));
            break;

        case TAG_MISS:
            if (unlikely(miss_used >= miss_count)) return -EINVAL;

            /* Streaming XOR-delta reconstruction */
            prev3 ^= r3[miss_used];
            prev2 ^= r2[miss_used];
            prev1 ^= r1[miss_used];
            prev0 ^= r0[miss_used];

            value = ((u32)prev0) | ((u32)prev1 << 8) | ((u32)prev2 << 16) | ((u32)prev3 << 24);
            miss_used++;

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

/* ============================================================
 * 9. CONTEXT ALLOCATION
 * ============================================================ */
static void *hybrid_alloc_ctx(struct crypto_scomp *tfm)
{
    struct hybrid_ctx *ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
    if (!ctx) return ERR_PTR(-ENOMEM);

    ctx->lz4hc_workspace = vmalloc(LZ4HC_MEM_COMPRESS);
    if (!ctx->lz4hc_workspace) goto err_ctx;

    ctx->wkdm_buffer = kmalloc(WKDM_MAX_CAPACITY, GFP_KERNEL);
    if (!ctx->wkdm_buffer) goto err_workspace;

    ctx->wkdm_dict = kmalloc(WKDM_DICT_BUCKETS * WKDM_DICT_WAYS * sizeof(u32), GFP_KERNEL);
    if (!ctx->wkdm_dict) goto err_wkdm;

    ctx->index0_buffer = kmalloc(WKDM_MAX_INDEX_BYTES, GFP_KERNEL);
    if (!ctx->index0_buffer) goto err_dict;

    ctx->index1_buffer = kmalloc(WKDM_MAX_INDEX_BYTES, GFP_KERNEL);
    if (!ctx->index1_buffer) goto err_index0;

    ctx->raw_b0 = kmalloc(WKDM_RAW_PLANE_SIZE, GFP_KERNEL);
    ctx->raw_b1 = kmalloc(WKDM_RAW_PLANE_SIZE, GFP_KERNEL);
    ctx->raw_b2 = kmalloc(WKDM_RAW_PLANE_SIZE, GFP_KERNEL);
    ctx->raw_b3 = kmalloc(WKDM_RAW_PLANE_SIZE, GFP_KERNEL);

    if (!ctx->raw_b0 || !ctx->raw_b1 || !ctx->raw_b2 || !ctx->raw_b3) goto err_planes;

    return ctx;

err_planes:
    kfree(ctx->raw_b3); kfree(ctx->raw_b2); kfree(ctx->raw_b1); kfree(ctx->raw_b0);
    kfree(ctx->index1_buffer);
err_index0:
    kfree(ctx->index0_buffer);
err_dict:
    kfree(ctx->wkdm_dict);
err_wkdm:
    kfree(ctx->wkdm_buffer);
err_workspace:
    vfree(ctx->lz4hc_workspace);
err_ctx:
    kfree(ctx);
    return ERR_PTR(-ENOMEM);
}

static void hybrid_free_ctx(struct crypto_scomp *tfm, void *ctx_ptr)
{
    struct hybrid_ctx *ctx = ctx_ptr;
    if (!ctx) return;

    kfree(ctx->raw_b3); kfree(ctx->raw_b2); kfree(ctx->raw_b1); kfree(ctx->raw_b0);
    kfree(ctx->index1_buffer); kfree(ctx->index0_buffer);
    kfree(ctx->wkdm_dict); kfree(ctx->wkdm_buffer);
    vfree(ctx->lz4hc_workspace);
    kfree(ctx);
}

/* ============================================================
 * 10. ABSOLUTE LINEAR COMPRESS
 * ============================================================ */
static int hybrid_scompress(struct crypto_scomp *tfm, const u8 *src, unsigned int slen,
                            u8 *dst, unsigned int *dlen, void *ctx_ptr)
{
    struct hybrid_ctx *ctx = ctx_ptr;
    int wkdm_len, lz4_len;

    if (unlikely(!dlen || slen != WKDM_PAGE_SIZE || *dlen < WKDM_PAGE_SIZE))
        return -EINVAL;

    wkdm_len = wkdm_pack_split(src, ctx->wkdm_buffer, ctx);
    if (unlikely(wkdm_len <= 0)) return -ENOSPC;

    lz4_len = LZ4_compress_HC(ctx->wkdm_buffer, dst, wkdm_len, *dlen,
                              WKDM_LZ4HC_LEVEL, ctx->lz4hc_workspace);

    if (unlikely(lz4_len <= 0 || lz4_len >= WKDM_PAGE_SIZE))
        return -ENOSPC;

    *dlen = lz4_len;
    return 0;
}

/* ============================================================
 * 11. ABSOLUTE LINEAR DECOMPRESS
 * ============================================================ */
static int hybrid_sdecompress(struct crypto_scomp *tfm, const u8 *src, unsigned int slen,
                              u8 *dst, unsigned int *dlen, void *ctx_ptr)
{
    struct hybrid_ctx *ctx = ctx_ptr;
    int ret;

    if (unlikely(!dlen || slen == 0)) return -EINVAL;

    ret = LZ4_decompress_safe(src, ctx->wkdm_buffer, slen, WKDM_MAX_CAPACITY);
    if (unlikely(ret < 0)) return -EINVAL;

    if (unlikely(wkdm_unpack_linear(ctx->wkdm_buffer, ret, dst, ctx) < 0))
        return -EINVAL;

    *dlen = WKDM_PAGE_SIZE;
    return 0;
}

/* ============================================================
 * 12. SCOMP REGISTRATION
 * ============================================================ */
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

static int __init wkdm_lz4hc_mod_init(void) { return crypto_register_scomp(&scomp); }
static void __exit wkdm_lz4hc_mod_fini(void) { crypto_unregister_scomp(&scomp); }

module_init(wkdm_lz4hc_mod_init);
module_exit(wkdm_lz4hc_mod_fini);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("WKdm-LZ4HC V20.1 Super Dense XOR Pipeline Level 12");
MODULE_ALIAS_CRYPTO("wkdm_lz4hc");
