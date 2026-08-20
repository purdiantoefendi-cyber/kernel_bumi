/*
 * Cryptographic API.
 *
 * WKdm-LZ4HC Absolute Linear Compressor V16 (Entropy-Sorted & Aligned)
 *
 * Architecture:
 *
 *      4096-byte page
 *            |
 *       WKdm 1-PASS
 *            |
 *   +----------------------+
 *   | Header (8 Bytes)     |
 *   | Tags (256 Bytes)     |
 *   | Dictionary Index     |
 *   | Raw Plane 3 (MSB)    | <--- Entropy paling rendah, memanaskan LZ4HC
 *   | Raw Plane 2          |
 *   | Raw Plane 1          |
 *   | Raw Plane 0 (LSB)    | <--- Paling acak ditaruh di akhir
 *   +----------------------+
 *            |
 *       LZ4HC Level 12
 *            |
 *           ZRAM
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
 * 1. PAGE / WKDM CONSTANTS
 * ============================================================ */
#define WKDM_PAGE_SIZE          4096
#define WKDM_WORD_SIZE          4
#define WKDM_WORDS              1024

#define WKDM_DICT_BUCKETS       128
#define WKDM_DICT_WAYS          2

#define WKDM_TAG_BITS           2
#define WKDM_TAG_BYTES          (WKDM_WORDS / 4)

#define WKDM_MAX_INDEX_BYTES    WKDM_WORDS
#define WKDM_MAX_MISS           WKDM_WORDS
#define WKDM_MAX_RAW_PLANE      WKDM_WORDS

#define WKDM_HEADER_SIZE        8

#define WKDM_MAX_CAPACITY       \
        (WKDM_HEADER_SIZE + WKDM_TAG_BYTES + \
         WKDM_MAX_INDEX_BYTES + WKDM_PAGE_SIZE)

#define HYBRID_MAX_OUTPUT       4095
#define WKDM_LZ4HC_LEVEL        12

#define WKDM_MAGIC              0x3157

#define TAG_ZERO                0x00
#define TAG_DICT_0              0x01
#define TAG_DICT_1              0x02
#define TAG_MISS                0x03

/* ============================================================
 * 2. CONTEXT
 * ============================================================ */
struct hybrid_ctx {
    void *lz4hc_workspace;
    u8 *wkdm_buffer;
    u32 *wkdm_dict;
    u8 *index_buffer;
    u8 *raw_buffer;
};

/* ============================================================
 * 3. FAST HASH
 * ============================================================ */
static __always_inline u32 hash_word(u32 word)
{
    return (word * 2654435761U) >> 25;
}

/* ============================================================
 * 4. HEADER HELPERS
 * ============================================================ */
static __always_inline void
wkdm_write_header(u8 *dst, u16 index_len, u16 miss_count)
{
    put_unaligned_le16(WKDM_MAGIC, dst + 0);
    put_unaligned_le16(index_len,   dst + 2);
    put_unaligned_le16(miss_count,  dst + 4);
    put_unaligned_le16(0,           dst + 6); /* Reserved / Padding */
}

static __always_inline int
wkdm_read_header(const u8 *src, unsigned int slen, u16 *index_len, u16 *miss_count)
{
    if (slen < WKDM_HEADER_SIZE) return -EINVAL;
    if (get_unaligned_le16(src + 0) != WKDM_MAGIC) return -EINVAL;

    *index_len  = get_unaligned_le16(src + 2);
    *miss_count = get_unaligned_le16(src + 4);

    if (*index_len > WKDM_MAX_INDEX_BYTES) return -EINVAL;
    if (*miss_count > WKDM_MAX_MISS) return -EINVAL;

    return 0;
}

/* ============================================================
 * 5. WKDM PACK (Entropy-Sorted Planes)
 * ============================================================ */
static int wkdm_pack_split(const u8 *src, u8 *out, struct hybrid_ctx *ctx)
{
    u32 *dict = ctx->wkdm_dict;
    u8 *index_buf = ctx->index_buffer;
    u8 *raw_base  = ctx->raw_buffer;

    u8 *r0 = raw_base;
    u8 *r1 = raw_base + WKDM_MAX_RAW_PLANE;
    u8 *r2 = raw_base + (WKDM_MAX_RAW_PLANE * 2);
    u8 *r3 = raw_base + (WKDM_MAX_RAW_PLANE * 3);

    u8 tags[WKDM_TAG_BYTES] = { 0 };

    unsigned int index_len = 0;
    unsigned int miss_count = 0;
    unsigned int word, offset;

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
                index_buf[index_len++] = (u8)bucket;
            }
            else if (entry[1] == value) {
                tag = TAG_DICT_1;
                index_buf[index_len++] = (u8)bucket;
                
                entry[1] = entry[0];
                entry[0] = value;
            }
            else {
                tag = TAG_MISS;
                r0[miss_count] = (u8)(value);
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

    /* Perakitan Super Rapi: Header -> Tags -> Index -> MSB -> LSB */
    offset = 0;
    wkdm_write_header(out, (u16)index_len, (u16)miss_count);
    offset += WKDM_HEADER_SIZE;

    memcpy(out + offset, tags, WKDM_TAG_BYTES);
    offset += WKDM_TAG_BYTES;

    memcpy(out + offset, index_buf, index_len);
    offset += index_len;
    
    /* Entropy Sorting: Plane 3 (MSB) diletakkan lebih dulu agar LZ4HC panas! */
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

/* ============================================================
 * 6. WKDM UNPACK
 * ============================================================ */
static int wkdm_unpack_split(const u8 *src, unsigned int slen, u8 *dst)
{
    u32 dict[WKDM_DICT_BUCKETS][WKDM_DICT_WAYS] = { { 0 } };
    const u8 *tags, *index_ptr, *r0, *r1, *r2, *r3;
    u16 index_len, miss_count;
    unsigned int index_used = 0, miss_used = 0, expected_size, word;

    if (wkdm_read_header(src, slen, &index_len, &miss_count)) return -EINVAL;

    expected_size = WKDM_HEADER_SIZE + WKDM_TAG_BYTES + index_len + (miss_count * 4);
    if (expected_size != slen) return -EINVAL;

    tags = src + WKDM_HEADER_SIZE;
    index_ptr = tags + WKDM_TAG_BYTES;
    
    /* Resolusi Pointer dibalik mengikuti struktur Entropy-Sorted */
    r3 = index_ptr + index_len;
    r2 = r3 + miss_count;
    r1 = r2 + miss_count;
    r0 = r1 + miss_count;

    for (word = 0; word < WKDM_WORDS; word++) {
        u8 tag = (tags[word >> 2] >> ((word & 3) << 1)) & 0x03;
        u32 bucket, value;

        switch (tag) {
        case TAG_ZERO:
            put_unaligned_le32(0, dst + (word << 2));
            break;

        case TAG_DICT_0:
            if (index_used >= index_len) return -EINVAL;
            bucket = index_ptr[index_used++];
            if (bucket >= WKDM_DICT_BUCKETS) return -EINVAL;
            value = dict[bucket][0];
            put_unaligned_le32(value, dst + (word << 2));
            break;

        case TAG_DICT_1:
            if (index_used >= index_len) return -EINVAL;
            bucket = index_ptr[index_used++];
            if (bucket >= WKDM_DICT_BUCKETS) return -EINVAL;
            value = dict[bucket][1];
            dict[bucket][1] = dict[bucket][0];
            dict[bucket][0] = value;
            put_unaligned_le32(value, dst + (word << 2));
            break;

        case TAG_MISS:
            if (miss_used >= miss_count) return -EINVAL;
            value = ((u32)r0[miss_used]) | ((u32)r1[miss_used] << 8) |
                    ((u32)r2[miss_used] << 16) | ((u32)r3[miss_used] << 24);
            miss_used++;
            
            bucket = hash_word(value);
            dict[bucket][1] = dict[bucket][0];
            dict[bucket][0] = value;
            put_unaligned_le32(value, dst + (word << 2));
            break;

        default:
            return -EINVAL;
        }
    }

    if (index_used != index_len || miss_used != miss_count) return -EINVAL;
    return 0;
}

/* ============================================================
 * 7. CONTEXT ALLOCATION
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

    ctx->index_buffer = kmalloc(WKDM_MAX_INDEX_BYTES, GFP_KERNEL);
    if (!ctx->index_buffer) goto err_dict;

    ctx->raw_buffer = kmalloc(WKDM_PAGE_SIZE, GFP_KERNEL);
    if (!ctx->raw_buffer) goto err_index;

    return ctx;

err_index: kfree(ctx->index_buffer);
err_dict: kfree(ctx->wkdm_dict);
err_wkdm: kfree(ctx->wkdm_buffer);
err_workspace: vfree(ctx->lz4hc_workspace);
err_ctx: kfree(ctx);
    return ERR_PTR(-ENOMEM);
}

static void hybrid_free_ctx(struct crypto_scomp *tfm, void *ctx_ptr)
{
    struct hybrid_ctx *ctx = ctx_ptr;
    if (!ctx) return;
    kfree(ctx->raw_buffer);
    kfree(ctx->index_buffer);
    kfree(ctx->wkdm_dict);
    kfree(ctx->wkdm_buffer);
    vfree(ctx->lz4hc_workspace);
    kfree(ctx);
}

/* ============================================================
 * 8. ABSOLUTE LINEAR COMPRESS
 * ============================================================ */
static int hybrid_scompress(struct crypto_scomp *tfm, const u8 *src, unsigned int slen,
                            u8 *dst, unsigned int *dlen, void *ctx_ptr)
{
    struct hybrid_ctx *ctx = ctx_ptr;
    int wkdm_len, lz4_len;

    if (!dlen || slen != WKDM_PAGE_SIZE || *dlen < WKDM_PAGE_SIZE) return -EINVAL;

    wkdm_len = wkdm_pack_split(src, ctx->wkdm_buffer, ctx);
    if (wkdm_len <= 0) return -ENOSPC;

    lz4_len = LZ4_compress_HC(ctx->wkdm_buffer, dst, wkdm_len, *dlen,
                              WKDM_LZ4HC_LEVEL, ctx->lz4hc_workspace);

    if (lz4_len <= 0 || lz4_len >= WKDM_PAGE_SIZE) return -ENOSPC;

    *dlen = lz4_len;
    return 0;
}

/* ============================================================
 * 9. ABSOLUTE LINEAR DECOMPRESS
 * ============================================================ */
static int hybrid_sdecompress(struct crypto_scomp *tfm, const u8 *src, unsigned int slen,
                              u8 *dst, unsigned int *dlen, void *ctx_ptr)
{
    struct hybrid_ctx *ctx = ctx_ptr;
    int ret;

    if (!dlen || slen == 0) return -EINVAL;

    ret = LZ4_decompress_safe(src, ctx->wkdm_buffer, slen, WKDM_MAX_CAPACITY);
    if (ret < 0) return -EINVAL;

    if (wkdm_unpack_split(ctx->wkdm_buffer, ret, dst) < 0) return -EINVAL;

    *dlen = WKDM_PAGE_SIZE;
    return 0;
}

/* ============================================================
 * 10. SCOMP REGISTRATION
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
    }
};

static int __init wkdm_lz4hc_mod_init(void) { return crypto_register_scomp(&scomp); }
static void __exit wkdm_lz4hc_mod_fini(void) { crypto_unregister_scomp(&scomp); }

module_init(wkdm_lz4hc_mod_init);
module_exit(wkdm_lz4hc_mod_fini);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("WKdm-LZ4HC V16 Entropy-Sorted Pipeline Level 12");
MODULE_ALIAS_CRYPTO("wkdm_lz4hc");
