/*
 * Cryptographic API.
 * Adaptive WKdm-LZ4HC Hybrid Compressor (V5 - Enterprise Ready)
 * Engineered STRICTLY for 4096-Byte Memory Pages (ZRAM)
 */
#include <linux/init.h>
#include <linux/module.h>
#include <linux/crypto.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/lz4.h>
#include <crypto/internal/scompress.h>
#include <asm/unaligned.h>

/* ========================================================
 * 1. DEFINISI ARSITEKTUR & KEAMANAN
 * ======================================================== */
#define WKDM_PAGE_SIZE      4096
#define HYBRID_MAX_OUTPUT   4095
#define HYBRID_MIN_SAVING   16   /* ROI CPU: Hybrid harus hemat minimal 16 bytes */
#define WKDM_DICT_BUCKETS   128  /* 128 Buckets x 2-Way = 256 Entries */
#define WKDM_MAX_CAPACITY   8192

/* 2-Bit Packed Tags (Pure Word-Domain, Zero-Run dihapus) */
#define TAG_ZERO       0x00      /* Payload: None */
#define TAG_DICT_0     0x01      /* Payload: 1-byte index */
#define TAG_DICT_1     0x02      /* Payload: 1-byte index */
#define TAG_MISS       0x03      /* Payload: 4-byte raw word */

/* Header Flags (RAW ditangani oleh lapisan ZRAM) */
#define FLAG_PLAIN_LZ4 0x00
#define FLAG_HYBRID    0x01

struct hybrid_ctx {
    void *lz4hc_workspace;
    u8 *wkdm_buffer;
    u8 *hybrid_comp_buf;
};

/* Hash Perkalian Ringan (7-bit untuk 128 buckets) */
static inline u32 hash_word(u32 word) {
    return (word * 2654435761U) >> 25; 
}

/* ========================================================
 * 2. QUICK ANALYZER (Cost Estimator)
 * ======================================================== */
static bool should_use_hybrid(const u8 *src) {
    int zeros = 0, repeats = 0, score;
    u32 sample_dict[64] = {0}; 
    int i;
    
    /* Sampling 64 Words (256 bytes) awal */
    for (i = 0; i < 64; i++) {
        u32 word = get_unaligned_le32(src + (i * 4));
        if (word == 0) {
            zeros++;
        } else {
            u32 h = (word * 2654435761U) >> 26; /* 6-bit hash for 64-entry stack */
            if (sample_dict[h] == word)
                repeats++;
            else
                sample_dict[h] = word;
        }
    }
    
    /* Scoring Heuristik: Repetisi kata lebih berharga bagi WKdm daripada sekadar nol */
    score = (zeros * 2) + (repeats * 3);
    
    /* Threshold: Eksekusi Hybrid jika skor >= 18 */
    return (score >= 18); 
}

/* ========================================================
 * 3. MESIN FILTER & DE-FILTER (2-Way Associative + MRU)
 * ======================================================== */
static int wkdm_pack(const u8 *src, u8 *out_buf, unsigned int capacity) {
    u32 dict[WKDM_DICT_BUCKETS][2] = {{0}};
    const u8 *in_ptr = src;
    const u8 *in_end = src + WKDM_PAGE_SIZE;
    u8 *out_ptr = out_buf;
    u8 *out_end = out_buf + capacity;

    u8 *tag_ptr = NULL;
    int tag_shift = 8;

    while (in_ptr < in_end) {
        u32 word = get_unaligned_le32(in_ptr);
        in_ptr += 4;

        if (tag_shift == 8) {
            if (out_ptr >= out_end) return -ENOSPC;
            tag_ptr = out_ptr++;
            *tag_ptr = 0;
            tag_shift = 0;
        }

        if (word == 0) {
            *tag_ptr |= (TAG_ZERO << tag_shift);
        } else {
            u32 idx = hash_word(word);
            
            if (dict[idx][0] == word) {
                *tag_ptr |= (TAG_DICT_0 << tag_shift);
                if (out_ptr >= out_end) return -ENOSPC;
                *out_ptr++ = (u8)idx;
            } 
            else if (dict[idx][1] == word) {
                *tag_ptr |= (TAG_DICT_1 << tag_shift);
                if (out_ptr >= out_end) return -ENOSPC;
                *out_ptr++ = (u8)idx;
                
                /* MRU Promotion */
                dict[idx][1] = dict[idx][0];
                dict[idx][0] = word;
            } 
            else {
                /* DICT MISS */
                dict[idx][1] = dict[idx][0];
                dict[idx][0] = word;
                *tag_ptr |= (TAG_MISS << tag_shift);
                
                if (out_ptr + 4 > out_end) return -ENOSPC;
                put_unaligned_le32(word, out_ptr);
                out_ptr += 4;
            }
        }
        tag_shift += 2;
    }
    return (int)(out_ptr - out_buf);
}

static int wkdm_unpack(const u8 *src, unsigned int slen, u8 *out_buf) {
    u32 dict[WKDM_DICT_BUCKETS][2] = {{0}};
    const u8 *in_ptr = src;
    const u8 *in_end = src + slen;
    u8 *out_ptr = out_buf;
    u8 *out_end = out_buf + WKDM_PAGE_SIZE;

    u8 current_tags = 0;
    int tag_shift = 8;

    while (out_ptr < out_end) {
        if (tag_shift == 8) {
            if (in_ptr >= in_end) return -EINVAL;
            current_tags = *in_ptr++;
            tag_shift = 0;
        }

        u8 tag = (current_tags >> tag_shift) & 0x03;
        tag_shift += 2;

        if (tag == TAG_ZERO) {
            put_unaligned_le32(0, out_ptr);
            out_ptr += 4;
        } 
        else if (tag == TAG_DICT_0) {
            u8 idx;
            if (in_ptr >= in_end) return -EINVAL;
            idx = *in_ptr++;
            if (idx >= WKDM_DICT_BUCKETS) return -EINVAL;
            
            put_unaligned_le32(dict[idx][0], out_ptr);
            out_ptr += 4;
        } 
        else if (tag == TAG_DICT_1) {
            u8 idx;
            u32 word;
            if (in_ptr >= in_end) return -EINVAL;
            idx = *in_ptr++;
            if (idx >= WKDM_DICT_BUCKETS) return -EINVAL;
            
            word = dict[idx][1];
            /* MRU Promotion (Wajib sinkron dengan Pack) */
            dict[idx][1] = dict[idx][0];
            dict[idx][0] = word;
            
            put_unaligned_le32(word, out_ptr);
            out_ptr += 4;
        } 
        else { /* TAG_MISS */
            u32 word, idx;
            if (in_ptr + 4 > in_end) return -EINVAL;
            word = get_unaligned_le32(in_ptr);
            in_ptr += 4;
            put_unaligned_le32(word, out_ptr);
            out_ptr += 4;
            
            idx = hash_word(word);
            dict[idx][1] = dict[idx][0];
            dict[idx][0] = word;
        }
    }
    return 0;
}

/* ========================================================
 * 4. MANAJEMEN MEMORI PER-CPU (Aman dari Fragmentasi)
 * ======================================================== */
static void *hybrid_alloc_ctx(struct crypto_scomp *tfm)
{
    struct hybrid_ctx *ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
    if (!ctx) return ERR_PTR(-ENOMEM);

    /* Menggunakan kvmalloc untuk workspace raksasa LZ4HC agar tidak gagal saat OOM */
    ctx->lz4hc_workspace = kvmalloc(LZ4HC_MEM_COMPRESS, GFP_KERNEL);
    if (!ctx->lz4hc_workspace) goto err_workspace;

    ctx->wkdm_buffer = kmalloc(WKDM_MAX_CAPACITY, GFP_KERNEL);
    if (!ctx->wkdm_buffer) goto err_wkdm;

    ctx->hybrid_comp_buf = kmalloc(WKDM_MAX_CAPACITY, GFP_KERNEL);
    if (!ctx->hybrid_comp_buf) goto err_hybrid;

    return ctx;

err_hybrid:
    kfree(ctx->wkdm_buffer);
err_wkdm:
    kvfree(ctx->lz4hc_workspace);
err_workspace:
    kfree(ctx);
    return ERR_PTR(-ENOMEM);
}

static void hybrid_free_ctx(struct crypto_scomp *tfm, void *ctx_ptr)
{
    struct hybrid_ctx *ctx = ctx_ptr;
    if (ctx) {
        kfree(ctx->hybrid_comp_buf);
        kfree(ctx->wkdm_buffer);
        kvfree(ctx->lz4hc_workspace);
        kfree(ctx);
    }
}

/* ========================================================
 * 5. FUNGSI EKSEKUSI (ROI ADAPTIVE FALLBACK)
 * ======================================================== */
static int hybrid_scompress(struct crypto_scomp *tfm, const u8 *src,
                            unsigned int slen, u8 *dst, unsigned int *dlen,
                            void *ctx_ptr)
{
    struct hybrid_ctx *ctx = ctx_ptr;
    int len_plain = 0, len_wkdm = 0, len_hybrid = 0;
    u8 flag = FLAG_PLAIN_LZ4;
    
    if (slen != WKDM_PAGE_SIZE || !dlen || *dlen < WKDM_PAGE_SIZE) 
        return -EINVAL;

    if (should_use_hybrid(src)) {
        len_wkdm = wkdm_pack(src, ctx->wkdm_buffer, WKDM_MAX_CAPACITY);
        if (len_wkdm > 0 && len_wkdm < WKDM_PAGE_SIZE) {
            len_hybrid = LZ4_compress_HC(ctx->wkdm_buffer, ctx->hybrid_comp_buf, 
                                         len_wkdm, HYBRID_MAX_OUTPUT, 6, ctx->lz4hc_workspace);
        }
    } 
    
    len_plain = LZ4_compress_HC(src, dst + 1, WKDM_PAGE_SIZE, HYBRID_MAX_OUTPUT, 6, ctx->lz4hc_workspace);

    /* Pemilihan Kepadatan dengan Margin Penghematan CPU */
    if (len_hybrid > 0 && len_plain > 0) {
        if (len_hybrid + HYBRID_MIN_SAVING < len_plain) {
            flag = FLAG_HYBRID;
        }
    } else if (len_hybrid > 0 && len_plain <= 0) {
        flag = FLAG_HYBRID;
    } else if (len_plain <= 0) {
        /* Baik Hybrid maupun Plain gagal memadatkan data, serahkan mentah ke ZRAM */
        return -ENOSPC; 
    }

    /* Penulisan Output Final */
    if (flag == FLAG_HYBRID) {
        dst[0] = FLAG_HYBRID;
        memcpy(dst + 1, ctx->hybrid_comp_buf, len_hybrid);
        *dlen = len_hybrid + 1;
        return 0;
    } else {
        dst[0] = FLAG_PLAIN_LZ4;
        *dlen = len_plain + 1;
        return 0;
    }
}

static int hybrid_sdecompress(struct crypto_scomp *tfm, const u8 *src,
                              unsigned int slen, u8 *dst, unsigned int *dlen,
                              void *ctx_ptr)
{
    struct hybrid_ctx *ctx = ctx_ptr;
    int ret, err;
    u8 flag;

    if (!dlen || slen < 2) return -EINVAL;
    
    flag = src[0];

    if (flag == FLAG_PLAIN_LZ4) {
        ret = LZ4_decompress_safe(src + 1, dst, slen - 1, WKDM_PAGE_SIZE);
        if (ret < 0 || ret != WKDM_PAGE_SIZE) return -EINVAL;
        *dlen = ret;
        return 0;
    } 
    else if (flag == FLAG_HYBRID) {
        ret = LZ4_decompress_safe(src + 1, ctx->wkdm_buffer, slen - 1, WKDM_MAX_CAPACITY);
        if (ret < 0) return -EINVAL;
        
        err = wkdm_unpack(ctx->wkdm_buffer, ret, dst);
        if (err < 0) return -EINVAL;
        
        *dlen = WKDM_PAGE_SIZE;
        return 0;
    }

    return -EINVAL;
}

/* ========================================================
 * 6. REGISTRASI ALGORITMA SCOMP (INDEPENDEN)
 * ======================================================== */
static struct scomp_alg scomp = {
    .alloc_ctx              = hybrid_alloc_ctx,
    .free_ctx               = hybrid_free_ctx,
    .compress               = hybrid_scompress,
    .decompress             = hybrid_sdecompress,
    .base                   = {
        .cra_name           = "wkdm_lz4hc",
        .cra_driver_name    = "wkdm_lz4hc-scomp",
        .cra_module         = THIS_MODULE,
    }
};

static int __init wkdm_lz4hc_mod_init(void)
{
    return crypto_register_scomp(&scomp);
}

static void __exit wkdm_lz4hc_mod_fini(void)
{
    crypto_unregister_scomp(&scomp);
}

module_init(wkdm_lz4hc_mod_init);
module_exit(wkdm_lz4hc_mod_fini);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("V5 ZRAM Hybrid Compressor: WKdm Word-Domain + LZ4HC Byte-Domain");
MODULE_ALIAS_CRYPTO("wkdm_lz4hc");
