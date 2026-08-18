/*
 * Cryptographic API.
 *
 * Copyright (c) 2013 Chanho Min <chanho.min@lge.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published by
 * the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 *
 */
/*
 * Cryptographic API.
 * WKdm-LZ4HC Hybrid Compressor
 */
#include <linux/init.h>
#include <linux/module.h>
#include <linux/crypto.h>
#include <linux/vmalloc.h>
#include <linux/lz4.h>
#include <crypto/internal/scompress.h>
#include <linux/slab.h>

/* ========================================================
 * 1. DEFINISI HYBRID & PER-CPU WORKSPACE
 * ======================================================== */
#define WKDM_DICTIONARY_SIZE 16
#define WKDM_ZERO_TAG  0x00
#define WKDM_EXACT_TAG 0x03
#define WKDM_MISS_TAG  0x02

/* HANYA ADA SATU STRUKTUR KONTEKS (Bebas Redefinisi) */
struct lz4hc_ctx {
    void *lz4hc_workspace;  /* Memori kerja bawaan untuk mesin LZ4HC */
    u8 *wkdm_buffer;        /* Buffer 8KB permanen untuk hasil filter tokenisasi */
};

/* Tabel hash statis dari WKdm murni */
static const unsigned char wkdm_hashLookupTable[256] = {
   0, 52,  8, 56, 16, 12, 28, 20,  4, 36, 48, 24, 44, 40, 32, 60,
   8, 12, 28, 20,  4, 60, 16, 36, 24, 48, 44, 32, 52, 56, 40, 12,
   8, 48, 16, 52, 60, 28, 56, 32, 20, 24, 36, 40, 44,  4,  8, 40,
  60, 32, 20, 44,  4, 36, 52, 24, 16, 56, 48, 12, 28, 16,  8, 40,
  36, 28, 32, 12,  4, 44, 52, 20, 24, 48, 60, 56, 40, 48,  8, 32,
  28, 36,  4, 44, 20, 56, 60, 24, 52, 16, 12, 12,  4, 48, 20,  8,
  52, 16, 60, 24, 36, 44, 28, 56, 40, 32, 36, 20, 24, 60, 40, 44,
  52, 16, 32,  4, 48,  8, 28, 56, 12, 28, 32, 40, 52, 36, 16, 20,
  48,  8,  4, 60, 24, 56, 44, 12,  8, 36, 24, 28, 16, 60, 20, 56,
  32, 40, 48, 12,  4, 44, 52, 44, 40, 12, 56,  8, 36, 24, 60, 28,
  48,  4, 32, 20, 16, 52, 60, 12, 24, 36,  8,  4, 16, 56, 48, 44,
  40, 52, 32, 20, 28, 32, 12, 36, 28, 24, 56, 40, 16, 52, 44,  4,
  20, 60,  8, 48, 48, 52, 12, 20, 32, 44, 36, 28,  4, 40, 24,  8,
  56, 60, 16, 36, 32,  8, 40,  4, 52, 24, 44, 20, 12, 28, 48, 56,
  16, 60,  4, 52, 60, 48, 20, 16, 56, 44, 24,  8, 40, 12, 32, 28,
  36, 24, 32, 12,  4, 20, 16, 60, 36, 28,  8, 52, 40, 48, 44, 56
};

/* ========================================================
 * 2. MESIN FILTER & DE-FILTER WKDM
 * ======================================================== */

static int wkdm_linear_filter(const u8 *src, unsigned int slen, u8 *out_buf) {
    u32 dictionary[WKDM_DICTIONARY_SIZE] = {1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1};
    const u32 *input_word = (const u32 *)src;
    const u32 *end_input = (const u32 *)(src + slen);
    u8 *out_ptr = out_buf;

    while (input_word < end_input) {
        u32 word = *input_word;
        if (word == 0) {
            *out_ptr++ = WKDM_ZERO_TAG;
        } else {
            u32 hash = ((word >> 10) & 0xFF);
            u32 dict_idx = wkdm_hashLookupTable[hash] / 4; 
            
            if (dictionary[dict_idx] == word) {
                *out_ptr++ = WKDM_EXACT_TAG;
                *out_ptr++ = (u8)dict_idx;
            } else {
                dictionary[dict_idx] = word;
                *out_ptr++ = WKDM_MISS_TAG;
                memcpy(out_ptr, &word, 4);
                out_ptr += 4;
            }
        }
        input_word++;
    }
    return (int)(out_ptr - out_buf);
}

static int wkdm_linear_defilter(const u8 *src, unsigned int slen, u8 *out_buf) {
    u32 dictionary[WKDM_DICTIONARY_SIZE] = {1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1};
    const u8 *input_ptr = src;
    const u8 *end_input = src + slen;
    u32 *out_word = (u32 *)out_buf;

    while (input_ptr < end_input) {
        u8 tag = *input_ptr++;
        
        if (tag == WKDM_ZERO_TAG) {
            *out_word++ = 0;
        } else if (tag == WKDM_EXACT_TAG) {
            u8 dict_idx = *input_ptr++;
            *out_word++ = dictionary[dict_idx];
        } else if (tag == WKDM_MISS_TAG) {
            u32 word;
            memcpy(&word, input_ptr, 4);
            input_ptr += 4;
            
            u32 hash = ((word >> 10) & 0xFF);
            u32 dict_idx = wkdm_hashLookupTable[hash] / 4;
            dictionary[dict_idx] = word;
            
            *out_word++ = word;
        } else {
            return -EINVAL; /* Tag rusak */
        }
    }
    return (int)((u8 *)out_word - out_buf);
}

/* ========================================================
 * 3. MANAJEMEN MEMORI PER-CPU
 * ======================================================== */

static void *lz4hc_alloc_ctx(struct crypto_scomp *tfm)
{
    struct lz4hc_ctx *ctx;

    ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
    if (!ctx)
        return ERR_PTR(-ENOMEM);

    ctx->lz4hc_workspace = vmalloc(LZ4HC_MEM_COMPRESS);
    if (!ctx->lz4hc_workspace) {
        kfree(ctx);
        return ERR_PTR(-ENOMEM);
    }

    ctx->wkdm_buffer = kmalloc(8192, GFP_KERNEL);
    if (!ctx->wkdm_buffer) {
        vfree(ctx->lz4hc_workspace);
        kfree(ctx);
        return ERR_PTR(-ENOMEM);
    }

    return ctx;
}

static void lz4hc_free_ctx(struct crypto_scomp *tfm, void *ctx_ptr)
{
    struct lz4hc_ctx *ctx = ctx_ptr;

    if (ctx) {
        vfree(ctx->lz4hc_workspace);
        kfree(ctx->wkdm_buffer);
        kfree(ctx);
    }
}

/* ========================================================
 * 4. FUNGSI EKSEKUSI UTAMA (SCOMP API - MODERN ZRAM)
 * ======================================================== */

static int lz4hc_scompress(struct crypto_scomp *tfm, const u8 *src,
                           unsigned int slen, u8 *dst, unsigned int *dlen,
                           void *ctx_ptr)
{
    struct lz4hc_ctx *ctx = ctx_ptr;
    int filtered_len;
    int ret;

    /* TAHAP 1: Filter WKdm (Memori Mentah -> wkdm_buffer) */
    filtered_len = wkdm_linear_filter(src, slen, ctx->wkdm_buffer);

    /* TAHAP 2: LZ4HC Compress (wkdm_buffer -> dst) */
    ret = LZ4_compress_HC((const char *)ctx->wkdm_buffer, (char *)dst, 
                          filtered_len, *dlen, 12, ctx->lz4hc_workspace);

    if (!ret)
        return -EINVAL;

    *dlen = ret;
    return 0;
}

static int lz4hc_sdecompress(struct crypto_scomp *tfm, const u8 *src,
                             unsigned int slen, u8 *dst, unsigned int *dlen,
                             void *ctx_ptr)
{
    struct lz4hc_ctx *ctx = ctx_ptr;
    int decompressed_len;
    int final_unpacked_len;

    /* TAHAP 1: LZ4HC Decompress (dst -> wkdm_buffer) */
    decompressed_len = LZ4_decompress_safe((const char *)src, 
                                           (char *)ctx->wkdm_buffer, 
                                           slen, 8192);
    if (decompressed_len < 0)
        return -EINVAL;

    /* TAHAP 2: Defilter WKdm (wkdm_buffer -> Memori Mentah) */
    final_unpacked_len = wkdm_linear_defilter(ctx->wkdm_buffer, decompressed_len, dst);
    
    if (final_unpacked_len < 0)
        return -EINVAL;

    *dlen = final_unpacked_len;
    return 0;
}

/* ========================================================
 * 5. LEGACY CRYPTO API (KOMPATIBILITAS MUNDUR & BYPASS FIX)
 * ======================================================== */

static int lz4hc_init(struct crypto_tfm *tfm)
{
    struct lz4hc_ctx *ctx = crypto_tfm_ctx(tfm);

    /* Alokasi manual ruang kerja untuk jalur lawas */
    ctx->lz4hc_workspace = vmalloc(LZ4HC_MEM_COMPRESS);
    if (!ctx->lz4hc_workspace)
        return -ENOMEM;

    ctx->wkdm_buffer = kmalloc(8192, GFP_KERNEL);
    if (!ctx->wkdm_buffer) {
        vfree(ctx->lz4hc_workspace);
        return -ENOMEM;
    }

    return 0;
}

static void lz4hc_exit(struct crypto_tfm *tfm)
{
    struct lz4hc_ctx *ctx = crypto_tfm_ctx(tfm);

    vfree(ctx->lz4hc_workspace);
    kfree(ctx->wkdm_buffer);
}

static int lz4hc_compress_crypto(struct crypto_tfm *tfm, const u8 *src,
                                 unsigned int slen, u8 *dst,
                                 unsigned int *dlen)
{
    struct lz4hc_ctx *ctx = crypto_tfm_ctx(tfm);
    
    /* Redirect jalur lawas ke SCOMP Hybrid agar filter dieksekusi! */
    return lz4hc_scompress(NULL, src, slen, dst, dlen, ctx);
}

static int lz4hc_decompress_crypto(struct crypto_tfm *tfm, const u8 *src,
                                   unsigned int slen, u8 *dst,
                                   unsigned int *dlen)
{
    struct lz4hc_ctx *ctx = crypto_tfm_ctx(tfm);
    
    /* Redirect jalur lawas ke SCOMP Hybrid agar de-filter dieksekusi! */
    return lz4hc_sdecompress(NULL, src, slen, dst, dlen, ctx);
}

/* ========================================================
 * 6. REGISTRASI ALGORITMA
 * ======================================================== */

static struct crypto_alg alg_lz4hc = {
        .cra_name               = "lz4hc",
        .cra_flags              = CRYPTO_ALG_TYPE_COMPRESS,
        .cra_ctxsize            = sizeof(struct lz4hc_ctx),
        .cra_module             = THIS_MODULE,
        .cra_list               = LIST_HEAD_INIT(alg_lz4hc.cra_list),
        .cra_init               = lz4hc_init,
        .cra_exit               = lz4hc_exit,
        .cra_u                  = { .compress = {
            .coa_compress       = lz4hc_compress_crypto,
            .coa_decompress     = lz4hc_decompress_crypto } }
};

static struct scomp_alg scomp = {
        .alloc_ctx              = lz4hc_alloc_ctx,
        .free_ctx               = lz4hc_free_ctx,
        .compress               = lz4hc_scompress,
        .decompress             = lz4hc_sdecompress,
        .base                   = {
                .cra_name       = "lz4hc",
                .cra_driver_name= "lz4hc-scomp",
                .cra_module     = THIS_MODULE,
        }
};

static int __init lz4hc_mod_init(void)
{
        int ret;

        ret = crypto_register_alg(&alg_lz4hc);
        if (ret)
                return ret;

        ret = crypto_register_scomp(&scomp);
        if (ret) {
                crypto_unregister_alg(&alg_lz4hc);
                return ret;
        }

        return ret;
}

static void __exit lz4hc_mod_fini(void)
{
        crypto_unregister_alg(&alg_lz4hc);
        crypto_unregister_scomp(&scomp);
}

module_init(lz4hc_mod_init);
module_exit(lz4hc_mod_fini);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("WKdm-LZ4HC Hybrid Compression Algorithm");
MODULE_ALIAS_CRYPTO("lz4hc");
