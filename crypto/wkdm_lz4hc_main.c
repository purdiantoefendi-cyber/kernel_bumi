/*
 * Cryptographic API.
 *
 * WKdm-LZ4/HC V45 BEYOND SILICON (/*
 * Cryptographic API.
 *
 * WKdm-LZ4/HC V46 ETERNITY (APEX CRITICAL 25)
 * Architecture: Hybrid C + Pure ASM Split
 * 
 * Target: Helio G85 @ HZ=1000 | AArch64
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
#include <crypto/internal/scompress.h>
#include <asm/unaligned.h>

#define WKDM_PAGE_SIZE 4096
#define WKDM_WORDS 1024
#define WKDM_DICT_BITS 8
#define WKDM_DICT_BUCKETS (1U << WKDM_DICT_BITS)
#define WKDM_DICT_WAYS 2
#define WKDM_TAG_BYTES (WKDM_WORDS / 4)
#define WKDM_MAX_INDEX_BYTES WKDM_WORDS
#define WKDM_MAX_MISS WKDM_WORDS
#define WKDM_RAW_PLANE_SIZE WKDM_MAX_MISS
#define WKDM_TOTAL_RAW_BYTES (WKDM_RAW_PLANE_SIZE * 4)
#define WKDM_TOTAL_INDEX_BYTES (WKDM_MAX_INDEX_BYTES * 2)
#define WKDM_HEADER_SIZE 6
#define WKDM_MAX_CAPACITY (WKDM_HEADER_SIZE + WKDM_TAG_BYTES + WKDM_TOTAL_INDEX_BYTES + WKDM_TOTAL_RAW_BYTES)

#define WKDM_LZ4HC_LEVEL 12
#define WKDM_COMPRESS_RATE_CRITICAL 25
#define WKDM_DECAY_MAX_SHIFT 4

#define TAG_ZERO 0x00
#define TAG_DICT_0 0x01
#define TAG_DICT_1 0x02
#define TAG_MISS 0x03
#define ZERO_MARKER_U16 0x4B57

/* ARM64 Native Streaming Prefetch */
#define PRFM_PLDL1STRM(addr) asm volatile("prfm pldl1strm, [%0]" :: "r"(addr) : "memory")
#define PRFM_PSTL1STRM(addr) asm volatile("prfm pstl1strm, [%0]" :: "r"(addr) : "memory")

#if defined(__clang__)
    #define PRAGMA_UNROLL_4 _Pragma("unroll 4")
#elif defined(__GNUC__) && __GNUC__ >= 8
    #define PRAGMA_UNROLL_4 _Pragma("GCC unroll 4")
#else
    #define PRAGMA_UNROLL_4
#endif

/* PURE ASSEMBLY EXTERNS (Dari wkdm_lz4hc_arm64.S) */
extern void fast_arm64_zero_4k(u8 *dst);
extern void fast_arm64_zero_dict(u32 *dict);
extern void fast_arm64_memcpy_nt(u8 *dst, const u8 *src, unsigned int len);
extern void fast_arm64_fusion_delta_nt(u8 *dst, const u8 *src, unsigned int len);

/* Absolute Cache-Line Alignment 64-byte untuk Cortex-A75 */
struct wkdm_memory_pool {
    u32 dict[WKDM_DICT_BUCKETS * WKDM_DICT_WAYS] __attribute__((aligned(64)));
    u8 index_buffer[WKDM_TOTAL_INDEX_BYTES] __attribute__((aligned(64)));
    u8 raw_buffer[WKDM_TOTAL_RAW_BYTES] __attribute__((aligned(64)));
    u8 tags_buffer[WKDM_TAG_BYTES] __attribute__((aligned(64)));
} ____cacheline_aligned;

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

static __always_inline u32 hash_word(u32 w){ return (w * 2654435761U) >> (32 - WKDM_DICT_BITS); }
static __always_inline void wkdm_write_header(u8 *d,u16 a,u16 b,u16 c){ put_unaligned_le16(a,d); put_unaligned_le16(b,d+2); put_unaligned_le16(c,d+4); }

static __always_inline void wkdm_update_burst(struct hybrid_ctx *c, unsigned long now){
    unsigned long d=now-c->last_jiffy; if(d){ if(d>=WKDM_DECAY_MAX_SHIFT) c->burst_count=0; else c->burst_count>>=d; c->last_jiffy=now; }
    if(c->burst_count<0xffff) c->burst_count++;
}

static int wkdm_pack_split(const u8 *src, u8 *out, struct hybrid_ctx *ctx)
{
    u32 *dict=ctx->wkdm_dict; u8 *tags=ctx->tags_buffer;
    u8 *i0=ctx->index_buffer; u8 *i1=i0+WKDM_MAX_INDEX_BYTES;
    u8 *r0=ctx->raw_buffer; u8 *r1=r0+WKDM_RAW_PLANE_SIZE; u8 *r2=r1+WKDM_RAW_PLANE_SIZE; u8 *r3=r2+WKDM_RAW_PLANE_SIZE;
    u16 l0=0,l1=0,miss=0; u32 page_or=0; 
    
    fast_arm64_zero_dict(dict);

    PRAGMA_UNROLL_4
    for(u16 w=0; w<WKDM_WORDS; w+=4){
        u32 v0=get_unaligned_le32(src+((w+0)<<2)), v1=get_unaligned_le32(src+((w+1)<<2)), v2=get_unaligned_le32(src+((w+2)<<2)), v3=get_unaligned_le32(src+((w+3)<<2));
        page_or|=v0|v1|v2|v3; 
        PRFM_PLDL1STRM(src + ((w + 16) << 2)); 
        u8 tp=0;

#define P(v,s,b) if(unlikely(!(v))) tp|=(TAG_ZERO<<(s)); else {u32 *e=&dict[(b)<<1]; if(likely(e[0]==(v))){tp|=(TAG_DICT_0<<(s)); i0[l0++]=(u8)(b);} else if(e[1]==(v)){tp|=(TAG_DICT_1<<(s)); i1[l1++]=(u8)(b); e[1]=e[0]; e[0]=(v);} else {tp|=(TAG_MISS<<(s)); r0[miss]=(u8)(v); r1[miss]=(u8)((v)>>8); r2[miss]=(u8)((v)>>16); r3[miss]=(u8)((v)>>24); miss++; e[1]=e[0]; e[0]=(v);} }
        
        /* Asynchronous Prefetch Interleaving */
        u32 h1 = hash_word(v1);
        PRFM_PLDL1STRM(&dict[h1 << 1]); 
        P(v0, 0, hash_word(v0));
        
        u32 h2 = hash_word(v2);
        PRFM_PLDL1STRM(&dict[h2 << 1]);
        P(v1, 2, h1);
        
        u32 h3 = hash_word(v3);
        PRFM_PLDL1STRM(&dict[h3 << 1]);
        P(v2, 4, h2);
        
        P(v3, 6, h3);
#undef P
        tags[w>>2]=tp;
    }
    
    if(unlikely(page_or==0)) return 0;

    unsigned int off=0; wkdm_write_header(out,l0,l1,miss); off+=6;
    fast_arm64_memcpy_nt(out+off,tags,WKDM_TAG_BYTES); off+=WKDM_TAG_BYTES;
    
    fast_arm64_fusion_delta_nt(out+off, i0, l0); off+=l0;
    fast_arm64_fusion_delta_nt(out+off, i1, l1); off+=l1;
    fast_arm64_fusion_delta_nt(out+off, r3, miss); off+=miss;
    fast_arm64_fusion_delta_nt(out+off, r2, miss); off+=miss;
    fast_arm64_fusion_delta_nt(out+off, r1, miss); off+=miss;
    fast_arm64_fusion_delta_nt(out+off, r0, miss); off+=miss;
    
    if(unlikely(off>WKDM_MAX_CAPACITY)) return -ENOSPC;
    return off;
}

static int wkdm_unpack_linear(const u8 *src, unsigned int slen, u8 *dst, struct hybrid_ctx *ctx)
{
    u16 l0=get_unaligned_le16(src), l1=get_unaligned_le16(src+2), miss=get_unaligned_le16(src+4);
    unsigned int exp=6+256+l0+l1+miss*4;
    if(unlikely(exp!=slen || exp>WKDM_MAX_CAPACITY || l0>1024 || l1>1024 || miss>1024)) return -EINVAL;

    const u8 *tags=src+6, *ii0=tags+256, *ii1=ii0+l0, *r3=ii1+l1, *r2=r3+miss, *r1=r2+miss, *r0=r1+miss;
    u32 *dict=ctx->wkdm_dict; 
    fast_arm64_zero_dict(dict);
    
    u16 a0=0,a1=0,mi=0; u8 p0=0,p1=0,p2=0,p3=0,pi0=0,pi1=0;

    PRFM_PSTL1STRM(dst);
    PRFM_PSTL1STRM(dst + 64);

    for(u16 w=0; w<1024; w+=4){ 
        PRFM_PSTL1STRM(dst + ((w + 32) << 2));

        u8 tp=tags[w>>2];
        u8 tag = tp & 0x03;
        if(tag==0) put_unaligned_le32(0,dst+((w+0)<<2));
        else if(tag==3){ p3^=r3[mi]; p2^=r2[mi]; p1^=r1[mi]; p0^=r0[mi]; mi++; u32 v=p0|p1<<8|p2<<16|p3<<24; u32 b=hash_word(v); u32 *e=&dict[b<<1]; e[1]=e[0]; e[0]=v; put_unaligned_le32(v,dst+((w+0)<<2));}
        else if(tag==1){ pi0^=ii0[a0++]; put_unaligned_le32(dict[pi0<<1],dst+((w+0)<<2));}
        else { pi1^=ii1[a1++]; u32 *e=&dict[pi1<<1]; u32 v=e[1]; e[1]=e[0]; e[0]=v; put_unaligned_le32(v,dst+((w+0)<<2));}

        tag = (tp >> 2) & 0x03;
        if(tag==0) put_unaligned_le32(0,dst+((w+1)<<2));
        else if(tag==3){ p3^=r3[mi]; p2^=r2[mi]; p1^=r1[mi]; p0^=r0[mi]; mi++; u32 v=p0|p1<<8|p2<<16|p3<<24; u32 b=hash_word(v); u32 *e=&dict[b<<1]; e[1]=e[0]; e[0]=v; put_unaligned_le32(v,dst+((w+1)<<2));}
        else if(tag==1){ pi0^=ii0[a0++]; put_unaligned_le32(dict[pi0<<1],dst+((w+1)<<2));}
        else { pi1^=ii1[a1++]; u32 *e=&dict[pi1<<1]; u32 v=e[1]; e[1]=e[0]; e[0]=v; put_unaligned_le32(v,dst+((w+1)<<2));}

        tag = (tp >> 4) & 0x03;
        if(tag==0) put_unaligned_le32(0,dst+((w+2)<<2));
        else if(tag==3){ p3^=r3[mi]; p2^=r2[mi]; p1^=r1[mi]; p0^=r0[mi]; mi++; u32 v=p0|p1<<8|p2<<16|p3<<24; u32 b=hash_word(v); u32 *e=&dict[b<<1]; e[1]=e[0]; e[0]=v; put_unaligned_le32(v,dst+((w+2)<<2));}
        else if(tag==1){ pi0^=ii0[a0++]; put_unaligned_le32(dict[pi0<<1],dst+((w+2)<<2));}
        else { pi1^=ii1[a1++]; u32 *e=&dict[pi1<<1]; u32 v=e[1]; e[1]=e[0]; e[0]=v; put_unaligned_le32(v,dst+((w+2)<<2));}

        tag = (tp >> 6) & 0x03;
        if(tag==0) put_unaligned_le32(0,dst+((w+3)<<2));
        else if(tag==3){ p3^=r3[mi]; p2^=r2[mi]; p1^=r1[mi]; p0^=r0[mi]; mi++; u32 v=p0|p1<<8|p2<<16|p3<<24; u32 b=hash_word(v); u32 *e=&dict[b<<1]; e[1]=e[0]; e[0]=v; put_unaligned_le32(v,dst+((w+3)<<2));}
        else if(tag==1){ pi0^=ii0[a0++]; put_unaligned_le32(dict[pi0<<1],dst+((w+3)<<2));}
        else { pi1^=ii1[a1++]; u32 *e=&dict[pi1<<1]; u32 v=e[1]; e[1]=e[0]; e[0]=v; put_unaligned_le32(v,dst+((w+3)<<2));}
    } 
    
    if(unlikely(a0!=l0 || a1!=l1 || mi!=miss)) return -EINVAL;
    return 0;
}

static void *hybrid_alloc_ctx(struct crypto_scomp *tfm)
{
    struct hybrid_ctx *c = kzalloc(sizeof(*c), GFP_KERNEL);
    if(!c) return ERR_PTR(-ENOMEM);
    c->lz4_workspace = kmalloc(LZ4_sizeofState(), GFP_KERNEL);
    c->lz4hc_workspace = vmalloc(LZ4_sizeofStateHC());
    c->wkdm_buffer = kmalloc(WKDM_MAX_CAPACITY, GFP_KERNEL);
    c->pool = kmalloc(sizeof(*c->pool), GFP_KERNEL);
    if(!c->pool || !c->wkdm_buffer || !c->lz4_workspace || !c->lz4hc_workspace){
        kfree(c->pool); kfree(c->wkdm_buffer); kfree(c->lz4_workspace); vfree(c->lz4hc_workspace); kfree(c); 
        return ERR_PTR(-ENOMEM);
    }
    c->wkdm_dict = c->pool->dict; c->index_buffer = c->pool->index_buffer;
    c->raw_buffer = c->pool->raw_buffer; c->tags_buffer = c->pool->tags_buffer;
    c->last_jiffy = jiffies; return c;
}

static void hybrid_free_ctx(struct crypto_scomp *tfm, void *p){ 
    struct hybrid_ctx *c = p; if(!c) return; 
    kfree(c->pool); kfree(c->wkdm_buffer); kfree(c->lz4_workspace); vfree(c->lz4hc_workspace); kfree(c); 
}

static int hybrid_scompress(struct crypto_scomp *tfm, const u8 *src, unsigned int slen, u8 *dst, unsigned int *dlen, void *ctx_ptr)
{
    struct hybrid_ctx *c=ctx_ptr; if(!dlen||slen!=4096||*dlen<4096) return -EINVAL;
    wkdm_update_burst(c,jiffies); int wl=wkdm_pack_split(src,c->wkdm_buffer,c);
    
    if(unlikely(wl==0)){ put_unaligned_le16(ZERO_MARKER_U16, dst); *dlen=2; return 0; }
    if(wl<0) return wl; int ll;
    
    PRFM_PSTL1STRM(dst); 
    
    if(c->burst_count>=WKDM_COMPRESS_RATE_CRITICAL) ll=LZ4_compress_default(c->wkdm_buffer,dst,wl,*dlen,c->lz4_workspace);
    else ll=LZ4_compress_HC(c->wkdm_buffer,dst,wl,*dlen,12,c->lz4hc_workspace);
    if(ll<=0||ll>=4096) return -ENOSPC; *dlen=ll; return 0;
}

static int hybrid_sdecompress(struct crypto_scomp *tfm, const u8 *src, unsigned int slen, u8 *dst, unsigned int *dlen, void *ctx_ptr)
{
    struct hybrid_ctx *c=ctx_ptr;
    
    if(unlikely(slen==2 && get_unaligned_le16(src)==ZERO_MARKER_U16)){ fast_arm64_zero_4k(dst); *dlen=4096; return 0; }
    
    int r=LZ4_decompress_safe(src,c->wkdm_buffer,slen,WKDM_MAX_CAPACITY); if(r<6) return -EINVAL;
    if(wkdm_unpack_linear(c->wkdm_buffer,r,dst,c)<0) return -EINVAL; *dlen=4096; return 0;
}

static struct scomp_alg scomp={.alloc_ctx=hybrid_alloc_ctx,.free_ctx=hybrid_free_ctx,.compress=hybrid_scompress,.decompress=hybrid_sdecompress,.base={.cra_name="wkdm_lz4hc",.cra_driver_name="wkdm_lz4hc-scomp",.cra_module=THIS_MODULE,},};
static int __init wkdm_lz4hc_mod_init(void){ BUILD_BUG_ON(WKDM_DICT_BITS>8); return crypto_register_scomp(&scomp); }
static void __exit wkdm_lz4hc_mod_fini(void){ crypto_unregister_scomp(&scomp); }
module_init(wkdm_lz4hc_mod_init); module_exit(wkdm_lz4hc_mod_fini);
MODULE_LICENSE("GPL"); MODULE_DESCRIPTION("WKdm-LZ4/HC V46 ETERNITY Split-Architecture"); MODULE_ALIAS_CRYPTO("wkdm_lz4hc");
 CRITICAL 25)
 * Split-Architecture: C Logic + Pure .S Assembly Core
 * 
 * Target: Helio G85 @ HZ=1000 | AArch64
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
#include <crypto/internal/scompress.h>
#include <asm/unaligned.h>

#define WKDM_PAGE_SIZE 4096
#define WKDM_WORDS 1024
#define WKDM_DICT_BITS 8
#define WKDM_DICT_BUCKETS (1U << WKDM_DICT_BITS)
#define WKDM_DICT_WAYS 2
#define WKDM_TAG_BYTES (WKDM_WORDS / 4)
#define WKDM_MAX_INDEX_BYTES WKDM_WORDS
#define WKDM_MAX_MISS WKDM_WORDS
#define WKDM_RAW_PLANE_SIZE WKDM_MAX_MISS
#define WKDM_TOTAL_RAW_BYTES (WKDM_RAW_PLANE_SIZE * 4)
#define WKDM_TOTAL_INDEX_BYTES (WKDM_MAX_INDEX_BYTES * 2)
#define WKDM_HEADER_SIZE 6
#define WKDM_MAX_CAPACITY (WKDM_HEADER_SIZE + WKDM_TAG_BYTES + WKDM_TOTAL_INDEX_BYTES + WKDM_TOTAL_RAW_BYTES)

#define WKDM_LZ4HC_LEVEL 12
#define WKDM_COMPRESS_RATE_CRITICAL 25
#define WKDM_DECAY_MAX_SHIFT 4

#define TAG_ZERO 0x00
#define TAG_DICT_0 0x01
#define TAG_DICT_1 0x02
#define TAG_MISS 0x03
#define ZERO_MARKER_U16 0x4B57

/* ARM64 Native Streaming Prefetch (Bypasses Cache Pollution) */
#define PRFM_PLDL1STRM(addr) asm volatile("prfm pldl1strm, [%0]" :: "r"(addr) : "memory")
#define PRFM_PSTL1STRM(addr) asm volatile("prfm pstl1strm, [%0]" :: "r"(addr) : "memory")

#if defined(__clang__)
    #define PRAGMA_UNROLL_4 _Pragma("unroll 4")
#elif defined(__GNUC__) && __GNUC__ >= 8
    #define PRAGMA_UNROLL_4 _Pragma("GCC unroll 4")
#else
    #define PRAGMA_UNROLL_4
#endif

/* EXTERN PURE ASSEMBLY FUNCTIONS (Linked from wkdm_arm64.S) */
extern void fast_arm64_zero_4k(u8 *dst);
extern void fast_arm64_zero_dict(u32 *dict);
extern void fast_arm64_memcpy_nt(u8 *dst, const u8 *src, unsigned int len);

struct wkdm_memory_pool {
    u32 dict[WKDM_DICT_BUCKETS * WKDM_DICT_WAYS];
    u8 index_buffer[WKDM_TOTAL_INDEX_BYTES];
    u8 raw_buffer[WKDM_TOTAL_RAW_BYTES];
    u8 tags_buffer[WKDM_TAG_BYTES];
} ____cacheline_aligned;

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

static __always_inline u32 hash_word(u32 w){ return (w * 2654435761U) >> (32 - WKDM_DICT_BITS); }
static __always_inline void wkdm_write_header(u8 *d,u16 a,u16 b,u16 c){ put_unaligned_le16(a,d); put_unaligned_le16(b,d+2); put_unaligned_le16(c,d+4); }

/* FUSION DELTA-COPY NT (Safe 64-Bit ALU Core in C) */
static __always_inline void fusion_delta_memcpy_nt(u8 *dst, const u8 *src, unsigned int len)
{
    if (unlikely(len == 0)) return;
    if (len == 1) { *dst = *src; return; }
    
    u8 prev = src[0];
    dst[0] = prev;
    const u8 *s = src + 1;
    u8 *d = dst + 1;
    unsigned int n = len - 1;

    while (n >= 8) {
        u64 curr; __builtin_memcpy(&curr, s, 8);
        u64 shifted = (curr << 8) | prev;
        u64 enc = curr ^ shifted;
        __builtin_memcpy(d, &enc, 8);
        prev = curr >> 56;
        s += 8; d += 8; n -= 8;
    }
    while (n--) { u8 c = *s++; *d++ = c ^ prev; prev = c; }
}

static __always_inline void wkdm_update_burst(struct hybrid_ctx *c, unsigned long now){
    unsigned long d=now-c->last_jiffy; if(d){ if(d>=WKDM_DECAY_MAX_SHIFT) c->burst_count=0; else c->burst_count>>=d; c->last_jiffy=now; }
    if(c->burst_count<0xffff) c->burst_count++;
}

static int wkdm_pack_split(const u8 *src, u8 *out, struct hybrid_ctx *ctx)
{
    u32 *dict=ctx->wkdm_dict; u8 *tags=ctx->tags_buffer;
    u8 *i0=ctx->index_buffer; u8 *i1=i0+WKDM_MAX_INDEX_BYTES;
    u8 *r0=ctx->raw_buffer; u8 *r1=r0+WKDM_RAW_PLANE_SIZE; u8 *r2=r1+WKDM_RAW_PLANE_SIZE; u8 *r3=r2+WKDM_RAW_PLANE_SIZE;
    u16 l0=0,l1=0,miss=0; u32 page_or=0; 
    
    fast_arm64_zero_dict(dict); /* Call to .S Assembly */

    PRAGMA_UNROLL_4
    for(u16 w=0; w<WKDM_WORDS; w+=4){
        u32 v0=get_unaligned_le32(src+((w+0)<<2)), v1=get_unaligned_le32(src+((w+1)<<2)), v2=get_unaligned_le32(src+((w+2)<<2)), v3=get_unaligned_le32(src+((w+3)<<2));
        page_or|=v0|v1|v2|v3; 
        PRFM_PLDL1STRM(src + ((w + 16) << 2)); 
        u8 tp=0;
#define P(v,s) if(unlikely(!(v))) tp|=(TAG_ZERO<<(s)); else {u32 b=hash_word(v); u32 *e=&dict[b<<1]; if(likely(e[0]==(v))){tp|=(TAG_DICT_0<<(s)); i0[l0++]=(u8)b;} else if(e[1]==(v)){tp|=(TAG_DICT_1<<(s)); i1[l1++]=(u8)b; e[1]=e[0]; e[0]=(v);} else {tp|=(TAG_MISS<<(s)); r0[miss]=(u8)(v); r1[miss]=(u8)((v)>>8); r2[miss]=(u8)((v)>>16); r3[miss]=(u8)((v)>>24); miss++; e[1]=e[0]; e[0]=(v);} }
        P(v0,0); P(v1,2); P(v2,4); P(v3,6);
#undef P
        tags[w>>2]=tp;
    }
    
    if(unlikely(page_or==0)) return 0;

    unsigned int off=0; wkdm_write_header(out,l0,l1,miss); off+=6;
    fast_arm64_memcpy_nt(out+off,tags,WKDM_TAG_BYTES); off+=WKDM_TAG_BYTES; /* Call to .S Assembly */
    
    fusion_delta_memcpy_nt(out+off, i0, l0); off+=l0;
    fusion_delta_memcpy_nt(out+off, i1, l1); off+=l1;
    fusion_delta_memcpy_nt(out+off, r3, miss); off+=miss;
    fusion_delta_memcpy_nt(out+off, r2, miss); off+=miss;
    fusion_delta_memcpy_nt(out+off, r1, miss); off+=miss;
    fusion_delta_memcpy_nt(out+off, r0, miss); off+=miss;
    
    if(unlikely(off>WKDM_MAX_CAPACITY)) return -ENOSPC;
    return off;
}

static int wkdm_unpack_linear(const u8 *src, unsigned int slen, u8 *dst, struct hybrid_ctx *ctx)
{
    u16 l0=get_unaligned_le16(src), l1=get_unaligned_le16(src+2), miss=get_unaligned_le16(src+4);
    unsigned int exp=6+256+l0+l1+miss*4;
    if(unlikely(exp!=slen || exp>WKDM_MAX_CAPACITY || l0>1024 || l1>1024 || miss>1024)) return -EINVAL;

    const u8 *tags=src+6, *ii0=tags+256, *ii1=ii0+l0, *r3=ii1+l1, *r2=r3+miss, *r1=r2+miss, *r0=r1+miss;
    u32 *dict=ctx->wkdm_dict; 
    fast_arm64_zero_dict(dict); /* Call to .S Assembly */
    
    u16 a0=0,a1=0,mi=0; u8 p0=0,p1=0,p2=0,p3=0,pi0=0,pi1=0;

    PRFM_PSTL1STRM(dst);
    PRFM_PSTL1STRM(dst + 64);

    for(u16 w=0; w<1024; w+=4){ 
        PRFM_PSTL1STRM(dst + ((w + 32) << 2)); 

        u8 tp=tags[w>>2];
        u8 tag = tp & 0x03;
        if(tag==0) put_unaligned_le32(0,dst+((w+0)<<2));
        else if(tag==3){ p3^=r3[mi]; p2^=r2[mi]; p1^=r1[mi]; p0^=r0[mi]; mi++; u32 v=p0|p1<<8|p2<<16|p3<<24; u32 b=hash_word(v); u32 *e=&dict[b<<1]; e[1]=e[0]; e[0]=v; put_unaligned_le32(v,dst+((w+0)<<2));}
        else if(tag==1){ pi0^=ii0[a0++]; put_unaligned_le32(dict[pi0<<1],dst+((w+0)<<2));}
        else { pi1^=ii1[a1++]; u32 *e=&dict[pi1<<1]; u32 v=e[1]; e[1]=e[0]; e[0]=v; put_unaligned_le32(v,dst+((w+0)<<2));}

        tag = (tp >> 2) & 0x03;
        if(tag==0) put_unaligned_le32(0,dst+((w+1)<<2));
        else if(tag==3){ p3^=r3[mi]; p2^=r2[mi]; p1^=r1[mi]; p0^=r0[mi]; mi++; u32 v=p0|p1<<8|p2<<16|p3<<24; u32 b=hash_word(v); u32 *e=&dict[b<<1]; e[1]=e[0]; e[0]=v; put_unaligned_le32(v,dst+((w+1)<<2));}
        else if(tag==1){ pi0^=ii0[a0++]; put_unaligned_le32(dict[pi0<<1],dst+((w+1)<<2));}
        else { pi1^=ii1[a1++]; u32 *e=&dict[pi1<<1]; u32 v=e[1]; e[1]=e[0]; e[0]=v; put_unaligned_le32(v,dst+((w+1)<<2));}

        tag = (tp >> 4) & 0x03;
        if(tag==0) put_unaligned_le32(0,dst+((w+2)<<2));
        else if(tag==3){ p3^=r3[mi]; p2^=r2[mi]; p1^=r1[mi]; p0^=r0[mi]; mi++; u32 v=p0|p1<<8|p2<<16|p3<<24; u32 b=hash_word(v); u32 *e=&dict[b<<1]; e[1]=e[0]; e[0]=v; put_unaligned_le32(v,dst+((w+2)<<2));}
        else if(tag==1){ pi0^=ii0[a0++]; put_unaligned_le32(dict[pi0<<1],dst+((w+2)<<2));}
        else { pi1^=ii1[a1++]; u32 *e=&dict[pi1<<1]; u32 v=e[1]; e[1]=e[0]; e[0]=v; put_unaligned_le32(v,dst+((w+2)<<2));}

        tag = (tp >> 6) & 0x03;
        if(tag==0) put_unaligned_le32(0,dst+((w+3)<<2));
        else if(tag==3){ p3^=r3[mi]; p2^=r2[mi]; p1^=r1[mi]; p0^=r0[mi]; mi++; u32 v=p0|p1<<8|p2<<16|p3<<24; u32 b=hash_word(v); u32 *e=&dict[b<<1]; e[1]=e[0]; e[0]=v; put_unaligned_le32(v,dst+((w+3)<<2));}
        else if(tag==1){ pi0^=ii0[a0++]; put_unaligned_le32(dict[pi0<<1],dst+((w+3)<<2));}
        else { pi1^=ii1[a1++]; u32 *e=&dict[pi1<<1]; u32 v=e[1]; e[1]=e[0]; e[0]=v; put_unaligned_le32(v,dst+((w+3)<<2));}
    } 
    
    if(unlikely(a0!=l0 || a1!=l1 || mi!=miss)) return -EINVAL;
    return 0;
}

static void *hybrid_alloc_ctx(struct crypto_scomp *tfm)
{
    struct hybrid_ctx *c = kzalloc(sizeof(*c), GFP_KERNEL);
    if(!c) return ERR_PTR(-ENOMEM);
    c->lz4_workspace = kmalloc(LZ4_sizeofState(), GFP_KERNEL);
    c->lz4hc_workspace = vmalloc(LZ4_sizeofStateHC());
    c->wkdm_buffer = kmalloc(WKDM_MAX_CAPACITY, GFP_KERNEL);
    c->pool = kmalloc(sizeof(*c->pool), GFP_KERNEL);
    if(!c->pool || !c->wkdm_buffer || !c->lz4_workspace || !c->lz4hc_workspace){
        kfree(c->pool); kfree(c->wkdm_buffer); kfree(c->lz4_workspace); vfree(c->lz4hc_workspace); kfree(c); 
        return ERR_PTR(-ENOMEM);
    }
    c->wkdm_dict = c->pool->dict; c->index_buffer = c->pool->index_buffer;
    c->raw_buffer = c->pool->raw_buffer; c->tags_buffer = c->pool->tags_buffer;
    c->last_jiffy = jiffies; return c;
}

static void hybrid_free_ctx(struct crypto_scomp *tfm, void *p){ 
    struct hybrid_ctx *c = p; if(!c) return; 
    kfree(c->pool); kfree(c->wkdm_buffer); kfree(c->lz4_workspace); vfree(c->lz4hc_workspace); kfree(c); 
}

static int hybrid_scompress(struct crypto_scomp *tfm, const u8 *src, unsigned int slen, u8 *dst, unsigned int *dlen, void *ctx_ptr)
{
    struct hybrid_ctx *c=ctx_ptr; if(!dlen||slen!=4096||*dlen<4096) return -EINVAL;
    wkdm_update_burst(c,jiffies); int wl=wkdm_pack_split(src,c->wkdm_buffer,c);
    
    if(unlikely(wl==0)){ put_unaligned_le16(ZERO_MARKER_U16, dst); *dlen=2; return 0; }
    if(wl<0) return wl; int ll;
    
    PRFM_PSTL1STRM(dst); 
    
    if(c->burst_count>=WKDM_COMPRESS_RATE_CRITICAL) ll=LZ4_compress_default(c->wkdm_buffer,dst,wl,*dlen,c->lz4_workspace);
    else ll=LZ4_compress_HC(c->wkdm_buffer,dst,wl,*dlen,12,c->lz4hc_workspace);
    if(ll<=0||ll>=4096) return -ENOSPC; *dlen=ll; return 0;
}

static int hybrid_sdecompress(struct crypto_scomp *tfm, const u8 *src, unsigned int slen, u8 *dst, unsigned int *dlen, void *ctx_ptr)
{
    struct hybrid_ctx *c=ctx_ptr;
    
    if(unlikely(slen==2 && get_unaligned_le16(src)==ZERO_MARKER_U16)){ fast_arm64_zero_4k(dst); *dlen=4096; return 0; }
    
    int r=LZ4_decompress_safe(src,c->wkdm_buffer,slen,WKDM_MAX_CAPACITY); if(r<6) return -EINVAL;
    if(wkdm_unpack_linear(c->wkdm_buffer,r,dst,c)<0) return -EINVAL; *dlen=4096; return 0;
}

static struct scomp_alg scomp={.alloc_ctx=hybrid_alloc_ctx,.free_ctx=hybrid_free_ctx,.compress=hybrid_scompress,.decompress=hybrid_sdecompress,.base={.cra_name="wkdm_lz4hc",.cra_driver_name="wkdm_lz4hc-scomp",.cra_module=THIS_MODULE,},};
static int __init wkdm_lz4hc_mod_init(void){ BUILD_BUG_ON(WKDM_DICT_BITS>8); return crypto_register_scomp(&scomp); }
static void __exit wkdm_lz4hc_mod_fini(void){ crypto_unregister_scomp(&scomp); }
module_init(wkdm_lz4hc_mod_init); module_exit(wkdm_lz4hc_mod_fini);
MODULE_LICENSE("GPL"); MODULE_DESCRIPTION("WKdm-LZ4/HC V45 BEYOND SILICON Split-Architecture"); MODULE_ALIAS_CRYPTO("wkdm_lz4hc");
