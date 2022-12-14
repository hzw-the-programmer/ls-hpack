/*
MIT License

Copyright (c) 2018 - 2021 LiteSpeed Technologies Inc

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>

#include "lshpack.h"
#if LS_HPACK_EMIT_TEST_CODE
#include "lshpack-test.h"
#endif
#if 1 // hezhiwen
#include "xxhash.h"
#else
#include XXH_HEADER_NAME
#endif

#ifndef LS_HPACK_USE_LARGE_TABLES
#define LS_HPACK_USE_LARGE_TABLES 1
#endif

#include "huff-tables.h"

#define HPACK_STATIC_TABLE_SIZE   61
#define INITIAL_DYNAMIC_TABLE_SIZE  4096

/* RFC 7541, Section 4.1:
 *
 * " The size of the dynamic table is the sum of the size of its entries.
 * "
 * " The size of an entry is the sum of its name's length in octets (as
 * " defined in Section 5.2), its value's length in octets, and 32.
 */
#define DYNAMIC_ENTRY_OVERHEAD 32

#define NAME_VAL(a, b) sizeof(a) - 1, sizeof(b) - 1, (a), (b)

static const struct
{
    unsigned          name_len;
    unsigned          val_len;
    const char       *name;
    const char       *val;
}
static_table[HPACK_STATIC_TABLE_SIZE] =
{
    { NAME_VAL(":authority",                    "") },
    { NAME_VAL(":method",                       "GET") },
    { NAME_VAL(":method",                       "POST") },
    { NAME_VAL(":path",                         "/") },
    { NAME_VAL(":path",                         "/index.html") },
    { NAME_VAL(":scheme",                       "http") },
    { NAME_VAL(":scheme",                       "https") },
    { NAME_VAL(":status",                       "200") },
    { NAME_VAL(":status",                       "204") },
    { NAME_VAL(":status",                       "206") },
    { NAME_VAL(":status",                       "304") },
    { NAME_VAL(":status",                       "400") },
    { NAME_VAL(":status",                       "404") },
    { NAME_VAL(":status",                       "500") },
    { NAME_VAL("accept-charset",                "") },
    { NAME_VAL("accept-encoding",               "gzip, deflate") },
    { NAME_VAL("accept-language",               "") },
    { NAME_VAL("accept-ranges",                 "") },
    { NAME_VAL("accept",                        "") },
    { NAME_VAL("access-control-allow-origin",   "") },
    { NAME_VAL("age",                           "") },
    { NAME_VAL("allow",                         "") },
    { NAME_VAL("authorization",                 "") },
    { NAME_VAL("cache-control",                 "") },
    { NAME_VAL("content-disposition",           "") },
    { NAME_VAL("content-encoding",              "") },
    { NAME_VAL("content-language",              "") },
    { NAME_VAL("content-length",                "") },
    { NAME_VAL("content-location",              "") },
    { NAME_VAL("content-range",                 "") },
    { NAME_VAL("content-type",                  "") },
    { NAME_VAL("cookie",                        "") },
    { NAME_VAL("date",                          "") },
    { NAME_VAL("etag",                          "") },
    { NAME_VAL("expect",                        "") },
    { NAME_VAL("expires",                       "") },
    { NAME_VAL("from",                          "") },
    { NAME_VAL("host",                          "") },
    { NAME_VAL("if-match",                      "") },
    { NAME_VAL("if-modified-since",             "") },
    { NAME_VAL("if-none-match",                 "") },
    { NAME_VAL("if-range",                      "") },
    { NAME_VAL("if-unmodified-since",           "") },
    { NAME_VAL("last-modified",                 "") },
    { NAME_VAL("link",                          "") },
    { NAME_VAL("location",                      "") },
    { NAME_VAL("max-forwards",                  "") },
    { NAME_VAL("proxy-authenticate",            "") },
    { NAME_VAL("proxy-authorization",           "") },
    { NAME_VAL("range",                         "") },
    { NAME_VAL("referer",                       "") },
    { NAME_VAL("refresh",                       "") },
    { NAME_VAL("retry-after",                   "") },
    { NAME_VAL("server",                        "") },
    { NAME_VAL("set-cookie",                    "") },
    { NAME_VAL("strict-transport-security",     "") },
    { NAME_VAL("transfer-encoding",             "") },
    { NAME_VAL("user-agent",                    "") },
    { NAME_VAL("vary",                          "") },
    { NAME_VAL("via",                           "") },
    { NAME_VAL("www-authenticate",              "") }
};


static const uint32_t static_table_name_hash[HPACK_STATIC_TABLE_SIZE] =
{
    0x653A915Bu, 0xC7742BE4u, 0xC7742BE4u, 0x3513518Du, 0x3513518Du,
    0xF49F1451u, 0xF49F1451u, 0x672BDA53u, 0x672BDA53u, 0x672BDA53u,
    0x672BDA53u, 0x672BDA53u, 0x672BDA53u, 0x672BDA53u, 0xCD2C0296u,
    0xF93AD8A9u, 0x98BD32D3u, 0x1DC691C8u, 0x1AB214F8u, 0x7D3B7A3Bu,
    0xBEC8E440u, 0xE9C1D9E1u, 0x19D88141u, 0xC25511F2u, 0x16020A90u,
    0x48011191u, 0x7D9AAB7Eu, 0x48F5CC19u, 0x8847A08Cu, 0x0D19F766u,
    0x085EF7C5u, 0x0B486ED8u, 0x1A7AA369u, 0x6DE855BAu, 0xA6006EFDu,
    0xA1BB4284u, 0xAE56E25Fu, 0xB6787110u, 0x791C6A0Du, 0xF2BADABEu,
    0xD8CA2594u, 0xFBA64C54u, 0x4BEB0951u, 0x6B86C0B5u, 0xC62FECD2u,
    0x8DA64A26u, 0x6CA35045u, 0xF614D165u, 0xE4D1DF14u, 0xB396750Au,
    0x01F10233u, 0x798BEE18u, 0x5239F142u, 0x82E1B4E1u, 0x8F7E493Eu,
    0x85E74C58u, 0xBD17F160u, 0x34C0456Au, 0x1A04DF3Du, 0xB1B15AB2u,
    0xDDDAB6FFu,
};


static const uint32_t static_table_nameval_hash[HPACK_STATIC_TABLE_SIZE] =
{
    0xF8614896u, 0x25D95A15u, 0x33968BB7u, 0xC8C267F6u, 0x8351136Fu,
    0x98573F68u, 0x16DDE443u, 0x352A6556u, 0xD4F462D2u, 0x125E66E0u,
    0xD7988BC9u, 0x4C3C90DEu, 0x65E6ECA1u, 0xB05B7B87u, 0x96816317u,
    0x8BBF5398u, 0x97E01849u, 0xD7B48DD4u, 0x9C180569u, 0xC7C63B45u,
    0xF4223EE5u, 0x12C8A744u, 0xAA95A0BCu, 0x14F65730u, 0x8410A906u,
    0x98F440DDu, 0x627E4803u, 0x5A5CC325u, 0x137FC223u, 0x1529262Fu,
    0x7950B9BDu, 0x51D448A4u, 0x52C167CFu, 0xFB22AA54u, 0x540DB9FEu,
    0x75A6C685u, 0xE1C54196u, 0xDC0C3733u, 0x6D78CB84u, 0x4F5272CDu,
    0x9D4170E4u, 0xD4E28BA1u, 0x028C7846u, 0x4E8C1DC3u, 0x684BDDBCu,
    0xE113A2B0u, 0x55F7BBD1u, 0x15BD3710u, 0xE82B715Du, 0x3674BC1Fu,
    0x5010D24Bu, 0x953DE1CBu, 0x9F2C92D9u, 0xB2DE5570u, 0xBCA5998Fu,
    0x0FF5B88Eu, 0x1FED156Bu, 0xDC83E7ECu, 0x07B79E35u, 0xA6D145A9u,
    0x43638CBAu,
};


#define lshpack_arr_init(a) do {                                        \
    memset((a), 0, sizeof(*(a)));                                       \
} while (0)

#define lshpack_arr_cleanup(a) do {                                     \
    free((a)->els);                                                     \
    memset((a), 0, sizeof(*(a)));                                       \
} while (0)

#define lshpack_arr_get(a, i) (                                         \
    assert((i) < (a)->nelem),                                           \
    (a)->els[(a)->off + (i)]                                            \
)

#define lshpack_arr_shift(a) (                                          \
    assert((a)->nelem > 0),                                             \
    (a)->nelem -= 1,                                                    \
    (a)->els[(a)->off++]                                                \
)

#define lshpack_arr_pop(a) (                                            \
    assert((a)->nelem > 0),                                             \
    (a)->nelem -= 1,                                                    \
    (a)->els[(a)->off + (a)->nelem]                                     \
)

#define lshpack_arr_count(a) (+(a)->nelem)

static int
lshpack_arr_push (struct lshpack_arr *arr, uintptr_t val)
{
    uintptr_t *new_els;
    unsigned n;

    if (arr->off + arr->nelem < arr->nalloc)
    {
        arr->els[arr->off + arr->nelem] = val;
        ++arr->nelem;
        return 0;
    }

    if (arr->off > arr->nalloc / 2)
    {
        memmove(arr->els, arr->els + arr->off,
                                        sizeof(arr->els[0]) * arr->nelem);
        arr->off = 0;
        arr->els[arr->nelem] = val;
        ++arr->nelem;
        return 0;
    }

    if (arr->nalloc)
        n = arr->nalloc * 2;
    else
        n = 64;
    new_els = malloc(n * sizeof(arr->els[0]));
    if (!new_els)
        return -1;
    memcpy(new_els, arr->els + arr->off, sizeof(arr->els[0]) * arr->nelem);
    free(arr->els);
    arr->off = 0;
    arr->els = new_els;
    arr->nalloc = n;
    arr->els[arr->off + arr->nelem] = val;
    ++arr->nelem;
    return 0;
}

struct lshpack_double_enc_head
{
    struct lshpack_enc_head by_name;
    struct lshpack_enc_head by_nameval;
};

struct lshpack_enc_table_entry
{
    /* An entry always lives on the `all' and `nameval' lists.  If its name
     * is not in the static table, it also lives on the `name' list.
     */
    STAILQ_ENTRY(lshpack_enc_table_entry)
                                    ete_next_nameval,
                                    ete_next_name,
                                    ete_next_all;
    unsigned                        ete_id;
    unsigned                        ete_nameval_hash;
    unsigned                        ete_name_hash;
    unsigned                        ete_name_len;
    unsigned                        ete_val_len;
    char                            ete_buf[];
};

#define ETE_NAME(ete) ((ete)->ete_buf)
#define ETE_VALUE(ete) (&(ete)->ete_buf[(ete)->ete_name_len])


#define N_BUCKETS(n_bits) (1U << (n_bits))
#define BUCKNO(n_bits, hash) ((hash) & (N_BUCKETS(n_bits) - 1))


/* We estimate average number of entries in the dynamic table to be 1/3
 * of the theoretical maximum.  This number is used to size the history
 * buffer: we want it large enough to cover recent entries, yet not too
 * large to cover entries that appear with a period larger than the
 * dynamic table.
 */
static unsigned
henc_hist_size (unsigned max_capacity)
{
    return max_capacity / DYNAMIC_ENTRY_OVERHEAD / 3;
}


int
lshpack_enc_init (struct lshpack_enc *enc)
{
    struct lshpack_double_enc_head *buckets;
    unsigned nbits = 2;
    unsigned i;

    buckets = malloc(sizeof(buckets[0]) * N_BUCKETS(nbits));
    if (!buckets)
        return -1;

    for (i = 0; i < N_BUCKETS(nbits); ++i)
    {
        STAILQ_INIT(&buckets[i].by_name);
        STAILQ_INIT(&buckets[i].by_nameval);
    }

    memset(enc, 0, sizeof(*enc));
    STAILQ_INIT(&enc->hpe_all_entries);
    enc->hpe_max_capacity = INITIAL_DYNAMIC_TABLE_SIZE;
    enc->hpe_buckets      = buckets;
    /* The initial value of the entry ID is completely arbitrary.  As long as
     * there are fewer than 2^32 dynamic table entries, the math to calculate
     * the entry ID works.  To prove to ourselves that the wraparound works
     * and to have the unit tests cover it, we initialize the next ID so that
     * it is just about to wrap around.
     */
    enc->hpe_next_id      = ~0 - 3;
    enc->hpe_nbits        = nbits;
    enc->hpe_nelem        = 0;
    return 0;
}


void
lshpack_enc_cleanup (struct lshpack_enc *enc)
{
    struct lshpack_enc_table_entry *entry, *next;
    for (entry = STAILQ_FIRST(&enc->hpe_all_entries); entry; entry = next)
    {
        next = STAILQ_NEXT(entry, ete_next_all);
        free(entry);
    }
    free(enc->hpe_hist_buf);
    free(enc->hpe_buckets);
}


static int
henc_use_hist (struct lshpack_enc *enc)
{
    unsigned hist_size;

    if (enc->hpe_hist_buf)
        return 0;

    hist_size = henc_hist_size(INITIAL_DYNAMIC_TABLE_SIZE);
    if (!hist_size)
        return 0;

    enc->hpe_hist_buf = malloc(sizeof(enc->hpe_hist_buf[0]) * (hist_size + 1));
    if (!enc->hpe_hist_buf)
        return -1;

    enc->hpe_hist_size = hist_size;
    enc->hpe_flags |= LSHPACK_ENC_USE_HIST;
    return 0;
}


int
lshpack_enc_use_hist (struct lshpack_enc *enc, int on)
{
    if (on)
        return henc_use_hist(enc);
    else
    {
        enc->hpe_flags &= ~LSHPACK_ENC_USE_HIST;
        free(enc->hpe_hist_buf);
        enc->hpe_hist_buf = NULL;
        enc->hpe_hist_size = 0;
        enc->hpe_hist_idx = 0;
        enc->hpe_hist_wrapped = 0;
        return 0;
    }
}


int
lshpack_enc_hist_used (const struct lshpack_enc *enc)
{
    return (enc->hpe_flags & LSHPACK_ENC_USE_HIST) != 0;
}


#define LSHPACK_XXH_SEED 39378473
#define XXH_NAMEVAL_WIDTH 9
#define XXH_NAMEVAL_SHIFT 0
#define XXH_NAME_WIDTH 9
#define XXH_NAME_SHIFT 0

static const unsigned char nameval2id[ 1 << XXH_NAMEVAL_WIDTH ] =
{
#if 1 // hezhiwen
    0,  // 0
    0,  // 1
    0,  // 2
    27, // 3
    0,  // 4
    0,  // 5
    0,  // 6
    0,  // 7
    0,  // 8
    0,  // 9
    0,  // 10
    0,  // 11
    0,  // 12
    0,  // 13
    0,  // 14
    0,  // 15
    0,  // 16
    0,  // 17
    0,  // 18
    0,  // 19
    0,  // 20
    2,  // 21
    0,  // 22
    0,  // 23
    0,  // 24
    0,  // 25
    0,  // 26
    0,  // 27
    0,  // 28
    0,  // 29
    0,  // 30
    50, // 31
    0,  // 32
    0,  // 33
    0,  // 34
    29, // 35
    0,  // 36
    0,  // 37
    0,  // 38
    0,  // 39
    0,  // 40
    0,  // 41
    0,  // 42
    0,  // 43
    0,  // 44
    0,  // 45
    0,  // 46
    30, // 47
    0,  // 48
    0,  // 49
    0,  // 50
    0,  // 51
    0,  // 52
    59, // 53
    0,  // 54
    0,  // 55
    0,  // 56
    0,  // 57
    0,  // 58
    0,  // 59
    0,  // 60
    0,  // 61
    0,  // 62
    0,  // 63
    0,  // 64
    0,  // 65
    0,  // 66
    7,  // 67
    0,  // 68
    0,  // 69
    43, // 70
    0,  // 71
    0,  // 72
    17, // 73
    0,  // 74
    51, // 75
    0,  // 76
    0,  // 77
    0,  // 78
    0,  // 79
    0,  // 80
    0,  // 81
    0,  // 82
    0,  // 83
    34, // 84
    0,  // 85
    0,  // 86
    0,  // 87
    0,  // 88
    0,  // 89
    0,  // 90
    0,  // 91
    0,  // 92
    0,  // 93
    0,  // 94
    0,  // 95
    0,  // 96
    0,  // 97
    0,  // 98
    0,  // 99
    0,  // 100
    0,  // 101
    0,  // 102
    0,  // 103
    0,  // 104
    0,  // 105
    0,  // 106
    0,  // 107
    0,  // 108
    0,  // 109
    0,  // 110
    0,  // 111
    0,  // 112
    0,  // 113
    0,  // 114
    0,  // 115
    0,  // 116
    0,  // 117
    0,  // 118
    0,  // 119
    0,  // 120
    0,  // 121
    0,  // 122
    0,  // 123
    0,  // 124
    0,  // 125
    0,  // 126
    0,  // 127
    0,  // 128
    0,  // 129
    0,  // 130
    0,  // 131
    0,  // 132
    36, // 133
    0,  // 134
    0,  // 135
    0,  // 136
    0,  // 137
    0,  // 138
    0,  // 139
    0,  // 140
    0,  // 141
    56, // 142
    0,  // 143
    0,  // 144
    0,  // 145
    0,  // 146
    0,  // 147
    0,  // 148
    0,  // 149
    1,  // 150
    0,  // 151
    0,  // 152
    0,  // 153
    0,  // 154
    0,  // 155
    0,  // 156
    0,  // 157
    0,  // 158
    0,  // 159
    0,  // 160
    13, // 161
    0,  // 162
    0,  // 163
    32, // 164
    0,  // 165
    0,  // 166
    0,  // 167
    0,  // 168
    0,  // 169
    0,  // 170
    0,  // 171
    0,  // 172
    0,  // 173
    0,  // 174
    0,  // 175
    46, // 176
    0,  // 177
    0,  // 178
    0,  // 179
    0,  // 180
    0,  // 181
    0,  // 182
    0,  // 183
    0,  // 184
    0,  // 185
    61, // 186
    0,  // 187
    23, // 188
    0,  // 189
    0,  // 190
    0,  // 191
    0,  // 192
    0,  // 193
    0,  // 194
    0,  // 195
    0,  // 196
    0,  // 197
    0,  // 198
    0,  // 199
    0,  // 200
    0,  // 201
    0,  // 202
    0,  // 203
    0,  // 204
    40, // 205
    0,  // 206
    0,  // 207
    0,  // 208
    0,  // 209
    9,  // 210
    0,  // 211
    0,  // 212
    0,  // 213
    0,  // 214
    0,  // 215
    0,  // 216
    53, // 217
    0,  // 218
    0,  // 219
    0,  // 220
    26, // 221
    12, // 222
    0,  // 223
    10, // 224
    0,  // 225
    0,  // 226
    0,  // 227
    41, // 228
    21, // 229
    0,  // 230
    0,  // 231
    0,  // 232
    0,  // 233
    0,  // 234
    0,  // 235
    0,  // 236
    0,  // 237
    0,  // 238
    0,  // 239
    0,  // 240
    0,  // 241
    0,  // 242
    0,  // 243
    0,  // 244
    0,  // 245
    0,  // 246
    0,  // 247
    0,  // 248
    0,  // 249
    0,  // 250
    0,  // 251
    0,  // 252
    0,  // 253
    0,  // 254
    0,  // 255
    0,  // 256
    0,  // 257
    0,  // 258
    0,  // 259
    0,  // 260
    0,  // 261
    25, // 262
    0,  // 263
    0,  // 264
    0,  // 265
    0,  // 266
    0,  // 267
    0,  // 268
    0,  // 269
    0,  // 270
    0,  // 271
    48, // 272
    0,  // 273
    0,  // 274
    0,  // 275
    0,  // 276
    0,  // 277
    0,  // 278
    15, // 279
    0,  // 280
    0,  // 281
    0,  // 282
    0,  // 283
    0,  // 284
    0,  // 285
    0,  // 286
    0,  // 287
    0,  // 288
    0,  // 289
    0,  // 290
    0,  // 291
    0,  // 292
    28, // 293
    0,  // 294
    0,  // 295
    0,  // 296
    0,  // 297
    0,  // 298
    0,  // 299
    0,  // 300
    0,  // 301
    0,  // 302
    0,  // 303
    24, // 304
    0,  // 305
    0,  // 306
    38, // 307
    0,  // 308
    0,  // 309
    0,  // 310
    0,  // 311
    0,  // 312
    0,  // 313
    0,  // 314
    0,  // 315
    0,  // 316
    0,  // 317
    0,  // 318
    0,  // 319
    0,  // 320
    0,  // 321
    0,  // 322
    0,  // 323
    22, // 324
    20, // 325
    0,  // 326
    0,  // 327
    0,  // 328
    0,  // 329
    0,  // 330
    0,  // 331
    0,  // 332
    0,  // 333
    0,  // 334
    0,  // 335
    0,  // 336
    0,  // 337
    0,  // 338
    0,  // 339
    0,  // 340
    0,  // 341
    8,  // 342
    0,  // 343
    0,  // 344
    0,  // 345
    0,  // 346
    0,  // 347
    0,  // 348
    49, // 349
    0,  // 350
    0,  // 351
    0,  // 352
    0,  // 353
    0,  // 354
    0,  // 355
    0,  // 356
    0,  // 357
    0,  // 358
    0,  // 359
    6,  // 360
    19, // 361
    0,  // 362
    57, // 363
    0,  // 364
    0,  // 365
    0,  // 366
    5,  // 367
    54, // 368
    0,  // 369
    0,  // 370
    0,  // 371
    0,  // 372
    0,  // 373
    0,  // 374
    0,  // 375
    0,  // 376
    0,  // 377
    0,  // 378
    0,  // 379
    0,  // 380
    0,  // 381
    0,  // 382
    0,  // 383
    0,  // 384
    0,  // 385
    0,  // 386
    0,  // 387
    39, // 388
    0,  // 389
    0,  // 390
    14, // 391
    0,  // 392
    0,  // 393
    0,  // 394
    0,  // 395
    0,  // 396
    0,  // 397
    0,  // 398
    55, // 399
    0,  // 400
    0,  // 401
    0,  // 402
    0,  // 403
    0,  // 404
    0,  // 405
    37, // 406
    0,  // 407
    16, // 408
    0,  // 409
    0,  // 410
    0,  // 411
    0,  // 412
    0,  // 413
    0,  // 414
    0,  // 415
    0,  // 416
    42, // 417
    0,  // 418
    0,  // 419
    0,  // 420
    0,  // 421
    0,  // 422
    0,  // 423
    0,  // 424
    60, // 425
    0,  // 426
    0,  // 427
    0,  // 428
    0,  // 429
    0,  // 430
    0,  // 431
    0,  // 432
    0,  // 433
    0,  // 434
    0,  // 435
    0,  // 436
    0,  // 437
    0,  // 438
    3,  // 439
    0,  // 440
    0,  // 441
    0,  // 442
    0,  // 443
    45, // 444
    31, // 445
    0,  // 446
    0,  // 447
    0,  // 448
    0,  // 449
    0,  // 450
    44, // 451
    0,  // 452
    0,  // 453
    0,  // 454
    0,  // 455
    0,  // 456
    11, // 457
    0,  // 458
    52, // 459
    0,  // 460
    0,  // 461
    0,  // 462
    33, // 463
    0,  // 464
    47, // 465
    0,  // 466
    0,  // 467
    18, // 468
    0,  // 469
    0,  // 470
    0,  // 471
    0,  // 472
    0,  // 473
    0,  // 474
    0,  // 475
    0,  // 476
    0,  // 477
    0,  // 478
    0,  // 479
    0,  // 480
    0,  // 481
    0,  // 482
    0,  // 483
    0,  // 484
    0,  // 485
    0,  // 486
    0,  // 487
    0,  // 488
    0,  // 489
    0,  // 490
    0,  // 491
    58, // 492
    0,  // 493
    0,  // 494
    0,  // 495
    0,  // 496
    0,  // 497
    0,  // 498
    0,  // 499
    0,  // 500
    0,  // 501
    4,  // 502
    0,  // 503
    0,  // 504
    0,  // 505
    0,  // 506
    0,  // 507
    0,  // 508
    0,  // 509
    35, // 510
#else
    [150]  =  1,   [21]   =  2,   [439]  =  3,   [502]  =  4,   [367]  =  5,
    [360]  =  6,   [67]   =  7,   [342]  =  8,   [210]  =  9,   [224]  =  10,
    [457]  =  11,  [222]  =  12,  [161]  =  13,  [391]  =  14,  [279]  =  15,
    [408]  =  16,  [73]   =  17,  [468]  =  18,  [361]  =  19,  [325]  =  20,
    [229]  =  21,  [324]  =  22,  [188]  =  23,  [304]  =  24,  [262]  =  25,
    [221]  =  26,  [3]    =  27,  [293]  =  28,  [35]   =  29,  [47]   =  30,
    [445]  =  31,  [164]  =  32,  [463]  =  33,  [84]   =  34,  [510]  =  35,
    [133]  =  36,  [406]  =  37,  [307]  =  38,  [388]  =  39,  [205]  =  40,
    [228]  =  41,  [417]  =  42,  [70]   =  43,  [451]  =  44,  [444]  =  45,
    [176]  =  46,  [465]  =  47,  [272]  =  48,  [349]  =  49,  [31]   =  50,
    [75]   =  51,  [459]  =  52,  [217]  =  53,  [368]  =  54,  [399]  =  55,
    [142]  =  56,  [363]  =  57,  [492]  =  58,  [53]   =  59,  [425]  =  60,
    [186]  =  61,
#endif
};

static const unsigned char name2id[ 1 << XXH_NAME_WIDTH ] =
{
#if 1 // hezhiwen
    0,  // 0
    0,  // 1
    0,  // 2
    0,  // 3
    0,  // 4
    0,  // 5
    0,  // 6
    0,  // 7
    0,  // 8
    0,  // 9
    0,  // 10
    0,  // 11
    0,  // 12
    39, // 13
    0,  // 14
    0,  // 15
    0,  // 16
    0,  // 17
    0,  // 18
    0,  // 19
    0,  // 20
    0,  // 21
    0,  // 22
    0,  // 23
    52, // 24
    28, // 25
    0,  // 26
    0,  // 27
    0,  // 28
    0,  // 29
    0,  // 30
    0,  // 31
    0,  // 32
    0,  // 33
    0,  // 34
    0,  // 35
    0,  // 36
    0,  // 37
    46, // 38
    0,  // 39
    0,  // 40
    0,  // 41
    0,  // 42
    0,  // 43
    0,  // 44
    0,  // 45
    0,  // 46
    0,  // 47
    0,  // 48
    0,  // 49
    0,  // 50
    51, // 51
    0,  // 52
    0,  // 53
    0,  // 54
    0,  // 55
    0,  // 56
    0,  // 57
    0,  // 58
    20, // 59
    0,  // 60
    0,  // 61
    0,  // 62
    0,  // 63
    21, // 64
    0,  // 65
    0,  // 66
    0,  // 67
    0,  // 68
    47, // 69
    0,  // 70
    0,  // 71
    0,  // 72
    0,  // 73
    0,  // 74
    0,  // 75
    0,  // 76
    0,  // 77
    0,  // 78
    0,  // 79
    0,  // 80
    6,  // 81
    0,  // 82
    8,  // 83
    42, // 84
    0,  // 85
    0,  // 86
    0,  // 87
    56, // 88
    0,  // 89
    0,  // 90
    0,  // 91
    0,  // 92
    0,  // 93
    0,  // 94
    37, // 95
    0,  // 96
    0,  // 97
    0,  // 98
    0,  // 99
    0,  // 100
    0,  // 101
    0,  // 102
    0,  // 103
    0,  // 104
    0,  // 105
    0,  // 106
    0,  // 107
    0,  // 108
    0,  // 109
    0,  // 110
    0,  // 111
    0,  // 112
    0,  // 113
    0,  // 114
    0,  // 115
    0,  // 116
    0,  // 117
    0,  // 118
    0,  // 119
    0,  // 120
    0,  // 121
    0,  // 122
    0,  // 123
    0,  // 124
    0,  // 125
    0,  // 126
    0,  // 127
    0,  // 128
    0,  // 129
    0,  // 130
    0,  // 131
    36, // 132
    0,  // 133
    0,  // 134
    0,  // 135
    0,  // 136
    0,  // 137
    0,  // 138
    0,  // 139
    29, // 140
    0,  // 141
    0,  // 142
    0,  // 143
    25, // 144
    0,  // 145
    0,  // 146
    0,  // 147
    0,  // 148
    0,  // 149
    15, // 150
    0,  // 151
    0,  // 152
    0,  // 153
    0,  // 154
    0,  // 155
    0,  // 156
    0,  // 157
    0,  // 158
    0,  // 159
    0,  // 160
    0,  // 161
    0,  // 162
    0,  // 163
    0,  // 164
    0,  // 165
    0,  // 166
    0,  // 167
    0,  // 168
    16, // 169
    0,  // 170
    0,  // 171
    0,  // 172
    0,  // 173
    0,  // 174
    0,  // 175
    0,  // 176
    0,  // 177
    60, // 178
    0,  // 179
    0,  // 180
    44, // 181
    0,  // 182
    0,  // 183
    0,  // 184
    0,  // 185
    0,  // 186
    0,  // 187
    0,  // 188
    0,  // 189
    40, // 190
    0,  // 191
    0,  // 192
    0,  // 193
    0,  // 194
    0,  // 195
    0,  // 196
    0,  // 197
    0,  // 198
    0,  // 199
    0,  // 200
    0,  // 201
    0,  // 202
    0,  // 203
    0,  // 204
    0,  // 205
    0,  // 206
    0,  // 207
    0,  // 208
    0,  // 209
    45, // 210
    17, // 211
    0,  // 212
    0,  // 213
    0,  // 214
    0,  // 215
    32, // 216
    0,  // 217
    0,  // 218
    0,  // 219
    0,  // 220
    0,  // 221
    0,  // 222
    0,  // 223
    0,  // 224
    54, // 225
    0,  // 226
    0,  // 227
    0,  // 228
    0,  // 229
    0,  // 230
    0,  // 231
    0,  // 232
    0,  // 233
    0,  // 234
    0,  // 235
    0,  // 236
    0,  // 237
    0,  // 238
    0,  // 239
    0,  // 240
    0,  // 241
    0,  // 242
    0,  // 243
    0,  // 244
    0,  // 245
    0,  // 246
    0,  // 247
    19, // 248
    0,  // 249
    0,  // 250
    0,  // 251
    0,  // 252
    35, // 253
    0,  // 254
    61, // 255
    0,  // 256
    0,  // 257
    0,  // 258
    0,  // 259
    0,  // 260
    0,  // 261
    0,  // 262
    0,  // 263
    0,  // 264
    0,  // 265
    50, // 266
    0,  // 267
    0,  // 268
    0,  // 269
    0,  // 270
    0,  // 271
    38, // 272
    0,  // 273
    0,  // 274
    0,  // 275
    49, // 276
    0,  // 277
    0,  // 278
    0,  // 279
    0,  // 280
    0,  // 281
    0,  // 282
    0,  // 283
    0,  // 284
    0,  // 285
    0,  // 286
    0,  // 287
    0,  // 288
    0,  // 289
    0,  // 290
    0,  // 291
    0,  // 292
    0,  // 293
    0,  // 294
    0,  // 295
    0,  // 296
    0,  // 297
    0,  // 298
    0,  // 299
    0,  // 300
    0,  // 301
    0,  // 302
    0,  // 303
    0,  // 304
    0,  // 305
    0,  // 306
    0,  // 307
    0,  // 308
    0,  // 309
    0,  // 310
    0,  // 311
    0,  // 312
    0,  // 313
    0,  // 314
    0,  // 315
    0,  // 316
    59, // 317
    55, // 318
    0,  // 319
    0,  // 320
    23, // 321
    53, // 322
    0,  // 323
    0,  // 324
    0,  // 325
    0,  // 326
    0,  // 327
    0,  // 328
    0,  // 329
    0,  // 330
    0,  // 331
    0,  // 332
    0,  // 333
    0,  // 334
    0,  // 335
    0,  // 336
    43, // 337
    0,  // 338
    0,  // 339
    0,  // 340
    0,  // 341
    0,  // 342
    0,  // 343
    0,  // 344
    0,  // 345
    0,  // 346
    1,  // 347
    0,  // 348
    0,  // 349
    0,  // 350
    0,  // 351
    57, // 352
    0,  // 353
    0,  // 354
    0,  // 355
    0,  // 356
    48, // 357
    30, // 358
    0,  // 359
    0,  // 360
    33, // 361
    58, // 362
    0,  // 363
    0,  // 364
    0,  // 365
    0,  // 366
    0,  // 367
    0,  // 368
    0,  // 369
    0,  // 370
    0,  // 371
    0,  // 372
    0,  // 373
    0,  // 374
    0,  // 375
    0,  // 376
    0,  // 377
    0,  // 378
    0,  // 379
    0,  // 380
    0,  // 381
    27, // 382
    0,  // 383
    0,  // 384
    0,  // 385
    0,  // 386
    0,  // 387
    0,  // 388
    0,  // 389
    0,  // 390
    0,  // 391
    0,  // 392
    0,  // 393
    0,  // 394
    0,  // 395
    0,  // 396
    4,  // 397
    0,  // 398
    0,  // 399
    0,  // 400
    26, // 401
    0,  // 402
    0,  // 403
    41, // 404
    0,  // 405
    0,  // 406
    0,  // 407
    0,  // 408
    0,  // 409
    0,  // 410
    0,  // 411
    0,  // 412
    0,  // 413
    0,  // 414
    0,  // 415
    0,  // 416
    0,  // 417
    0,  // 418
    0,  // 419
    0,  // 420
    0,  // 421
    0,  // 422
    0,  // 423
    0,  // 424
    0,  // 425
    0,  // 426
    0,  // 427
    0,  // 428
    0,  // 429
    0,  // 430
    0,  // 431
    0,  // 432
    0,  // 433
    0,  // 434
    0,  // 435
    0,  // 436
    0,  // 437
    0,  // 438
    0,  // 439
    0,  // 440
    0,  // 441
    34, // 442
    0,  // 443
    0,  // 444
    0,  // 445
    0,  // 446
    0,  // 447
    0,  // 448
    0,  // 449
    0,  // 450
    0,  // 451
    0,  // 452
    31, // 453
    0,  // 454
    0,  // 455
    18, // 456
    0,  // 457
    0,  // 458
    0,  // 459
    0,  // 460
    0,  // 461
    0,  // 462
    0,  // 463
    0,  // 464
    0,  // 465
    0,  // 466
    0,  // 467
    0,  // 468
    0,  // 469
    0,  // 470
    0,  // 471
    0,  // 472
    0,  // 473
    0,  // 474
    0,  // 475
    0,  // 476
    0,  // 477
    0,  // 478
    0,  // 479
    0,  // 480
    22, // 481
    0,  // 482
    0,  // 483
    2,  // 484
    0,  // 485
    0,  // 486
    0,  // 487
    0,  // 488
    0,  // 489
    0,  // 490
    0,  // 491
    0,  // 492
    0,  // 493
    0,  // 494
    0,  // 495
    0,  // 496
    0,  // 497
    24, // 498
#else
    [347]  =  1,   [484]  =  2,   [397]  =  4,   [81]   =  6,   [83]   =  8,
    [150]  =  15,  [169]  =  16,  [211]  =  17,  [456]  =  18,  [248]  =  19,
    [59]   =  20,  [64]   =  21,  [481]  =  22,  [321]  =  23,  [498]  =  24,
    [144]  =  25,  [401]  =  26,  [382]  =  27,  [25]   =  28,  [140]  =  29,
    [358]  =  30,  [453]  =  31,  [216]  =  32,  [361]  =  33,  [442]  =  34,
    [253]  =  35,  [132]  =  36,  [95]   =  37,  [272]  =  38,  [13]   =  39,
    [190]  =  40,  [404]  =  41,  [84]   =  42,  [337]  =  43,  [181]  =  44,
    [210]  =  45,  [38]   =  46,  [69]   =  47,  [357]  =  48,  [276]  =  49,
    [266]  =  50,  [51]   =  51,  [24]   =  52,  [322]  =  53,  [225]  =  54,
    [318]  =  55,  [88]   =  56,  [352]  =  57,  [362]  =  58,  [317]  =  59,
    [178]  =  60,  [255]  =  61,
#endif
};

//not find return 0, otherwise return the index
#if !LS_HPACK_EMIT_TEST_CODE
static
#endif
       unsigned
lshpack_enc_get_static_nameval (const struct lsxpack_header *input)
{
    unsigned i;

    assert(input->name_len > 0);
    assert(input->flags & LSXPACK_NAMEVAL_HASH);
    i = (input->nameval_hash >> XXH_NAMEVAL_SHIFT) & ((1 << XXH_NAMEVAL_WIDTH) - 1);
    if (nameval2id[i])
    {
        i = nameval2id[i] - 1;
        if (static_table[i].name_len == input->name_len
            && static_table[i].val_len == input->val_len
            && memcmp(lsxpack_header_get_name(input), static_table[i].name, input->name_len) == 0
            && memcmp(lsxpack_header_get_value(input), static_table[i].val, input->val_len) == 0)
        {
            return i + 1;
        }
    }

    return 0;
}

#if !LS_HPACK_EMIT_TEST_CODE
static
#endif
       unsigned
lshpack_enc_get_static_name (const struct lsxpack_header *input)
{
    unsigned i;

    assert(input->flags & LSXPACK_NAME_HASH);
    i = (input->name_hash >> XXH_NAME_SHIFT) & ((1 << XXH_NAME_WIDTH) - 1);
    if (name2id[i])
    {
        i = name2id[i] - 1;
        if (static_table[i].name_len == input->name_len
            && memcmp(lsxpack_header_get_name(input), static_table[i].name,
                      input->name_len) == 0)
        {
            return i + 1;
        }
    }

    return 0;
}


static void
update_hash (struct lsxpack_header *input)
{
    if (!(input->flags & LSXPACK_NAME_HASH))
        input->name_hash = XXH32(lsxpack_header_get_name(input),
                                 input->name_len, LSHPACK_XXH_SEED);
    else
        assert(input->name_hash == XXH32(lsxpack_header_get_name(input),
                                         input->name_len, LSHPACK_XXH_SEED));

    if (!(input->flags & LSXPACK_NAMEVAL_HASH))
        input->nameval_hash = XXH32(input->buf + input->val_offset,
                                    input->val_len, input->name_hash);
    else
        assert(input->nameval_hash == XXH32(input->buf + input->val_offset,
                                            input->val_len, input->name_hash));

    input->flags |= (LSXPACK_NAME_HASH | LSXPACK_NAMEVAL_HASH);
}


unsigned
lshpack_enc_get_stx_tab_id (struct lsxpack_header *input)
{
    unsigned i;

    update_hash(input);

    i = (input->nameval_hash >> XXH_NAMEVAL_SHIFT) & ((1 << XXH_NAMEVAL_WIDTH) - 1);
    if (nameval2id[i])
    {
        i = nameval2id[i] - 1;
        if (static_table[i].name_len == input->name_len
            && static_table[i].val_len == input->val_len
            && memcmp(lsxpack_header_get_name(input), static_table[i].name,
                      input->name_len) == 0
            && memcmp(input->buf + input->val_offset, static_table[i].val,
                      input->val_len) == 0)
        {
            return i + 1;
        }
    }

    i = (input->name_hash >> XXH_NAME_SHIFT) & ((1 << XXH_NAME_WIDTH) - 1);
    if (name2id[i])
    {
        i = name2id[i] - 1;
        if (static_table[i].name_len == input->name_len
            && memcmp(lsxpack_header_get_name(input), static_table[i].name,
                      input->name_len) == 0)
        {
            return i + 1;
        }
    }

    return 0;
}


/* Given a dynamic entry, return its table ID */
static unsigned
henc_calc_table_id (const struct lshpack_enc *enc,
                                    const struct lshpack_enc_table_entry *entry)
{
    return HPACK_STATIC_TABLE_SIZE
         + (enc->hpe_next_id - entry->ete_id)
    ;
}


static unsigned
henc_find_table_id (struct lshpack_enc *enc, lsxpack_header_t *input,
                    int *val_matched)
{
    struct lshpack_enc_table_entry *entry;
    unsigned buckno, id;
    const char *val_ptr = input->buf + input->val_offset;
    const char *name;
    unsigned int name_len;

    name_len = input->name_len;
    name = lsxpack_header_get_name(input);

    /* First, look for a match in the static table: */
    if (input->hpack_index)
    {
        id = input->hpack_index - 1;
#ifndef NDEBUG
        if (name_len)
        {
            lsxpack_header_t input_copy = *input;
            const unsigned hpack_index = lshpack_enc_get_stx_tab_id(&input_copy);
            assert(input_copy.hpack_index == hpack_index);
        }
#endif
        if (id <= LSHPACK_HDR_ACCEPT_ENCODING || input->val_len == 0)
        {
            if (static_table[id].val_len == input->val_len
                && memcmp(val_ptr, static_table[id].val, input->val_len) == 0)
            {
                input->flags |= LSXPACK_HPACK_VAL_MATCHED;
                *val_matched = 1;
                return input->hpack_index;
            }
        }
        if (!name_len)
        {
            name = static_table[id].name;
            name_len = static_table[id].name_len;
        }

        if (!(input->flags & LSXPACK_NAME_HASH))
            input->name_hash = static_table_name_hash[id];
        else
            assert(input->name_hash == static_table_name_hash[id]);
        if (!(input->flags & LSXPACK_NAMEVAL_HASH))
            input->nameval_hash = XXH32(val_ptr, input->val_len,
                                        input->name_hash);
        else
            assert(input->nameval_hash == XXH32(val_ptr, input->val_len,
                                                input->name_hash));
        input->flags |= (LSXPACK_NAME_HASH | LSXPACK_NAMEVAL_HASH);
    }
    else
    {
        update_hash(input);
        input->hpack_index = lshpack_enc_get_static_nameval(input);
        if (input->hpack_index != LSHPACK_HDR_UNKNOWN)
        {
            input->flags |= LSXPACK_HPACK_VAL_MATCHED;
            *val_matched = 1;
            return input->hpack_index;
        }
    }

    /* Search by name and value: */
    buckno = BUCKNO(enc->hpe_nbits, input->nameval_hash);
    STAILQ_FOREACH(entry, &enc->hpe_buckets[buckno].by_nameval,
                                                        ete_next_nameval)
        if (input->nameval_hash == entry->ete_nameval_hash &&
            name_len == entry->ete_name_len &&
            input->val_len == entry->ete_val_len &&
            0 == memcmp(name, ETE_NAME(entry), name_len) &&
            0 == memcmp(val_ptr, ETE_VALUE(entry), input->val_len))
        {
            *val_matched = 1;
            return henc_calc_table_id(enc, entry);
        }

    /* Name/value match is not found, look for header: */
    if (input->hpack_index == LSHPACK_HDR_UNKNOWN)
        input->hpack_index = lshpack_enc_get_static_name(input);
    if (input->hpack_index != LSHPACK_HDR_UNKNOWN)
    {
        input->flags &= ~LSXPACK_HPACK_VAL_MATCHED;
        return input->hpack_index;
    }

    /* Search by name only: */
    buckno = BUCKNO(enc->hpe_nbits, input->name_hash);
    STAILQ_FOREACH(entry, &enc->hpe_buckets[buckno].by_name, ete_next_name)
        if (input->name_hash == entry->ete_name_hash &&
            input->name_len == entry->ete_name_len &&
            0 == memcmp(name, ETE_NAME(entry), name_len))
        {
            input->flags &= ~LSXPACK_HPACK_VAL_MATCHED;
            return henc_calc_table_id(enc, entry);
        }

    return 0;
}


#if !LS_HPACK_EMIT_TEST_CODE
static
#endif
       unsigned char *
lshpack_enc_enc_int (unsigned char *dst, unsigned char *const end,
                                        uint32_t value, uint8_t prefix_bits)
{
    unsigned char *const dst_orig = dst;

    /* This function assumes that at least one byte is available */
    assert(dst < end);
    if (value < (uint32_t)(1 << prefix_bits) - 1)
        *dst++ |= value;
    else
    {
        *dst++ |= (1 << prefix_bits) - 1;
        value -= (1 << prefix_bits) - 1;
        while (value >= 128)
        {
            if (dst < end)
            {
                *dst++ = (0x80 | value);
                value >>= 7;
            }
            else
                return dst_orig;
        }
        if (dst < end)
            *dst++ = value;
        else
            return dst_orig;
    }
    return dst;
}


/* This whole pragma business has to do with turning off uninitialized warnings.
 * We do it for gcc and clang.  Other compilers get slightly slower code, where
 * unnecessary initialization is performed.
 */
#if __GNUC__
#pragma GCC diagnostic ignored "-Wunknown-pragmas"
#if __clang__
#pragma GCC diagnostic ignored "-Wunknown-warning-option"
#endif
#endif


int
lshpack_enc_huff_encode (const unsigned char *src,
    const unsigned char *const src_end, unsigned char *const dst, int dst_len)
{
    unsigned char *p_dst = dst;
    unsigned char *dst_end = p_dst + dst_len;
    uintptr_t bits;  /* OK not to initialize this variable */
    unsigned bits_used = 0, adj;
    struct encode_el cur_enc_code;
#if LS_HPACK_USE_LARGE_TABLES
#if 1 // hezhiwen
    const struct henc *henc;
    uint16_t idx;
#endif
#endif
#if __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmaybe-uninitialized"
#pragma GCC diagnostic ignored "-Wuninitialized"
#else
    bits = 0;
#endif
#if LS_HPACK_USE_LARGE_TABLES
#if 0 // hezhiwen
    const struct henc *henc;
    uint16_t idx;
#endif

    while (src + sizeof(bits) * 8 / 5 + sizeof(idx) < src_end
                                    && p_dst + sizeof(bits) <= dst_end)
    {
        memcpy(&idx, src, 2);
        henc = &hencs[idx];
        src += 2;
        while (bits_used + henc->lens < sizeof(bits) * 8)
        {
            bits <<= henc->lens;
            bits |= henc->code;
            bits_used += henc->lens;
            memcpy(&idx, src, 2);
            henc = &hencs[idx];
            src += 2;
        }
        if (henc->lens < 64)
        {
            bits <<= sizeof(bits) * 8 - bits_used;
            bits_used = henc->lens - (sizeof(bits) * 8 - bits_used);
            bits |= henc->code >> bits_used;
#if UINTPTR_MAX == 18446744073709551615ull
            *p_dst++ = bits >> 56;
            *p_dst++ = bits >> 48;
            *p_dst++ = bits >> 40;
            *p_dst++ = bits >> 32;
#endif
            *p_dst++ = bits >> 24;
            *p_dst++ = bits >> 16;
            *p_dst++ = bits >> 8;
            *p_dst++ = bits;
            bits = henc->code;   /* OK not to clear high bits */
        }
        else
        {
            src -= 2;
            break;
        }
    }
#endif

    while (src != src_end)
    {
        cur_enc_code = encode_table[*src++];
        if (bits_used + cur_enc_code.bits < sizeof(bits) * 8)
        {
            bits <<= cur_enc_code.bits;
            bits |= cur_enc_code.code;
            bits_used += cur_enc_code.bits;
            continue;
        }
        else if (p_dst + sizeof(bits) <= dst_end)
        {
            bits <<= sizeof(bits) * 8 - bits_used;
            bits_used = cur_enc_code.bits - (sizeof(bits) * 8 - bits_used);
            bits |= cur_enc_code.code >> bits_used;
#if UINTPTR_MAX == 18446744073709551615ull
            *p_dst++ = bits >> 56;
            *p_dst++ = bits >> 48;
            *p_dst++ = bits >> 40;
            *p_dst++ = bits >> 32;
#endif
            *p_dst++ = bits >> 24;
            *p_dst++ = bits >> 16;
            *p_dst++ = bits >> 8;
            *p_dst++ = bits;
            bits = cur_enc_code.code;   /* OK not to clear high bits */
        }
        else
            return -1;
    }

    adj = bits_used + (-bits_used & 7);     /* Round up to 8 */
    if (bits_used && p_dst + (adj >> 3) <= dst_end)
    {
        bits <<= -bits_used & 7;            /* Align to byte boundary */
        bits |= ((1 << (-bits_used & 7)) - 1);  /* EOF */
        switch (adj >> 3)
        {                               /* Write out */
#if UINTPTR_MAX == 18446744073709551615ull
        case 8: *p_dst++ = bits >> 56;
        /* fall through */
        case 7: *p_dst++ = bits >> 48;
        /* fall through */
        case 6: *p_dst++ = bits >> 40;
        /* fall through */
        case 5: *p_dst++ = bits >> 32;
#endif
        /* fall through */
        case 4: *p_dst++ = bits >> 24;
        /* fall through */
        case 3: *p_dst++ = bits >> 16;
        /* fall through */
        case 2: *p_dst++ = bits >> 8;
        /* fall through */
        default: *p_dst++ = bits;
        }
        return p_dst - dst;
    }
    else if (p_dst + (adj >> 3) <= dst_end)
        return p_dst - dst;
    else
        return -1;
#if __GNUC__
#pragma GCC diagnostic pop
#endif
}


#if !LS_HPACK_EMIT_TEST_CODE
static
#endif
       int
lshpack_enc_enc_str (unsigned char *const dst, size_t dst_len,
                        const unsigned char *str, unsigned str_len)
{
    unsigned char size_buf[4];
    unsigned char *p;
    unsigned size_len;
    int rc;

    if (dst_len > 1)
        /* We guess that the string size fits into a single byte -- meaning
         * compressed string of size 126 and smaller -- which is the normal
         * case.  Thus, we immediately write compressed string to the output
         * buffer.  If our guess is not correct, we fix it later.
         */
        rc = lshpack_enc_huff_encode(str, str + str_len, dst + 1, dst_len - 1);
    else if (dst_len == 1)
        /* Here, the call can only succeed if the string to encode is empty. */
        rc = 0;
    else
        return -1;

    /*
     * Check if need huffman encoding or not
     * Comment: (size_t)rc <= str_len   = means if same length, still use
     *                                                              Huffman
     *                     ^
     */
    if (rc > 0 && (size_t)rc <= str_len)
    {
        if (rc < 127)
        {
            *dst = 0x80 | rc;
            return 1 + rc;
        }
        size_buf[0] = 0x80;
        str_len = rc;
        str = dst + 1;
    }
    else if (str_len <= dst_len - 1)
    {
        if (str_len < 127)
        {
            *dst = (unsigned char) str_len;
            memcpy(dst + 1, str, str_len);
            return 1 + str_len;
        }
        size_buf[0] = 0x00;
    }
    else
        return -1;

    /* The guess of one-byte size was incorrect.  Perform necessary
     * adjustments.
     */
    p = lshpack_enc_enc_int(size_buf, size_buf + sizeof(size_buf), str_len, 7);
    if (p == size_buf)
        return -1;

    size_len = p - size_buf;
    assert(size_len > 1);

    /* Check if there is enough room in the output buffer for both
     * encoded size and the string.
     */
    if (size_len + str_len > dst_len)
        return -1;

    memmove(dst + size_len, str, str_len);
    memcpy(dst, size_buf, size_len);
    return size_len + str_len;
}


static void
henc_drop_oldest_entry (struct lshpack_enc *enc)
{
    struct lshpack_enc_table_entry *entry;
    unsigned buckno;

    entry = STAILQ_FIRST(&enc->hpe_all_entries);
    assert(entry);
    STAILQ_REMOVE_HEAD(&enc->hpe_all_entries, ete_next_all);
    buckno = BUCKNO(enc->hpe_nbits, entry->ete_nameval_hash);
    assert(entry == STAILQ_FIRST(&enc->hpe_buckets[buckno].by_nameval));
    STAILQ_REMOVE_HEAD(&enc->hpe_buckets[buckno].by_nameval, ete_next_nameval);
    buckno = BUCKNO(enc->hpe_nbits, entry->ete_name_hash);
    if (entry == STAILQ_FIRST(&enc->hpe_buckets[buckno].by_name))
        STAILQ_REMOVE_HEAD(&enc->hpe_buckets[buckno].by_name, ete_next_name);

    enc->hpe_cur_capacity -= DYNAMIC_ENTRY_OVERHEAD + entry->ete_name_len
                                                        + entry->ete_val_len;
    --enc->hpe_nelem;
    free(entry);
}


static void
henc_remove_overflow_entries (struct lshpack_enc *enc)
{
    while (enc->hpe_cur_capacity > enc->hpe_max_capacity)
        henc_drop_oldest_entry(enc);
}


static int
henc_grow_tables (struct lshpack_enc *enc)
{
    struct lshpack_double_enc_head *new_buckets, *new[2];
    struct lshpack_enc_table_entry *entry;
    unsigned n, old_nbits;
    int idx;

    old_nbits = enc->hpe_nbits;
    new_buckets = malloc(sizeof(enc->hpe_buckets[0])
                                                * N_BUCKETS(old_nbits + 1));
    if (!new_buckets)
        return -1;

    for (n = 0; n < N_BUCKETS(old_nbits); ++n)
    {
        new[0] = &new_buckets[n];
        new[1] = &new_buckets[n + N_BUCKETS(old_nbits)];
        STAILQ_INIT(&new[0]->by_name);
        STAILQ_INIT(&new[1]->by_name);
        STAILQ_INIT(&new[0]->by_nameval);
        STAILQ_INIT(&new[1]->by_nameval);
        while ((entry = STAILQ_FIRST(&enc->hpe_buckets[n].by_name)))
        {
            STAILQ_REMOVE_HEAD(&enc->hpe_buckets[n].by_name, ete_next_name);
            idx = (BUCKNO(old_nbits + 1, entry->ete_name_hash)
                                                        >> old_nbits) & 1;
            STAILQ_INSERT_TAIL(&new[idx]->by_name, entry, ete_next_name);
        }
        while ((entry = STAILQ_FIRST(&enc->hpe_buckets[n].by_nameval)))
        {
            STAILQ_REMOVE_HEAD(&enc->hpe_buckets[n].by_nameval,
                                                        ete_next_nameval);
            idx = (BUCKNO(old_nbits + 1, entry->ete_nameval_hash)
                                                        >> old_nbits) & 1;
            STAILQ_INSERT_TAIL(&new[idx]->by_nameval, entry,
                                                        ete_next_nameval);
        }
    }

    free(enc->hpe_buckets);
    enc->hpe_nbits   = old_nbits + 1;
    enc->hpe_buckets = new_buckets;
    return 0;
}


#if !LS_HPACK_EMIT_TEST_CODE
static
#endif
       int
lshpack_enc_push_entry (struct lshpack_enc *enc,
                        const struct lsxpack_header *input)
{
    unsigned buckno;
    struct lshpack_enc_table_entry *entry;
    size_t size;
    const char *name;
    unsigned int name_len;

    if (enc->hpe_nelem >= N_BUCKETS(enc->hpe_nbits) / 2 &&
                                                0 != henc_grow_tables(enc))
        return -1;
    name_len = input->name_len;
    if (name_len == 0)
    {
        assert(input->hpack_index != LSHPACK_HDR_UNKNOWN);
        name = static_table[input->hpack_index - 1].name;
        name_len = static_table[input->hpack_index - 1].name_len;
    }
    else
        name = lsxpack_header_get_name(input);
    size = sizeof(*entry) + name_len + input->val_len;
    entry = malloc(size);
    if (!entry)
        return -1;

    entry->ete_name_hash = input->name_hash;
    entry->ete_nameval_hash = input->nameval_hash;
    entry->ete_name_len = name_len;
    entry->ete_val_len = input->val_len;
    entry->ete_id = enc->hpe_next_id++;
    memcpy(ETE_NAME(entry), name, name_len);
    memcpy(ETE_VALUE(entry), input->buf + input->val_offset, input->val_len);

    STAILQ_INSERT_TAIL(&enc->hpe_all_entries, entry, ete_next_all);
    buckno = BUCKNO(enc->hpe_nbits, input->nameval_hash);
    STAILQ_INSERT_TAIL(&enc->hpe_buckets[buckno].by_nameval, entry,
                                                        ete_next_nameval);
    if (input->hpack_index == LSHPACK_HDR_UNKNOWN)
    {
        buckno = BUCKNO(enc->hpe_nbits, input->name_hash);
        STAILQ_INSERT_TAIL(&enc->hpe_buckets[buckno].by_name, entry,
                                                            ete_next_name);
    }
    enc->hpe_cur_capacity += DYNAMIC_ENTRY_OVERHEAD + name_len
                             + input->val_len;
    ++enc->hpe_nelem;
    henc_remove_overflow_entries(enc);
    return 0;
}


static void
henc_resize_history (struct lshpack_enc *enc)
{
    uint32_t *hist_buf;
    unsigned hist_size, first, count, i, j;

    hist_size = henc_hist_size(enc->hpe_max_capacity);

    if (hist_size == enc->hpe_hist_size)
        return;

    if (hist_size == 0)
    {
        free(enc->hpe_hist_buf);
        enc->hpe_hist_buf = NULL;
        enc->hpe_hist_size = 0;
        enc->hpe_hist_idx = 0;
        enc->hpe_hist_wrapped = 0;
        return;
    }

    hist_buf = malloc(sizeof(hist_buf[0]) * (hist_size + 1));
    if (!hist_buf)
        return;

    if (enc->hpe_hist_wrapped)
    {
        first = (enc->hpe_hist_idx + 1) % enc->hpe_hist_size;
        count = enc->hpe_hist_size;
    }
    else
    {
        first = 0;
        count = enc->hpe_hist_idx;
    }
    for (i = 0, j = 0; count > 0 && j < hist_size; ++i, ++j, --count)
        hist_buf[j] = enc->hpe_hist_buf[ (first + i) % enc->hpe_hist_size ];
    enc->hpe_hist_size = hist_size;
    enc->hpe_hist_idx = j % hist_size;
    enc->hpe_hist_wrapped = enc->hpe_hist_idx == 0;
    free(enc->hpe_hist_buf);
    enc->hpe_hist_buf = hist_buf;
}


/* Returns true if `nameval_hash' was already in history, false otherwise. */
static int
henc_hist_add (struct lshpack_enc *enc, uint32_t nameval_hash)
{
    unsigned last;
    uint32_t *p;

    if (enc->hpe_hist_wrapped)
        last = enc->hpe_hist_size;
    else
        last = enc->hpe_hist_idx;

    enc->hpe_hist_buf[ last ] = nameval_hash;
    for (p = enc->hpe_hist_buf; *p != nameval_hash; ++p)
        ;
    enc->hpe_hist_buf[ enc->hpe_hist_idx ] = nameval_hash;
    enc->hpe_hist_idx = (enc->hpe_hist_idx + 1) % enc->hpe_hist_size;
    enc->hpe_hist_wrapped |= enc->hpe_hist_idx == 0;

    return p < enc->hpe_hist_buf + last;
}


unsigned char *
lshpack_enc_encode (struct lshpack_enc *enc, unsigned char *dst,
        unsigned char *dst_end, lsxpack_header_t *input)
{
    //indexed_type: 0, Add, 1,: without, 2: never
    static const char indexed_prefix_number[] = {0x40, 0x00, 0x10};
    unsigned char *const dst_org = dst;
    int rc;
    int val_matched = 0;
    unsigned table_id;

    if (dst_end <= dst)
        return dst_org;

    if (input->flags & LSXPACK_HPACK_VAL_MATCHED)
    {
        assert(input->hpack_index != LSHPACK_HDR_UNKNOWN);
        assert(input->val_len == static_table[input->hpack_index - 1].val_len);
        assert(memcmp(lsxpack_header_get_value(input),
                      static_table[input->hpack_index - 1].val,
                      input->val_len) == 0);
        table_id = input->hpack_index;
        val_matched = 1;
    }
    else
    {
        if (input->flags & LSXPACK_NEVER_INDEX)
            input->indexed_type = 2;
        table_id = henc_find_table_id(enc, input, &val_matched);
        if (enc->hpe_hist_buf)
        {
            rc = henc_hist_add(enc, input->nameval_hash);
            if (!rc && enc->hpe_hist_wrapped && input->indexed_type == 0)
                input->indexed_type = 1;
        }
    }

    if (table_id > 0)
    {
        if (val_matched)
        {
            // LSXPACK_VAL_MATCHED MUST NOT set for dynamic table
            // otherwise, it may cause trouble when feed the input to a different encoder.
            if (table_id > HPACK_STATIC_TABLE_SIZE)
                assert(!(input->flags & LSXPACK_HPACK_VAL_MATCHED));

            *dst = 0x80;
            dst = lshpack_enc_enc_int(dst, dst_end, table_id, 7);
            /* No need to check return value: we pass it up as-is because
             * the behavior is the same.
             */
            return dst;
        }
        else
        {
            *dst = indexed_prefix_number[input->indexed_type];
            dst = lshpack_enc_enc_int(dst, dst_end, table_id,
                                      ((input->indexed_type == 0) ? 6 : 4));
            if (dst == dst_org)
                return dst_org;
        }
    }
    else
    {
        assert(input->name_len > 0);
        *dst++ = indexed_prefix_number[input->indexed_type];
        rc = lshpack_enc_enc_str(dst, dst_end - dst,
                                 (unsigned char *)lsxpack_header_get_name(input),
                                 input->name_len);
        if (rc < 0)
            return dst_org; //Failed to enc this header, return unchanged ptr.
        dst += rc;
    }

    rc = lshpack_enc_enc_str(dst, dst_end - dst,
                             (const unsigned char *)input->buf + input->val_offset,
                             input->val_len);
    if (rc < 0)
        return dst_org; //Failed to enc this header, return unchanged ptr.
    dst += rc;

    if (input->indexed_type == 0)
    {
        rc = lshpack_enc_push_entry(enc, input);
        if (rc != 0)
            return dst_org; //Failed to enc this header, return unchanged ptr.
    }

    return dst;
}


void
lshpack_enc_set_max_capacity (struct lshpack_enc *enc, unsigned max_capacity)
{
    enc->hpe_max_capacity = max_capacity;
    henc_remove_overflow_entries(enc);
    if (lshpack_enc_hist_used(enc))
        henc_resize_history(enc);
}

#if LS_HPACK_EMIT_TEST_CODE
void
lshpack_enc_iter_init (struct lshpack_enc *enc, void **iter)
{
    *iter = STAILQ_FIRST(&enc->hpe_all_entries);
}


/* Returns 0 if entry is found */
int
lshpack_enc_iter_next (struct lshpack_enc *enc, void **iter,
                                        struct enc_dyn_table_entry *retval)
{
    const struct lshpack_enc_table_entry *entry;

    entry = *iter;
    if (!entry)
        return -1;

    *iter = STAILQ_NEXT(entry, ete_next_all);

    retval->name = ETE_NAME(entry);
    retval->value = ETE_VALUE(entry);
    retval->name_len = entry->ete_name_len;
    retval->value_len = entry->ete_val_len;
    retval->entry_id = henc_calc_table_id(enc, entry);
    return 0;
}
#endif


/* Dynamic table entry: */
struct dec_table_entry
{
    unsigned    dte_name_len;
    unsigned    dte_val_len;
#if LSHPACK_DEC_CALC_HASH
    uint32_t    dte_name_hash;
    uint32_t    dte_nameval_hash;
    enum {
        DTEF_NAME_HASH      = LSXPACK_NAME_HASH,
        DTEF_NAMEVAL_HASH   = LSXPACK_NAMEVAL_HASH,
    }           dte_flags:8;
#endif
    uint8_t     dte_name_idx;
    char        dte_buf[];     /* Contains both name and value */
};

#define DTE_NAME(dte) ((dte)->dte_buf)
#define DTE_VALUE(dte) (&(dte)->dte_buf[(dte)->dte_name_len])

enum
{
    HPACK_HUFFMAN_FLAG_ACCEPTED = 0x01,
    HPACK_HUFFMAN_FLAG_SYM = 0x02,
    HPACK_HUFFMAN_FLAG_FAIL = 0x04,
};

struct decode_status
{
    uint8_t state;
    uint8_t eos;
};


void
lshpack_dec_init (struct lshpack_dec *dec)
{
    memset(dec, 0, sizeof(*dec));
    dec->hpd_max_capacity = INITIAL_DYNAMIC_TABLE_SIZE;
    dec->hpd_cur_max_capacity = INITIAL_DYNAMIC_TABLE_SIZE;
    lshpack_arr_init(&dec->hpd_dyn_table);
}


void
lshpack_dec_cleanup (struct lshpack_dec *dec)
{
    uintptr_t val;

    while (lshpack_arr_count(&dec->hpd_dyn_table) > 0)
    {
        val = lshpack_arr_pop(&dec->hpd_dyn_table);
        free((struct dec_table_entry *) val);
    }
    lshpack_arr_cleanup(&dec->hpd_dyn_table);
}


/* Maximum number of bytes required to encode a 32-bit integer */
#define LSHPACK_UINT32_ENC_SZ 6


/* Assumption: we have at least one byte to work with */
#if !LS_HPACK_EMIT_TEST_CODE
static
#endif
       int
lshpack_dec_dec_int (const unsigned char **src_p, const unsigned char *src_end,
                                        unsigned prefix_bits, uint32_t *value_p)
{
    const unsigned char *const orig_src = *src_p;
    const unsigned char *src;
    unsigned prefix_max, M;
    uint32_t val, B;

    src = *src_p;

    prefix_max = (1 << prefix_bits) - 1;
    val = *src++;
    val &= prefix_max;

    if (val < prefix_max)
    {
        *src_p = src;
        *value_p = val;
        return 0;
    }

    M = 0;
    do
    {
        if (src < src_end)
        {
            B = *src++;
            val = val + ((B & 0x7f) << M);
            M += 7;
        }
        else if (src - orig_src < LSHPACK_UINT32_ENC_SZ)
            return -1;
        else
            return -2;
    }
    while (B & 0x80);

    if (M <= 28 || (M == 35 && src[-1] <= 0xF && val - (src[-1] << 28) < val))
    {
        *src_p = src;
        *value_p = val;
        return 0;
    }
    else
        return -2;
}


static void
hdec_drop_oldest_entry (struct lshpack_dec *dec)
{
    struct dec_table_entry *entry;
    entry = (void *) lshpack_arr_shift(&dec->hpd_dyn_table);
    dec->hpd_cur_capacity -= DYNAMIC_ENTRY_OVERHEAD + entry->dte_name_len
                                                        + entry->dte_val_len;
    ++dec->hpd_state;
    free(entry);
}


static void
hdec_remove_overflow_entries (struct lshpack_dec *dec)
{
    while (dec->hpd_cur_capacity > dec->hpd_cur_max_capacity)
        hdec_drop_oldest_entry(dec);
}


static void
hdec_update_max_capacity (struct lshpack_dec *dec, uint32_t new_capacity)
{
    dec->hpd_cur_max_capacity = new_capacity;
    hdec_remove_overflow_entries(dec);
}


void
lshpack_dec_set_max_capacity (struct lshpack_dec *dec, unsigned max_capacity)
{
    dec->hpd_max_capacity = max_capacity;
    hdec_update_max_capacity(dec, max_capacity);
}


static unsigned char *
hdec_huff_dec4bits (uint8_t src_4bits, unsigned char *dst,
                                        struct decode_status *status)
{
    const struct decode_el cur_dec_code =
        decode_tables[status->state][src_4bits];
    if (cur_dec_code.flags & HPACK_HUFFMAN_FLAG_FAIL) {
        return NULL; //failed
    }
    if (cur_dec_code.flags & HPACK_HUFFMAN_FLAG_SYM)
    {
        *dst = cur_dec_code.sym;
        dst++;
    }

    status->state = cur_dec_code.state;
    status->eos = ((cur_dec_code.flags & HPACK_HUFFMAN_FLAG_ACCEPTED) != 0);
    return dst;
}


#if !LS_HPACK_USE_LARGE_TABLES
#define lshpack_dec_huff_decode_full lshpack_dec_huff_decode
#endif

int
lshpack_dec_huff_decode_full (const unsigned char *src, int src_len,
                                            unsigned char *dst, int dst_len)
{
    const unsigned char *p_src = src;
    const unsigned char *const src_end = src + src_len;
    unsigned char *p_dst = dst;
    unsigned char *dst_end = dst + dst_len;
    struct decode_status status = { 0, 1 };

    while (p_src != src_end)
    {
        if (p_dst == dst_end)
            return LSHPACK_ERR_MORE_BUF;
        if ((p_dst = hdec_huff_dec4bits(*p_src >> 4, p_dst, &status))
                == NULL)
            return -1;
        if (p_dst == dst_end)
            return LSHPACK_ERR_MORE_BUF;
        if ((p_dst = hdec_huff_dec4bits(*p_src & 0xf, p_dst, &status))
                == NULL)
            return -1;
        ++p_src;
    }

    if (!status.eos)
        return -1;

    return p_dst - dst;
}


int
lshpack_dec_huff_decode (const unsigned char *src, int src_len,
                                            unsigned char *dst, int dst_len);


//reutrn the length in the dst, also update the src
#if !LS_HPACK_EMIT_TEST_CODE
static
#endif
       int
hdec_dec_str (unsigned char *dst, size_t dst_len, const unsigned char **src,
        const unsigned char *src_end)
{
#if 1 // hezhiwen
    int is_huffman;
    uint32_t len;
    int ret = 0;
#endif
    if ((*src) == src_end)
        return 0;

#if 1 // hezhiwen
    is_huffman = (*(*src) & 0x80);
#else
    int is_huffman = (*(*src) & 0x80);
    uint32_t len;
#endif
    if (0 != lshpack_dec_dec_int(src, src_end, 7, &len))
        return LSHPACK_ERR_BAD_DATA;  //wrong int

#if 0 // hezhiwen
    int ret = 0;
#endif
    if ((uint32_t)(src_end - (*src)) < len) {
        return LSHPACK_ERR_BAD_DATA;  //wrong int
    }

    if (is_huffman)
    {
        ret = lshpack_dec_huff_decode(*src, len, dst, dst_len);
        if (ret < 0)
            return ret; //Wrong code

        (*src) += len;
    }
    else
    {
        if (dst_len < len)
        {
            ret = dst_len - len;
            if (ret > LSHPACK_ERR_MORE_BUF)
                ret = LSHPACK_ERR_MORE_BUF;  //dst not enough space
        }
        else
        {
            memcpy(dst, (*src), len);
            (*src) += len;
            ret = len;
        }
    }

    return ret;
}


/* hpd_dyn_table is a dynamic array.  New entries are pushed onto it,
 * while old entries are shifted from it.
 */
static struct dec_table_entry *
hdec_get_table_entry (struct lshpack_dec *dec, uint32_t index)
{
    uintptr_t val;

    index -= HPACK_STATIC_TABLE_SIZE;
    if (index == 0 || index > lshpack_arr_count(&dec->hpd_dyn_table))
        return NULL;

    index = lshpack_arr_count(&dec->hpd_dyn_table) - index;
    val = lshpack_arr_get(&dec->hpd_dyn_table, index);
    return (struct dec_table_entry *) val;
}


#if !LS_HPACK_EMIT_TEST_CODE
static
#endif
       int
lshpack_dec_push_entry (struct lshpack_dec *dec,
                                        const struct lsxpack_header *xhdr)
{
    struct dec_table_entry *entry;
    unsigned name_len, val_len;
    size_t size;

    name_len = xhdr->name_len;
    val_len = xhdr->val_len;

    size = sizeof(*entry) + name_len + val_len;
    entry = malloc(size);
    if (!entry)
        return -1;

    if (0 != lshpack_arr_push(&dec->hpd_dyn_table, (uintptr_t) entry))
    {
        free(entry);
        return -1;
    }
    ++dec->hpd_state;
    dec->hpd_cur_capacity += DYNAMIC_ENTRY_OVERHEAD + name_len + val_len;
    entry->dte_name_len = name_len;
    entry->dte_val_len = val_len;
    entry->dte_name_idx = xhdr->hpack_index;
#if LSHPACK_DEC_CALC_HASH
    entry->dte_flags = xhdr->flags & (LSXPACK_NAME_HASH|LSXPACK_NAMEVAL_HASH);
    entry->dte_name_hash = xhdr->name_hash;
    entry->dte_nameval_hash = xhdr->nameval_hash;
#endif
    memcpy(DTE_NAME(entry), lsxpack_header_get_name(xhdr), name_len);
    memcpy(DTE_VALUE(entry), lsxpack_header_get_value(xhdr), val_len);

    hdec_remove_overflow_entries(dec);
    return 0;
}


static int
lshpack_dec_copy_value (lsxpack_header_t *output, char *dest, const char *val,
                       unsigned val_len)
{
    if (val_len + LSHPACK_DEC_HTTP1X_EXTRA > (unsigned)output->val_len)
        return LSHPACK_ERR_MORE_BUF;
    output->val_offset = output->name_offset + output->name_len
                         + LSHPACK_DEC_HTTP1X_EXTRA;

    assert(dest == output->buf + output->val_offset);
    output->val_len = val_len;
    memcpy(dest, val, output->val_len);
    dest += output->val_len;
#if LSHPACK_DEC_HTTP1X_OUTPUT
    *dest++ = '\r';
    *dest++ = '\n';
#endif
    return 0;
}


static int
lshpack_dec_copy_name (lsxpack_header_t *output, char **dest, const char *name,
                       unsigned name_len)
{
    if (name_len + LSHPACK_DEC_HTTP1X_EXTRA > (unsigned)output->val_len)
        return LSHPACK_ERR_MORE_BUF;
    output->val_len -= name_len + LSHPACK_DEC_HTTP1X_EXTRA;
    output->name_len = name_len;
    memcpy(*dest, name, name_len);
    *dest += name_len;
#if LSHPACK_DEC_HTTP1X_OUTPUT
    *(*dest)++ = ':';
    *(*dest)++ = ' ';
#endif
    return 0;
}


enum
{
    LSHPACK_ADD_INDEX = 0,
    LSHPACK_NO_INDEX  = 1,
    LSHPACK_NEVER_INDEX = 2,
    LSHPACK_VAL_INDEX = 3,
};


int
lshpack_dec_decode (struct lshpack_dec *dec,
    const unsigned char **src, const unsigned char *src_end,
    struct lsxpack_header *output)
{
    struct dec_table_entry *entry;
    uint32_t index, new_capacity;
    int indexed_type, len;
    const unsigned char *s;
    size_t buf_len = output->val_len;
    size_t extra_buf = 0;
#if 1 // hezhiwen
    char *name;
#endif

    if ((*src) == src_end)
        return LSHPACK_ERR_BAD_DATA;

    buf_len = output->val_len;
    extra_buf = 0;
    s = *src;
    while ((*s & 0xe0) == 0x20)    //001 xxxxx
    {
        if (0 != lshpack_dec_dec_int(&s, src_end, 5, &new_capacity))
            return LSHPACK_ERR_BAD_DATA;
        if (new_capacity > dec->hpd_max_capacity)
            return LSHPACK_ERR_BAD_DATA;
        hdec_update_max_capacity(dec, new_capacity);
        if (s == src_end)
            return LSHPACK_ERR_BAD_DATA;
    }

    /* lshpack_dec_dec_int() sets `index' and advances `src'.  If we do not
     * call it, we set `index' and advance `src' ourselves:
     */
    if (*s & 0x80) //1 xxxxxxx
    {
        if (0 != lshpack_dec_dec_int(&s, src_end, 7, &index))
            return LSHPACK_ERR_BAD_DATA;
        if (index == 0)
            return LSHPACK_ERR_BAD_DATA;
        indexed_type = LSHPACK_VAL_INDEX; //need to parse value
    }
    else if (*s > 0x40) //01 xxxxxx
    {
        if (0 != lshpack_dec_dec_int(&s, src_end, 6, &index))
            return LSHPACK_ERR_BAD_DATA;

        indexed_type = LSHPACK_ADD_INDEX;
    }
    else if (*s == 0x40) //custmized //0100 0000
    {
        indexed_type = LSHPACK_ADD_INDEX;
        index = LSHPACK_HDR_UNKNOWN;
        ++s;
    }

    //Never indexed
    else if (*s == 0x10)  //00010000
    {
        indexed_type = LSHPACK_NEVER_INDEX;
        output->flags |= LSXPACK_NEVER_INDEX;
        index = LSHPACK_HDR_UNKNOWN;
        ++s;
    }
    else if ((*s & 0xf0) == 0x10)  //0001 xxxx
    {
        if (0 != lshpack_dec_dec_int(&s, src_end, 4, &index))
            return LSHPACK_ERR_BAD_DATA;

        indexed_type = LSHPACK_NEVER_INDEX;
        output->flags |= LSXPACK_NEVER_INDEX;
    }

    //without indexed
    else if (*s == 0x00)  //0000 0000
    {
        indexed_type = LSHPACK_NO_INDEX;
        index = LSHPACK_HDR_UNKNOWN;
        ++s;
    }
    else // 0000 xxxx
    {
        if (0 != lshpack_dec_dec_int(&s, src_end, 4, &index))
            return LSHPACK_ERR_BAD_DATA;

        indexed_type = LSHPACK_NO_INDEX;
    }
    if (index != LSHPACK_HDR_UNKNOWN && index <= LSHPACK_HDR_WWW_AUTHENTICATE)
    {
        output->hpack_index = index;
    }

#if 1 // hezhiwen
    name = output->buf + output->name_offset;
#else
    char *name = output->buf + output->name_offset;
#endif
    if (index > 0)
    {
        if (index <= HPACK_STATIC_TABLE_SIZE) //static table
        {
            if (lshpack_dec_copy_name(output, &name,
                    static_table[index - 1].name,
                    static_table[index - 1].name_len) == LSHPACK_ERR_MORE_BUF)
            {
                extra_buf = static_table[index - 1].name_len
                        + LSHPACK_DEC_HTTP1X_EXTRA;
                goto need_more_buf;
            }
            output->flags |= LSXPACK_NAME_HASH;
            output->name_hash = static_table_name_hash[index - 1];

            if (indexed_type == LSHPACK_VAL_INDEX)
            {
                if (lshpack_dec_copy_value(output, name,
                                  static_table[index - 1].val,
                                  static_table[index - 1].val_len) == 0)
                {
                    output->flags |= LSXPACK_NAMEVAL_HASH;
                    output->nameval_hash = static_table_nameval_hash[index - 1];
                    goto decode_end;
                }
                else
                {
                    extra_buf = static_table[index - 1].val_len
                                + LSHPACK_DEC_HTTP1X_EXTRA;
                    goto need_more_buf;
                }
            }
        }
        else
        {
            entry = hdec_get_table_entry(dec, index);
            if (entry == NULL)
                return LSHPACK_ERR_BAD_DATA;
            if (lshpack_dec_copy_name(output, &name, DTE_NAME(entry),
                    entry->dte_name_len) == LSHPACK_ERR_MORE_BUF)
            {
                extra_buf = entry->dte_name_len + LSHPACK_DEC_HTTP1X_EXTRA;
                goto need_more_buf;
            }

            if (entry->dte_name_idx)
                output->hpack_index = entry->dte_name_idx;
            else
                output->hpack_index = LSHPACK_HDR_UNKNOWN;
#if LSHPACK_DEC_CALC_HASH
            output->flags |= entry->dte_flags & DTEF_NAME_HASH;
            output->name_hash = entry->dte_name_hash;
#endif
            if (indexed_type == LSHPACK_VAL_INDEX)
            {
                if (lshpack_dec_copy_value(output, name, DTE_VALUE(entry),
                                           entry->dte_val_len) == 0)
                {
#if LSHPACK_DEC_CALC_HASH
                    output->flags |= entry->dte_flags & DTEF_NAMEVAL_HASH;
                    output->nameval_hash = entry->dte_nameval_hash;
#endif
                    goto decode_end;
                }
                else
                {
                    extra_buf = entry->dte_val_len + LSHPACK_DEC_HTTP1X_EXTRA;
                    goto need_more_buf;
                }
            }
        }
    }
    else
    {
        len = hdec_dec_str((unsigned char *)name, output->val_len,
                           &s, src_end);
        if (len < 0)
        {
            if (len <= LSHPACK_ERR_MORE_BUF)
            {
                extra_buf = -len;
                goto need_more_buf;
            }
            return len; //error
        }
        if (len > UINT16_MAX)
            return LSHPACK_ERR_TOO_LARGE;
#if LSHPACK_DEC_CALC_HASH
        output->flags |= LSXPACK_NAME_HASH;
        output->name_hash = XXH32(name, (size_t) len, LSHPACK_XXH_SEED);
#endif
        output->name_len = len;
        name += output->name_len;
#if LSHPACK_DEC_HTTP1X_OUTPUT
        if (output->name_len + 2 <= output->val_len)
        {
            *name++ = ':';
            *name++ = ' ';
        }
        else
        {
            extra_buf = 2;
            goto need_more_buf;
        }
#endif
        output->val_len -= len + LSHPACK_DEC_HTTP1X_EXTRA;
    }

    len = hdec_dec_str((unsigned char *)name, output->val_len, &s, src_end);
    if (len < 0)
    {
        if (len <= LSHPACK_ERR_MORE_BUF)
        {
            extra_buf = -len;
            goto need_more_buf;
        }
        return len; //error
    }
    if (len > UINT16_MAX)
        return LSHPACK_ERR_TOO_LARGE;
#if LSHPACK_DEC_CALC_HASH
    assert(output->flags & LSXPACK_NAME_HASH);
    output->flags |= LSXPACK_NAMEVAL_HASH;
    output->nameval_hash = XXH32(name, (size_t) len, output->name_hash);
#endif
#if LSHPACK_DEC_HTTP1X_OUTPUT
    if ((unsigned) len + 2 <= output->val_len)
        memcpy(name + len, "\r\n", 2);
    else
    {
        extra_buf = 2;
        goto need_more_buf;
    }
#endif
    output->val_offset = output->name_offset + output->name_len
                        + LSHPACK_DEC_HTTP1X_EXTRA;
    output->val_len = len;

    if (indexed_type == LSHPACK_ADD_INDEX &&
                                0 != lshpack_dec_push_entry(dec, output))
        return LSHPACK_ERR_BAD_DATA;  //error
decode_end:
    *src = s;
#if LSHPACK_DEC_HTTP1X_OUTPUT
    output->dec_overhead = 4;
#endif
    return 0;
need_more_buf:
    buf_len += extra_buf;
    output->val_len = buf_len;
    return LSHPACK_ERR_MORE_BUF;
}


#if LS_HPACK_USE_LARGE_TABLES
#define SHORTEST_CODE 5


/* The decoder is optimized for the common case.  Most of the time, we decode
 * data whose encoding is 16 bits or shorter.  This lets us use a 64 KB table
 * indexed by two bytes of input and outputs 1, 2, or 3 bytes at a time.
 *
 * In the case a longer code is encoutered, we fall back to the original
 * Huffman decoder that supports all code lengths.
 */
int
lshpack_dec_huff_decode (const unsigned char *src, int src_len,
                                            unsigned char *dst, int dst_len)
{
    unsigned char *const orig_dst = dst;
    const unsigned char *const src_end = src + src_len;
    unsigned char *const dst_end = dst + dst_len;
    uintptr_t buf;      /* OK not to initialize the buffer */
    unsigned avail_bits, len;
    struct hdec hdec;
    uint16_t idx;
    int r;

#if __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmaybe-uninitialized"
#pragma GCC diagnostic ignored "-Wuninitialized"
#else
    buf = 0;
#endif

    avail_bits = 0;
    while (1)
    {
        if (src + sizeof(buf) <= src_end)
        {
            len = (sizeof(buf) * 8 - avail_bits) >> 3;
            avail_bits += len << 3;
            switch (len)
            {
#if UINTPTR_MAX == 18446744073709551615ull
            case 8:
                buf <<= 8;
                buf |= (uintptr_t) *src++;
                /* fall through */
            case 7:
                buf <<= 8;
                buf |= (uintptr_t) *src++;
                /* fall through */
            default:
                buf <<= 48;
                buf |= (uintptr_t) *src++ << 40;
                buf |= (uintptr_t) *src++ << 32;
                buf |= (uintptr_t) *src++ << 24;
                buf |= (uintptr_t) *src++ << 16;
#else
                /* fall through */
            case 4:
                buf <<= 8;
                buf |= (uintptr_t) *src++;
                /* fall through */
            case 3:
                buf <<= 8;
                buf |= (uintptr_t) *src++;
                /* fall through */
            default:
                buf <<= 16;
#endif
                buf |= (uintptr_t) *src++ <<  8;
                buf |= (uintptr_t) *src++ <<  0;
            }
        }
        else if (src < src_end)
            do
            {
                buf <<= 8;
                buf |= (uintptr_t) *src++;
                avail_bits += 8;
            }
            while (src < src_end && avail_bits <= sizeof(buf) * 8 - 8);
        else
            break;  /* Normal case terminating condition: out of input */

        if (dst_end - dst >= (ptrdiff_t) (8 * sizeof(buf) / SHORTEST_CODE)
                                                            && avail_bits >= 16)
        {
            /* Fast path: don't check destination bounds */
            do
            {
                idx = buf >> (avail_bits - 16);
                hdec = hdecs[idx];
                dst[0] = hdec.out[0];
                dst[1] = hdec.out[1];
                dst[2] = hdec.out[2];
                dst += hdec.lens & 3;
                avail_bits -= hdec.lens >> 2;
            }
            while (avail_bits >= 16 && hdec.lens);
            if (avail_bits < 16)
                continue;
            goto slow_path;
        }
        else
            while (avail_bits >= 16)
            {
                idx = buf >> (avail_bits - 16);
                hdec = hdecs[idx];
                len = hdec.lens & 3;
                if (len && dst + len <= dst_end)
                {
                    switch (len)
                    {
                    case 3:
                        *dst++ = hdec.out[0];
                        *dst++ = hdec.out[1];
                        *dst++ = hdec.out[2];
                        break;
                    case 2:
                        *dst++ = hdec.out[0];
                        *dst++ = hdec.out[1];
                        break;
                    default:
                        *dst++ = hdec.out[0];
                        break;
                    }
                    avail_bits -= hdec.lens >> 2;
                }
                else if (dst + len > dst_end)
                {
                    r = dst_end - dst - len;
                    if (r > LSHPACK_ERR_MORE_BUF)
                        r = LSHPACK_ERR_MORE_BUF;
                    return r;
                }
                else
                    goto slow_path;
            }
    }

    if (avail_bits >= SHORTEST_CODE)
    {
        idx = buf << (16 - avail_bits);
        idx |= (1 << (16 - avail_bits)) - 1;    /* EOF */
        if (idx == 0xFFFF && avail_bits < 8)
            goto end;
        /* If a byte or more of input is left, this mean there is a valid
         * encoding, not just EOF.
         */
        hdec = hdecs[idx];
        len = hdec.lens & 3;
        if (((unsigned) hdec.lens >> 2) > avail_bits)
            return -1;
        if (len && dst + len <= dst_end)
        {
            switch (len)
            {
            case 3:
                *dst++ = hdec.out[0];
                *dst++ = hdec.out[1];
                *dst++ = hdec.out[2];
                break;
            case 2:
                *dst++ = hdec.out[0];
                *dst++ = hdec.out[1];
                break;
            default:
                *dst++ = hdec.out[0];
                break;
            }
            avail_bits -= hdec.lens >> 2;
        }
        else if (dst + len > dst_end)
        {
            r = dst_end - dst - len;
            if (r > LSHPACK_ERR_MORE_BUF)
                r = LSHPACK_ERR_MORE_BUF;
            return r;
        }
        else
            /* This must be an invalid code, otherwise it would have fit */
            return -1;
    }

    if (avail_bits > 0)
    {
        if (((1u << avail_bits) - 1) != (buf & ((1u << avail_bits) - 1)))
            return -1;  /* Not EOF as expected */
    }
#if __GNUC__
#pragma GCC diagnostic pop
#endif

  end:
    return dst - orig_dst;

  slow_path:
    /* Find previous byte boundary and finish decoding thence. */
    while ((avail_bits & 7) && dst > orig_dst)
        avail_bits += encode_table[ *--dst ].bits;
    assert((avail_bits & 7) == 0);
    src -= avail_bits >> 3;
    r = lshpack_dec_huff_decode_full(src, src_end - src, dst, dst_end - dst);
    if (r >= 0)
        return dst - orig_dst + r;
    else
        return r;
}
#endif
#if __GNUC__
#pragma GCC diagnostic pop  /* -Wunknown-pragmas */
#endif
