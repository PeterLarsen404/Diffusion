
// We need to define _GNU_SOURCE before
// _any_ headers files are imported to get
// the usage statistics of a thread (i.e. have RUSAGE_THREAD) on GNU/Linux
// https://manpages.courier-mta.org/htmlman2/getrusage.2.html
#ifndef _GNU_SOURCE // Avoid possible double-definition warning.
#define _GNU_SOURCE
#endif

#ifdef __clang__
#pragma clang diagnostic ignored "-Wunused-function"
#pragma clang diagnostic ignored "-Wunused-variable"
#pragma clang diagnostic ignored "-Wparentheses"
#pragma clang diagnostic ignored "-Wunused-label"
#elif __GNUC__
#pragma GCC diagnostic ignored "-Wunused-function"
#pragma GCC diagnostic ignored "-Wunused-variable"
#pragma GCC diagnostic ignored "-Wparentheses"
#pragma GCC diagnostic ignored "-Wunused-label"
#pragma GCC diagnostic ignored "-Wunused-but-set-variable"
#endif

// Headers
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>
#include <float.h>

#ifdef __cplusplus
extern "C" {
#endif

// Initialisation
struct futhark_context_config;
struct futhark_context_config *futhark_context_config_new(void);
void futhark_context_config_free(struct futhark_context_config *cfg);
void futhark_context_config_set_debugging(struct futhark_context_config *cfg,
                                          int flag);
void futhark_context_config_set_profiling(struct futhark_context_config *cfg,
                                          int flag);
void futhark_context_config_set_logging(struct futhark_context_config *cfg,
                                        int flag);
struct futhark_context;
struct futhark_context *futhark_context_new(struct futhark_context_config *cfg);
void futhark_context_free(struct futhark_context *ctx);
int futhark_context_config_set_tuning_param(struct futhark_context_config *cfg,
                                            const char *param_name,
                                            size_t param_value);
int futhark_get_tuning_param_count(void);
const char *futhark_get_tuning_param_name(int);
const char *futhark_get_tuning_param_class(int);

// Arrays
struct futhark_f64_1d;
struct futhark_f64_1d *futhark_new_f64_1d(struct futhark_context *ctx, const
                                          double *data, int64_t dim0);
struct futhark_f64_1d *futhark_new_raw_f64_1d(struct futhark_context *ctx, const
                                              unsigned char *data,
                                              int64_t offset, int64_t dim0);
int futhark_free_f64_1d(struct futhark_context *ctx,
                        struct futhark_f64_1d *arr);
int futhark_values_f64_1d(struct futhark_context *ctx,
                          struct futhark_f64_1d *arr, double *data);
unsigned char *futhark_values_raw_f64_1d(struct futhark_context *ctx,
                                         struct futhark_f64_1d *arr);
const int64_t *futhark_shape_f64_1d(struct futhark_context *ctx,
                                    struct futhark_f64_1d *arr);
struct futhark_f64_3d;
struct futhark_f64_3d *futhark_new_f64_3d(struct futhark_context *ctx, const
                                          double *data, int64_t dim0,
                                          int64_t dim1, int64_t dim2);
struct futhark_f64_3d *futhark_new_raw_f64_3d(struct futhark_context *ctx, const
                                              unsigned char *data,
                                              int64_t offset, int64_t dim0,
                                              int64_t dim1, int64_t dim2);
int futhark_free_f64_3d(struct futhark_context *ctx,
                        struct futhark_f64_3d *arr);
int futhark_values_f64_3d(struct futhark_context *ctx,
                          struct futhark_f64_3d *arr, double *data);
unsigned char *futhark_values_raw_f64_3d(struct futhark_context *ctx,
                                         struct futhark_f64_3d *arr);
const int64_t *futhark_shape_f64_3d(struct futhark_context *ctx,
                                    struct futhark_f64_3d *arr);
struct futhark_f64_4d;
struct futhark_f64_4d *futhark_new_f64_4d(struct futhark_context *ctx, const
                                          double *data, int64_t dim0,
                                          int64_t dim1, int64_t dim2,
                                          int64_t dim3);
struct futhark_f64_4d *futhark_new_raw_f64_4d(struct futhark_context *ctx, const
                                              unsigned char *data,
                                              int64_t offset, int64_t dim0,
                                              int64_t dim1, int64_t dim2,
                                              int64_t dim3);
int futhark_free_f64_4d(struct futhark_context *ctx,
                        struct futhark_f64_4d *arr);
int futhark_values_f64_4d(struct futhark_context *ctx,
                          struct futhark_f64_4d *arr, double *data);
unsigned char *futhark_values_raw_f64_4d(struct futhark_context *ctx,
                                         struct futhark_f64_4d *arr);
const int64_t *futhark_shape_f64_4d(struct futhark_context *ctx,
                                    struct futhark_f64_4d *arr);

// Opaque values



// Entry points
int futhark_entry_convolve2d_b_bench(struct futhark_context *ctx,
                                     struct futhark_f64_3d **out0,
                                     struct futhark_f64_4d **out1,
                                     struct futhark_f64_1d **out2, const
                                     struct futhark_f64_3d *in0, const
                                     struct futhark_f64_3d *in1, const
                                     struct futhark_f64_4d *in2);
int futhark_entry_convolve2d_b_test(struct futhark_context *ctx,
                                    struct futhark_f64_3d **out0,
                                    struct futhark_f64_4d **out1,
                                    struct futhark_f64_1d **out2, const
                                    struct futhark_f64_3d *in0, const
                                    struct futhark_f64_3d *in1, const
                                    struct futhark_f64_4d *in2, const
                                    int64_t in3, const int64_t in4);
int futhark_entry_convolve2d_test(struct futhark_context *ctx,
                                  struct futhark_f64_3d **out0, const
                                  struct futhark_f64_3d *in0, const
                                  struct futhark_f64_4d *in1, const
                                  struct futhark_f64_1d *in2, const
                                  int64_t in3);

// Miscellaneous
int futhark_context_sync(struct futhark_context *ctx);
void futhark_context_config_set_cache_file(struct futhark_context_config *cfg,
                                           const char *f);
char *futhark_context_report(struct futhark_context *ctx);
char *futhark_context_get_error(struct futhark_context *ctx);
void futhark_context_set_logging_file(struct futhark_context *ctx, FILE *f);
void futhark_context_pause_profiling(struct futhark_context *ctx);
void futhark_context_unpause_profiling(struct futhark_context *ctx);
int futhark_context_clear_caches(struct futhark_context *ctx);
#define FUTHARK_BACKEND_c
#define FUTHARK_SUCCESS 0
#define FUTHARK_PROGRAM_ERROR 2
#define FUTHARK_OUT_OF_MEMORY 3

#ifdef __cplusplus
}
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <math.h>
#include <stdint.h>
// If NDEBUG is set, the assert() macro will do nothing. Since Futhark
// (unfortunately) makes use of assert() for error detection (and even some
// side effects), we want to avoid that.
#undef NDEBUG
#include <assert.h>
#include <stdarg.h>
// Start of util.h.
//
// Various helper functions that are useful in all generated C code.

#include <errno.h>
#include <string.h>

static const char *fut_progname = "(embedded Futhark)";

static void futhark_panic(int eval, const char *fmt, ...) __attribute__((noreturn));
static char* msgprintf(const char *s, ...);
static void* slurp_file(const char *filename, size_t *size);
static int dump_file(const char *file, const void *buf, size_t n);
struct str_builder;
static void str_builder_init(struct str_builder *b);
static void str_builder(struct str_builder *b, const char *s, ...);

static void futhark_panic(int eval, const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  fprintf(stderr, "%s: ", fut_progname);
  vfprintf(stderr, fmt, ap);
  va_end(ap);
  exit(eval);
}

// For generating arbitrary-sized error messages.  It is the callers
// responsibility to free the buffer at some point.
static char* msgprintf(const char *s, ...) {
  va_list vl;
  va_start(vl, s);
  size_t needed = 1 + (size_t)vsnprintf(NULL, 0, s, vl);
  char *buffer = (char*) malloc(needed);
  va_start(vl, s); // Must re-init.
  vsnprintf(buffer, needed, s, vl);
  return buffer;
}

static inline void check_err(int errval, int sets_errno, const char *fun, int line,
                             const char *msg, ...) {
  if (errval) {
    char errnum[10];

    va_list vl;
    va_start(vl, msg);

    fprintf(stderr, "ERROR: ");
    vfprintf(stderr, msg, vl);
    fprintf(stderr, " in %s() at line %d with error code %s\n",
            fun, line,
            sets_errno ? strerror(errno) : errnum);
    exit(errval);
  }
}

#define CHECK_ERR(err, ...) check_err(err, 0, __func__, __LINE__, __VA_ARGS__)
#define CHECK_ERRNO(err, ...) check_err(err, 1, __func__, __LINE__, __VA_ARGS__)

// Read the rest of an open file into a NUL-terminated string; returns
// NULL on error.
static void* fslurp_file(FILE *f, size_t *size) {
  long start = ftell(f);
  fseek(f, 0, SEEK_END);
  long src_size = ftell(f)-start;
  fseek(f, start, SEEK_SET);
  unsigned char *s = (unsigned char*) malloc((size_t)src_size + 1);
  if (fread(s, 1, (size_t)src_size, f) != (size_t)src_size) {
    free(s);
    s = NULL;
  } else {
    s[src_size] = '\0';
  }

  if (size) {
    *size = (size_t)src_size;
  }

  return s;
}

// Read a file into a NUL-terminated string; returns NULL on error.
static void* slurp_file(const char *filename, size_t *size) {
  FILE *f = fopen(filename, "rb"); // To avoid Windows messing with linebreaks.
  if (f == NULL) return NULL;
  unsigned char *s = fslurp_file(f, size);
  fclose(f);
  return s;
}

// Dump 'n' bytes from 'buf' into the file at the designated location.
// Returns 0 on success.
static int dump_file(const char *file, const void *buf, size_t n) {
  FILE *f = fopen(file, "w");

  if (f == NULL) {
    return 1;
  }

  if (fwrite(buf, sizeof(char), n, f) != n) {
    return 1;
  }

  if (fclose(f) != 0) {
    return 1;
  }

  return 0;
}

struct str_builder {
  char *str;
  size_t capacity; // Size of buffer.
  size_t used; // Bytes used, *not* including final zero.
};

static void str_builder_init(struct str_builder *b) {
  b->capacity = 10;
  b->used = 0;
  b->str = malloc(b->capacity);
  b->str[0] = 0;
}

static void str_builder(struct str_builder *b, const char *s, ...) {
  va_list vl;
  va_start(vl, s);
  size_t needed = (size_t)vsnprintf(NULL, 0, s, vl);

  while (b->capacity < b->used + needed + 1) {
    b->capacity *= 2;
    b->str = realloc(b->str, b->capacity);
  }

  va_start(vl, s); // Must re-init.
  vsnprintf(b->str+b->used, b->capacity-b->used, s, vl);
  b->used += needed;
}

// End of util.h.
// Start of cache.h

#define CACHE_HASH_SIZE 8 // In 32-bit words.

struct cache_hash {
  uint32_t hash[CACHE_HASH_SIZE];
};

// Initialise a blank cache.
static void cache_hash_init(struct cache_hash *c);

// Hash some bytes and add them to the accumulated hash.
static void cache_hash(struct cache_hash *out, const char *in, size_t n);

// Try to restore cache contents from a file with the given name.
// Assumes the cache is invalid if it contains the given hash.
// Allocates memory and reads the cache conents, which is returned in
// *buf with size *buflen.  If the cache is successfully loaded, this
// function returns 0.  Otherwise it returns nonzero.  Errno is set if
// the failure to load the cache is due to anything except invalid
// cache conents.  Note that failing to restore the cache is not
// necessarily a problem: it might just be invalid or not created yet.
static int cache_restore(const char *fname, const struct cache_hash *hash,
                         unsigned char **buf, size_t *buflen);

// Store cache contents in the given file, with the given hash.
static int cache_store(const char *fname, const struct cache_hash *hash,
                       const unsigned char *buf, size_t buflen);

// Now for the implementation.

static void cache_hash_init(struct cache_hash *c) {
  memset(c->hash, 0, CACHE_HASH_SIZE * sizeof(uint32_t));
}

static void cache_hash(struct cache_hash *out, const char *in, size_t n) {
  // Adaptation of djb2 for larger output size by storing intermediate
  // states.
  uint32_t hash = 5381;
  for (size_t i = 0; i < n; i++) {
    hash = ((hash << 5) + hash) + in[i];
    out->hash[i % CACHE_HASH_SIZE] ^= hash;
  }
}

#define CACHE_HEADER_SIZE 8
static const char cache_header[CACHE_HEADER_SIZE] = "FUTHARK\0";

static int cache_restore(const char *fname, const struct cache_hash *hash,
                         unsigned char **buf, size_t *buflen) {
  FILE *f = fopen(fname, "rb");

  if (f == NULL) {
    return 1;
  }

  char f_header[CACHE_HEADER_SIZE];

  if (fread(f_header, sizeof(char), CACHE_HEADER_SIZE, f) != CACHE_HEADER_SIZE) {
    goto error;
  }

  if (memcmp(f_header, cache_header, CACHE_HEADER_SIZE) != 0) {
    goto error;
  }

  if (fseek(f, 0, SEEK_END) != 0) {
    goto error;
  }
  int64_t f_size = (int64_t)ftell(f);
  if (fseek(f, CACHE_HEADER_SIZE, SEEK_SET) != 0) {
    goto error;
  }

  int64_t expected_size;

  if (fread(&expected_size, sizeof(int64_t), 1, f) != 1) {
    goto error;
  }

  if (f_size != expected_size) {
    errno = 0;
    goto error;
  }

  int32_t f_hash[CACHE_HASH_SIZE];

  if (fread(f_hash, sizeof(int32_t), CACHE_HASH_SIZE, f) != CACHE_HASH_SIZE) {
    goto error;
  }

  if (memcmp(f_hash, hash->hash, CACHE_HASH_SIZE) != 0) {
    errno = 0;
    goto error;
  }

  *buflen = f_size - CACHE_HEADER_SIZE - sizeof(int64_t) - CACHE_HASH_SIZE*sizeof(int32_t);
  *buf = malloc(*buflen);
  if (fread(*buf, sizeof(char), *buflen, f) != *buflen) {
    free(*buf);
    goto error;
  }

  fclose(f);

  return 0;

 error:
  fclose(f);
  return 1;
}

static int cache_store(const char *fname, const struct cache_hash *hash,
                       const unsigned char *buf, size_t buflen) {
  FILE *f = fopen(fname, "wb");

  if (f == NULL) {
    return 1;
  }

  if (fwrite(cache_header, CACHE_HEADER_SIZE, 1, f) != 1) {
    goto error;
  }

  int64_t size = CACHE_HEADER_SIZE + sizeof(int64_t) + CACHE_HASH_SIZE*sizeof(int32_t) + buflen;

  if (fwrite(&size, sizeof(size), 1, f) != 1) {
    goto error;
  }

  if (fwrite(hash->hash, sizeof(int32_t), CACHE_HASH_SIZE, f) != CACHE_HASH_SIZE) {
    goto error;
  }

  if (fwrite(buf, sizeof(unsigned char), buflen, f) != buflen) {
    goto error;
  }

  fclose(f);

  return 0;

 error:
  fclose(f);
  return 1;
}

// End of cache.h
// Start of half.h.

// Conversion functions are from http://half.sourceforge.net/, but
// translated to C.
//
// Copyright (c) 2012-2021 Christian Rau
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

#ifndef __OPENCL_VERSION__
#define __constant
#endif

__constant static const uint16_t base_table[512] = {
  0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
  0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
  0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
  0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
  0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
  0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
  0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0001, 0x0002, 0x0004, 0x0008, 0x0010, 0x0020, 0x0040, 0x0080, 0x0100,
  0x0200, 0x0400, 0x0800, 0x0C00, 0x1000, 0x1400, 0x1800, 0x1C00, 0x2000, 0x2400, 0x2800, 0x2C00, 0x3000, 0x3400, 0x3800, 0x3C00,
  0x4000, 0x4400, 0x4800, 0x4C00, 0x5000, 0x5400, 0x5800, 0x5C00, 0x6000, 0x6400, 0x6800, 0x6C00, 0x7000, 0x7400, 0x7800, 0x7C00,
  0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00,
  0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00,
  0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00,
  0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00,
  0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00,
  0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00,
  0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00,
  0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x8000,
  0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x8000,
  0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x8000,
  0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x8000,
  0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x8000,
  0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x8000,
  0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x8001, 0x8002, 0x8004, 0x8008, 0x8010, 0x8020, 0x8040, 0x8080, 0x8100,
  0x8200, 0x8400, 0x8800, 0x8C00, 0x9000, 0x9400, 0x9800, 0x9C00, 0xA000, 0xA400, 0xA800, 0xAC00, 0xB000, 0xB400, 0xB800, 0xBC00,
  0xC000, 0xC400, 0xC800, 0xCC00, 0xD000, 0xD400, 0xD800, 0xDC00, 0xE000, 0xE400, 0xE800, 0xEC00, 0xF000, 0xF400, 0xF800, 0xFC00,
  0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00,
  0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00,
  0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00,
  0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00,
  0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00,
  0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00,
  0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00 };

__constant static const unsigned char shift_table[512] = {
  24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24,
  24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24,
  24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24,
  24, 24, 24, 24, 24, 24, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
  13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24,
  24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24,
  24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24,
  24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 13,
  24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24,
  24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24,
  24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24,
  24, 24, 24, 24, 24, 24, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
  13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24,
  24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24,
  24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24,
  24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 13 };

__constant static const uint32_t mantissa_table[2048] = {
  0x00000000, 0x33800000, 0x34000000, 0x34400000, 0x34800000, 0x34A00000, 0x34C00000, 0x34E00000, 0x35000000, 0x35100000, 0x35200000, 0x35300000, 0x35400000, 0x35500000, 0x35600000, 0x35700000,
  0x35800000, 0x35880000, 0x35900000, 0x35980000, 0x35A00000, 0x35A80000, 0x35B00000, 0x35B80000, 0x35C00000, 0x35C80000, 0x35D00000, 0x35D80000, 0x35E00000, 0x35E80000, 0x35F00000, 0x35F80000,
  0x36000000, 0x36040000, 0x36080000, 0x360C0000, 0x36100000, 0x36140000, 0x36180000, 0x361C0000, 0x36200000, 0x36240000, 0x36280000, 0x362C0000, 0x36300000, 0x36340000, 0x36380000, 0x363C0000,
  0x36400000, 0x36440000, 0x36480000, 0x364C0000, 0x36500000, 0x36540000, 0x36580000, 0x365C0000, 0x36600000, 0x36640000, 0x36680000, 0x366C0000, 0x36700000, 0x36740000, 0x36780000, 0x367C0000,
  0x36800000, 0x36820000, 0x36840000, 0x36860000, 0x36880000, 0x368A0000, 0x368C0000, 0x368E0000, 0x36900000, 0x36920000, 0x36940000, 0x36960000, 0x36980000, 0x369A0000, 0x369C0000, 0x369E0000,
  0x36A00000, 0x36A20000, 0x36A40000, 0x36A60000, 0x36A80000, 0x36AA0000, 0x36AC0000, 0x36AE0000, 0x36B00000, 0x36B20000, 0x36B40000, 0x36B60000, 0x36B80000, 0x36BA0000, 0x36BC0000, 0x36BE0000,
  0x36C00000, 0x36C20000, 0x36C40000, 0x36C60000, 0x36C80000, 0x36CA0000, 0x36CC0000, 0x36CE0000, 0x36D00000, 0x36D20000, 0x36D40000, 0x36D60000, 0x36D80000, 0x36DA0000, 0x36DC0000, 0x36DE0000,
  0x36E00000, 0x36E20000, 0x36E40000, 0x36E60000, 0x36E80000, 0x36EA0000, 0x36EC0000, 0x36EE0000, 0x36F00000, 0x36F20000, 0x36F40000, 0x36F60000, 0x36F80000, 0x36FA0000, 0x36FC0000, 0x36FE0000,
  0x37000000, 0x37010000, 0x37020000, 0x37030000, 0x37040000, 0x37050000, 0x37060000, 0x37070000, 0x37080000, 0x37090000, 0x370A0000, 0x370B0000, 0x370C0000, 0x370D0000, 0x370E0000, 0x370F0000,
  0x37100000, 0x37110000, 0x37120000, 0x37130000, 0x37140000, 0x37150000, 0x37160000, 0x37170000, 0x37180000, 0x37190000, 0x371A0000, 0x371B0000, 0x371C0000, 0x371D0000, 0x371E0000, 0x371F0000,
  0x37200000, 0x37210000, 0x37220000, 0x37230000, 0x37240000, 0x37250000, 0x37260000, 0x37270000, 0x37280000, 0x37290000, 0x372A0000, 0x372B0000, 0x372C0000, 0x372D0000, 0x372E0000, 0x372F0000,
  0x37300000, 0x37310000, 0x37320000, 0x37330000, 0x37340000, 0x37350000, 0x37360000, 0x37370000, 0x37380000, 0x37390000, 0x373A0000, 0x373B0000, 0x373C0000, 0x373D0000, 0x373E0000, 0x373F0000,
  0x37400000, 0x37410000, 0x37420000, 0x37430000, 0x37440000, 0x37450000, 0x37460000, 0x37470000, 0x37480000, 0x37490000, 0x374A0000, 0x374B0000, 0x374C0000, 0x374D0000, 0x374E0000, 0x374F0000,
  0x37500000, 0x37510000, 0x37520000, 0x37530000, 0x37540000, 0x37550000, 0x37560000, 0x37570000, 0x37580000, 0x37590000, 0x375A0000, 0x375B0000, 0x375C0000, 0x375D0000, 0x375E0000, 0x375F0000,
  0x37600000, 0x37610000, 0x37620000, 0x37630000, 0x37640000, 0x37650000, 0x37660000, 0x37670000, 0x37680000, 0x37690000, 0x376A0000, 0x376B0000, 0x376C0000, 0x376D0000, 0x376E0000, 0x376F0000,
  0x37700000, 0x37710000, 0x37720000, 0x37730000, 0x37740000, 0x37750000, 0x37760000, 0x37770000, 0x37780000, 0x37790000, 0x377A0000, 0x377B0000, 0x377C0000, 0x377D0000, 0x377E0000, 0x377F0000,
  0x37800000, 0x37808000, 0x37810000, 0x37818000, 0x37820000, 0x37828000, 0x37830000, 0x37838000, 0x37840000, 0x37848000, 0x37850000, 0x37858000, 0x37860000, 0x37868000, 0x37870000, 0x37878000,
  0x37880000, 0x37888000, 0x37890000, 0x37898000, 0x378A0000, 0x378A8000, 0x378B0000, 0x378B8000, 0x378C0000, 0x378C8000, 0x378D0000, 0x378D8000, 0x378E0000, 0x378E8000, 0x378F0000, 0x378F8000,
  0x37900000, 0x37908000, 0x37910000, 0x37918000, 0x37920000, 0x37928000, 0x37930000, 0x37938000, 0x37940000, 0x37948000, 0x37950000, 0x37958000, 0x37960000, 0x37968000, 0x37970000, 0x37978000,
  0x37980000, 0x37988000, 0x37990000, 0x37998000, 0x379A0000, 0x379A8000, 0x379B0000, 0x379B8000, 0x379C0000, 0x379C8000, 0x379D0000, 0x379D8000, 0x379E0000, 0x379E8000, 0x379F0000, 0x379F8000,
  0x37A00000, 0x37A08000, 0x37A10000, 0x37A18000, 0x37A20000, 0x37A28000, 0x37A30000, 0x37A38000, 0x37A40000, 0x37A48000, 0x37A50000, 0x37A58000, 0x37A60000, 0x37A68000, 0x37A70000, 0x37A78000,
  0x37A80000, 0x37A88000, 0x37A90000, 0x37A98000, 0x37AA0000, 0x37AA8000, 0x37AB0000, 0x37AB8000, 0x37AC0000, 0x37AC8000, 0x37AD0000, 0x37AD8000, 0x37AE0000, 0x37AE8000, 0x37AF0000, 0x37AF8000,
  0x37B00000, 0x37B08000, 0x37B10000, 0x37B18000, 0x37B20000, 0x37B28000, 0x37B30000, 0x37B38000, 0x37B40000, 0x37B48000, 0x37B50000, 0x37B58000, 0x37B60000, 0x37B68000, 0x37B70000, 0x37B78000,
  0x37B80000, 0x37B88000, 0x37B90000, 0x37B98000, 0x37BA0000, 0x37BA8000, 0x37BB0000, 0x37BB8000, 0x37BC0000, 0x37BC8000, 0x37BD0000, 0x37BD8000, 0x37BE0000, 0x37BE8000, 0x37BF0000, 0x37BF8000,
  0x37C00000, 0x37C08000, 0x37C10000, 0x37C18000, 0x37C20000, 0x37C28000, 0x37C30000, 0x37C38000, 0x37C40000, 0x37C48000, 0x37C50000, 0x37C58000, 0x37C60000, 0x37C68000, 0x37C70000, 0x37C78000,
  0x37C80000, 0x37C88000, 0x37C90000, 0x37C98000, 0x37CA0000, 0x37CA8000, 0x37CB0000, 0x37CB8000, 0x37CC0000, 0x37CC8000, 0x37CD0000, 0x37CD8000, 0x37CE0000, 0x37CE8000, 0x37CF0000, 0x37CF8000,
  0x37D00000, 0x37D08000, 0x37D10000, 0x37D18000, 0x37D20000, 0x37D28000, 0x37D30000, 0x37D38000, 0x37D40000, 0x37D48000, 0x37D50000, 0x37D58000, 0x37D60000, 0x37D68000, 0x37D70000, 0x37D78000,
  0x37D80000, 0x37D88000, 0x37D90000, 0x37D98000, 0x37DA0000, 0x37DA8000, 0x37DB0000, 0x37DB8000, 0x37DC0000, 0x37DC8000, 0x37DD0000, 0x37DD8000, 0x37DE0000, 0x37DE8000, 0x37DF0000, 0x37DF8000,
  0x37E00000, 0x37E08000, 0x37E10000, 0x37E18000, 0x37E20000, 0x37E28000, 0x37E30000, 0x37E38000, 0x37E40000, 0x37E48000, 0x37E50000, 0x37E58000, 0x37E60000, 0x37E68000, 0x37E70000, 0x37E78000,
  0x37E80000, 0x37E88000, 0x37E90000, 0x37E98000, 0x37EA0000, 0x37EA8000, 0x37EB0000, 0x37EB8000, 0x37EC0000, 0x37EC8000, 0x37ED0000, 0x37ED8000, 0x37EE0000, 0x37EE8000, 0x37EF0000, 0x37EF8000,
  0x37F00000, 0x37F08000, 0x37F10000, 0x37F18000, 0x37F20000, 0x37F28000, 0x37F30000, 0x37F38000, 0x37F40000, 0x37F48000, 0x37F50000, 0x37F58000, 0x37F60000, 0x37F68000, 0x37F70000, 0x37F78000,
  0x37F80000, 0x37F88000, 0x37F90000, 0x37F98000, 0x37FA0000, 0x37FA8000, 0x37FB0000, 0x37FB8000, 0x37FC0000, 0x37FC8000, 0x37FD0000, 0x37FD8000, 0x37FE0000, 0x37FE8000, 0x37FF0000, 0x37FF8000,
  0x38000000, 0x38004000, 0x38008000, 0x3800C000, 0x38010000, 0x38014000, 0x38018000, 0x3801C000, 0x38020000, 0x38024000, 0x38028000, 0x3802C000, 0x38030000, 0x38034000, 0x38038000, 0x3803C000,
  0x38040000, 0x38044000, 0x38048000, 0x3804C000, 0x38050000, 0x38054000, 0x38058000, 0x3805C000, 0x38060000, 0x38064000, 0x38068000, 0x3806C000, 0x38070000, 0x38074000, 0x38078000, 0x3807C000,
  0x38080000, 0x38084000, 0x38088000, 0x3808C000, 0x38090000, 0x38094000, 0x38098000, 0x3809C000, 0x380A0000, 0x380A4000, 0x380A8000, 0x380AC000, 0x380B0000, 0x380B4000, 0x380B8000, 0x380BC000,
  0x380C0000, 0x380C4000, 0x380C8000, 0x380CC000, 0x380D0000, 0x380D4000, 0x380D8000, 0x380DC000, 0x380E0000, 0x380E4000, 0x380E8000, 0x380EC000, 0x380F0000, 0x380F4000, 0x380F8000, 0x380FC000,
  0x38100000, 0x38104000, 0x38108000, 0x3810C000, 0x38110000, 0x38114000, 0x38118000, 0x3811C000, 0x38120000, 0x38124000, 0x38128000, 0x3812C000, 0x38130000, 0x38134000, 0x38138000, 0x3813C000,
  0x38140000, 0x38144000, 0x38148000, 0x3814C000, 0x38150000, 0x38154000, 0x38158000, 0x3815C000, 0x38160000, 0x38164000, 0x38168000, 0x3816C000, 0x38170000, 0x38174000, 0x38178000, 0x3817C000,
  0x38180000, 0x38184000, 0x38188000, 0x3818C000, 0x38190000, 0x38194000, 0x38198000, 0x3819C000, 0x381A0000, 0x381A4000, 0x381A8000, 0x381AC000, 0x381B0000, 0x381B4000, 0x381B8000, 0x381BC000,
  0x381C0000, 0x381C4000, 0x381C8000, 0x381CC000, 0x381D0000, 0x381D4000, 0x381D8000, 0x381DC000, 0x381E0000, 0x381E4000, 0x381E8000, 0x381EC000, 0x381F0000, 0x381F4000, 0x381F8000, 0x381FC000,
  0x38200000, 0x38204000, 0x38208000, 0x3820C000, 0x38210000, 0x38214000, 0x38218000, 0x3821C000, 0x38220000, 0x38224000, 0x38228000, 0x3822C000, 0x38230000, 0x38234000, 0x38238000, 0x3823C000,
  0x38240000, 0x38244000, 0x38248000, 0x3824C000, 0x38250000, 0x38254000, 0x38258000, 0x3825C000, 0x38260000, 0x38264000, 0x38268000, 0x3826C000, 0x38270000, 0x38274000, 0x38278000, 0x3827C000,
  0x38280000, 0x38284000, 0x38288000, 0x3828C000, 0x38290000, 0x38294000, 0x38298000, 0x3829C000, 0x382A0000, 0x382A4000, 0x382A8000, 0x382AC000, 0x382B0000, 0x382B4000, 0x382B8000, 0x382BC000,
  0x382C0000, 0x382C4000, 0x382C8000, 0x382CC000, 0x382D0000, 0x382D4000, 0x382D8000, 0x382DC000, 0x382E0000, 0x382E4000, 0x382E8000, 0x382EC000, 0x382F0000, 0x382F4000, 0x382F8000, 0x382FC000,
  0x38300000, 0x38304000, 0x38308000, 0x3830C000, 0x38310000, 0x38314000, 0x38318000, 0x3831C000, 0x38320000, 0x38324000, 0x38328000, 0x3832C000, 0x38330000, 0x38334000, 0x38338000, 0x3833C000,
  0x38340000, 0x38344000, 0x38348000, 0x3834C000, 0x38350000, 0x38354000, 0x38358000, 0x3835C000, 0x38360000, 0x38364000, 0x38368000, 0x3836C000, 0x38370000, 0x38374000, 0x38378000, 0x3837C000,
  0x38380000, 0x38384000, 0x38388000, 0x3838C000, 0x38390000, 0x38394000, 0x38398000, 0x3839C000, 0x383A0000, 0x383A4000, 0x383A8000, 0x383AC000, 0x383B0000, 0x383B4000, 0x383B8000, 0x383BC000,
  0x383C0000, 0x383C4000, 0x383C8000, 0x383CC000, 0x383D0000, 0x383D4000, 0x383D8000, 0x383DC000, 0x383E0000, 0x383E4000, 0x383E8000, 0x383EC000, 0x383F0000, 0x383F4000, 0x383F8000, 0x383FC000,
  0x38400000, 0x38404000, 0x38408000, 0x3840C000, 0x38410000, 0x38414000, 0x38418000, 0x3841C000, 0x38420000, 0x38424000, 0x38428000, 0x3842C000, 0x38430000, 0x38434000, 0x38438000, 0x3843C000,
  0x38440000, 0x38444000, 0x38448000, 0x3844C000, 0x38450000, 0x38454000, 0x38458000, 0x3845C000, 0x38460000, 0x38464000, 0x38468000, 0x3846C000, 0x38470000, 0x38474000, 0x38478000, 0x3847C000,
  0x38480000, 0x38484000, 0x38488000, 0x3848C000, 0x38490000, 0x38494000, 0x38498000, 0x3849C000, 0x384A0000, 0x384A4000, 0x384A8000, 0x384AC000, 0x384B0000, 0x384B4000, 0x384B8000, 0x384BC000,
  0x384C0000, 0x384C4000, 0x384C8000, 0x384CC000, 0x384D0000, 0x384D4000, 0x384D8000, 0x384DC000, 0x384E0000, 0x384E4000, 0x384E8000, 0x384EC000, 0x384F0000, 0x384F4000, 0x384F8000, 0x384FC000,
  0x38500000, 0x38504000, 0x38508000, 0x3850C000, 0x38510000, 0x38514000, 0x38518000, 0x3851C000, 0x38520000, 0x38524000, 0x38528000, 0x3852C000, 0x38530000, 0x38534000, 0x38538000, 0x3853C000,
  0x38540000, 0x38544000, 0x38548000, 0x3854C000, 0x38550000, 0x38554000, 0x38558000, 0x3855C000, 0x38560000, 0x38564000, 0x38568000, 0x3856C000, 0x38570000, 0x38574000, 0x38578000, 0x3857C000,
  0x38580000, 0x38584000, 0x38588000, 0x3858C000, 0x38590000, 0x38594000, 0x38598000, 0x3859C000, 0x385A0000, 0x385A4000, 0x385A8000, 0x385AC000, 0x385B0000, 0x385B4000, 0x385B8000, 0x385BC000,
  0x385C0000, 0x385C4000, 0x385C8000, 0x385CC000, 0x385D0000, 0x385D4000, 0x385D8000, 0x385DC000, 0x385E0000, 0x385E4000, 0x385E8000, 0x385EC000, 0x385F0000, 0x385F4000, 0x385F8000, 0x385FC000,
  0x38600000, 0x38604000, 0x38608000, 0x3860C000, 0x38610000, 0x38614000, 0x38618000, 0x3861C000, 0x38620000, 0x38624000, 0x38628000, 0x3862C000, 0x38630000, 0x38634000, 0x38638000, 0x3863C000,
  0x38640000, 0x38644000, 0x38648000, 0x3864C000, 0x38650000, 0x38654000, 0x38658000, 0x3865C000, 0x38660000, 0x38664000, 0x38668000, 0x3866C000, 0x38670000, 0x38674000, 0x38678000, 0x3867C000,
  0x38680000, 0x38684000, 0x38688000, 0x3868C000, 0x38690000, 0x38694000, 0x38698000, 0x3869C000, 0x386A0000, 0x386A4000, 0x386A8000, 0x386AC000, 0x386B0000, 0x386B4000, 0x386B8000, 0x386BC000,
  0x386C0000, 0x386C4000, 0x386C8000, 0x386CC000, 0x386D0000, 0x386D4000, 0x386D8000, 0x386DC000, 0x386E0000, 0x386E4000, 0x386E8000, 0x386EC000, 0x386F0000, 0x386F4000, 0x386F8000, 0x386FC000,
  0x38700000, 0x38704000, 0x38708000, 0x3870C000, 0x38710000, 0x38714000, 0x38718000, 0x3871C000, 0x38720000, 0x38724000, 0x38728000, 0x3872C000, 0x38730000, 0x38734000, 0x38738000, 0x3873C000,
  0x38740000, 0x38744000, 0x38748000, 0x3874C000, 0x38750000, 0x38754000, 0x38758000, 0x3875C000, 0x38760000, 0x38764000, 0x38768000, 0x3876C000, 0x38770000, 0x38774000, 0x38778000, 0x3877C000,
  0x38780000, 0x38784000, 0x38788000, 0x3878C000, 0x38790000, 0x38794000, 0x38798000, 0x3879C000, 0x387A0000, 0x387A4000, 0x387A8000, 0x387AC000, 0x387B0000, 0x387B4000, 0x387B8000, 0x387BC000,
  0x387C0000, 0x387C4000, 0x387C8000, 0x387CC000, 0x387D0000, 0x387D4000, 0x387D8000, 0x387DC000, 0x387E0000, 0x387E4000, 0x387E8000, 0x387EC000, 0x387F0000, 0x387F4000, 0x387F8000, 0x387FC000,
  0x38000000, 0x38002000, 0x38004000, 0x38006000, 0x38008000, 0x3800A000, 0x3800C000, 0x3800E000, 0x38010000, 0x38012000, 0x38014000, 0x38016000, 0x38018000, 0x3801A000, 0x3801C000, 0x3801E000,
  0x38020000, 0x38022000, 0x38024000, 0x38026000, 0x38028000, 0x3802A000, 0x3802C000, 0x3802E000, 0x38030000, 0x38032000, 0x38034000, 0x38036000, 0x38038000, 0x3803A000, 0x3803C000, 0x3803E000,
  0x38040000, 0x38042000, 0x38044000, 0x38046000, 0x38048000, 0x3804A000, 0x3804C000, 0x3804E000, 0x38050000, 0x38052000, 0x38054000, 0x38056000, 0x38058000, 0x3805A000, 0x3805C000, 0x3805E000,
  0x38060000, 0x38062000, 0x38064000, 0x38066000, 0x38068000, 0x3806A000, 0x3806C000, 0x3806E000, 0x38070000, 0x38072000, 0x38074000, 0x38076000, 0x38078000, 0x3807A000, 0x3807C000, 0x3807E000,
  0x38080000, 0x38082000, 0x38084000, 0x38086000, 0x38088000, 0x3808A000, 0x3808C000, 0x3808E000, 0x38090000, 0x38092000, 0x38094000, 0x38096000, 0x38098000, 0x3809A000, 0x3809C000, 0x3809E000,
  0x380A0000, 0x380A2000, 0x380A4000, 0x380A6000, 0x380A8000, 0x380AA000, 0x380AC000, 0x380AE000, 0x380B0000, 0x380B2000, 0x380B4000, 0x380B6000, 0x380B8000, 0x380BA000, 0x380BC000, 0x380BE000,
  0x380C0000, 0x380C2000, 0x380C4000, 0x380C6000, 0x380C8000, 0x380CA000, 0x380CC000, 0x380CE000, 0x380D0000, 0x380D2000, 0x380D4000, 0x380D6000, 0x380D8000, 0x380DA000, 0x380DC000, 0x380DE000,
  0x380E0000, 0x380E2000, 0x380E4000, 0x380E6000, 0x380E8000, 0x380EA000, 0x380EC000, 0x380EE000, 0x380F0000, 0x380F2000, 0x380F4000, 0x380F6000, 0x380F8000, 0x380FA000, 0x380FC000, 0x380FE000,
  0x38100000, 0x38102000, 0x38104000, 0x38106000, 0x38108000, 0x3810A000, 0x3810C000, 0x3810E000, 0x38110000, 0x38112000, 0x38114000, 0x38116000, 0x38118000, 0x3811A000, 0x3811C000, 0x3811E000,
  0x38120000, 0x38122000, 0x38124000, 0x38126000, 0x38128000, 0x3812A000, 0x3812C000, 0x3812E000, 0x38130000, 0x38132000, 0x38134000, 0x38136000, 0x38138000, 0x3813A000, 0x3813C000, 0x3813E000,
  0x38140000, 0x38142000, 0x38144000, 0x38146000, 0x38148000, 0x3814A000, 0x3814C000, 0x3814E000, 0x38150000, 0x38152000, 0x38154000, 0x38156000, 0x38158000, 0x3815A000, 0x3815C000, 0x3815E000,
  0x38160000, 0x38162000, 0x38164000, 0x38166000, 0x38168000, 0x3816A000, 0x3816C000, 0x3816E000, 0x38170000, 0x38172000, 0x38174000, 0x38176000, 0x38178000, 0x3817A000, 0x3817C000, 0x3817E000,
  0x38180000, 0x38182000, 0x38184000, 0x38186000, 0x38188000, 0x3818A000, 0x3818C000, 0x3818E000, 0x38190000, 0x38192000, 0x38194000, 0x38196000, 0x38198000, 0x3819A000, 0x3819C000, 0x3819E000,
  0x381A0000, 0x381A2000, 0x381A4000, 0x381A6000, 0x381A8000, 0x381AA000, 0x381AC000, 0x381AE000, 0x381B0000, 0x381B2000, 0x381B4000, 0x381B6000, 0x381B8000, 0x381BA000, 0x381BC000, 0x381BE000,
  0x381C0000, 0x381C2000, 0x381C4000, 0x381C6000, 0x381C8000, 0x381CA000, 0x381CC000, 0x381CE000, 0x381D0000, 0x381D2000, 0x381D4000, 0x381D6000, 0x381D8000, 0x381DA000, 0x381DC000, 0x381DE000,
  0x381E0000, 0x381E2000, 0x381E4000, 0x381E6000, 0x381E8000, 0x381EA000, 0x381EC000, 0x381EE000, 0x381F0000, 0x381F2000, 0x381F4000, 0x381F6000, 0x381F8000, 0x381FA000, 0x381FC000, 0x381FE000,
  0x38200000, 0x38202000, 0x38204000, 0x38206000, 0x38208000, 0x3820A000, 0x3820C000, 0x3820E000, 0x38210000, 0x38212000, 0x38214000, 0x38216000, 0x38218000, 0x3821A000, 0x3821C000, 0x3821E000,
  0x38220000, 0x38222000, 0x38224000, 0x38226000, 0x38228000, 0x3822A000, 0x3822C000, 0x3822E000, 0x38230000, 0x38232000, 0x38234000, 0x38236000, 0x38238000, 0x3823A000, 0x3823C000, 0x3823E000,
  0x38240000, 0x38242000, 0x38244000, 0x38246000, 0x38248000, 0x3824A000, 0x3824C000, 0x3824E000, 0x38250000, 0x38252000, 0x38254000, 0x38256000, 0x38258000, 0x3825A000, 0x3825C000, 0x3825E000,
  0x38260000, 0x38262000, 0x38264000, 0x38266000, 0x38268000, 0x3826A000, 0x3826C000, 0x3826E000, 0x38270000, 0x38272000, 0x38274000, 0x38276000, 0x38278000, 0x3827A000, 0x3827C000, 0x3827E000,
  0x38280000, 0x38282000, 0x38284000, 0x38286000, 0x38288000, 0x3828A000, 0x3828C000, 0x3828E000, 0x38290000, 0x38292000, 0x38294000, 0x38296000, 0x38298000, 0x3829A000, 0x3829C000, 0x3829E000,
  0x382A0000, 0x382A2000, 0x382A4000, 0x382A6000, 0x382A8000, 0x382AA000, 0x382AC000, 0x382AE000, 0x382B0000, 0x382B2000, 0x382B4000, 0x382B6000, 0x382B8000, 0x382BA000, 0x382BC000, 0x382BE000,
  0x382C0000, 0x382C2000, 0x382C4000, 0x382C6000, 0x382C8000, 0x382CA000, 0x382CC000, 0x382CE000, 0x382D0000, 0x382D2000, 0x382D4000, 0x382D6000, 0x382D8000, 0x382DA000, 0x382DC000, 0x382DE000,
  0x382E0000, 0x382E2000, 0x382E4000, 0x382E6000, 0x382E8000, 0x382EA000, 0x382EC000, 0x382EE000, 0x382F0000, 0x382F2000, 0x382F4000, 0x382F6000, 0x382F8000, 0x382FA000, 0x382FC000, 0x382FE000,
  0x38300000, 0x38302000, 0x38304000, 0x38306000, 0x38308000, 0x3830A000, 0x3830C000, 0x3830E000, 0x38310000, 0x38312000, 0x38314000, 0x38316000, 0x38318000, 0x3831A000, 0x3831C000, 0x3831E000,
  0x38320000, 0x38322000, 0x38324000, 0x38326000, 0x38328000, 0x3832A000, 0x3832C000, 0x3832E000, 0x38330000, 0x38332000, 0x38334000, 0x38336000, 0x38338000, 0x3833A000, 0x3833C000, 0x3833E000,
  0x38340000, 0x38342000, 0x38344000, 0x38346000, 0x38348000, 0x3834A000, 0x3834C000, 0x3834E000, 0x38350000, 0x38352000, 0x38354000, 0x38356000, 0x38358000, 0x3835A000, 0x3835C000, 0x3835E000,
  0x38360000, 0x38362000, 0x38364000, 0x38366000, 0x38368000, 0x3836A000, 0x3836C000, 0x3836E000, 0x38370000, 0x38372000, 0x38374000, 0x38376000, 0x38378000, 0x3837A000, 0x3837C000, 0x3837E000,
  0x38380000, 0x38382000, 0x38384000, 0x38386000, 0x38388000, 0x3838A000, 0x3838C000, 0x3838E000, 0x38390000, 0x38392000, 0x38394000, 0x38396000, 0x38398000, 0x3839A000, 0x3839C000, 0x3839E000,
  0x383A0000, 0x383A2000, 0x383A4000, 0x383A6000, 0x383A8000, 0x383AA000, 0x383AC000, 0x383AE000, 0x383B0000, 0x383B2000, 0x383B4000, 0x383B6000, 0x383B8000, 0x383BA000, 0x383BC000, 0x383BE000,
  0x383C0000, 0x383C2000, 0x383C4000, 0x383C6000, 0x383C8000, 0x383CA000, 0x383CC000, 0x383CE000, 0x383D0000, 0x383D2000, 0x383D4000, 0x383D6000, 0x383D8000, 0x383DA000, 0x383DC000, 0x383DE000,
  0x383E0000, 0x383E2000, 0x383E4000, 0x383E6000, 0x383E8000, 0x383EA000, 0x383EC000, 0x383EE000, 0x383F0000, 0x383F2000, 0x383F4000, 0x383F6000, 0x383F8000, 0x383FA000, 0x383FC000, 0x383FE000,
  0x38400000, 0x38402000, 0x38404000, 0x38406000, 0x38408000, 0x3840A000, 0x3840C000, 0x3840E000, 0x38410000, 0x38412000, 0x38414000, 0x38416000, 0x38418000, 0x3841A000, 0x3841C000, 0x3841E000,
  0x38420000, 0x38422000, 0x38424000, 0x38426000, 0x38428000, 0x3842A000, 0x3842C000, 0x3842E000, 0x38430000, 0x38432000, 0x38434000, 0x38436000, 0x38438000, 0x3843A000, 0x3843C000, 0x3843E000,
  0x38440000, 0x38442000, 0x38444000, 0x38446000, 0x38448000, 0x3844A000, 0x3844C000, 0x3844E000, 0x38450000, 0x38452000, 0x38454000, 0x38456000, 0x38458000, 0x3845A000, 0x3845C000, 0x3845E000,
  0x38460000, 0x38462000, 0x38464000, 0x38466000, 0x38468000, 0x3846A000, 0x3846C000, 0x3846E000, 0x38470000, 0x38472000, 0x38474000, 0x38476000, 0x38478000, 0x3847A000, 0x3847C000, 0x3847E000,
  0x38480000, 0x38482000, 0x38484000, 0x38486000, 0x38488000, 0x3848A000, 0x3848C000, 0x3848E000, 0x38490000, 0x38492000, 0x38494000, 0x38496000, 0x38498000, 0x3849A000, 0x3849C000, 0x3849E000,
  0x384A0000, 0x384A2000, 0x384A4000, 0x384A6000, 0x384A8000, 0x384AA000, 0x384AC000, 0x384AE000, 0x384B0000, 0x384B2000, 0x384B4000, 0x384B6000, 0x384B8000, 0x384BA000, 0x384BC000, 0x384BE000,
  0x384C0000, 0x384C2000, 0x384C4000, 0x384C6000, 0x384C8000, 0x384CA000, 0x384CC000, 0x384CE000, 0x384D0000, 0x384D2000, 0x384D4000, 0x384D6000, 0x384D8000, 0x384DA000, 0x384DC000, 0x384DE000,
  0x384E0000, 0x384E2000, 0x384E4000, 0x384E6000, 0x384E8000, 0x384EA000, 0x384EC000, 0x384EE000, 0x384F0000, 0x384F2000, 0x384F4000, 0x384F6000, 0x384F8000, 0x384FA000, 0x384FC000, 0x384FE000,
  0x38500000, 0x38502000, 0x38504000, 0x38506000, 0x38508000, 0x3850A000, 0x3850C000, 0x3850E000, 0x38510000, 0x38512000, 0x38514000, 0x38516000, 0x38518000, 0x3851A000, 0x3851C000, 0x3851E000,
  0x38520000, 0x38522000, 0x38524000, 0x38526000, 0x38528000, 0x3852A000, 0x3852C000, 0x3852E000, 0x38530000, 0x38532000, 0x38534000, 0x38536000, 0x38538000, 0x3853A000, 0x3853C000, 0x3853E000,
  0x38540000, 0x38542000, 0x38544000, 0x38546000, 0x38548000, 0x3854A000, 0x3854C000, 0x3854E000, 0x38550000, 0x38552000, 0x38554000, 0x38556000, 0x38558000, 0x3855A000, 0x3855C000, 0x3855E000,
  0x38560000, 0x38562000, 0x38564000, 0x38566000, 0x38568000, 0x3856A000, 0x3856C000, 0x3856E000, 0x38570000, 0x38572000, 0x38574000, 0x38576000, 0x38578000, 0x3857A000, 0x3857C000, 0x3857E000,
  0x38580000, 0x38582000, 0x38584000, 0x38586000, 0x38588000, 0x3858A000, 0x3858C000, 0x3858E000, 0x38590000, 0x38592000, 0x38594000, 0x38596000, 0x38598000, 0x3859A000, 0x3859C000, 0x3859E000,
  0x385A0000, 0x385A2000, 0x385A4000, 0x385A6000, 0x385A8000, 0x385AA000, 0x385AC000, 0x385AE000, 0x385B0000, 0x385B2000, 0x385B4000, 0x385B6000, 0x385B8000, 0x385BA000, 0x385BC000, 0x385BE000,
  0x385C0000, 0x385C2000, 0x385C4000, 0x385C6000, 0x385C8000, 0x385CA000, 0x385CC000, 0x385CE000, 0x385D0000, 0x385D2000, 0x385D4000, 0x385D6000, 0x385D8000, 0x385DA000, 0x385DC000, 0x385DE000,
  0x385E0000, 0x385E2000, 0x385E4000, 0x385E6000, 0x385E8000, 0x385EA000, 0x385EC000, 0x385EE000, 0x385F0000, 0x385F2000, 0x385F4000, 0x385F6000, 0x385F8000, 0x385FA000, 0x385FC000, 0x385FE000,
  0x38600000, 0x38602000, 0x38604000, 0x38606000, 0x38608000, 0x3860A000, 0x3860C000, 0x3860E000, 0x38610000, 0x38612000, 0x38614000, 0x38616000, 0x38618000, 0x3861A000, 0x3861C000, 0x3861E000,
  0x38620000, 0x38622000, 0x38624000, 0x38626000, 0x38628000, 0x3862A000, 0x3862C000, 0x3862E000, 0x38630000, 0x38632000, 0x38634000, 0x38636000, 0x38638000, 0x3863A000, 0x3863C000, 0x3863E000,
  0x38640000, 0x38642000, 0x38644000, 0x38646000, 0x38648000, 0x3864A000, 0x3864C000, 0x3864E000, 0x38650000, 0x38652000, 0x38654000, 0x38656000, 0x38658000, 0x3865A000, 0x3865C000, 0x3865E000,
  0x38660000, 0x38662000, 0x38664000, 0x38666000, 0x38668000, 0x3866A000, 0x3866C000, 0x3866E000, 0x38670000, 0x38672000, 0x38674000, 0x38676000, 0x38678000, 0x3867A000, 0x3867C000, 0x3867E000,
  0x38680000, 0x38682000, 0x38684000, 0x38686000, 0x38688000, 0x3868A000, 0x3868C000, 0x3868E000, 0x38690000, 0x38692000, 0x38694000, 0x38696000, 0x38698000, 0x3869A000, 0x3869C000, 0x3869E000,
  0x386A0000, 0x386A2000, 0x386A4000, 0x386A6000, 0x386A8000, 0x386AA000, 0x386AC000, 0x386AE000, 0x386B0000, 0x386B2000, 0x386B4000, 0x386B6000, 0x386B8000, 0x386BA000, 0x386BC000, 0x386BE000,
  0x386C0000, 0x386C2000, 0x386C4000, 0x386C6000, 0x386C8000, 0x386CA000, 0x386CC000, 0x386CE000, 0x386D0000, 0x386D2000, 0x386D4000, 0x386D6000, 0x386D8000, 0x386DA000, 0x386DC000, 0x386DE000,
  0x386E0000, 0x386E2000, 0x386E4000, 0x386E6000, 0x386E8000, 0x386EA000, 0x386EC000, 0x386EE000, 0x386F0000, 0x386F2000, 0x386F4000, 0x386F6000, 0x386F8000, 0x386FA000, 0x386FC000, 0x386FE000,
  0x38700000, 0x38702000, 0x38704000, 0x38706000, 0x38708000, 0x3870A000, 0x3870C000, 0x3870E000, 0x38710000, 0x38712000, 0x38714000, 0x38716000, 0x38718000, 0x3871A000, 0x3871C000, 0x3871E000,
  0x38720000, 0x38722000, 0x38724000, 0x38726000, 0x38728000, 0x3872A000, 0x3872C000, 0x3872E000, 0x38730000, 0x38732000, 0x38734000, 0x38736000, 0x38738000, 0x3873A000, 0x3873C000, 0x3873E000,
  0x38740000, 0x38742000, 0x38744000, 0x38746000, 0x38748000, 0x3874A000, 0x3874C000, 0x3874E000, 0x38750000, 0x38752000, 0x38754000, 0x38756000, 0x38758000, 0x3875A000, 0x3875C000, 0x3875E000,
  0x38760000, 0x38762000, 0x38764000, 0x38766000, 0x38768000, 0x3876A000, 0x3876C000, 0x3876E000, 0x38770000, 0x38772000, 0x38774000, 0x38776000, 0x38778000, 0x3877A000, 0x3877C000, 0x3877E000,
  0x38780000, 0x38782000, 0x38784000, 0x38786000, 0x38788000, 0x3878A000, 0x3878C000, 0x3878E000, 0x38790000, 0x38792000, 0x38794000, 0x38796000, 0x38798000, 0x3879A000, 0x3879C000, 0x3879E000,
  0x387A0000, 0x387A2000, 0x387A4000, 0x387A6000, 0x387A8000, 0x387AA000, 0x387AC000, 0x387AE000, 0x387B0000, 0x387B2000, 0x387B4000, 0x387B6000, 0x387B8000, 0x387BA000, 0x387BC000, 0x387BE000,
  0x387C0000, 0x387C2000, 0x387C4000, 0x387C6000, 0x387C8000, 0x387CA000, 0x387CC000, 0x387CE000, 0x387D0000, 0x387D2000, 0x387D4000, 0x387D6000, 0x387D8000, 0x387DA000, 0x387DC000, 0x387DE000,
  0x387E0000, 0x387E2000, 0x387E4000, 0x387E6000, 0x387E8000, 0x387EA000, 0x387EC000, 0x387EE000, 0x387F0000, 0x387F2000, 0x387F4000, 0x387F6000, 0x387F8000, 0x387FA000, 0x387FC000, 0x387FE000 };
__constant static const uint32_t exponent_table[64] = {
  0x00000000, 0x00800000, 0x01000000, 0x01800000, 0x02000000, 0x02800000, 0x03000000, 0x03800000, 0x04000000, 0x04800000, 0x05000000, 0x05800000, 0x06000000, 0x06800000, 0x07000000, 0x07800000,
  0x08000000, 0x08800000, 0x09000000, 0x09800000, 0x0A000000, 0x0A800000, 0x0B000000, 0x0B800000, 0x0C000000, 0x0C800000, 0x0D000000, 0x0D800000, 0x0E000000, 0x0E800000, 0x0F000000, 0x47800000,
  0x80000000, 0x80800000, 0x81000000, 0x81800000, 0x82000000, 0x82800000, 0x83000000, 0x83800000, 0x84000000, 0x84800000, 0x85000000, 0x85800000, 0x86000000, 0x86800000, 0x87000000, 0x87800000,
  0x88000000, 0x88800000, 0x89000000, 0x89800000, 0x8A000000, 0x8A800000, 0x8B000000, 0x8B800000, 0x8C000000, 0x8C800000, 0x8D000000, 0x8D800000, 0x8E000000, 0x8E800000, 0x8F000000, 0xC7800000 };
__constant static const unsigned short offset_table[64] = {
  0, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024,
  0, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024 };

static uint16_t float2halfbits(float value) {
  union { float x; uint32_t y; } u;
  u.x = value;
  uint32_t bits = u.y;

  uint16_t hbits = base_table[bits>>23] + (uint16_t)((bits&0x7FFFFF)>>shift_table[bits>>23]);;

  return hbits;
}

static float halfbits2float(uint16_t value) {
  uint32_t bits = mantissa_table[offset_table[value>>10]+(value&0x3FF)] + exponent_table[value>>10];

  union { uint32_t x; float y; } u;
  u.x = bits;
  return u.y;
}

// End of half.h.
// Start of timing.h.

// The function get_wall_time() returns the wall time in microseconds
// (with an unspecified offset).

#ifdef _WIN32

#include <windows.h>

static int64_t get_wall_time(void) {
  LARGE_INTEGER time,freq;
  assert(QueryPerformanceFrequency(&freq));
  assert(QueryPerformanceCounter(&time));
  return ((double)time.QuadPart / freq.QuadPart) * 1000000;
}

#else
// Assuming POSIX

#include <time.h>
#include <sys/time.h>

static int64_t get_wall_time(void) {
  struct timeval time;
  assert(gettimeofday(&time,NULL) == 0);
  return time.tv_sec * 1000000 + time.tv_usec;
}

static int64_t get_wall_time_ns(void) {
  struct timespec time;
  assert(clock_gettime(CLOCK_REALTIME, &time) == 0);
  return time.tv_sec * 1000000000 + time.tv_nsec;
}

#endif

// End of timing.h.
#include <getopt.h>
#include <ctype.h>
#include <inttypes.h>
static const char *entry_point = "main";
// Start of values.h.

//// Text I/O

typedef int (*writer)(FILE*, const void*);
typedef int (*bin_reader)(void*);
typedef int (*str_reader)(const char *, void*);

struct array_reader {
  char* elems;
  int64_t n_elems_space;
  int64_t elem_size;
  int64_t n_elems_used;
  int64_t *shape;
  str_reader elem_reader;
};

static void skipspaces(FILE *f) {
  int c;
  do {
    c = getc(f);
  } while (isspace(c));

  if (c != EOF) {
    ungetc(c, f);
  }
}

static int constituent(char c) {
  return isalnum(c) || c == '.' || c == '-' || c == '+' || c == '_';
}

// Produces an empty token only on EOF.
static void next_token(FILE *f, char *buf, int bufsize) {
 start:
  skipspaces(f);

  int i = 0;
  while (i < bufsize) {
    int c = getc(f);
    buf[i] = (char)c;

    if (c == EOF) {
      buf[i] = 0;
      return;
    } else if (c == '-' && i == 1 && buf[0] == '-') {
      // Line comment, so skip to end of line and start over.
      for (; c != '\n' && c != EOF; c = getc(f));
      goto start;
    } else if (!constituent((char)c)) {
      if (i == 0) {
        // We permit single-character tokens that are not
        // constituents; this lets things like ']' and ',' be
        // tokens.
        buf[i+1] = 0;
        return;
      } else {
        ungetc(c, f);
        buf[i] = 0;
        return;
      }
    }

    i++;
  }

  buf[bufsize-1] = 0;
}

static int next_token_is(FILE *f, char *buf, int bufsize, const char* expected) {
  next_token(f, buf, bufsize);
  return strcmp(buf, expected) == 0;
}

static void remove_underscores(char *buf) {
  char *w = buf;

  for (char *r = buf; *r; r++) {
    if (*r != '_') {
      *w++ = *r;
    }
  }

  *w++ = 0;
}

static int read_str_elem(char *buf, struct array_reader *reader) {
  int ret;
  if (reader->n_elems_used == reader->n_elems_space) {
    reader->n_elems_space *= 2;
    reader->elems = (char*) realloc(reader->elems,
                                    (size_t)(reader->n_elems_space * reader->elem_size));
  }

  ret = reader->elem_reader(buf, reader->elems + reader->n_elems_used * reader->elem_size);

  if (ret == 0) {
    reader->n_elems_used++;
  }

  return ret;
}

static int read_str_array_elems(FILE *f,
                                char *buf, int bufsize,
                                struct array_reader *reader, int64_t dims) {
  int ret;
  int first = 1;
  char *knows_dimsize = (char*) calloc((size_t)dims, sizeof(char));
  int cur_dim = (int)dims-1;
  int64_t *elems_read_in_dim = (int64_t*) calloc((size_t)dims, sizeof(int64_t));

  while (1) {
    next_token(f, buf, bufsize);

    if (strcmp(buf, "]") == 0) {
      if (knows_dimsize[cur_dim]) {
        if (reader->shape[cur_dim] != elems_read_in_dim[cur_dim]) {
          ret = 1;
          break;
        }
      } else {
        knows_dimsize[cur_dim] = 1;
        reader->shape[cur_dim] = elems_read_in_dim[cur_dim];
      }
      if (cur_dim == 0) {
        ret = 0;
        break;
      } else {
        cur_dim--;
        elems_read_in_dim[cur_dim]++;
      }
    } else if (strcmp(buf, ",") == 0) {
      next_token(f, buf, bufsize);
      if (strcmp(buf, "[") == 0) {
        if (cur_dim == dims - 1) {
          ret = 1;
          break;
        }
        first = 1;
        cur_dim++;
        elems_read_in_dim[cur_dim] = 0;
      } else if (cur_dim == dims - 1) {
        ret = read_str_elem(buf, reader);
        if (ret != 0) {
          break;
        }
        elems_read_in_dim[cur_dim]++;
      } else {
        ret = 1;
        break;
      }
    } else if (strlen(buf) == 0) {
      // EOF
      ret = 1;
      break;
    } else if (first) {
      if (strcmp(buf, "[") == 0) {
        if (cur_dim == dims - 1) {
          ret = 1;
          break;
        }
        cur_dim++;
        elems_read_in_dim[cur_dim] = 0;
      } else {
        ret = read_str_elem(buf, reader);
        if (ret != 0) {
          break;
        }
        elems_read_in_dim[cur_dim]++;
        first = 0;
      }
    } else {
      ret = 1;
      break;
    }
  }

  free(knows_dimsize);
  free(elems_read_in_dim);
  return ret;
}

static int read_str_empty_array(FILE *f, char *buf, int bufsize,
                                const char *type_name, int64_t *shape, int64_t dims) {
  if (strlen(buf) == 0) {
    // EOF
    return 1;
  }

  if (strcmp(buf, "empty") != 0) {
    return 1;
  }

  if (!next_token_is(f, buf, bufsize, "(")) {
    return 1;
  }

  for (int i = 0; i < dims; i++) {
    if (!next_token_is(f, buf, bufsize, "[")) {
      return 1;
    }

    next_token(f, buf, bufsize);

    if (sscanf(buf, "%"SCNu64, (uint64_t*)&shape[i]) != 1) {
      return 1;
    }

    if (!next_token_is(f, buf, bufsize, "]")) {
      return 1;
    }
  }

  if (!next_token_is(f, buf, bufsize, type_name)) {
    return 1;
  }


  if (!next_token_is(f, buf, bufsize, ")")) {
    return 1;
  }

  // Check whether the array really is empty.
  for (int i = 0; i < dims; i++) {
    if (shape[i] == 0) {
      return 0;
    }
  }

  // Not an empty array!
  return 1;
}

static int read_str_array(FILE *f,
                          int64_t elem_size, str_reader elem_reader,
                          const char *type_name,
                          void **data, int64_t *shape, int64_t dims) {
  int ret;
  struct array_reader reader;
  char buf[100];

  int dims_seen;
  for (dims_seen = 0; dims_seen < dims; dims_seen++) {
    if (!next_token_is(f, buf, sizeof(buf), "[")) {
      break;
    }
  }

  if (dims_seen == 0) {
    return read_str_empty_array(f, buf, sizeof(buf), type_name, shape, dims);
  }

  if (dims_seen != dims) {
    return 1;
  }

  reader.shape = shape;
  reader.n_elems_used = 0;
  reader.elem_size = elem_size;
  reader.n_elems_space = 16;
  reader.elems = (char*) realloc(*data, (size_t)(elem_size*reader.n_elems_space));
  reader.elem_reader = elem_reader;

  ret = read_str_array_elems(f, buf, sizeof(buf), &reader, dims);

  *data = reader.elems;

  return ret;
}

#define READ_STR(MACRO, PTR, SUFFIX)                                   \
  remove_underscores(buf);                                              \
  int j;                                                                \
  if (sscanf(buf, "%"MACRO"%n", (PTR*)dest, &j) == 1) {                 \
    return !(strcmp(buf+j, "") == 0 || strcmp(buf+j, SUFFIX) == 0);     \
  } else {                                                              \
    return 1;                                                           \
  }

static int read_str_i8(char *buf, void* dest) {
  // Some platforms (WINDOWS) does not support scanf %hhd or its
  // cousin, %SCNi8.  Read into int first to avoid corrupting
  // memory.
  //
  // https://gcc.gnu.org/bugzilla/show_bug.cgi?id=63417
  remove_underscores(buf);
  int j, x;
  if (sscanf(buf, "%i%n", &x, &j) == 1) {
    *(int8_t*)dest = (int8_t)x;
    return !(strcmp(buf+j, "") == 0 || strcmp(buf+j, "i8") == 0);
  } else {
    return 1;
  }
}

static int read_str_u8(char *buf, void* dest) {
  // Some platforms (WINDOWS) does not support scanf %hhd or its
  // cousin, %SCNu8.  Read into int first to avoid corrupting
  // memory.
  //
  // https://gcc.gnu.org/bugzilla/show_bug.cgi?id=63417
  remove_underscores(buf);
  int j, x;
  if (sscanf(buf, "%i%n", &x, &j) == 1) {
    *(uint8_t*)dest = (uint8_t)x;
    return !(strcmp(buf+j, "") == 0 || strcmp(buf+j, "u8") == 0);
  } else {
    return 1;
  }
}

static int read_str_i16(char *buf, void* dest) {
  READ_STR(SCNi16, int16_t, "i16");
}

static int read_str_u16(char *buf, void* dest) {
  READ_STR(SCNi16, int16_t, "u16");
}

static int read_str_i32(char *buf, void* dest) {
  READ_STR(SCNi32, int32_t, "i32");
}

static int read_str_u32(char *buf, void* dest) {
  READ_STR(SCNi32, int32_t, "u32");
}

static int read_str_i64(char *buf, void* dest) {
  READ_STR(SCNi64, int64_t, "i64");
}

static int read_str_u64(char *buf, void* dest) {
  // FIXME: This is not correct, as SCNu64 only permits decimal
  // literals.  However, SCNi64 does not handle very large numbers
  // correctly (it's really for signed numbers, so that's fair).
  READ_STR(SCNu64, uint64_t, "u64");
}

static int read_str_f16(char *buf, void* dest) {
  remove_underscores(buf);
  if (strcmp(buf, "f16.nan") == 0) {
    *(uint16_t*)dest = float2halfbits(NAN);
    return 0;
  } else if (strcmp(buf, "f16.inf") == 0) {
    *(uint16_t*)dest = float2halfbits(INFINITY);
    return 0;
  } else if (strcmp(buf, "-f16.inf") == 0) {
    *(uint16_t*)dest = float2halfbits(-INFINITY);
    return 0;
  } else {
    int j;
    float x;
    if (sscanf(buf, "%f%n", &x, &j) == 1) {
      if (strcmp(buf+j, "") == 0 || strcmp(buf+j, "f16") == 0) {
        *(uint16_t*)dest = float2halfbits(x);
        return 0;
      }
    }
    return 1;
  }
}

static int read_str_f32(char *buf, void* dest) {
  remove_underscores(buf);
  if (strcmp(buf, "f32.nan") == 0) {
    *(float*)dest = (float)NAN;
    return 0;
  } else if (strcmp(buf, "f32.inf") == 0) {
    *(float*)dest = (float)INFINITY;
    return 0;
  } else if (strcmp(buf, "-f32.inf") == 0) {
    *(float*)dest = (float)-INFINITY;
    return 0;
  } else {
    READ_STR("f", float, "f32");
  }
}

static int read_str_f64(char *buf, void* dest) {
  remove_underscores(buf);
  if (strcmp(buf, "f64.nan") == 0) {
    *(double*)dest = (double)NAN;
    return 0;
  } else if (strcmp(buf, "f64.inf") == 0) {
    *(double*)dest = (double)INFINITY;
    return 0;
  } else if (strcmp(buf, "-f64.inf") == 0) {
    *(double*)dest = (double)-INFINITY;
    return 0;
  } else {
    READ_STR("lf", double, "f64");
  }
}

static int read_str_bool(char *buf, void* dest) {
  if (strcmp(buf, "true") == 0) {
    *(char*)dest = 1;
    return 0;
  } else if (strcmp(buf, "false") == 0) {
    *(char*)dest = 0;
    return 0;
  } else {
    return 1;
  }
}

static int write_str_i8(FILE *out, int8_t *src) {
  return fprintf(out, "%hhdi8", *src);
}

static int write_str_u8(FILE *out, uint8_t *src) {
  return fprintf(out, "%hhuu8", *src);
}

static int write_str_i16(FILE *out, int16_t *src) {
  return fprintf(out, "%hdi16", *src);
}

static int write_str_u16(FILE *out, uint16_t *src) {
  return fprintf(out, "%huu16", *src);
}

static int write_str_i32(FILE *out, int32_t *src) {
  return fprintf(out, "%di32", *src);
}

static int write_str_u32(FILE *out, uint32_t *src) {
  return fprintf(out, "%uu32", *src);
}

static int write_str_i64(FILE *out, int64_t *src) {
  return fprintf(out, "%"PRIi64"i64", *src);
}

static int write_str_u64(FILE *out, uint64_t *src) {
  return fprintf(out, "%"PRIu64"u64", *src);
}

static int write_str_f16(FILE *out, uint16_t *src) {
  float x = halfbits2float(*src);
  if (isnan(x)) {
    return fprintf(out, "f16.nan");
  } else if (isinf(x) && x >= 0) {
    return fprintf(out, "f16.inf");
  } else if (isinf(x)) {
    return fprintf(out, "-f16.inf");
  } else {
    return fprintf(out, "%.6ff16", x);
  }
}

static int write_str_f32(FILE *out, float *src) {
  float x = *src;
  if (isnan(x)) {
    return fprintf(out, "f32.nan");
  } else if (isinf(x) && x >= 0) {
    return fprintf(out, "f32.inf");
  } else if (isinf(x)) {
    return fprintf(out, "-f32.inf");
  } else {
    return fprintf(out, "%.6ff32", x);
  }
}

static int write_str_f64(FILE *out, double *src) {
  double x = *src;
  if (isnan(x)) {
    return fprintf(out, "f64.nan");
  } else if (isinf(x) && x >= 0) {
    return fprintf(out, "f64.inf");
  } else if (isinf(x)) {
    return fprintf(out, "-f64.inf");
  } else {
    return fprintf(out, "%.6ff64", *src);
  }
}

static int write_str_bool(FILE *out, void *src) {
  return fprintf(out, *(char*)src ? "true" : "false");
}

//// Binary I/O

#define BINARY_FORMAT_VERSION 2
#define IS_BIG_ENDIAN (!*(unsigned char *)&(uint16_t){1})

static void flip_bytes(size_t elem_size, unsigned char *elem) {
  for (size_t j=0; j<elem_size/2; j++) {
    unsigned char head = elem[j];
    size_t tail_index = elem_size-1-j;
    elem[j] = elem[tail_index];
    elem[tail_index] = head;
  }
}

// On Windows we need to explicitly set the file mode to not mangle
// newline characters.  On *nix there is no difference.
#ifdef _WIN32
#include <io.h>
#include <fcntl.h>
static void set_binary_mode(FILE *f) {
  setmode(fileno(f), O_BINARY);
}
#else
static void set_binary_mode(FILE *f) {
  (void)f;
}
#endif

static int read_byte(FILE *f, void* dest) {
  size_t num_elems_read = fread(dest, 1, 1, f);
  return num_elems_read == 1 ? 0 : 1;
}

//// Types

struct primtype_info_t {
  const char binname[4]; // Used for parsing binary data.
  const char* type_name; // Same name as in Futhark.
  const int64_t size; // in bytes
  const writer write_str; // Write in text format.
  const str_reader read_str; // Read in text format.
};

static const struct primtype_info_t i8_info =
  {.binname = "  i8", .type_name = "i8",   .size = 1,
   .write_str = (writer)write_str_i8, .read_str = (str_reader)read_str_i8};
static const struct primtype_info_t i16_info =
  {.binname = " i16", .type_name = "i16",  .size = 2,
   .write_str = (writer)write_str_i16, .read_str = (str_reader)read_str_i16};
static const struct primtype_info_t i32_info =
  {.binname = " i32", .type_name = "i32",  .size = 4,
   .write_str = (writer)write_str_i32, .read_str = (str_reader)read_str_i32};
static const struct primtype_info_t i64_info =
  {.binname = " i64", .type_name = "i64",  .size = 8,
   .write_str = (writer)write_str_i64, .read_str = (str_reader)read_str_i64};
static const struct primtype_info_t u8_info =
  {.binname = "  u8", .type_name = "u8",   .size = 1,
   .write_str = (writer)write_str_u8, .read_str = (str_reader)read_str_u8};
static const struct primtype_info_t u16_info =
  {.binname = " u16", .type_name = "u16",  .size = 2,
   .write_str = (writer)write_str_u16, .read_str = (str_reader)read_str_u16};
static const struct primtype_info_t u32_info =
  {.binname = " u32", .type_name = "u32",  .size = 4,
   .write_str = (writer)write_str_u32, .read_str = (str_reader)read_str_u32};
static const struct primtype_info_t u64_info =
  {.binname = " u64", .type_name = "u64",  .size = 8,
   .write_str = (writer)write_str_u64, .read_str = (str_reader)read_str_u64};
static const struct primtype_info_t f16_info =
  {.binname = " f16", .type_name = "f16",  .size = 2,
   .write_str = (writer)write_str_f16, .read_str = (str_reader)read_str_f16};
static const struct primtype_info_t f32_info =
  {.binname = " f32", .type_name = "f32",  .size = 4,
   .write_str = (writer)write_str_f32, .read_str = (str_reader)read_str_f32};
static const struct primtype_info_t f64_info =
  {.binname = " f64", .type_name = "f64",  .size = 8,
   .write_str = (writer)write_str_f64, .read_str = (str_reader)read_str_f64};
static const struct primtype_info_t bool_info =
  {.binname = "bool", .type_name = "bool", .size = 1,
   .write_str = (writer)write_str_bool, .read_str = (str_reader)read_str_bool};

static const struct primtype_info_t* primtypes[] = {
  &i8_info, &i16_info, &i32_info, &i64_info,
  &u8_info, &u16_info, &u32_info, &u64_info,
  &f16_info, &f32_info, &f64_info,
  &bool_info,
  NULL // NULL-terminated
};

// General value interface.  All endian business taken care of at
// lower layers.

static int read_is_binary(FILE *f) {
  skipspaces(f);
  int c = getc(f);
  if (c == 'b') {
    int8_t bin_version;
    int ret = read_byte(f, &bin_version);

    if (ret != 0) { futhark_panic(1, "binary-input: could not read version.\n"); }

    if (bin_version != BINARY_FORMAT_VERSION) {
      futhark_panic(1, "binary-input: File uses version %i, but I only understand version %i.\n",
            bin_version, BINARY_FORMAT_VERSION);
    }

    return 1;
  }
  ungetc(c, f);
  return 0;
}

static const struct primtype_info_t* read_bin_read_type_enum(FILE *f) {
  char read_binname[4];

  int num_matched = fscanf(f, "%4c", read_binname);
  if (num_matched != 1) { futhark_panic(1, "binary-input: Couldn't read element type.\n"); }

  const struct primtype_info_t **type = primtypes;

  for (; *type != NULL; type++) {
    // I compare the 4 characters manually instead of using strncmp because
    // this allows any value to be used, also NULL bytes
    if (memcmp(read_binname, (*type)->binname, 4) == 0) {
      return *type;
    }
  }
  futhark_panic(1, "binary-input: Did not recognize the type '%s'.\n", read_binname);
  return NULL;
}

static void read_bin_ensure_scalar(FILE *f, const struct primtype_info_t *expected_type) {
  int8_t bin_dims;
  int ret = read_byte(f, &bin_dims);
  if (ret != 0) { futhark_panic(1, "binary-input: Couldn't get dims.\n"); }

  if (bin_dims != 0) {
    futhark_panic(1, "binary-input: Expected scalar (0 dimensions), but got array with %i dimensions.\n",
          bin_dims);
  }

  const struct primtype_info_t *bin_type = read_bin_read_type_enum(f);
  if (bin_type != expected_type) {
    futhark_panic(1, "binary-input: Expected scalar of type %s but got scalar of type %s.\n",
          expected_type->type_name,
          bin_type->type_name);
  }
}

//// High-level interface

static int read_bin_array(FILE *f,
                          const struct primtype_info_t *expected_type, void **data, int64_t *shape, int64_t dims) {
  int ret;

  int8_t bin_dims;
  ret = read_byte(f, &bin_dims);
  if (ret != 0) { futhark_panic(1, "binary-input: Couldn't get dims.\n"); }

  if (bin_dims != dims) {
    futhark_panic(1, "binary-input: Expected %i dimensions, but got array with %i dimensions.\n",
          dims, bin_dims);
  }

  const struct primtype_info_t *bin_primtype = read_bin_read_type_enum(f);
  if (expected_type != bin_primtype) {
    futhark_panic(1, "binary-input: Expected %iD-array with element type '%s' but got %iD-array with element type '%s'.\n",
          dims, expected_type->type_name, dims, bin_primtype->type_name);
  }

  int64_t elem_count = 1;
  for (int i=0; i<dims; i++) {
    int64_t bin_shape;
    ret = (int)fread(&bin_shape, sizeof(bin_shape), 1, f);
    if (ret != 1) {
      futhark_panic(1, "binary-input: Couldn't read size for dimension %i of array.\n", i);
    }
    if (IS_BIG_ENDIAN) {
      flip_bytes(sizeof(bin_shape), (unsigned char*) &bin_shape);
    }
    elem_count *= bin_shape;
    shape[i] = bin_shape;
  }

  int64_t elem_size = expected_type->size;
  void* tmp = realloc(*data, (size_t)(elem_count * elem_size));
  if (tmp == NULL) {
    futhark_panic(1, "binary-input: Failed to allocate array of size %i.\n",
          elem_count * elem_size);
  }
  *data = tmp;

  int64_t num_elems_read = (int64_t)fread(*data, (size_t)elem_size, (size_t)elem_count, f);
  if (num_elems_read != elem_count) {
    futhark_panic(1, "binary-input: tried to read %i elements of an array, but only got %i elements.\n",
          elem_count, num_elems_read);
  }

  // If we're on big endian platform we must change all multibyte elements
  // from using little endian to big endian
  if (IS_BIG_ENDIAN && elem_size != 1) {
    flip_bytes((size_t)elem_size, (unsigned char*) *data);
  }

  return 0;
}

static int read_array(FILE *f, const struct primtype_info_t *expected_type, void **data, int64_t *shape, int64_t dims) {
  if (!read_is_binary(f)) {
    return read_str_array(f, expected_type->size, (str_reader)expected_type->read_str, expected_type->type_name, data, shape, dims);
  } else {
    return read_bin_array(f, expected_type, data, shape, dims);
  }
}

static int end_of_input(FILE *f) {
  skipspaces(f);
  char token[2];
  next_token(f, token, sizeof(token));
  if (strcmp(token, "") == 0) {
    return 0;
  } else {
    return 1;
  }
}

static int write_str_array(FILE *out,
                           const struct primtype_info_t *elem_type,
                           const unsigned char *data,
                           const int64_t *shape,
                           int8_t rank) {
  if (rank==0) {
    elem_type->write_str(out, (const void*)data);
  } else {
    int64_t len = (int64_t)shape[0];
    int64_t slice_size = 1;

    int64_t elem_size = elem_type->size;
    for (int8_t i = 1; i < rank; i++) {
      slice_size *= shape[i];
    }

    if (len*slice_size == 0) {
      fprintf(out, "empty(");
      for (int64_t i = 0; i < rank; i++) {
        fprintf(out, "[%"PRIi64"]", shape[i]);
      }
      fprintf(out, "%s", elem_type->type_name);
      fprintf(out, ")");
    } else if (rank==1) {
      fputc('[', out);
      for (int64_t i = 0; i < len; i++) {
        elem_type->write_str(out, (const void*) (data + i * elem_size));
        if (i != len-1) {
          fprintf(out, ", ");
        }
      }
      fputc(']', out);
    } else {
      fputc('[', out);
      for (int64_t i = 0; i < len; i++) {
        write_str_array(out, elem_type, data + i * slice_size * elem_size, shape+1, rank-1);
        if (i != len-1) {
          fprintf(out, ", ");
        }
      }
      fputc(']', out);
    }
  }
  return 0;
}

static int write_bin_array(FILE *out,
                           const struct primtype_info_t *elem_type,
                           const unsigned char *data,
                           const int64_t *shape,
                           int8_t rank) {
  int64_t num_elems = 1;
  for (int64_t i = 0; i < rank; i++) {
    num_elems *= shape[i];
  }

  fputc('b', out);
  fputc((char)BINARY_FORMAT_VERSION, out);
  fwrite(&rank, sizeof(int8_t), 1, out);
  fwrite(elem_type->binname, 4, 1, out);
  if (shape != NULL) {
    fwrite(shape, sizeof(int64_t), (size_t)rank, out);
  }

  if (IS_BIG_ENDIAN) {
    for (int64_t i = 0; i < num_elems; i++) {
      const unsigned char *elem = data+i*elem_type->size;
      for (int64_t j = 0; j < elem_type->size; j++) {
        fwrite(&elem[elem_type->size-j], 1, 1, out);
      }
    }
  } else {
    fwrite(data, (size_t)elem_type->size, (size_t)num_elems, out);
  }

  return 0;
}

static int write_array(FILE *out, int write_binary,
                       const struct primtype_info_t *elem_type,
                       const void *data,
                       const int64_t *shape,
                       const int8_t rank) {
  if (write_binary) {
    return write_bin_array(out, elem_type, data, shape, rank);
  } else {
    return write_str_array(out, elem_type, data, shape, rank);
  }
}

static int read_scalar(FILE *f,
                       const struct primtype_info_t *expected_type, void *dest) {
  if (!read_is_binary(f)) {
    char buf[100];
    next_token(f, buf, sizeof(buf));
    return expected_type->read_str(buf, dest);
  } else {
    read_bin_ensure_scalar(f, expected_type);
    size_t elem_size = (size_t)expected_type->size;
    size_t num_elems_read = fread(dest, elem_size, 1, f);
    if (IS_BIG_ENDIAN) {
      flip_bytes(elem_size, (unsigned char*) dest);
    }
    return num_elems_read == 1 ? 0 : 1;
  }
}

static int write_scalar(FILE *out, int write_binary, const struct primtype_info_t *type, void *src) {
  if (write_binary) {
    return write_bin_array(out, type, src, NULL, 0);
  } else {
    return type->write_str(out, src);
  }
}

// End of values.h.

// Start of server.h.

// Forward declarations of things that we technically don't know until
// the application header file is included, but which we need.
struct futhark_context_config;
struct futhark_context;
char *futhark_context_get_error(struct futhark_context *ctx);
int futhark_context_sync(struct futhark_context *ctx);
int futhark_context_clear_caches(struct futhark_context *ctx);
int futhark_context_config_set_tuning_param(struct futhark_context_config *cfg,
                                            const char *param_name,
                                            size_t new_value);

typedef int (*restore_fn)(const void*, FILE *, struct futhark_context*, void*);
typedef void (*store_fn)(const void*, FILE *, struct futhark_context*, void*);
typedef int (*free_fn)(const void*, struct futhark_context*, void*);
typedef int (*project_fn)(struct futhark_context*, void*, const void*);
typedef int (*new_fn)(struct futhark_context*, void**, const void*[]);

struct field {
  const char *name;
  const struct type *type;
  project_fn project;
};

struct record {
  int num_fields;
  const struct field* fields;
  new_fn new;
};

struct type {
  const char *name;
  restore_fn restore;
  store_fn store;
  free_fn free;
  const void *aux;
  const struct record *record;
};

int free_scalar(const void *aux, struct futhark_context *ctx, void *p) {
  (void)aux;
  (void)ctx;
  (void)p;
  // Nothing to do.
  return 0;
}

#define DEF_SCALAR_TYPE(T)                                      \
  int restore_##T(const void *aux, FILE *f,                     \
                  struct futhark_context *ctx, void *p) {       \
    (void)aux;                                                  \
    (void)ctx;                                                  \
    return read_scalar(f, &T##_info, p);                        \
  }                                                             \
                                                                \
  void store_##T(const void *aux, FILE *f,                      \
                 struct futhark_context *ctx, void *p) {        \
    (void)aux;                                                  \
    (void)ctx;                                                  \
    write_scalar(f, 1, &T##_info, p);                           \
  }                                                             \
                                                                \
  struct type type_##T =                                        \
    { .name = #T,                                               \
      .restore = restore_##T,                                   \
      .store = store_##T,                                       \
      .free = free_scalar                                       \
    }                                                           \

DEF_SCALAR_TYPE(i8);
DEF_SCALAR_TYPE(i16);
DEF_SCALAR_TYPE(i32);
DEF_SCALAR_TYPE(i64);
DEF_SCALAR_TYPE(u8);
DEF_SCALAR_TYPE(u16);
DEF_SCALAR_TYPE(u32);
DEF_SCALAR_TYPE(u64);
DEF_SCALAR_TYPE(f16);
DEF_SCALAR_TYPE(f32);
DEF_SCALAR_TYPE(f64);
DEF_SCALAR_TYPE(bool);

struct value {
  const struct type *type;
  union {
    void *v_ptr;
    int8_t  v_i8;
    int16_t v_i16;
    int32_t v_i32;
    int64_t v_i64;

    uint8_t  v_u8;
    uint16_t v_u16;
    uint32_t v_u32;
    uint64_t v_u64;

    uint16_t v_f16;
    float v_f32;
    double v_f64;

    bool v_bool;
  } value;
};

void* value_ptr(struct value *v) {
  if (v->type == &type_i8) {
    return &v->value.v_i8;
  }
  if (v->type == &type_i16) {
    return &v->value.v_i16;
  }
  if (v->type == &type_i32) {
    return &v->value.v_i32;
  }
  if (v->type == &type_i64) {
    return &v->value.v_i64;
  }
  if (v->type == &type_u8) {
    return &v->value.v_u8;
  }
  if (v->type == &type_u16) {
    return &v->value.v_u16;
  }
  if (v->type == &type_u32) {
    return &v->value.v_u32;
  }
  if (v->type == &type_u64) {
    return &v->value.v_u64;
  }
  if (v->type == &type_f16) {
    return &v->value.v_f16;
  }
  if (v->type == &type_f32) {
    return &v->value.v_f32;
  }
  if (v->type == &type_f64) {
    return &v->value.v_f64;
  }
  if (v->type == &type_bool) {
    return &v->value.v_bool;
  }
  return &v->value.v_ptr;
}

struct variable {
  // NULL name indicates free slot.  Name is owned by this struct.
  char *name;
  struct value value;
};

typedef int (*entry_point_fn)(struct futhark_context*, void**, void**);

struct entry_point {
  const char *name;
  entry_point_fn f;
  const struct type **out_types;
  bool *out_unique;
  const struct type **in_types;
  bool *in_unique;
};

int entry_num_ins(struct entry_point *e) {
  int count = 0;
  while (e->in_types[count]) {
    count++;
  }
  return count;
}

int entry_num_outs(struct entry_point *e) {
  int count = 0;
  while (e->out_types[count]) {
    count++;
  }
  return count;
}

struct futhark_prog {
  // Last entry point identified by NULL name.
  struct entry_point *entry_points;
  // Last type identified by NULL name.
  const struct type **types;
};

struct server_state {
  struct futhark_prog prog;
  struct futhark_context_config *cfg;
  struct futhark_context *ctx;
  int variables_capacity;
  struct variable *variables;
};

struct variable* get_variable(struct server_state *s,
                              const char *name) {
  for (int i = 0; i < s->variables_capacity; i++) {
    if (s->variables[i].name != NULL &&
        strcmp(s->variables[i].name, name) == 0) {
      return &s->variables[i];
    }
  }

  return NULL;
}

struct variable* create_variable(struct server_state *s,
                                 const char *name,
                                 const struct type *type) {
  int found = -1;
  for (int i = 0; i < s->variables_capacity; i++) {
    if (found == -1 && s->variables[i].name == NULL) {
      found = i;
    } else if (s->variables[i].name != NULL &&
               strcmp(s->variables[i].name, name) == 0) {
      return NULL;
    }
  }

  if (found != -1) {
    // Found a free spot.
    s->variables[found].name = strdup(name);
    s->variables[found].value.type = type;
    return &s->variables[found];
  }

  // Need to grow the buffer.
  found = s->variables_capacity;
  s->variables_capacity *= 2;
  s->variables = realloc(s->variables,
                         s->variables_capacity * sizeof(struct variable));

  s->variables[found].name = strdup(name);
  s->variables[found].value.type = type;

  for (int i = found+1; i < s->variables_capacity; i++) {
    s->variables[i].name = NULL;
  }

  return &s->variables[found];
}

void drop_variable(struct variable *v) {
  free(v->name);
  v->name = NULL;
}

int arg_exists(const char *args[], int i) {
  return args[i] != NULL;
}

const char* get_arg(const char *args[], int i) {
  if (!arg_exists(args, i)) {
    futhark_panic(1, "Insufficient command args.\n");
  }
  return args[i];
}

const struct type* get_type(struct server_state *s, const char *name) {
  for (int i = 0; s->prog.types[i]; i++) {
    if (strcmp(s->prog.types[i]->name, name) == 0) {
      return s->prog.types[i];
    }
  }

  futhark_panic(1, "Unknown type %s\n", name);
  return NULL;
}

struct entry_point* get_entry_point(struct server_state *s, const char *name) {
  for (int i = 0; s->prog.entry_points[i].name; i++) {
    if (strcmp(s->prog.entry_points[i].name, name) == 0) {
      return &s->prog.entry_points[i];
    }
  }

  return NULL;
}

// Print the command-done marker, indicating that we are ready for
// more input.
void ok() {
  printf("%%%%%% OK\n");
  fflush(stdout);
}

// Print the failure marker.  Output is now an error message until the
// next ok().
void failure() {
  printf("%%%%%% FAILURE\n");
}

void error_check(struct server_state *s, int err) {
  if (err != 0) {
    failure();
    char *error = futhark_context_get_error(s->ctx);
    if (error != NULL) {
      puts(error);
    }
    free(error);
  }
}

void cmd_call(struct server_state *s, const char *args[]) {
  const char *name = get_arg(args, 0);

  struct entry_point *e = get_entry_point(s, name);

  if (e == NULL) {
    failure();
    printf("Unknown entry point: %s\n", name);
    return;
  }

  int num_outs = entry_num_outs(e);
  int num_ins = entry_num_ins(e);
  // +1 to avoid zero-size arrays, which is UB.
  void* outs[num_outs+1];
  void* ins[num_ins+1];

  for (int i = 0; i < num_ins; i++) {
    const char *in_name = get_arg(args, 1+num_outs+i);
    struct variable *v = get_variable(s, in_name);
    if (v == NULL) {
      failure();
      printf("Unknown variable: %s\n", in_name);
      return;
    }
    if (v->value.type != e->in_types[i]) {
      failure();
      printf("Wrong input type.  Expected %s, got %s.\n",
             e->in_types[i]->name, v->value.type->name);
      return;
    }
    ins[i] = value_ptr(&v->value);
  }

  for (int i = 0; i < num_outs; i++) {
    const char *out_name = get_arg(args, 1+i);
    struct variable *v = create_variable(s, out_name, e->out_types[i]);
    if (v == NULL) {
      failure();
      printf("Variable already exists: %s\n", out_name);
      return;
    }
    outs[i] = value_ptr(&v->value);
  }

  int64_t t_start = get_wall_time();
  int err = e->f(s->ctx, outs, ins);
  err |= futhark_context_sync(s->ctx);
  int64_t t_end = get_wall_time();
  long long int elapsed_usec = t_end - t_start;
  printf("runtime: %lld\n", elapsed_usec);

  error_check(s, err);
  if (err != 0) {
    // Need to uncreate the output variables, which would otherwise be left
    // in an uninitialised state.
    for (int i = 0; i < num_outs; i++) {
      const char *out_name = get_arg(args, 1+i);
      struct variable *v = get_variable(s, out_name);
      if (v) {
        drop_variable(v);
      }
    }
  }
}

void cmd_restore(struct server_state *s, const char *args[]) {
  const char *fname = get_arg(args, 0);

  FILE *f = fopen(fname, "rb");
  if (f == NULL) {
    failure();
    printf("Failed to open %s: %s\n", fname, strerror(errno));
  } else {
    int values = 0;
    for (int i = 1; arg_exists(args, i); i+=2, values++) {
      const char *vname = get_arg(args, i);
      const char *type = get_arg(args, i+1);

      const struct type *t = get_type(s, type);
      struct variable *v = create_variable(s, vname, t);

      if (v == NULL) {
        failure();
        printf("Variable already exists: %s\n", vname);
        return;
      }

      if (t->restore(t->aux, f, s->ctx, value_ptr(&v->value)) != 0) {
        failure();
        printf("Failed to restore variable %s.\n"
               "Possibly malformed data in %s (errno: %s)\n",
               vname, fname, strerror(errno));
        drop_variable(v);
        break;
      }
    }

    if (end_of_input(f) != 0) {
      failure();
      printf("Expected EOF after reading %d values from %s\n",
             values, fname);
    }

    fclose(f);
  }

  int err = futhark_context_sync(s->ctx);
  error_check(s, err);
}

void cmd_store(struct server_state *s, const char *args[]) {
  const char *fname = get_arg(args, 0);

  FILE *f = fopen(fname, "wb");
  if (f == NULL) {
    failure();
    printf("Failed to open %s: %s\n", fname, strerror(errno));
  } else {
    for (int i = 1; arg_exists(args, i); i++) {
      const char *vname = get_arg(args, i);
      struct variable *v = get_variable(s, vname);

      if (v == NULL) {
        failure();
        printf("Unknown variable: %s\n", vname);
        return;
      }

      const struct type *t = v->value.type;
      t->store(t->aux, f, s->ctx, value_ptr(&v->value));
    }
    fclose(f);
  }
}

void cmd_free(struct server_state *s, const char *args[]) {
  for (int i = 0; arg_exists(args, i); i++) {
    const char *name = get_arg(args, i);
    struct variable *v = get_variable(s, name);

    if (v == NULL) {
      failure();
      printf("Unknown variable: %s\n", name);
      return;
    }

    const struct type *t = v->value.type;

    int err = t->free(t->aux, s->ctx, value_ptr(&v->value));
    error_check(s, err);
    drop_variable(v);
  }
}

void cmd_rename(struct server_state *s, const char *args[]) {
  const char *oldname = get_arg(args, 0);
  const char *newname = get_arg(args, 1);
  struct variable *old = get_variable(s, oldname);
  struct variable *new = get_variable(s, newname);

  if (old == NULL) {
    failure();
    printf("Unknown variable: %s\n", oldname);
    return;
  }

  if (new != NULL) {
    failure();
    printf("Variable already exists: %s\n", newname);
    return;
  }

  free(old->name);
  old->name = strdup(newname);
}

void cmd_inputs(struct server_state *s, const char *args[]) {
  const char *name = get_arg(args, 0);
  struct entry_point *e = get_entry_point(s, name);

  if (e == NULL) {
    failure();
    printf("Unknown entry point: %s\n", name);
    return;
  }

  int num_ins = entry_num_ins(e);
  for (int i = 0; i < num_ins; i++) {
    if (e->in_unique[i]) {
      putchar('*');
    }
    puts(e->in_types[i]->name);
  }
}

void cmd_outputs(struct server_state *s, const char *args[]) {
  const char *name = get_arg(args, 0);
  struct entry_point *e = get_entry_point(s, name);

  if (e == NULL) {
    failure();
    printf("Unknown entry point: %s\n", name);
    return;
  }

  int num_outs = entry_num_outs(e);
  for (int i = 0; i < num_outs; i++) {
    if (e->out_unique[i]) {
      putchar('*');
    }
    puts(e->out_types[i]->name);
  }
}

void cmd_clear(struct server_state *s, const char *args[]) {
  (void)args;
  int err = 0;
  for (int i = 0; i < s->variables_capacity; i++) {
    struct variable *v = &s->variables[i];
    if (v->name != NULL) {
      err |= v->value.type->free(v->value.type->aux, s->ctx, value_ptr(&v->value));
      drop_variable(v);
    }
  }
  err |= futhark_context_clear_caches(s->ctx);
  error_check(s, err);
}

void cmd_pause_profiling(struct server_state *s, const char *args[]) {
  (void)args;
  futhark_context_pause_profiling(s->ctx);
}

void cmd_unpause_profiling(struct server_state *s, const char *args[]) {
  (void)args;
  futhark_context_unpause_profiling(s->ctx);
}

void cmd_report(struct server_state *s, const char *args[]) {
  (void)args;
  char *report = futhark_context_report(s->ctx);
  puts(report);
  free(report);
}

void cmd_set_tuning_param(struct server_state *s, const char *args[]) {
  const char *param = get_arg(args, 0);
  const char *val_s = get_arg(args, 1);
  size_t val = atol(val_s);
  int err = futhark_context_config_set_tuning_param(s->cfg, param, val);

  error_check(s, err);

  if (err != 0) {
    printf("Failed to set tuning parameter %s to %ld\n", param, (long)val);
  }
}

void cmd_fields(struct server_state *s, const char *args[]) {
  const char *type = get_arg(args, 0);
  const struct type *t = get_type(s, type);
  const struct record *r = t->record;

  if (r == NULL) {
    failure();
    printf("Not a record type\n");
    return;
  }

  for (int i = 0; i < r->num_fields; i++) {
    const struct field f = r->fields[i];
    printf("%s %s\n", f.name, f.type->name);
  }
}

void cmd_project(struct server_state *s, const char *args[]) {
  const char *to_name = get_arg(args, 0);
  const char *from_name = get_arg(args, 1);
  const char *field_name = get_arg(args, 2);

  struct variable *from = get_variable(s, from_name);

  if (from == NULL) {
    failure();
    printf("Unknown variable: %s\n", from_name);
    return;
  }

  const struct type *from_type = from->value.type;
  const struct record *r = from_type->record;

  if (r == NULL) {
    failure();
    printf("Not a record type\n");
    return;
  }

  const struct field *field = NULL;
  for (int i = 0; i < r->num_fields; i++) {
    if (strcmp(r->fields[i].name, field_name) == 0) {
      field = &r->fields[i];
      break;
    }
  }

  if (field == NULL) {
    failure();
    printf("No such field\n");
  }

  struct variable *to = create_variable(s, to_name, field->type);

  if (to == NULL) {
    failure();
    printf("Variable already exists: %s\n", to_name);
    return;
  }

  field->project(s->ctx, value_ptr(&to->value), from->value.value.v_ptr);
}

void cmd_new(struct server_state *s, const char *args[]) {
  const char *to_name = get_arg(args, 0);
  const char *type_name = get_arg(args, 1);
  const struct type *type = get_type(s, type_name);
  struct variable *to = create_variable(s, to_name, type);

  if (to == NULL) {
    failure();
    printf("Variable already exists: %s\n", to_name);
    return;
  }

  const struct record* r = type->record;

  if (r == NULL) {
    failure();
    printf("Not a record type\n");
    return;
  }

  int num_args = 0;
  for (int i = 2; arg_exists(args, i); i++) {
    num_args++;
  }

  if (num_args != r->num_fields) {
    failure();
    printf("%d fields expected byt %d values provided.\n", num_args, r->num_fields);
    return;
  }

  const void** value_ptrs = alloca(num_args * sizeof(void*));

  for (int i = 0; i < num_args; i++) {
    struct variable* v = get_variable(s, args[2+i]);

    if (v == NULL) {
      failure();
      printf("Unknown variable: %s\n", args[2+i]);
      return;
    }

    if (strcmp(v->value.type->name, r->fields[i].type->name) != 0) {
      failure();
      printf("Field %s mismatch: expected type %s, got %s\n",
             r->fields[i].name, r->fields[i].type->name, v->value.type->name);
      return;
    }

    value_ptrs[i] = value_ptr(&v->value);
  }

  r->new(s->ctx, value_ptr(&to->value), value_ptrs);
}

void cmd_entry_points(struct server_state *s, const char *args[]) {
  (void)args;
  for (int i = 0; s->prog.entry_points[i].name; i++) {
    puts(s->prog.entry_points[i].name);
  }
}

void cmd_types(struct server_state *s, const char *args[]) {
  (void)args;
  for (int i = 0; s->prog.types[i] != NULL; i++) {
    puts(s->prog.types[i]->name);
  }
}

char *next_word(char **line) {
  char *p = *line;

  while (isspace(*p)) {
    p++;
  }

  if (*p == 0) {
    return NULL;
  }

  if (*p == '"') {
    char *save = p+1;
    // Skip ahead till closing quote.
    p++;

    while (*p && *p != '"') {
      p++;
    }

    if (*p == '"') {
      *p = 0;
      *line = p+1;
      return save;
    } else {
      return NULL;
    }
  } else {
    char *save = p;
    // Skip ahead till next whitespace.

    while (*p && !isspace(*p)) {
      p++;
    }

    if (*p) {
      *p = 0;
      *line = p+1;
    } else {
      *line = p;
    }
    return save;
  }
}

void process_line(struct server_state *s, char *line) {
  int max_num_tokens = 1000;
  const char* tokens[max_num_tokens];
  int num_tokens = 0;

  while ((tokens[num_tokens] = next_word(&line)) != NULL) {
    num_tokens++;
    if (num_tokens == max_num_tokens) {
      futhark_panic(1, "Line too long.\n");
    }
  }

  const char *command = tokens[0];

  if (command == NULL) {
    failure();
    printf("Empty line\n");
  } else if (strcmp(command, "call") == 0) {
    cmd_call(s, tokens+1);
  } else if (strcmp(command, "restore") == 0) {
    cmd_restore(s, tokens+1);
  } else if (strcmp(command, "store") == 0) {
    cmd_store(s, tokens+1);
  } else if (strcmp(command, "free") == 0) {
    cmd_free(s, tokens+1);
  } else if (strcmp(command, "rename") == 0) {
    cmd_rename(s, tokens+1);
  } else if (strcmp(command, "inputs") == 0) {
    cmd_inputs(s, tokens+1);
  } else if (strcmp(command, "outputs") == 0) {
    cmd_outputs(s, tokens+1);
  } else if (strcmp(command, "clear") == 0) {
    cmd_clear(s, tokens+1);
  } else if (strcmp(command, "pause_profiling") == 0) {
    cmd_pause_profiling(s, tokens+1);
  } else if (strcmp(command, "unpause_profiling") == 0) {
    cmd_unpause_profiling(s, tokens+1);
  } else if (strcmp(command, "report") == 0) {
    cmd_report(s, tokens+1);
  } else if (strcmp(command, "set_tuning_param") == 0) {
    cmd_set_tuning_param(s, tokens+1);
  } else if (strcmp(command, "fields") == 0) {
    cmd_fields(s, tokens+1);
  } else if (strcmp(command, "new") == 0) {
    cmd_new(s, tokens+1);
  } else if (strcmp(command, "project") == 0) {
    cmd_project(s, tokens+1);
  } else if (strcmp(command, "entry_points") == 0) {
    cmd_entry_points(s, tokens+1);
  } else if (strcmp(command, "types") == 0) {
    cmd_types(s, tokens+1);
  } else {
    futhark_panic(1, "Unknown command: %s\n", command);
  }
}

void run_server(struct futhark_prog *prog,
                struct futhark_context_config *cfg,
                struct futhark_context *ctx) {
  char *line = NULL;
  size_t buflen = 0;
  ssize_t linelen;

  struct server_state s = {
    .cfg = cfg,
    .ctx = ctx,
    .variables_capacity = 100,
    .prog = *prog
  };

  s.variables = malloc(s.variables_capacity * sizeof(struct variable));

  for (int i = 0; i < s.variables_capacity; i++) {
    s.variables[i].name = NULL;
  }

  ok();
  while ((linelen = getline(&line, &buflen, stdin)) > 0) {
    process_line(&s, line);
    ok();
  }

  free(s.variables);
  free(line);
}

// The aux struct lets us write generic method implementations without
// code duplication.

typedef void* (*array_new_fn)(struct futhark_context *, const void*, const int64_t*);
typedef const int64_t* (*array_shape_fn)(struct futhark_context*, void*);
typedef int (*array_values_fn)(struct futhark_context*, void*, void*);
typedef int (*array_free_fn)(struct futhark_context*, void*);

struct array_aux {
  int rank;
  const struct primtype_info_t* info;
  const char *name;
  array_new_fn new;
  array_shape_fn shape;
  array_values_fn values;
  array_free_fn free;
};

int restore_array(const struct array_aux *aux, FILE *f,
                  struct futhark_context *ctx, void *p) {
  void *data = NULL;
  int64_t shape[aux->rank];
  if (read_array(f, aux->info, &data, shape, aux->rank) != 0) {
    return 1;
  }

  void *arr = aux->new(ctx, data, shape);
  if (arr == NULL) {
    return 1;
  }
  assert(futhark_context_sync(ctx) == 0);

  *(void**)p = arr;
  free(data);
  return 0;
}

void store_array(const struct array_aux *aux, FILE *f,
                 struct futhark_context *ctx, void *p) {
  void *arr = *(void**)p;
  const int64_t *shape = aux->shape(ctx, arr);
  int64_t size = sizeof(aux->info->size);
  for (int i = 0; i < aux->rank; i++) {
    size *= shape[i];
  }
  int32_t *data = malloc(size);
  assert(aux->values(ctx, arr, data) == 0);
  assert(futhark_context_sync(ctx) == 0);
  assert(write_array(f, 1, aux->info, data, shape, aux->rank) == 0);
  free(data);
}

int free_array(const struct array_aux *aux,
               struct futhark_context *ctx, void *p) {
  void *arr = *(void**)p;
  return aux->free(ctx, arr);
}

typedef void* (*opaque_restore_fn)(struct futhark_context*, void*);
typedef int (*opaque_store_fn)(struct futhark_context*, const void*, void **, size_t *);
typedef int (*opaque_free_fn)(struct futhark_context*, void*);

struct opaque_aux {
  opaque_restore_fn restore;
  opaque_store_fn store;
  opaque_free_fn free;
};

int restore_opaque(const struct opaque_aux *aux, FILE *f,
                   struct futhark_context *ctx, void *p) {
  // We have a problem: we need to load data from 'f', since the
  // restore function takes a pointer, but we don't know how much we
  // need (and cannot possibly).  So we do something hacky: we read
  // *all* of the file, pass all of the data to the restore function
  // (which doesn't care if there's extra at the end), then we compute
  // how much space the the object actually takes in serialised form
  // and rewind the file to that position.  The only downside is more IO.
  size_t start = ftell(f);
  size_t size;
  char *bytes = fslurp_file(f, &size);
  void *obj = aux->restore(ctx, bytes);
  free(bytes);
  if (obj != NULL) {
    *(void**)p = obj;
    size_t obj_size;
    (void)aux->store(ctx, obj, NULL, &obj_size);
    fseek(f, start+obj_size, SEEK_SET);
    return 0;
  } else {
    fseek(f, start, SEEK_SET);
    return 1;
  }
}

void store_opaque(const struct opaque_aux *aux, FILE *f,
                  struct futhark_context *ctx, void *p) {
  void *obj = *(void**)p;
  size_t obj_size;
  void *data = NULL;
  (void)aux->store(ctx, obj, &data, &obj_size);
  fwrite(data, sizeof(char), obj_size, f);
  free(data);
}

int free_opaque(const struct opaque_aux *aux,
                struct futhark_context *ctx, void *p) {
  void *obj = *(void**)p;
  return aux->free(ctx, obj);
}

// End of server.h.

// Start of tuning.h.

static char* load_tuning_file(const char *fname,
                              void *cfg,
                              int (*set_tuning_param)(void*, const char*, size_t)) {
  const int max_line_len = 1024;
  char* line = (char*) malloc(max_line_len);

  FILE *f = fopen(fname, "r");

  if (f == NULL) {
    snprintf(line, max_line_len, "Cannot open file: %s", strerror(errno));
    return line;
  }

  int lineno = 0;
  while (fgets(line, max_line_len, f) != NULL) {
    lineno++;
    char *eql = strstr(line, "=");
    if (eql) {
      *eql = 0;
      int value = atoi(eql+1);
      if (set_tuning_param(cfg, line, (size_t)value) != 0) {
        char* err = (char*) malloc(max_line_len + 50);
        snprintf(err, max_line_len + 50, "Unknown name '%s' on line %d.", line, lineno);
        free(line);
        return err;
      }
    } else {
      snprintf(line, max_line_len, "Invalid line %d (must be of form 'name=int').",
               lineno);
      return line;
    }
  }

  free(line);

  return NULL;
}

// End of tuning.h.

const struct type type_ZMZNZMZNZMZNZMZNf64;
const struct type type_ZMZNZMZNZMZNf64;
const struct type type_ZMZNf64;
void *futhark_new_f64_4d_wrap(struct futhark_context *ctx, const void *p, const
                              int64_t *shape)
{
    return futhark_new_f64_4d(ctx, p, shape[0], shape[1], shape[2], shape[3]);
}
const struct array_aux type_ZMZNZMZNZMZNZMZNf64_aux = {.name ="[][][][]f64",
                                                       .rank =4, .info =
                                                       &f64_info, .new =
                                                       (array_new_fn) futhark_new_f64_4d_wrap,
                                                       .free =
                                                       (array_free_fn) futhark_free_f64_4d,
                                                       .shape =
                                                       (array_shape_fn) futhark_shape_f64_4d,
                                                       .values =
                                                       (array_values_fn) futhark_values_f64_4d};
const struct type type_ZMZNZMZNZMZNZMZNf64 = {.name ="[][][][]f64", .restore =
                                              (restore_fn) restore_array,
                                              .store =(store_fn) store_array,
                                              .free =(free_fn) free_array,
                                              .aux =
                                              &type_ZMZNZMZNZMZNZMZNf64_aux};
void *futhark_new_f64_3d_wrap(struct futhark_context *ctx, const void *p, const
                              int64_t *shape)
{
    return futhark_new_f64_3d(ctx, p, shape[0], shape[1], shape[2]);
}
const struct array_aux type_ZMZNZMZNZMZNf64_aux = {.name ="[][][]f64", .rank =3,
                                                   .info =&f64_info, .new =
                                                   (array_new_fn) futhark_new_f64_3d_wrap,
                                                   .free =
                                                   (array_free_fn) futhark_free_f64_3d,
                                                   .shape =
                                                   (array_shape_fn) futhark_shape_f64_3d,
                                                   .values =
                                                   (array_values_fn) futhark_values_f64_3d};
const struct type type_ZMZNZMZNZMZNf64 = {.name ="[][][]f64", .restore =
                                          (restore_fn) restore_array, .store =
                                          (store_fn) store_array, .free =
                                          (free_fn) free_array, .aux =
                                          &type_ZMZNZMZNZMZNf64_aux};
void *futhark_new_f64_1d_wrap(struct futhark_context *ctx, const void *p, const
                              int64_t *shape)
{
    return futhark_new_f64_1d(ctx, p, shape[0]);
}
const struct array_aux type_ZMZNf64_aux = {.name ="[]f64", .rank =1, .info =
                                           &f64_info, .new =
                                           (array_new_fn) futhark_new_f64_1d_wrap,
                                           .free =
                                           (array_free_fn) futhark_free_f64_1d,
                                           .shape =
                                           (array_shape_fn) futhark_shape_f64_1d,
                                           .values =
                                           (array_values_fn) futhark_values_f64_1d};
const struct type type_ZMZNf64 = {.name ="[]f64", .restore =
                                  (restore_fn) restore_array, .store =
                                  (store_fn) store_array, .free =
                                  (free_fn) free_array, .aux =
                                  &type_ZMZNf64_aux};
const struct type *convolve2d_b_bench_out_types[] = {&type_ZMZNZMZNZMZNf64,
                                                     &type_ZMZNZMZNZMZNZMZNf64,
                                                     &type_ZMZNf64, NULL};
bool convolve2d_b_bench_out_unique[] = {false, false, false};
const struct type *convolve2d_b_bench_in_types[] = {&type_ZMZNZMZNZMZNf64,
                                                    &type_ZMZNZMZNZMZNf64,
                                                    &type_ZMZNZMZNZMZNZMZNf64,
                                                    NULL};
bool convolve2d_b_bench_in_unique[] = {false, false, false};
int call_convolve2d_b_bench(struct futhark_context *ctx, void **outs,
                            void **ins)
{
    struct futhark_f64_3d * *out0 = outs[0];
    struct futhark_f64_4d * *out1 = outs[1];
    struct futhark_f64_1d * *out2 = outs[2];
    struct futhark_f64_3d * in0 = *(struct futhark_f64_3d * *) ins[0];
    struct futhark_f64_3d * in1 = *(struct futhark_f64_3d * *) ins[1];
    struct futhark_f64_4d * in2 = *(struct futhark_f64_4d * *) ins[2];
    
    return futhark_entry_convolve2d_b_bench(ctx, out0, out1, out2, in0, in1,
                                            in2);
}
const struct type *convolve2d_b_test_out_types[] = {&type_ZMZNZMZNZMZNf64,
                                                    &type_ZMZNZMZNZMZNZMZNf64,
                                                    &type_ZMZNf64, NULL};
bool convolve2d_b_test_out_unique[] = {false, false, false};
const struct type *convolve2d_b_test_in_types[] = {&type_ZMZNZMZNZMZNf64,
                                                   &type_ZMZNZMZNZMZNf64,
                                                   &type_ZMZNZMZNZMZNZMZNf64,
                                                   &type_i64, &type_i64, NULL};
bool convolve2d_b_test_in_unique[] = {false, false, false, false, false};
int call_convolve2d_b_test(struct futhark_context *ctx, void **outs, void **ins)
{
    struct futhark_f64_3d * *out0 = outs[0];
    struct futhark_f64_4d * *out1 = outs[1];
    struct futhark_f64_1d * *out2 = outs[2];
    struct futhark_f64_3d * in0 = *(struct futhark_f64_3d * *) ins[0];
    struct futhark_f64_3d * in1 = *(struct futhark_f64_3d * *) ins[1];
    struct futhark_f64_4d * in2 = *(struct futhark_f64_4d * *) ins[2];
    int64_t in3 = *(int64_t *) ins[3];
    int64_t in4 = *(int64_t *) ins[4];
    
    return futhark_entry_convolve2d_b_test(ctx, out0, out1, out2, in0, in1, in2,
                                           in3, in4);
}
const struct type *convolve2d_test_out_types[] = {&type_ZMZNZMZNZMZNf64, NULL};
bool convolve2d_test_out_unique[] = {true};
const struct type *convolve2d_test_in_types[] = {&type_ZMZNZMZNZMZNf64,
                                                 &type_ZMZNZMZNZMZNZMZNf64,
                                                 &type_ZMZNf64, &type_i64,
                                                 NULL};
bool convolve2d_test_in_unique[] = {false, false, false, false};
int call_convolve2d_test(struct futhark_context *ctx, void **outs, void **ins)
{
    struct futhark_f64_3d * *out0 = outs[0];
    struct futhark_f64_3d * in0 = *(struct futhark_f64_3d * *) ins[0];
    struct futhark_f64_4d * in1 = *(struct futhark_f64_4d * *) ins[1];
    struct futhark_f64_1d * in2 = *(struct futhark_f64_1d * *) ins[2];
    int64_t in3 = *(int64_t *) ins[3];
    
    return futhark_entry_convolve2d_test(ctx, out0, in0, in1, in2, in3);
}
const struct type *types[] = {&type_i8, &type_i16, &type_i32, &type_i64,
                              &type_u8, &type_u16, &type_u32, &type_u64,
                              &type_f16, &type_f32, &type_f64, &type_bool,
                              &type_ZMZNZMZNZMZNZMZNf64, &type_ZMZNZMZNZMZNf64,
                              &type_ZMZNf64, NULL};
struct entry_point entry_points[] = {{.name ="convolve2d_b_bench", .f =
                                      call_convolve2d_b_bench, .in_types =
                                      convolve2d_b_bench_in_types, .out_types =
                                      convolve2d_b_bench_out_types, .in_unique =
                                      convolve2d_b_bench_in_unique,
                                      .out_unique =
                                      convolve2d_b_bench_out_unique}, {.name =
                                                                       "convolve2d_b_test",
                                                                       .f =
                                                                       call_convolve2d_b_test,
                                                                       .in_types =
                                                                       convolve2d_b_test_in_types,
                                                                       .out_types =
                                                                       convolve2d_b_test_out_types,
                                                                       .in_unique =
                                                                       convolve2d_b_test_in_unique,
                                                                       .out_unique =
                                                                       convolve2d_b_test_out_unique},
                                     {.name ="convolve2d_test", .f =
                                      call_convolve2d_test, .in_types =
                                      convolve2d_test_in_types, .out_types =
                                      convolve2d_test_out_types, .in_unique =
                                      convolve2d_test_in_unique, .out_unique =
                                      convolve2d_test_out_unique}, {.name =
                                     NULL}};
struct futhark_prog prog = {.types =types, .entry_points =entry_points};
int parse_options(struct futhark_context_config *cfg, int argc,
                  char *const argv[])
{
    int ch;
    static struct option long_options[] = {{"debugging", no_argument, NULL, 1},
                                           {"log", no_argument, NULL, 2},
                                           {"help", no_argument, NULL, 3},
                                           {"print-params", no_argument, NULL,
                                            4}, {"param", required_argument,
                                                 NULL, 5}, {"tuning",
                                                            required_argument,
                                                            NULL, 6},
                                           {"cache-file", required_argument,
                                            NULL, 7}, {0, 0, 0, 0}};
    static char *option_descriptions =
                "  -D/--debugging     Perform possibly expensive internal correctness checks and verbose logging.\n  -L/--log           Print various low-overhead logging information while running.\n  -h/--help          Print help information and exit.\n  --print-params     Print all tuning parameters that can be set with --param or --tuning.\n  --param ASSIGNMENT Set a tuning parameter to the given value.\n  --tuning FILE      Read size=value assignments from the given file.\n  --cache-file FILE  Store program cache here.\n";
    
    while ((ch = getopt_long(argc, argv, ":DLh", long_options, NULL)) != -1) {
        if (ch == 1 || ch == 'D')
            futhark_context_config_set_debugging(cfg, 1);
        if (ch == 2 || ch == 'L')
            futhark_context_config_set_logging(cfg, 1);
        if (ch == 3 || ch == 'h') {
            printf("Usage: %s [OPTIONS]...\nOptions:\n\n%s\nFor more information, consult the Futhark User's Guide or the man pages.\n",
                   fut_progname, option_descriptions);
            exit(0);
        }
        if (ch == 4) {
            int n = futhark_get_tuning_param_count();
            
            for (int i = 0; i < n; i++)
                printf("%s (%s)\n", futhark_get_tuning_param_name(i),
                       futhark_get_tuning_param_class(i));
            exit(0);
        }
        if (ch == 5) {
            char *name = optarg;
            char *equals = strstr(optarg, "=");
            char *value_str = equals != NULL ? equals + 1 : optarg;
            int value = atoi(value_str);
            
            if (equals != NULL) {
                *equals = 0;
                if (futhark_context_config_set_tuning_param(cfg, name, value) !=
                    0)
                    futhark_panic(1, "Unknown size: %s\n", name);
            } else
                futhark_panic(1, "Invalid argument for size option: %s\n",
                              optarg);
        }
        if (ch == 6) {
            char *ret = load_tuning_file(optarg, cfg, (int (*)(void *, const
                                                               char *,
                                                               size_t)) futhark_context_config_set_tuning_param);
            
            if (ret != NULL)
                futhark_panic(1, "When loading tuning from '%s': %s\n", optarg,
                              ret);
        }
        if (ch == 7)
            futhark_context_config_set_cache_file(cfg, optarg);
        if (ch == ':')
            futhark_panic(-1, "Missing argument for option %s\n", argv[optind -
                                                                       1]);
        if (ch == '?') {
            fprintf(stderr, "Usage: %s [OPTIONS]...\nOptions:\n\n%s\n",
                    fut_progname,
                    "  -D/--debugging     Perform possibly expensive internal correctness checks and verbose logging.\n  -L/--log           Print various low-overhead logging information while running.\n  -h/--help          Print help information and exit.\n  --print-params     Print all tuning parameters that can be set with --param or --tuning.\n  --param ASSIGNMENT Set a tuning parameter to the given value.\n  --tuning FILE      Read size=value assignments from the given file.\n  --cache-file FILE  Store program cache here.\n");
            futhark_panic(1, "Unknown option: %s\n", argv[optind - 1]);
        }
    }
    return optind;
}
int main(int argc, char **argv)
{
    fut_progname = argv[0];
    
    struct futhark_context_config *cfg = futhark_context_config_new();
    
    assert(cfg != NULL);
    
    int parsed_options = parse_options(cfg, argc, argv);
    
    argc -= parsed_options;
    argv += parsed_options;
    if (argc != 0)
        futhark_panic(1, "Excess non-option: %s\n", argv[0]);
    
    struct futhark_context *ctx = futhark_context_new(cfg);
    
    assert(ctx != NULL);
    futhark_context_set_logging_file(ctx, stdout);
    
    char *error = futhark_context_get_error(ctx);
    
    if (error != NULL)
        futhark_panic(1, "Error during context initialisation:\n%s", error);
    if (entry_point != NULL)
        run_server(&prog, cfg, ctx);
    futhark_context_free(ctx);
    futhark_context_config_free(cfg);
}

#ifdef _MSC_VER
#define inline __inline
#endif
#include <string.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <ctype.h>



// Start of lock.h.

// A very simple cross-platform implementation of locks.  Uses
// pthreads on Unix and some Windows thing there.  Futhark's
// host-level code is not multithreaded, but user code may be, so we
// need some mechanism for ensuring atomic access to API functions.
// This is that mechanism.  It is not exposed to user code at all, so
// we do not have to worry about name collisions.

#ifdef _WIN32

typedef HANDLE lock_t;

static void create_lock(lock_t *lock) {
  *lock = CreateMutex(NULL,  // Default security attributes.
                      FALSE, // Initially unlocked.
                      NULL); // Unnamed.
}

static void lock_lock(lock_t *lock) {
  assert(WaitForSingleObject(*lock, INFINITE) == WAIT_OBJECT_0);
}

static void lock_unlock(lock_t *lock) {
  assert(ReleaseMutex(*lock));
}

static void free_lock(lock_t *lock) {
  CloseHandle(*lock);
}

#else
// Assuming POSIX

#include <pthread.h>

typedef pthread_mutex_t lock_t;

static void create_lock(lock_t *lock) {
  int r = pthread_mutex_init(lock, NULL);
  assert(r == 0);
}

static void lock_lock(lock_t *lock) {
  int r = pthread_mutex_lock(lock);
  assert(r == 0);
}

static void lock_unlock(lock_t *lock) {
  int r = pthread_mutex_unlock(lock);
  assert(r == 0);
}

static void free_lock(lock_t *lock) {
  // Nothing to do for pthreads.
  (void)lock;
}

#endif

// End of lock.h.

#define FUTHARK_F64_ENABLED

// Start of scalar.h.

// Implementation of the primitive scalar operations.  Very
// repetitive.  This code is inserted directly into both CUDA and
// OpenCL programs, as well as the CPU code, so it has some #ifdefs to
// work everywhere.  Some operations are defined as macros because
// this allows us to use them as constant expressions in things like
// array sizes and static initialisers.

// Some of the #ifdefs are because OpenCL uses type-generic functions
// for some operations (e.g. sqrt), while C and CUDA sensibly use
// distinct functions for different precisions (e.g. sqrtf() and
// sqrt()).  This is quite annoying.  Due to C's unfortunate casting
// rules, it is also really easy to accidentally implement
// floating-point functions in the wrong precision, so be careful.

// Double-precision definitions are only included if the preprocessor
// macro FUTHARK_F64_ENABLED is set.

static inline uint8_t add8(uint8_t x, uint8_t y) {
  return x + y;
}

static inline uint16_t add16(uint16_t x, uint16_t y) {
  return x + y;
}

static inline uint32_t add32(uint32_t x, uint32_t y) {
  return x + y;
}

static inline uint64_t add64(uint64_t x, uint64_t y) {
  return x + y;
}

static inline uint8_t sub8(uint8_t x, uint8_t y) {
  return x - y;
}

static inline uint16_t sub16(uint16_t x, uint16_t y) {
  return x - y;
}

static inline uint32_t sub32(uint32_t x, uint32_t y) {
  return x - y;
}

static inline uint64_t sub64(uint64_t x, uint64_t y) {
  return x - y;
}

static inline uint8_t mul8(uint8_t x, uint8_t y) {
  return x * y;
}

static inline uint16_t mul16(uint16_t x, uint16_t y) {
  return x * y;
}

static inline uint32_t mul32(uint32_t x, uint32_t y) {
  return x * y;
}

static inline uint64_t mul64(uint64_t x, uint64_t y) {
  return x * y;
}

#if ISPC

static inline uint8_t udiv8(uint8_t x, uint8_t y) {
  // This strange pattern is used to prevent the ISPC compiler from
  // causing SIGFPEs and bogus results on divisions where inactive lanes
  // have 0-valued divisors. It ensures that any inactive lane instead
  // has a divisor of 1. https://github.com/ispc/ispc/issues/2292
  uint8_t ys = 1;
  foreach_active(i){
    ys = y;
  }

  return x / ys;
}

static inline uint16_t udiv16(uint16_t x, uint16_t y) {
  uint16_t ys = 1;
  foreach_active(i){
    ys = y;
  }
  
  return x / ys;
}

static inline uint32_t udiv32(uint32_t x, uint32_t y) {
  uint32_t ys = 1;
  foreach_active(i){
    ys = y;
  }
  

  return x / ys;
}

static inline uint64_t udiv64(uint64_t x, uint64_t y) {
  uint64_t ys = 1;
  foreach_active(i){
    ys = y;
  }
  

  return x / ys;
}

static inline uint8_t udiv_up8(uint8_t x, uint8_t y) {
  uint8_t ys = 1;
  foreach_active(i){
    ys = y;
  }
  

  return (x + y - 1) / ys;
}

static inline uint16_t udiv_up16(uint16_t x, uint16_t y) {
  uint16_t ys = 1;
  foreach_active(i){
    ys = y;
  }
  
  return (x + y - 1) / ys;
}

static inline uint32_t udiv_up32(uint32_t x, uint32_t y) {
  uint32_t ys = 1;
  foreach_active(i){
    ys = y;
  }
  
  return (x + y - 1) / ys;
}

static inline uint64_t udiv_up64(uint64_t x, uint64_t y) {
  uint64_t ys = 1;
  foreach_active(i){
    ys = y;
  }
  
  return (x + y - 1) / ys;
}

static inline uint8_t umod8(uint8_t x, uint8_t y) {
  uint8_t ys = 1;
  foreach_active(i){
    ys = y;
  }
  
  return x % ys;
}

static inline uint16_t umod16(uint16_t x, uint16_t y) {
  uint16_t ys = 1;
  foreach_active(i){
    ys = y;
  }
  

  return x % ys;
}

static inline uint32_t umod32(uint32_t x, uint32_t y) {
  uint32_t ys = 1;
  foreach_active(i){
    ys = y;
  }
  
  return x % ys;
}

static inline uint64_t umod64(uint64_t x, uint64_t y) {
  uint64_t ys = 1;
  foreach_active(i){
    ys = y;
  }
  
  return x % ys;
}

static inline uint8_t udiv_safe8(uint8_t x, uint8_t y) {
  uint8_t ys = 1;
  foreach_active(i){
    ys = y;
  }
  
  return y == 0 ? 0 : x / ys;
}

static inline uint16_t udiv_safe16(uint16_t x, uint16_t y) {
  uint16_t ys = 1;
  foreach_active(i){
    ys = y;
  }
  
  return y == 0 ? 0 : x / ys;
}

static inline uint32_t udiv_safe32(uint32_t x, uint32_t y) {
  uint32_t ys = 1;
  foreach_active(i){
    ys = y;
  }
  
  return y == 0 ? 0 : x / ys;
}

static inline uint64_t udiv_safe64(uint64_t x, uint64_t y) {
  uint64_t ys = 1;
  foreach_active(i){
    ys = y;
  }
  
  return y == 0 ? 0 : x / ys;
}

static inline uint8_t udiv_up_safe8(uint8_t x, uint8_t y) {
  uint8_t ys = 1;
  foreach_active(i){
    ys = y;
  }
  
  return y == 0 ? 0 : (x + y - 1) / ys;
}

static inline uint16_t udiv_up_safe16(uint16_t x, uint16_t y) {
  uint16_t ys = 1;
  foreach_active(i){
    ys = y;
  }
  
  return y == 0 ? 0 : (x + y - 1) / ys;
}

static inline uint32_t udiv_up_safe32(uint32_t x, uint32_t y) {
  uint32_t ys = 1;
  foreach_active(i){
    ys = y;
  }
  
  return y == 0 ? 0 : (x + y - 1) / ys;
}

static inline uint64_t udiv_up_safe64(uint64_t x, uint64_t y) {
  uint64_t ys = 1;
  foreach_active(i){
    ys = y;
  }
  
  return y == 0 ? 0 : (x + y - 1) / ys;
}

static inline uint8_t umod_safe8(uint8_t x, uint8_t y) {
  uint8_t ys = 1;
  foreach_active(i){
    ys = y;
  }
  
  return y == 0 ? 0 : x % ys;
}

static inline uint16_t umod_safe16(uint16_t x, uint16_t y) {
  uint16_t ys = 1;
  foreach_active(i){
    ys = y;
  }
  
  return y == 0 ? 0 : x % ys;
}

static inline uint32_t umod_safe32(uint32_t x, uint32_t y) {
  uint32_t ys = 1;
  foreach_active(i){
    ys = y;
  }
  
  return y == 0 ? 0 : x % ys;
}

static inline uint64_t umod_safe64(uint64_t x, uint64_t y) {
  uint64_t ys = 1;
  foreach_active(i){
    ys = y;
  }
  
  return y == 0 ? 0 : x % ys;
}

static inline int8_t sdiv8(int8_t x, int8_t y) {
  int8_t ys = 1;
  foreach_active(i){
    ys = y;
  }
  
  int8_t q = x / ys;
  int8_t r = x % ys;

  return q - ((r != 0 && r < 0 != y < 0) ? 1 : 0);
}

static inline int16_t sdiv16(int16_t x, int16_t y) {
  int16_t ys = 1;
  foreach_active(i){
    ys = y;
  }
  
  int16_t q = x / ys;
  int16_t r = x % ys;

  return q - ((r != 0 && r < 0 != y < 0) ? 1 : 0);
}

static inline int32_t sdiv32(int32_t x, int32_t y) {
  int32_t ys = 1;
  foreach_active(i){
    ys = y;
  }
  int32_t q = x / ys;
  int32_t r = x % ys;

  return q - ((r != 0 && r < 0 != y < 0) ? 1 : 0);
}

static inline int64_t sdiv64(int64_t x, int64_t y) {
  int64_t ys = 1;
  foreach_active(i){
    ys = y;
  }
  
  int64_t q = x / ys;
  int64_t r = x % ys;

  return q - ((r != 0 && r < 0 != y < 0) ? 1 : 0);
}

static inline int8_t sdiv_up8(int8_t x, int8_t y) {
  return sdiv8(x + y - 1, y);
}

static inline int16_t sdiv_up16(int16_t x, int16_t y) {
  return sdiv16(x + y - 1, y);
}

static inline int32_t sdiv_up32(int32_t x, int32_t y) {
  return sdiv32(x + y - 1, y);
}

static inline int64_t sdiv_up64(int64_t x, int64_t y) {
  return sdiv64(x + y - 1, y);
}

static inline int8_t smod8(int8_t x, int8_t y) {
  int8_t ys = 1;
  foreach_active(i){
    ys = y;
  }
  
  int8_t r = x % ys;

  return r + (r == 0 || (x > 0 && y > 0) || (x < 0 && y < 0) ? 0 : y);
}

static inline int16_t smod16(int16_t x, int16_t y) {
  int16_t ys = 1;
  foreach_active(i){
    ys = y;
  }
  
  int16_t r = x % ys;

  return r + (r == 0 || (x > 0 && y > 0) || (x < 0 && y < 0) ? 0 : y);
}

static inline int32_t smod32(int32_t x, int32_t y) {
  int32_t ys = 1;
  foreach_active(i){
    ys = y;
  }
  
  int32_t r = x % ys;

  return r + (r == 0 || (x > 0 && y > 0) || (x < 0 && y < 0) ? 0 : y);
}

static inline int64_t smod64(int64_t x, int64_t y) {
  int64_t ys = 1;
  foreach_active(i){
    ys = y;
  }
  
  int64_t r = x % ys;

  return r + (r == 0 || (x > 0 && y > 0) || (x < 0 && y < 0) ? 0 : y);
}

static inline int8_t sdiv_safe8(int8_t x, int8_t y) {
  return y == 0 ? 0 : sdiv8(x, y);
}

static inline int16_t sdiv_safe16(int16_t x, int16_t y) {
  return y == 0 ? 0 : sdiv16(x, y);
}

static inline int32_t sdiv_safe32(int32_t x, int32_t y) {
  return y == 0 ? 0 : sdiv32(x, y);
}

static inline int64_t sdiv_safe64(int64_t x, int64_t y) {
  return y == 0 ? 0 : sdiv64(x, y);
}

static inline int8_t sdiv_up_safe8(int8_t x, int8_t y) {
  return sdiv_safe8(x + y - 1, y);
}

static inline int16_t sdiv_up_safe16(int16_t x, int16_t y) {
  return sdiv_safe16(x + y - 1, y);
}

static inline int32_t sdiv_up_safe32(int32_t x, int32_t y) {
  return sdiv_safe32(x + y - 1, y);
}

static inline int64_t sdiv_up_safe64(int64_t x, int64_t y) {
  return sdiv_safe64(x + y - 1, y);
}

static inline int8_t smod_safe8(int8_t x, int8_t y) {
  return y == 0 ? 0 : smod8(x, y);
}

static inline int16_t smod_safe16(int16_t x, int16_t y) {
  return y == 0 ? 0 : smod16(x, y);
}

static inline int32_t smod_safe32(int32_t x, int32_t y) {
  return y == 0 ? 0 : smod32(x, y);
}

static inline int64_t smod_safe64(int64_t x, int64_t y) {
  return y == 0 ? 0 : smod64(x, y);
}

static inline int8_t squot8(int8_t x, int8_t y) {
  int8_t ys = 1;
  foreach_active(i){
    ys = y;
  }
  
  return x / ys;
}

static inline int16_t squot16(int16_t x, int16_t y) {
  int16_t ys = 1;
  foreach_active(i){
    ys = y;
  }
  
  return x / ys;
}

static inline int32_t squot32(int32_t x, int32_t y) {
  int32_t ys = 1;
  foreach_active(i){
    ys = y;
  }
  
  return x / ys;
}

static inline int64_t squot64(int64_t x, int64_t y) {
  int64_t ys = 1;
  foreach_active(i){
    ys = y;
  }
  
  return x / ys;
}

static inline int8_t srem8(int8_t x, int8_t y) {
  int8_t ys = 1;
  foreach_active(i){
    ys = y;
  }
  
  return x % ys;
}

static inline int16_t srem16(int16_t x, int16_t y) {
  int16_t ys = 1;
  foreach_active(i){
    ys = y;
  }
  
  return x % ys;
}

static inline int32_t srem32(int32_t x, int32_t y) {
  int32_t ys = 1;
  foreach_active(i){
    ys = y;
  }
  
  return x % ys;
}

static inline int64_t srem64(int64_t x, int64_t y) {
  int8_t ys = 1;
  foreach_active(i){
    ys = y;
  }
  
  return x % ys;
}

static inline int8_t squot_safe8(int8_t x, int8_t y) {
  int8_t ys = 1;
  foreach_active(i){
    ys = y;
  }
  
  return y == 0 ? 0 : x / ys;
}

static inline int16_t squot_safe16(int16_t x, int16_t y) {
  int16_t ys = 1;
  foreach_active(i){
    ys = y;
  }
  
  return y == 0 ? 0 : x / ys;
}

static inline int32_t squot_safe32(int32_t x, int32_t y) {
  int32_t ys = 1;
  foreach_active(i){
    ys = y;
  }
  
  return y == 0 ? 0 : x / ys;
}

static inline int64_t squot_safe64(int64_t x, int64_t y) {
  int64_t ys = 1;
  foreach_active(i){
    ys = y;
  }
  
  return y == 0 ? 0 : x / ys;
}

static inline int8_t srem_safe8(int8_t x, int8_t y) {
  int8_t ys = 1;
  foreach_active(i){
    ys = y;
  }
  
  return y == 0 ? 0 : x % ys;
}

static inline int16_t srem_safe16(int16_t x, int16_t y) {
  int16_t ys = 1;
  foreach_active(i){
    ys = y;
  }
  
  return y == 0 ? 0 : x % ys;
}

static inline int32_t srem_safe32(int32_t x, int32_t y) {
  int32_t ys = 1;
  foreach_active(i){
    ys = y;
  }
  
  return y == 0 ? 0 : x % ys;
}

static inline int64_t srem_safe64(int64_t x, int64_t y) {
  int64_t ys = 1;
  foreach_active(i){
    ys = y;
  }
  
  return y == 0 ? 0 : x % ys;
}

#else

static inline uint8_t udiv8(uint8_t x, uint8_t y) {
  return x / y;
}

static inline uint16_t udiv16(uint16_t x, uint16_t y) {
  return x / y;
}

static inline uint32_t udiv32(uint32_t x, uint32_t y) {
  return x / y;
}

static inline uint64_t udiv64(uint64_t x, uint64_t y) {
  return x / y;
}

static inline uint8_t udiv_up8(uint8_t x, uint8_t y) {
  return (x + y - 1) / y;
}

static inline uint16_t udiv_up16(uint16_t x, uint16_t y) {
  return (x + y - 1) / y;
}

static inline uint32_t udiv_up32(uint32_t x, uint32_t y) {
  return (x + y - 1) / y;
}

static inline uint64_t udiv_up64(uint64_t x, uint64_t y) {
  return (x + y - 1) / y;
}

static inline uint8_t umod8(uint8_t x, uint8_t y) {
  return x % y;
}

static inline uint16_t umod16(uint16_t x, uint16_t y) {
  return x % y;
}

static inline uint32_t umod32(uint32_t x, uint32_t y) {
  return x % y;
}

static inline uint64_t umod64(uint64_t x, uint64_t y) {
  return x % y;
}

static inline uint8_t udiv_safe8(uint8_t x, uint8_t y) {
  return y == 0 ? 0 : x / y;
}

static inline uint16_t udiv_safe16(uint16_t x, uint16_t y) {
  return y == 0 ? 0 : x / y;
}

static inline uint32_t udiv_safe32(uint32_t x, uint32_t y) {
  return y == 0 ? 0 : x / y;
}

static inline uint64_t udiv_safe64(uint64_t x, uint64_t y) {
  return y == 0 ? 0 : x / y;
}

static inline uint8_t udiv_up_safe8(uint8_t x, uint8_t y) {
  return y == 0 ? 0 : (x + y - 1) / y;
}

static inline uint16_t udiv_up_safe16(uint16_t x, uint16_t y) {
  return y == 0 ? 0 : (x + y - 1) / y;
}

static inline uint32_t udiv_up_safe32(uint32_t x, uint32_t y) {
  return y == 0 ? 0 : (x + y - 1) / y;
}

static inline uint64_t udiv_up_safe64(uint64_t x, uint64_t y) {
  return y == 0 ? 0 : (x + y - 1) / y;
}

static inline uint8_t umod_safe8(uint8_t x, uint8_t y) {
  return y == 0 ? 0 : x % y;
}

static inline uint16_t umod_safe16(uint16_t x, uint16_t y) {
  return y == 0 ? 0 : x % y;
}

static inline uint32_t umod_safe32(uint32_t x, uint32_t y) {
  return y == 0 ? 0 : x % y;
}

static inline uint64_t umod_safe64(uint64_t x, uint64_t y) {
  return y == 0 ? 0 : x % y;
}

static inline int8_t sdiv8(int8_t x, int8_t y) {
  int8_t q = x / y;
  int8_t r = x % y;

  return q - ((r != 0 && r < 0 != y < 0) ? 1 : 0);
}

static inline int16_t sdiv16(int16_t x, int16_t y) {
  int16_t q = x / y;
  int16_t r = x % y;

  return q - ((r != 0 && r < 0 != y < 0) ? 1 : 0);
}

static inline int32_t sdiv32(int32_t x, int32_t y) {
  int32_t q = x / y;
  int32_t r = x % y;

  return q - ((r != 0 && r < 0 != y < 0) ? 1 : 0);
}

static inline int64_t sdiv64(int64_t x, int64_t y) {
  int64_t q = x / y;
  int64_t r = x % y;

  return q - ((r != 0 && r < 0 != y < 0) ? 1 : 0);
}

static inline int8_t sdiv_up8(int8_t x, int8_t y) {
  return sdiv8(x + y - 1, y);
}

static inline int16_t sdiv_up16(int16_t x, int16_t y) {
  return sdiv16(x + y - 1, y);
}

static inline int32_t sdiv_up32(int32_t x, int32_t y) {
  return sdiv32(x + y - 1, y);
}

static inline int64_t sdiv_up64(int64_t x, int64_t y) {
  return sdiv64(x + y - 1, y);
}

static inline int8_t smod8(int8_t x, int8_t y) {
  int8_t r = x % y;

  return r + (r == 0 || (x > 0 && y > 0) || (x < 0 && y < 0) ? 0 : y);
}

static inline int16_t smod16(int16_t x, int16_t y) {
  int16_t r = x % y;

  return r + (r == 0 || (x > 0 && y > 0) || (x < 0 && y < 0) ? 0 : y);
}

static inline int32_t smod32(int32_t x, int32_t y) {
  int32_t r = x % y;

  return r + (r == 0 || (x > 0 && y > 0) || (x < 0 && y < 0) ? 0 : y);
}

static inline int64_t smod64(int64_t x, int64_t y) {
  int64_t r = x % y;

  return r + (r == 0 || (x > 0 && y > 0) || (x < 0 && y < 0) ? 0 : y);
}

static inline int8_t sdiv_safe8(int8_t x, int8_t y) {
  return y == 0 ? 0 : sdiv8(x, y);
}

static inline int16_t sdiv_safe16(int16_t x, int16_t y) {
  return y == 0 ? 0 : sdiv16(x, y);
}

static inline int32_t sdiv_safe32(int32_t x, int32_t y) {
  return y == 0 ? 0 : sdiv32(x, y);
}

static inline int64_t sdiv_safe64(int64_t x, int64_t y) {
  return y == 0 ? 0 : sdiv64(x, y);
}

static inline int8_t sdiv_up_safe8(int8_t x, int8_t y) {
  return sdiv_safe8(x + y - 1, y);
}

static inline int16_t sdiv_up_safe16(int16_t x, int16_t y) {
  return sdiv_safe16(x + y - 1, y);
}

static inline int32_t sdiv_up_safe32(int32_t x, int32_t y) {
  return sdiv_safe32(x + y - 1, y);
}

static inline int64_t sdiv_up_safe64(int64_t x, int64_t y) {
  return sdiv_safe64(x + y - 1, y);
}

static inline int8_t smod_safe8(int8_t x, int8_t y) {
  return y == 0 ? 0 : smod8(x, y);
}

static inline int16_t smod_safe16(int16_t x, int16_t y) {
  return y == 0 ? 0 : smod16(x, y);
}

static inline int32_t smod_safe32(int32_t x, int32_t y) {
  return y == 0 ? 0 : smod32(x, y);
}

static inline int64_t smod_safe64(int64_t x, int64_t y) {
  return y == 0 ? 0 : smod64(x, y);
}

static inline int8_t squot8(int8_t x, int8_t y) {
  return x / y;
}

static inline int16_t squot16(int16_t x, int16_t y) {
  return x / y;
}

static inline int32_t squot32(int32_t x, int32_t y) {
  return x / y;
}

static inline int64_t squot64(int64_t x, int64_t y) {
  return x / y;
}

static inline int8_t srem8(int8_t x, int8_t y) {
  return x % y;
}

static inline int16_t srem16(int16_t x, int16_t y) {
  return x % y;
}

static inline int32_t srem32(int32_t x, int32_t y) {
  return x % y;
}

static inline int64_t srem64(int64_t x, int64_t y) {
  return x % y;
}

static inline int8_t squot_safe8(int8_t x, int8_t y) {
  return y == 0 ? 0 : x / y;
}

static inline int16_t squot_safe16(int16_t x, int16_t y) {
  return y == 0 ? 0 : x / y;
}

static inline int32_t squot_safe32(int32_t x, int32_t y) {
  return y == 0 ? 0 : x / y;
}

static inline int64_t squot_safe64(int64_t x, int64_t y) {
  return y == 0 ? 0 : x / y;
}

static inline int8_t srem_safe8(int8_t x, int8_t y) {
  return y == 0 ? 0 : x % y;
}

static inline int16_t srem_safe16(int16_t x, int16_t y) {
  return y == 0 ? 0 : x % y;
}

static inline int32_t srem_safe32(int32_t x, int32_t y) {
  return y == 0 ? 0 : x % y;
}

static inline int64_t srem_safe64(int64_t x, int64_t y) {
  return y == 0 ? 0 : x % y;
}

#endif

static inline int8_t smin8(int8_t x, int8_t y) {
  return x < y ? x : y;
}

static inline int16_t smin16(int16_t x, int16_t y) {
  return x < y ? x : y;
}

static inline int32_t smin32(int32_t x, int32_t y) {
  return x < y ? x : y;
}

static inline int64_t smin64(int64_t x, int64_t y) {
  return x < y ? x : y;
}

static inline uint8_t umin8(uint8_t x, uint8_t y) {
  return x < y ? x : y;
}

static inline uint16_t umin16(uint16_t x, uint16_t y) {
  return x < y ? x : y;
}

static inline uint32_t umin32(uint32_t x, uint32_t y) {
  return x < y ? x : y;
}

static inline uint64_t umin64(uint64_t x, uint64_t y) {
  return x < y ? x : y;
}

static inline int8_t smax8(int8_t x, int8_t y) {
  return x < y ? y : x;
}

static inline int16_t smax16(int16_t x, int16_t y) {
  return x < y ? y : x;
}

static inline int32_t smax32(int32_t x, int32_t y) {
  return x < y ? y : x;
}

static inline int64_t smax64(int64_t x, int64_t y) {
  return x < y ? y : x;
}

static inline uint8_t umax8(uint8_t x, uint8_t y) {
  return x < y ? y : x;
}

static inline uint16_t umax16(uint16_t x, uint16_t y) {
  return x < y ? y : x;
}

static inline uint32_t umax32(uint32_t x, uint32_t y) {
  return x < y ? y : x;
}

static inline uint64_t umax64(uint64_t x, uint64_t y) {
  return x < y ? y : x;
}

static inline uint8_t shl8(uint8_t x, uint8_t y) {
  return (uint8_t)(x << y);
}

static inline uint16_t shl16(uint16_t x, uint16_t y) {
  return (uint16_t)(x << y);
}

static inline uint32_t shl32(uint32_t x, uint32_t y) {
  return x << y;
}

static inline uint64_t shl64(uint64_t x, uint64_t y) {
  return x << y;
}

static inline uint8_t lshr8(uint8_t x, uint8_t y) {
  return x >> y;
}

static inline uint16_t lshr16(uint16_t x, uint16_t y) {
  return x >> y;
}

static inline uint32_t lshr32(uint32_t x, uint32_t y) {
  return x >> y;
}

static inline uint64_t lshr64(uint64_t x, uint64_t y) {
  return x >> y;
}

static inline int8_t ashr8(int8_t x, int8_t y) {
  return x >> y;
}

static inline int16_t ashr16(int16_t x, int16_t y) {
  return x >> y;
}

static inline int32_t ashr32(int32_t x, int32_t y) {
  return x >> y;
}

static inline int64_t ashr64(int64_t x, int64_t y) {
  return x >> y;
}

static inline uint8_t and8(uint8_t x, uint8_t y) {
  return x & y;
}

static inline uint16_t and16(uint16_t x, uint16_t y) {
  return x & y;
}

static inline uint32_t and32(uint32_t x, uint32_t y) {
  return x & y;
}

static inline uint64_t and64(uint64_t x, uint64_t y) {
  return x & y;
}

static inline uint8_t or8(uint8_t x, uint8_t y) {
  return x | y;
}

static inline uint16_t or16(uint16_t x, uint16_t y) {
  return x | y;
}

static inline uint32_t or32(uint32_t x, uint32_t y) {
  return x | y;
}

static inline uint64_t or64(uint64_t x, uint64_t y) {
  return x | y;
}

static inline uint8_t xor8(uint8_t x, uint8_t y) {
  return x ^ y;
}

static inline uint16_t xor16(uint16_t x, uint16_t y) {
  return x ^ y;
}

static inline uint32_t xor32(uint32_t x, uint32_t y) {
  return x ^ y;
}

static inline uint64_t xor64(uint64_t x, uint64_t y) {
  return x ^ y;
}

static inline bool ult8(uint8_t x, uint8_t y) {
  return x < y;
}

static inline bool ult16(uint16_t x, uint16_t y) {
  return x < y;
}

static inline bool ult32(uint32_t x, uint32_t y) {
  return x < y;
}

static inline bool ult64(uint64_t x, uint64_t y) {
  return x < y;
}

static inline bool ule8(uint8_t x, uint8_t y) {
  return x <= y;
}

static inline bool ule16(uint16_t x, uint16_t y) {
  return x <= y;
}

static inline bool ule32(uint32_t x, uint32_t y) {
  return x <= y;
}

static inline bool ule64(uint64_t x, uint64_t y) {
  return x <= y;
}

static inline bool slt8(int8_t x, int8_t y) {
  return x < y;
}

static inline bool slt16(int16_t x, int16_t y) {
  return x < y;
}

static inline bool slt32(int32_t x, int32_t y) {
  return x < y;
}

static inline bool slt64(int64_t x, int64_t y) {
  return x < y;
}

static inline bool sle8(int8_t x, int8_t y) {
  return x <= y;
}

static inline bool sle16(int16_t x, int16_t y) {
  return x <= y;
}

static inline bool sle32(int32_t x, int32_t y) {
  return x <= y;
}

static inline bool sle64(int64_t x, int64_t y) {
  return x <= y;
}

static inline uint8_t pow8(uint8_t x, uint8_t y) {
  uint8_t res = 1, rem = y;

  while (rem != 0) {
    if (rem & 1)
      res *= x;
    rem >>= 1;
    x *= x;
  }
  return res;
}

static inline uint16_t pow16(uint16_t x, uint16_t y) {
  uint16_t res = 1, rem = y;

  while (rem != 0) {
    if (rem & 1)
      res *= x;
    rem >>= 1;
    x *= x;
  }
  return res;
}

static inline uint32_t pow32(uint32_t x, uint32_t y) {
  uint32_t res = 1, rem = y;

  while (rem != 0) {
    if (rem & 1)
      res *= x;
    rem >>= 1;
    x *= x;
  }
  return res;
}

static inline uint64_t pow64(uint64_t x, uint64_t y) {
  uint64_t res = 1, rem = y;

  while (rem != 0) {
    if (rem & 1)
      res *= x;
    rem >>= 1;
    x *= x;
  }
  return res;
}

static inline bool itob_i8_bool(int8_t x) {
  return x != 0;
}

static inline bool itob_i16_bool(int16_t x) {
  return x != 0;
}

static inline bool itob_i32_bool(int32_t x) {
  return x != 0;
}

static inline bool itob_i64_bool(int64_t x) {
  return x != 0;
}

static inline int8_t btoi_bool_i8(bool x) {
  return x;
}

static inline int16_t btoi_bool_i16(bool x) {
  return x;
}

static inline int32_t btoi_bool_i32(bool x) {
  return x;
}

static inline int64_t btoi_bool_i64(bool x) {
  return x;
}

#define sext_i8_i8(x) ((int8_t) (int8_t) (x))
#define sext_i8_i16(x) ((int16_t) (int8_t) (x))
#define sext_i8_i32(x) ((int32_t) (int8_t) (x))
#define sext_i8_i64(x) ((int64_t) (int8_t) (x))
#define sext_i16_i8(x) ((int8_t) (int16_t) (x))
#define sext_i16_i16(x) ((int16_t) (int16_t) (x))
#define sext_i16_i32(x) ((int32_t) (int16_t) (x))
#define sext_i16_i64(x) ((int64_t) (int16_t) (x))
#define sext_i32_i8(x) ((int8_t) (int32_t) (x))
#define sext_i32_i16(x) ((int16_t) (int32_t) (x))
#define sext_i32_i32(x) ((int32_t) (int32_t) (x))
#define sext_i32_i64(x) ((int64_t) (int32_t) (x))
#define sext_i64_i8(x) ((int8_t) (int64_t) (x))
#define sext_i64_i16(x) ((int16_t) (int64_t) (x))
#define sext_i64_i32(x) ((int32_t) (int64_t) (x))
#define sext_i64_i64(x) ((int64_t) (int64_t) (x))
#define zext_i8_i8(x) ((int8_t) (uint8_t) (x))
#define zext_i8_i16(x) ((int16_t) (uint8_t) (x))
#define zext_i8_i32(x) ((int32_t) (uint8_t) (x))
#define zext_i8_i64(x) ((int64_t) (uint8_t) (x))
#define zext_i16_i8(x) ((int8_t) (uint16_t) (x))
#define zext_i16_i16(x) ((int16_t) (uint16_t) (x))
#define zext_i16_i32(x) ((int32_t) (uint16_t) (x))
#define zext_i16_i64(x) ((int64_t) (uint16_t) (x))
#define zext_i32_i8(x) ((int8_t) (uint32_t) (x))
#define zext_i32_i16(x) ((int16_t) (uint32_t) (x))
#define zext_i32_i32(x) ((int32_t) (uint32_t) (x))
#define zext_i32_i64(x) ((int64_t) (uint32_t) (x))
#define zext_i64_i8(x) ((int8_t) (uint64_t) (x))
#define zext_i64_i16(x) ((int16_t) (uint64_t) (x))
#define zext_i64_i32(x) ((int32_t) (uint64_t) (x))
#define zext_i64_i64(x) ((int64_t) (uint64_t) (x))

static int8_t abs8(int8_t x) {
  return (int8_t)abs(x);
}

static int16_t abs16(int16_t x) {
  return (int16_t)abs(x);
}

static int32_t abs32(int32_t x) {
  return abs(x);
}

static int64_t abs64(int64_t x) {
#if defined(__OPENCL_VERSION__) || defined(ISPC)
  return abs(x);
#else
  return llabs(x);
#endif
}

#if defined(__OPENCL_VERSION__)
static int32_t futrts_popc8(int8_t x) {
  return popcount(x);
}

static int32_t futrts_popc16(int16_t x) {
  return popcount(x);
}

static int32_t futrts_popc32(int32_t x) {
  return popcount(x);
}

static int32_t futrts_popc64(int64_t x) {
  return popcount(x);
}
#elif defined(__CUDA_ARCH__)

static int32_t futrts_popc8(int8_t x) {
  return __popc(zext_i8_i32(x));
}

static int32_t futrts_popc16(int16_t x) {
  return __popc(zext_i16_i32(x));
}

static int32_t futrts_popc32(int32_t x) {
  return __popc(x);
}

static int32_t futrts_popc64(int64_t x) {
  return __popcll(x);
}

#else // Not OpenCL or CUDA, but plain C.

static int32_t futrts_popc8(uint8_t x) {
  int c = 0;
  for (; x; ++c) { x &= x - 1; }
  return c;
}

static int32_t futrts_popc16(uint16_t x) {
  int c = 0;
  for (; x; ++c) { x &= x - 1; }
  return c;
}

static int32_t futrts_popc32(uint32_t x) {
  int c = 0;
  for (; x; ++c) { x &= x - 1; }
  return c;
}

static int32_t futrts_popc64(uint64_t x) {
  int c = 0;
  for (; x; ++c) { x &= x - 1; }
  return c;
}
#endif

#if defined(__OPENCL_VERSION__)
static uint8_t futrts_mul_hi8(uint8_t a, uint8_t b) {
  return mul_hi(a, b);
}

static uint16_t futrts_mul_hi16(uint16_t a, uint16_t b) {
  return mul_hi(a, b);
}

static uint32_t futrts_mul_hi32(uint32_t a, uint32_t b) {
  return mul_hi(a, b);
}

static uint64_t futrts_mul_hi64(uint64_t a, uint64_t b) {
  return mul_hi(a, b);
}

#elif defined(__CUDA_ARCH__)

static uint8_t futrts_mul_hi8(uint8_t a, uint8_t b) {
  uint16_t aa = a;
  uint16_t bb = b;

  return aa * bb >> 8;
}

static uint16_t futrts_mul_hi16(uint16_t a, uint16_t b) {
  uint32_t aa = a;
  uint32_t bb = b;

  return aa * bb >> 16;
}

static uint32_t futrts_mul_hi32(uint32_t a, uint32_t b) {
  return mulhi(a, b);
}

static uint64_t futrts_mul_hi64(uint64_t a, uint64_t b) {
  return mul64hi(a, b);
}

#elif ISPC

static uint8_t futrts_mul_hi8(uint8_t a, uint8_t b) {
  uint16_t aa = a;
  uint16_t bb = b;

  return aa * bb >> 8;
}

static uint16_t futrts_mul_hi16(uint16_t a, uint16_t b) {
  uint32_t aa = a;
  uint32_t bb = b;

  return aa * bb >> 16;
}

static uint32_t futrts_mul_hi32(uint32_t a, uint32_t b) {
  uint64_t aa = a;
  uint64_t bb = b;

  return aa * bb >> 32;
}

static uint64_t futrts_mul_hi64(uint64_t a, uint64_t b) {
  uint64_t ah = a >> 32;
  uint64_t al = a & 0xffffffff;
  uint64_t bh = b >> 32;
  uint64_t bl = b & 0xffffffff;

  uint64_t p1 = al * bl;
  uint64_t p2 = al * bh;
  uint64_t p3 = ah * bl;
  uint64_t p4 = ah * bh;

  uint64_t p1h = p1 >> 32;
  uint64_t p2h = p2 >> 32;
  uint64_t p3h = p3 >> 32;
  uint64_t p2l = p2 & 0xffffffff;
  uint64_t p3l = p3 & 0xffffffff;

  uint64_t l = p1h + p2l  + p3l;
  uint64_t m = (p2 >> 32) + (p3 >> 32);
  uint64_t h = (l >> 32) + m + p4;

  return h;
}

#else // Not OpenCL, ISPC, or CUDA, but plain C.

static uint8_t futrts_mul_hi8(uint8_t a, uint8_t b) {
  uint16_t aa = a;
  uint16_t bb = b;

  return aa * bb >> 8;
}

static uint16_t futrts_mul_hi16(uint16_t a, uint16_t b) {
  uint32_t aa = a;
  uint32_t bb = b;

  return aa * bb >> 16;
}

static uint32_t futrts_mul_hi32(uint32_t a, uint32_t b) {
  uint64_t aa = a;
  uint64_t bb = b;

  return aa * bb >> 32;
}

static uint64_t futrts_mul_hi64(uint64_t a, uint64_t b) {
  __uint128_t aa = a;
  __uint128_t bb = b;

  return aa * bb >> 64;
}
#endif

#if defined(__OPENCL_VERSION__)
static uint8_t futrts_mad_hi8(uint8_t a, uint8_t b, uint8_t c) {
  return mad_hi(a, b, c);
}

static uint16_t futrts_mad_hi16(uint16_t a, uint16_t b, uint16_t c) {
  return mad_hi(a, b, c);
}

static uint32_t futrts_mad_hi32(uint32_t a, uint32_t b, uint32_t c) {
  return mad_hi(a, b, c);
}

static uint64_t futrts_mad_hi64(uint64_t a, uint64_t b, uint64_t c) {
  return mad_hi(a, b, c);
}

#else // Not OpenCL

static uint8_t futrts_mad_hi8(uint8_t a, uint8_t b, uint8_t c) {
  return futrts_mul_hi8(a, b) + c;
}

static uint16_t futrts_mad_hi16(uint16_t a, uint16_t b, uint16_t c) {
  return futrts_mul_hi16(a, b) + c;
}

static uint32_t futrts_mad_hi32(uint32_t a, uint32_t b, uint32_t c) {
  return futrts_mul_hi32(a, b) + c;
}

static uint64_t futrts_mad_hi64(uint64_t a, uint64_t b, uint64_t c) {
  return futrts_mul_hi64(a, b) + c;
}
#endif

#if defined(__OPENCL_VERSION__)
static int32_t futrts_clzz8(int8_t x) {
  return clz(x);
}

static int32_t futrts_clzz16(int16_t x) {
  return clz(x);
}

static int32_t futrts_clzz32(int32_t x) {
  return clz(x);
}

static int32_t futrts_clzz64(int64_t x) {
  return clz(x);
}

#elif defined(__CUDA_ARCH__)

static int32_t futrts_clzz8(int8_t x) {
  return __clz(zext_i8_i32(x)) - 24;
}

static int32_t futrts_clzz16(int16_t x) {
  return __clz(zext_i16_i32(x)) - 16;
}

static int32_t futrts_clzz32(int32_t x) {
  return __clz(x);
}

static int32_t futrts_clzz64(int64_t x) {
  return __clzll(x);
}

#elif ISPC

static int32_t futrts_clzz8(int8_t x) {
  return count_leading_zeros((int32_t)(uint8_t)x)-24;
}

static int32_t futrts_clzz16(int16_t x) {
  return count_leading_zeros((int32_t)(uint16_t)x)-16;
}

static int32_t futrts_clzz32(int32_t x) {
  return count_leading_zeros(x);
}

static int32_t futrts_clzz64(int64_t x) {
  return count_leading_zeros(x);
}

#else // Not OpenCL, ISPC or CUDA, but plain C.

static int32_t futrts_clzz8(int8_t x) {
  return x == 0 ? 8 : __builtin_clz((uint32_t)zext_i8_i32(x)) - 24;
}

static int32_t futrts_clzz16(int16_t x) {
  return x == 0 ? 16 : __builtin_clz((uint32_t)zext_i16_i32(x)) - 16;
}

static int32_t futrts_clzz32(int32_t x) {
  return x == 0 ? 32 : __builtin_clz((uint32_t)x);
}

static int32_t futrts_clzz64(int64_t x) {
  return x == 0 ? 64 : __builtin_clzll((uint64_t)x);
}
#endif

#if defined(__OPENCL_VERSION__)
static int32_t futrts_ctzz8(int8_t x) {
  int i = 0;
  for (; i < 8 && (x & 1) == 0; i++, x >>= 1)
    ;
  return i;
}

static int32_t futrts_ctzz16(int16_t x) {
  int i = 0;
  for (; i < 16 && (x & 1) == 0; i++, x >>= 1)
    ;
  return i;
}

static int32_t futrts_ctzz32(int32_t x) {
  int i = 0;
  for (; i < 32 && (x & 1) == 0; i++, x >>= 1)
    ;
  return i;
}

static int32_t futrts_ctzz64(int64_t x) {
  int i = 0;
  for (; i < 64 && (x & 1) == 0; i++, x >>= 1)
    ;
  return i;
}

#elif defined(__CUDA_ARCH__)

static int32_t futrts_ctzz8(int8_t x) {
  int y = __ffs(x);
  return y == 0 ? 8 : y - 1;
}

static int32_t futrts_ctzz16(int16_t x) {
  int y = __ffs(x);
  return y == 0 ? 16 : y - 1;
}

static int32_t futrts_ctzz32(int32_t x) {
  int y = __ffs(x);
  return y == 0 ? 32 : y - 1;
}

static int32_t futrts_ctzz64(int64_t x) {
  int y = __ffsll(x);
  return y == 0 ? 64 : y - 1;
}

#elif ISPC

static int32_t futrts_ctzz8(int8_t x) {
  return x == 0 ? 8 : count_trailing_zeros((int32_t)x);
}

static int32_t futrts_ctzz16(int16_t x) {
  return x == 0 ? 16 : count_trailing_zeros((int32_t)x);
}

static int32_t futrts_ctzz32(int32_t x) {
  return count_trailing_zeros(x);
}

static int32_t futrts_ctzz64(int64_t x) {
  return count_trailing_zeros(x);
}

#else // Not OpenCL or CUDA, but plain C.

static int32_t futrts_ctzz8(int8_t x) {
  return x == 0 ? 8 : __builtin_ctz((uint32_t)x);
}

static int32_t futrts_ctzz16(int16_t x) {
  return x == 0 ? 16 : __builtin_ctz((uint32_t)x);
}

static int32_t futrts_ctzz32(int32_t x) {
  return x == 0 ? 32 : __builtin_ctz((uint32_t)x);
}

static int32_t futrts_ctzz64(int64_t x) {
  return x == 0 ? 64 : __builtin_ctzll((uint64_t)x);
}
#endif

static inline float fdiv32(float x, float y) {
  return x / y;
}

static inline float fadd32(float x, float y) {
  return x + y;
}

static inline float fsub32(float x, float y) {
  return x - y;
}

static inline float fmul32(float x, float y) {
  return x * y;
}

static inline bool cmplt32(float x, float y) {
  return x < y;
}

static inline bool cmple32(float x, float y) {
  return x <= y;
}

static inline float sitofp_i8_f32(int8_t x) {
  return (float) x;
}

static inline float sitofp_i16_f32(int16_t x) {
  return (float) x;
}

static inline float sitofp_i32_f32(int32_t x) {
  return (float) x;
}

static inline float sitofp_i64_f32(int64_t x) {
  return (float) x;
}

static inline float uitofp_i8_f32(uint8_t x) {
  return (float) x;
}

static inline float uitofp_i16_f32(uint16_t x) {
  return (float) x;
}

static inline float uitofp_i32_f32(uint32_t x) {
  return (float) x;
}

static inline float uitofp_i64_f32(uint64_t x) {
  return (float) x;
}

#ifdef __OPENCL_VERSION__
static inline float fabs32(float x) {
  return fabs(x);
}

static inline float fmax32(float x, float y) {
  return fmax(x, y);
}

static inline float fmin32(float x, float y) {
  return fmin(x, y);
}

static inline float fpow32(float x, float y) {
  return pow(x, y);
}

#elif ISPC

static inline float fabs32(float x) {
  return abs(x);
}

static inline float fmax32(float x, float y) {
  return isnan(x) ? y : isnan(y) ? x : max(x, y);
}

static inline float fmin32(float x, float y) {
  return isnan(x) ? y : isnan(y) ? x : min(x, y);
}

static inline float fpow32(float a, float b) {
  float ret;
  foreach_active (i) {
      uniform float r = __stdlib_powf(extract(a, i), extract(b, i));
      ret = insert(ret, i, r);
  }
  return ret;
}

#else // Not OpenCL, but CUDA or plain C.

static inline float fabs32(float x) {
  return fabsf(x);
}

static inline float fmax32(float x, float y) {
  return fmaxf(x, y);
}

static inline float fmin32(float x, float y) {
  return fminf(x, y);
}

static inline float fpow32(float x, float y) {
  return powf(x, y);
}
#endif

static inline bool futrts_isnan32(float x) {
  return isnan(x);
}

#if ISPC

static inline bool futrts_isinf32(float x) {
  return !isnan(x) && isnan(x - x);
}

static inline bool futrts_isfinite32(float x) {
  return !isnan(x) && !futrts_isinf32(x);
}

#else

static inline bool futrts_isinf32(float x) {
  return isinf(x);
}

#endif

static inline int8_t fptosi_f32_i8(float x) {
  if (futrts_isnan32(x) || futrts_isinf32(x)) {
    return 0;
  } else {
    return (int8_t) x;
  }
}

static inline int16_t fptosi_f32_i16(float x) {
  if (futrts_isnan32(x) || futrts_isinf32(x)) {
    return 0;
  } else {
    return (int16_t) x;
  }
}

static inline int32_t fptosi_f32_i32(float x) {
  if (futrts_isnan32(x) || futrts_isinf32(x)) {
    return 0;
  } else {
    return (int32_t) x;
  }
}

static inline int64_t fptosi_f32_i64(float x) {
  if (futrts_isnan32(x) || futrts_isinf32(x)) {
    return 0;
  } else {
    return (int64_t) x;
  };
}

static inline uint8_t fptoui_f32_i8(float x) {
  if (futrts_isnan32(x) || futrts_isinf32(x)) {
    return 0;
  } else {
    return (uint8_t) (int8_t) x;
  }
}

static inline uint16_t fptoui_f32_i16(float x) {
  if (futrts_isnan32(x) || futrts_isinf32(x)) {
    return 0;
  } else {
    return (uint16_t) (int16_t) x;
  }
}

static inline uint32_t fptoui_f32_i32(float x) {
  if (futrts_isnan32(x) || futrts_isinf32(x)) {
    return 0;
  } else {
    return (uint32_t) (int32_t) x;
  }
}

static inline uint64_t fptoui_f32_i64(float x) {
  if (futrts_isnan32(x) || futrts_isinf32(x)) {
    return 0;
  } else {
    return (uint64_t) (int64_t) x;
  }
}

static inline bool ftob_f32_bool(float x) {
  return x != 0;
}

static inline float btof_bool_f32(bool x) {
  return x ? 1 : 0;
}

#ifdef __OPENCL_VERSION__
static inline float futrts_log32(float x) {
  return log(x);
}

static inline float futrts_log2_32(float x) {
  return log2(x);
}

static inline float futrts_log10_32(float x) {
  return log10(x);
}

static inline float futrts_sqrt32(float x) {
  return sqrt(x);
}

static inline float futrts_cbrt32(float x) {
  return cbrt(x);
}

static inline float futrts_exp32(float x) {
  return exp(x);
}

static inline float futrts_cos32(float x) {
  return cos(x);
}

static inline float futrts_sin32(float x) {
  return sin(x);
}

static inline float futrts_tan32(float x) {
  return tan(x);
}

static inline float futrts_acos32(float x) {
  return acos(x);
}

static inline float futrts_asin32(float x) {
  return asin(x);
}

static inline float futrts_atan32(float x) {
  return atan(x);
}

static inline float futrts_cosh32(float x) {
  return cosh(x);
}

static inline float futrts_sinh32(float x) {
  return sinh(x);
}

static inline float futrts_tanh32(float x) {
  return tanh(x);
}

static inline float futrts_acosh32(float x) {
  return acosh(x);
}

static inline float futrts_asinh32(float x) {
  return asinh(x);
}

static inline float futrts_atanh32(float x) {
  return atanh(x);
}

static inline float futrts_atan2_32(float x, float y) {
  return atan2(x, y);
}

static inline float futrts_hypot32(float x, float y) {
  return hypot(x, y);
}

static inline float futrts_gamma32(float x) {
  return tgamma(x);
}

static inline float futrts_lgamma32(float x) {
  return lgamma(x);
}

static inline float futrts_erf32(float x) {
  return erf(x);
}

static inline float futrts_erfc32(float x) {
  return erfc(x);
}

static inline float fmod32(float x, float y) {
  return fmod(x, y);
}

static inline float futrts_round32(float x) {
  return rint(x);
}

static inline float futrts_floor32(float x) {
  return floor(x);
}

static inline float futrts_ceil32(float x) {
  return ceil(x);
}

static inline float futrts_lerp32(float v0, float v1, float t) {
  return mix(v0, v1, t);
}

static inline float futrts_mad32(float a, float b, float c) {
  return mad(a, b, c);
}

static inline float futrts_fma32(float a, float b, float c) {
  return fma(a, b, c);
}

#elif ISPC

static inline float futrts_log32(float x) {
  return futrts_isfinite32(x) || (futrts_isinf32(x) && x < 0)? log(x) : x;
}

static inline float futrts_log2_32(float x) {
  return futrts_log32(x) / log(2.0f);
}

static inline float futrts_log10_32(float x) {
  return futrts_log32(x) / log(10.0f);
}

static inline float futrts_sqrt32(float x) {
  return sqrt(x);
}

extern "C" unmasked uniform float cbrtf(uniform float);
static inline float futrts_cbrt32(float x) {
  float res;
  foreach_active (i) {
    uniform float r = cbrtf(extract(x, i));
    res = insert(res, i, r);
  }
  return res;
}

static inline float futrts_exp32(float x) {
  return exp(x);
}

static inline float futrts_cos32(float x) {
  return cos(x);
}

static inline float futrts_sin32(float x) {
  return sin(x);
}

static inline float futrts_tan32(float x) {
  return tan(x);
}

static inline float futrts_acos32(float x) {
  return acos(x);
}

static inline float futrts_asin32(float x) {
  return asin(x);
}

static inline float futrts_atan32(float x) {
  return atan(x);
}

static inline float futrts_cosh32(float x) {
  return (exp(x)+exp(-x)) / 2.0f;
}

static inline float futrts_sinh32(float x) {
  return (exp(x)-exp(-x)) / 2.0f;
}

static inline float futrts_tanh32(float x) {
  return futrts_sinh32(x)/futrts_cosh32(x);
}

static inline float futrts_acosh32(float x) {
  float f = x+sqrt(x*x-1);
  if(futrts_isfinite32(f)) return log(f);
  return f;
}

static inline float futrts_asinh32(float x) {
  float f = x+sqrt(x*x+1);
  if(futrts_isfinite32(f)) return log(f);
  return f;

}

static inline float futrts_atanh32(float x) {
  float f = (1+x)/(1-x);
  if(futrts_isfinite32(f)) return log(f)/2.0f;
  return f;

}

static inline float futrts_atan2_32(float x, float y) {
  return (x == 0.0f && y == 0.0f) ? 0.0f : atan2(x, y);
}

static inline float futrts_hypot32(float x, float y) {
  if (futrts_isfinite32(x) && futrts_isfinite32(y)) {
    x = abs(x);
    y = abs(y);
    float a;
    float b;
    if (x >= y){
        a = x;
        b = y;
    } else {
        a = y;
        b = x;
    }
    if(b == 0){
      return a;
    }

    int e;
    float an;
    float bn;
    an = frexp (a, &e);
    bn = ldexp (b, - e);
    float cn;
    cn = sqrt (an * an + bn * bn);
    return ldexp (cn, e);
  } else {
    if (futrts_isinf32(x) || futrts_isinf32(y)) return INFINITY;
    else return x + y;
  }

}

extern "C" unmasked uniform float tgammaf(uniform float x);
static inline float futrts_gamma32(float x) {
  float res;
  foreach_active (i) {
    uniform float r = tgammaf(extract(x, i));
    res = insert(res, i, r);
  }
  return res;
}

extern "C" unmasked uniform float lgammaf(uniform float x);
static inline float futrts_lgamma32(float x) {
  float res;
  foreach_active (i) {
    uniform float r = lgammaf(extract(x, i));
    res = insert(res, i, r);
  }
  return res;
}

extern "C" unmasked uniform float erff(uniform float x);
static inline float futrts_erf32(float x) {
  float res;
  foreach_active (i) {
    uniform float r = erff(extract(x, i));
    res = insert(res, i, r);
  }
  return res;
}

extern "C" unmasked uniform float erfcf(uniform float x);
static inline float futrts_erfc32(float x) {
  float res;
  foreach_active (i) {
    uniform float r = erfcf(extract(x, i));
    res = insert(res, i, r);
  }
  return res;
}

static inline float fmod32(float x, float y) {
  return x - y * trunc(x/y);
}

static inline float futrts_round32(float x) {
  return round(x);
}

static inline float futrts_floor32(float x) {
  return floor(x);
}

static inline float futrts_ceil32(float x) {
  return ceil(x);
}

static inline float futrts_lerp32(float v0, float v1, float t) {
  return v0 + (v1 - v0) * t;
}

static inline float futrts_mad32(float a, float b, float c) {
  return a * b + c;
}

static inline float futrts_fma32(float a, float b, float c) {
  return a * b + c;
}

#else // Not OpenCL or ISPC, but CUDA or plain C.

static inline float futrts_log32(float x) {
  return logf(x);
}

static inline float futrts_log2_32(float x) {
  return log2f(x);
}

static inline float futrts_log10_32(float x) {
  return log10f(x);
}

static inline float futrts_sqrt32(float x) {
  return sqrtf(x);
}

static inline float futrts_cbrt32(float x) {
  return cbrtf(x);
}

static inline float futrts_exp32(float x) {
  return expf(x);
}

static inline float futrts_cos32(float x) {
  return cosf(x);
}

static inline float futrts_sin32(float x) {
  return sinf(x);
}

static inline float futrts_tan32(float x) {
  return tanf(x);
}

static inline float futrts_acos32(float x) {
  return acosf(x);
}

static inline float futrts_asin32(float x) {
  return asinf(x);
}

static inline float futrts_atan32(float x) {
  return atanf(x);
}

static inline float futrts_cosh32(float x) {
  return coshf(x);
}

static inline float futrts_sinh32(float x) {
  return sinhf(x);
}

static inline float futrts_tanh32(float x) {
  return tanhf(x);
}

static inline float futrts_acosh32(float x) {
  return acoshf(x);
}

static inline float futrts_asinh32(float x) {
  return asinhf(x);
}

static inline float futrts_atanh32(float x) {
  return atanhf(x);
}

static inline float futrts_atan2_32(float x, float y) {
  return atan2f(x, y);
}

static inline float futrts_hypot32(float x, float y) {
  return hypotf(x, y);
}

static inline float futrts_gamma32(float x) {
  return tgammaf(x);
}

static inline float futrts_lgamma32(float x) {
  return lgammaf(x);
}

static inline float futrts_erf32(float x) {
  return erff(x);
}

static inline float futrts_erfc32(float x) {
  return erfcf(x);
}

static inline float fmod32(float x, float y) {
  return fmodf(x, y);
}

static inline float futrts_round32(float x) {
  return rintf(x);
}

static inline float futrts_floor32(float x) {
  return floorf(x);
}

static inline float futrts_ceil32(float x) {
  return ceilf(x);
}

static inline float futrts_lerp32(float v0, float v1, float t) {
  return v0 + (v1 - v0) * t;
}

static inline float futrts_mad32(float a, float b, float c) {
  return a * b + c;
}

static inline float futrts_fma32(float a, float b, float c) {
  return fmaf(a, b, c);
}
#endif

#if ISPC
static inline int32_t futrts_to_bits32(float x) {
  return intbits(x);
}

static inline float futrts_from_bits32(int32_t x) {
  return floatbits(x);
}
#else
static inline int32_t futrts_to_bits32(float x) {
  union {
    float f;
    int32_t t;
  } p;

  p.f = x;
  return p.t;
}

static inline float futrts_from_bits32(int32_t x) {
  union {
    int32_t f;
    float t;
  } p;

  p.f = x;
  return p.t;
}
#endif

static inline float fsignum32(float x) {
  return futrts_isnan32(x) ? x : (x > 0 ? 1 : 0) - (x < 0 ? 1 : 0);
}

#ifdef FUTHARK_F64_ENABLED

#if ISPC
static inline bool futrts_isinf64(float x) {
  return !isnan(x) && isnan(x - x);
}

static inline bool futrts_isfinite64(float x) {
  return !isnan(x) && !futrts_isinf64(x);
}

static inline double fdiv64(double x, double y) {
  return x / y;
}

static inline double fadd64(double x, double y) {
  return x + y;
}

static inline double fsub64(double x, double y) {
  return x - y;
}

static inline double fmul64(double x, double y) {
  return x * y;
}

static inline bool cmplt64(double x, double y) {
  return x < y;
}

static inline bool cmple64(double x, double y) {
  return x <= y;
}

static inline double sitofp_i8_f64(int8_t x) {
  return (double) x;
}

static inline double sitofp_i16_f64(int16_t x) {
  return (double) x;
}

static inline double sitofp_i32_f64(int32_t x) {
  return (double) x;
}

static inline double sitofp_i64_f64(int64_t x) {
  return (double) x;
}

static inline double uitofp_i8_f64(uint8_t x) {
  return (double) x;
}

static inline double uitofp_i16_f64(uint16_t x) {
  return (double) x;
}

static inline double uitofp_i32_f64(uint32_t x) {
  return (double) x;
}

static inline double uitofp_i64_f64(uint64_t x) {
  return (double) x;
}

static inline double fabs64(double x) {
  return abs(x);
}

static inline double fmax64(double x, double y) {
  return isnan(x) ? y : isnan(y) ? x : max(x, y);
}

static inline double fmin64(double x, double y) {
  return isnan(x) ? y : isnan(y) ? x : min(x, y);
}

static inline double fpow64(double a, double b) {
  float ret;
  foreach_active (i) {
      uniform float r = __stdlib_powf(extract(a, i), extract(b, i));
      ret = insert(ret, i, r);
  }
  return ret;
}

static inline double futrts_log64(double x) {
  return futrts_isfinite64(x) || (futrts_isinf64(x) && x < 0)? log(x) : x;
}

static inline double futrts_log2_64(double x) {
  return futrts_log64(x)/log(2.0d);
}

static inline double futrts_log10_64(double x) {
  return futrts_log64(x)/log(10.0d);
}

static inline double futrts_sqrt64(double x) {
  return sqrt(x);
}

extern "C" unmasked uniform double cbrt(uniform double);
static inline double futrts_cbrt64(double x) {
  double res;
  foreach_active (i) {
    uniform double r = cbrtf(extract(x, i));
    res = insert(res, i, r);
  }
  return res;
}

static inline double futrts_exp64(double x) {
  return exp(x);
}

static inline double futrts_cos64(double x) {
  return cos(x);
}

static inline double futrts_sin64(double x) {
  return sin(x);
}

static inline double futrts_tan64(double x) {
  return tan(x);
}

static inline double futrts_acos64(double x) {
  return acos(x);
}

static inline double futrts_asin64(double x) {
  return asin(x);
}

static inline double futrts_atan64(double x) {
  return atan(x);
}

static inline double futrts_cosh64(double x) {
  return (exp(x)+exp(-x)) / 2.0d;
}

static inline double futrts_sinh64(double x) {
  return (exp(x)-exp(-x)) / 2.0d;
}

static inline double futrts_tanh64(double x) {
  return futrts_sinh64(x)/futrts_cosh64(x);
}

static inline double futrts_acosh64(double x) {
  double f = x+sqrt(x*x-1.0d);
  if(futrts_isfinite64(f)) return log(f);
  return f;
}

static inline double futrts_asinh64(double x) {
  double f = x+sqrt(x*x+1.0d);
  if(futrts_isfinite64(f)) return log(f);
  return f;
}

static inline double futrts_atanh64(double x) {
  double f = (1.0d+x)/(1.0d-x);
  if(futrts_isfinite64(f)) return log(f)/2.0d;
  return f;

}

static inline double futrts_atan2_64(double x, double y) {
  return atan2(x, y);
}

extern "C" unmasked uniform double hypot(uniform double x, uniform double y);
static inline double futrts_hypot64(double x, double y) {
  double res;
  foreach_active (i) {
    uniform double r = hypot(extract(x, i), extract(y, i));
    res = insert(res, i, r);
  }
  return res;
}

extern "C" unmasked uniform double tgamma(uniform double x);
static inline double futrts_gamma64(double x) {
  double res;
  foreach_active (i) {
    uniform double r = tgamma(extract(x, i));
    res = insert(res, i, r);
  }
  return res;
}

extern "C" unmasked uniform double lgamma(uniform double x);
static inline double futrts_lgamma64(double x) {
  double res;
  foreach_active (i) {
    uniform double r = lgamma(extract(x, i));
    res = insert(res, i, r);
  }
  return res;
}

extern "C" unmasked uniform double erf(uniform double x);
static inline double futrts_erf64(double x) {
  double res;
  foreach_active (i) {
    uniform double r = erf(extract(x, i));
    res = insert(res, i, r);
  }
  return res;
}

extern "C" unmasked uniform double erfc(uniform double x);
static inline double futrts_erfc64(double x) {
  double res;
  foreach_active (i) {
    uniform double r = erfc(extract(x, i));
    res = insert(res, i, r);
  }
  return res;
}

static inline double futrts_fma64(double a, double b, double c) {
  return a * b + c;
}

static inline double futrts_round64(double x) {
  return round(x);
}

static inline double futrts_ceil64(double x) {
  return ceil(x);
}

static inline double futrts_floor64(double x) {
  return floor(x);
}

static inline bool futrts_isnan64(double x) {
  return isnan(x);
}

static inline int8_t fptosi_f64_i8(double x) {
  if (futrts_isnan64(x) || futrts_isinf64(x)) {
    return 0;
  } else {
    return (int8_t) x;
  }
}

static inline int16_t fptosi_f64_i16(double x) {
  if (futrts_isnan64(x) || futrts_isinf64(x)) {
    return 0;
  } else {
    return (int16_t) x;
  }
}

static inline int32_t fptosi_f64_i32(double x) {
  if (futrts_isnan64(x) || futrts_isinf64(x)) {
    return 0;
  } else {
    return (int32_t) x;
  }
}

static inline int64_t fptosi_f64_i64(double x) {
  if (futrts_isnan64(x) || futrts_isinf64(x)) {
    return 0;
  } else {
    return (int64_t) x;
  }
}

static inline uint8_t fptoui_f64_i8(double x) {
  if (futrts_isnan64(x) || futrts_isinf64(x)) {
    return 0;
  } else {
    return (uint8_t) (int8_t) x;
  }
}

static inline uint16_t fptoui_f64_i16(double x) {
  if (futrts_isnan64(x) || futrts_isinf64(x)) {
    return 0;
  } else {
    return (uint16_t) (int16_t) x;
  }
}

static inline uint32_t fptoui_f64_i32(double x) {
  if (futrts_isnan64(x) || futrts_isinf64(x)) {
    return 0;
  } else {
    return (uint32_t) (int32_t) x;
  }
}

static inline uint64_t fptoui_f64_i64(double x) {
  if (futrts_isnan64(x) || futrts_isinf64(x)) {
    return 0;
  } else {
    return (uint64_t) (int64_t) x;
  }
}

static inline bool ftob_f64_bool(double x) {
  return x != 0.0;
}

static inline double btof_bool_f64(bool x) {
  return x ? 1.0 : 0.0;
}

static inline int64_t futrts_to_bits64(double x) {
  int64_t res;
  foreach_active (i) {
    uniform double tmp = extract(x, i);
    uniform int64_t r = *((uniform int64_t* uniform)&tmp);
    res = insert(res, i, r);
  }
  return res;
}

static inline double futrts_from_bits64(int64_t x) {
  double res;
  foreach_active (i) {
    uniform int64_t tmp = extract(x, i);
    uniform double r = *((uniform double* uniform)&tmp);
    res = insert(res, i, r);
  }
  return res;
}

static inline double fmod64(double x, double y) {
  return x - y * trunc(x/y);
}

static inline double fsignum64(double x) {
  return futrts_isnan64(x) ? x : (x > 0 ? 1.0d : 0.0d) - (x < 0 ? 1.0d : 0.0d);
}

static inline double futrts_lerp64(double v0, double v1, double t) {
  return v0 + (v1 - v0) * t;
}

static inline double futrts_mad64(double a, double b, double c) {
  return a * b + c;
}

static inline float fpconv_f32_f32(float x) {
  return (float) x;
}

static inline double fpconv_f32_f64(float x) {
  return (double) x;
}

static inline float fpconv_f64_f32(double x) {
  return (float) x;
}

static inline double fpconv_f64_f64(double x) {
  return (double) x;
}

#else

static inline double fdiv64(double x, double y) {
  return x / y;
}

static inline double fadd64(double x, double y) {
  return x + y;
}

static inline double fsub64(double x, double y) {
  return x - y;
}

static inline double fmul64(double x, double y) {
  return x * y;
}

static inline bool cmplt64(double x, double y) {
  return x < y;
}

static inline bool cmple64(double x, double y) {
  return x <= y;
}

static inline double sitofp_i8_f64(int8_t x) {
  return (double) x;
}

static inline double sitofp_i16_f64(int16_t x) {
  return (double) x;
}

static inline double sitofp_i32_f64(int32_t x) {
  return (double) x;
}

static inline double sitofp_i64_f64(int64_t x) {
  return (double) x;
}

static inline double uitofp_i8_f64(uint8_t x) {
  return (double) x;
}

static inline double uitofp_i16_f64(uint16_t x) {
  return (double) x;
}

static inline double uitofp_i32_f64(uint32_t x) {
  return (double) x;
}

static inline double uitofp_i64_f64(uint64_t x) {
  return (double) x;
}

static inline double fabs64(double x) {
  return fabs(x);
}

static inline double fmax64(double x, double y) {
  return fmax(x, y);
}

static inline double fmin64(double x, double y) {
  return fmin(x, y);
}

static inline double fpow64(double x, double y) {
  return pow(x, y);
}

static inline double futrts_log64(double x) {
  return log(x);
}

static inline double futrts_log2_64(double x) {
  return log2(x);
}

static inline double futrts_log10_64(double x) {
  return log10(x);
}

static inline double futrts_sqrt64(double x) {
  return sqrt(x);
}

static inline double futrts_cbrt64(double x) {
  return cbrt(x);
}

static inline double futrts_exp64(double x) {
  return exp(x);
}

static inline double futrts_cos64(double x) {
  return cos(x);
}

static inline double futrts_sin64(double x) {
  return sin(x);
}

static inline double futrts_tan64(double x) {
  return tan(x);
}

static inline double futrts_acos64(double x) {
  return acos(x);
}

static inline double futrts_asin64(double x) {
  return asin(x);
}

static inline double futrts_atan64(double x) {
  return atan(x);
}

static inline double futrts_cosh64(double x) {
  return cosh(x);
}

static inline double futrts_sinh64(double x) {
  return sinh(x);
}

static inline double futrts_tanh64(double x) {
  return tanh(x);
}

static inline double futrts_acosh64(double x) {
  return acosh(x);
}

static inline double futrts_asinh64(double x) {
  return asinh(x);
}

static inline double futrts_atanh64(double x) {
  return atanh(x);
}

static inline double futrts_atan2_64(double x, double y) {
  return atan2(x, y);
}

static inline double futrts_hypot64(double x, double y) {
  return hypot(x, y);
}

static inline double futrts_gamma64(double x) {
  return tgamma(x);
}

static inline double futrts_lgamma64(double x) {
  return lgamma(x);
}

static inline double futrts_erf64(double x) {
  return erf(x);
}

static inline double futrts_erfc64(double x) {
  return erfc(x);
}

static inline double futrts_fma64(double a, double b, double c) {
  return fma(a, b, c);
}

static inline double futrts_round64(double x) {
  return rint(x);
}

static inline double futrts_ceil64(double x) {
  return ceil(x);
}

static inline double futrts_floor64(double x) {
  return floor(x);
}

static inline bool futrts_isnan64(double x) {
  return isnan(x);
}

static inline bool futrts_isinf64(double x) {
  return isinf(x);
}

static inline int8_t fptosi_f64_i8(double x) {
  if (futrts_isnan64(x) || futrts_isinf64(x)) {
    return 0;
  } else {
    return (int8_t) x;
  }
}

static inline int16_t fptosi_f64_i16(double x) {
  if (futrts_isnan64(x) || futrts_isinf64(x)) {
    return 0;
  } else {
    return (int16_t) x;
  }
}

static inline int32_t fptosi_f64_i32(double x) {
  if (futrts_isnan64(x) || futrts_isinf64(x)) {
    return 0;
  } else {
    return (int32_t) x;
  }
}

static inline int64_t fptosi_f64_i64(double x) {
  if (futrts_isnan64(x) || futrts_isinf64(x)) {
    return 0;
  } else {
    return (int64_t) x;
  }
}

static inline uint8_t fptoui_f64_i8(double x) {
  if (futrts_isnan64(x) || futrts_isinf64(x)) {
    return 0;
  } else {
    return (uint8_t) (int8_t) x;
  }
}

static inline uint16_t fptoui_f64_i16(double x) {
  if (futrts_isnan64(x) || futrts_isinf64(x)) {
    return 0;
  } else {
    return (uint16_t) (int16_t) x;
  }
}

static inline uint32_t fptoui_f64_i32(double x) {
  if (futrts_isnan64(x) || futrts_isinf64(x)) {
    return 0;
  } else {
    return (uint32_t) (int32_t) x;
  }
}

static inline uint64_t fptoui_f64_i64(double x) {
  if (futrts_isnan64(x) || futrts_isinf64(x)) {
    return 0;
  } else {
    return (uint64_t) (int64_t) x;
  }
}

static inline bool ftob_f64_bool(double x) {
  return x != 0;
}

static inline double btof_bool_f64(bool x) {
  return x ? 1 : 0;
}

static inline int64_t futrts_to_bits64(double x) {
  union {
    double f;
    int64_t t;
  } p;

  p.f = x;
  return p.t;
}

static inline double futrts_from_bits64(int64_t x) {
  union {
    int64_t f;
    double t;
  } p;

  p.f = x;
  return p.t;
}

static inline double fmod64(double x, double y) {
  return fmod(x, y);
}

static inline double fsignum64(double x) {
  return futrts_isnan64(x) ? x : (x > 0) - (x < 0);
}

static inline double futrts_lerp64(double v0, double v1, double t) {
#ifdef __OPENCL_VERSION__
  return mix(v0, v1, t);
#else
  return v0 + (v1 - v0) * t;
#endif
}

static inline double futrts_mad64(double a, double b, double c) {
#ifdef __OPENCL_VERSION__
  return mad(a, b, c);
#else
  return a * b + c;
#endif
}

static inline float fpconv_f32_f32(float x) {
  return (float) x;
}

static inline double fpconv_f32_f64(float x) {
  return (double) x;
}

static inline float fpconv_f64_f32(double x) {
  return (float) x;
}

static inline double fpconv_f64_f64(double x) {
  return (double) x;
}

#endif

#endif

// End of scalar.h.
// Start of scalar_f16.h.

// Half-precision is emulated if needed (e.g. in straight C) with the
// native type used if possible.  The emulation works by typedef'ing
// 'float' to 'f16', and then implementing all operations on single
// precision.  To cut down on duplication, we use the same code for
// those Futhark functions that require just operators or casts.  The
// in-memory representation for arrays will still be 16 bits even
// under emulation, so the compiler will have to be careful when
// generating reads or writes.

#if !defined(cl_khr_fp16) && !(defined(__CUDA_ARCH__) && __CUDA_ARCH__ >= 600) && !(defined(ISPC))
#define EMULATE_F16
#endif

#if !defined(EMULATE_F16) && defined(__OPENCL_VERSION__)
#pragma OPENCL EXTENSION cl_khr_fp16 : enable
#endif

#ifdef EMULATE_F16

// Note that the half-precision storage format is still 16 bits - the
// compiler will have to be real careful!
typedef float f16;

#elif ISPC
typedef float16 f16;

#else

#ifdef __CUDA_ARCH__
#include <cuda_fp16.h>
#endif

typedef half f16;

#endif

// Some of these functions convert to single precision because half
// precision versions are not available.

static inline f16 fadd16(f16 x, f16 y) {
  return x + y;
}

static inline f16 fsub16(f16 x, f16 y) {
  return x - y;
}

static inline f16 fmul16(f16 x, f16 y) {
  return x * y;
}

static inline bool cmplt16(f16 x, f16 y) {
  return x < y;
}

static inline bool cmple16(f16 x, f16 y) {
  return x <= y;
}

static inline f16 sitofp_i8_f16(int8_t x) {
  return (f16) x;
}

static inline f16 sitofp_i16_f16(int16_t x) {
  return (f16) x;
}

static inline f16 sitofp_i32_f16(int32_t x) {
  return (f16) x;
}

static inline f16 sitofp_i64_f16(int64_t x) {
  return (f16) x;
}

static inline f16 uitofp_i8_f16(uint8_t x) {
  return (f16) x;
}

static inline f16 uitofp_i16_f16(uint16_t x) {
  return (f16) x;
}

static inline f16 uitofp_i32_f16(uint32_t x) {
  return (f16) x;
}

static inline f16 uitofp_i64_f16(uint64_t x) {
  return (f16) x;
}

static inline int8_t fptosi_f16_i8(f16 x) {
  return (int8_t) (float) x;
}

static inline int16_t fptosi_f16_i16(f16 x) {
  return (int16_t) x;
}

static inline int32_t fptosi_f16_i32(f16 x) {
  return (int32_t) x;
}

static inline int64_t fptosi_f16_i64(f16 x) {
  return (int64_t) x;
}

static inline uint8_t fptoui_f16_i8(f16 x) {
  return (uint8_t) (float) x;
}

static inline uint16_t fptoui_f16_i16(f16 x) {
  return (uint16_t) x;
}

static inline uint32_t fptoui_f16_i32(f16 x) {
  return (uint32_t) x;
}

static inline uint64_t fptoui_f16_i64(f16 x) {
  return (uint64_t) x;
}

static inline bool ftob_f16_bool(f16 x) {
  return x != (f16)0;
}

static inline f16 btof_bool_f16(bool x) {
  return x ? 1 : 0;
}

#ifndef EMULATE_F16
static inline bool futrts_isnan16(f16 x) {
  return isnan((float)x);
}

#ifdef __OPENCL_VERSION__

static inline f16 fabs16(f16 x) {
  return fabs(x);
}

static inline f16 fmax16(f16 x, f16 y) {
  return fmax(x, y);
}

static inline f16 fmin16(f16 x, f16 y) {
  return fmin(x, y);
}

static inline f16 fpow16(f16 x, f16 y) {
  return pow(x, y);
}

#elif ISPC
static inline f16 fabs16(f16 x) {
  return abs(x);
}

static inline f16 fmax16(f16 x, f16 y) {
  return futrts_isnan16(x) ? y : futrts_isnan16(y) ? x : max(x, y);
}

static inline f16 fmin16(f16 x, f16 y) {
  return futrts_isnan16(x) ? y : futrts_isnan16(y) ? x : min(x, y);
}

static inline f16 fpow16(f16 x, f16 y) {
  return pow(x, y);
}
#else // Assuming CUDA.

static inline f16 fabs16(f16 x) {
  return fabsf(x);
}

static inline f16 fmax16(f16 x, f16 y) {
  return fmaxf(x, y);
}

static inline f16 fmin16(f16 x, f16 y) {
  return fminf(x, y);
}

static inline f16 fpow16(f16 x, f16 y) {
  return powf(x, y);
}
#endif

#if ISPC
static inline bool futrts_isinf16(float x) {
  return !futrts_isnan16(x) && futrts_isnan16(x - x);
}
static inline bool futrts_isfinite16(float x) {
  return !futrts_isnan16(x) && !futrts_isinf16(x);
}

#else

static inline bool futrts_isinf16(f16 x) {
  return isinf((float)x);
}
#endif

#ifdef __OPENCL_VERSION__
static inline f16 futrts_log16(f16 x) {
  return log(x);
}

static inline f16 futrts_log2_16(f16 x) {
  return log2(x);
}

static inline f16 futrts_log10_16(f16 x) {
  return log10(x);
}

static inline f16 futrts_sqrt16(f16 x) {
  return sqrt(x);
}

static inline f16 futrts_cbrt16(f16 x) {
  return cbrt(x);
}

static inline f16 futrts_exp16(f16 x) {
  return exp(x);
}

static inline f16 futrts_cos16(f16 x) {
  return cos(x);
}

static inline f16 futrts_sin16(f16 x) {
  return sin(x);
}

static inline f16 futrts_tan16(f16 x) {
  return tan(x);
}

static inline f16 futrts_acos16(f16 x) {
  return acos(x);
}

static inline f16 futrts_asin16(f16 x) {
  return asin(x);
}

static inline f16 futrts_atan16(f16 x) {
  return atan(x);
}

static inline f16 futrts_cosh16(f16 x) {
  return cosh(x);
}

static inline f16 futrts_sinh16(f16 x) {
  return sinh(x);
}

static inline f16 futrts_tanh16(f16 x) {
  return tanh(x);
}

static inline f16 futrts_acosh16(f16 x) {
  return acosh(x);
}

static inline f16 futrts_asinh16(f16 x) {
  return asinh(x);
}

static inline f16 futrts_atanh16(f16 x) {
  return atanh(x);
}

static inline f16 futrts_atan2_16(f16 x, f16 y) {
  return atan2(x, y);
}

static inline f16 futrts_hypot16(f16 x, f16 y) {
  return hypot(x, y);
}

static inline f16 futrts_gamma16(f16 x) {
  return tgamma(x);
}

static inline f16 futrts_lgamma16(f16 x) {
  return lgamma(x);
}

static inline f16 futrts_erf16(f16 x) {
  return erf(x);
}

static inline f16 futrts_erfc16(f16 x) {
  return erfc(x);
}

static inline f16 fmod16(f16 x, f16 y) {
  return fmod(x, y);
}

static inline f16 futrts_round16(f16 x) {
  return rint(x);
}

static inline f16 futrts_floor16(f16 x) {
  return floor(x);
}

static inline f16 futrts_ceil16(f16 x) {
  return ceil(x);
}

static inline f16 futrts_lerp16(f16 v0, f16 v1, f16 t) {
  return mix(v0, v1, t);
}

static inline f16 futrts_mad16(f16 a, f16 b, f16 c) {
  return mad(a, b, c);
}

static inline f16 futrts_fma16(f16 a, f16 b, f16 c) {
  return fma(a, b, c);
}
#elif ISPC

static inline f16 futrts_log16(f16 x) {
  return futrts_isfinite16(x) || (futrts_isinf16(x) && x < 0) ? log(x) : x;
}

static inline f16 futrts_log2_16(f16 x) {
  return futrts_log16(x) / log(2.0f16);
}

static inline f16 futrts_log10_16(f16 x) {
  return futrts_log16(x) / log(10.0f16);
}

static inline f16 futrts_sqrt16(f16 x) {
  return (float16)sqrt((float)x);
}

static inline f16 futrts_exp16(f16 x) {
  return exp(x);
}

static inline f16 futrts_cos16(f16 x) {
  return (float16)cos((float)x);
}

static inline f16 futrts_sin16(f16 x) {
  return (float16)sin((float)x);
}

static inline f16 futrts_tan16(f16 x) {
  return (float16)tan((float)x);
}

static inline f16 futrts_acos16(f16 x) {
  return (float16)acos((float)x);
}

static inline f16 futrts_asin16(f16 x) {
  return (float16)asin((float)x);
}

static inline f16 futrts_atan16(f16 x) {
  return (float16)atan((float)x);
}

static inline f16 futrts_cosh16(f16 x) {
  return (exp(x)+exp(-x)) / 2.0f16;
}

static inline f16 futrts_sinh16(f16 x) {
  return (exp(x)-exp(-x)) / 2.0f16;
}

static inline f16 futrts_tanh16(f16 x) {
  return futrts_sinh16(x)/futrts_cosh16(x);
}

static inline f16 futrts_acosh16(f16 x) {
  float16 f = x+(float16)sqrt((float)(x*x-1));
  if(futrts_isfinite16(f)) return log(f);
  return f;
}

static inline f16 futrts_asinh16(f16 x) {
  float16 f = x+(float16)sqrt((float)(x*x+1));
  if(futrts_isfinite16(f)) return log(f);
  return f;
}

static inline f16 futrts_atanh16(f16 x) {
  float16 f = (1+x)/(1-x);
  if(futrts_isfinite16(f)) return log(f)/2.0f16;
  return f;
}

static inline f16 futrts_atan2_16(f16 x, f16 y) {
  return (float16)atan2((float)x, (float)y);
}

static inline f16 futrts_hypot16(f16 x, f16 y) {
  return (float16)futrts_hypot32((float)x, (float)y);
}

extern "C" unmasked uniform float tgammaf(uniform float x);
static inline f16 futrts_gamma16(f16 x) {
  f16 res;
  foreach_active (i) {
    uniform f16 r = (f16)tgammaf(extract((float)x, i));
    res = insert(res, i, r);
  }
  return res;
}

extern "C" unmasked uniform float lgammaf(uniform float x);
static inline f16 futrts_lgamma16(f16 x) {
  f16 res;
  foreach_active (i) {
    uniform f16 r = (f16)lgammaf(extract((float)x, i));
    res = insert(res, i, r);
  }
  return res;
}

static inline f16 futrts_cbrt16(f16 x) {
  f16 res = (f16)futrts_cbrt32((float)x);
  return res;
}

static inline f16 futrts_erf16(f16 x) {
  f16 res = (f16)futrts_erf32((float)x);
  return res;
}

static inline f16 futrts_erfc16(f16 x) {
  f16 res = (f16)futrts_erfc32((float)x);
  return res;
}

static inline f16 fmod16(f16 x, f16 y) {
  return x - y * (float16)trunc((float) (x/y));
}

static inline f16 futrts_round16(f16 x) {
  return (float16)round((float)x);
}

static inline f16 futrts_floor16(f16 x) {
  return (float16)floor((float)x);
}

static inline f16 futrts_ceil16(f16 x) {
  return (float16)ceil((float)x);
}

static inline f16 futrts_lerp16(f16 v0, f16 v1, f16 t) {
  return v0 + (v1 - v0) * t;
}

static inline f16 futrts_mad16(f16 a, f16 b, f16 c) {
  return a * b + c;
}

static inline f16 futrts_fma16(f16 a, f16 b, f16 c) {
  return a * b + c;
}

#else // Assume CUDA.

static inline f16 futrts_log16(f16 x) {
  return hlog(x);
}

static inline f16 futrts_log2_16(f16 x) {
  return hlog2(x);
}

static inline f16 futrts_log10_16(f16 x) {
  return hlog10(x);
}

static inline f16 futrts_sqrt16(f16 x) {
  return hsqrt(x);
}

static inline f16 futrts_cbrt16(f16 x) {
  return cbrtf(x);
}

static inline f16 futrts_exp16(f16 x) {
  return hexp(x);
}

static inline f16 futrts_cos16(f16 x) {
  return hcos(x);
}

static inline f16 futrts_sin16(f16 x) {
  return hsin(x);
}

static inline f16 futrts_tan16(f16 x) {
  return tanf(x);
}

static inline f16 futrts_acos16(f16 x) {
  return acosf(x);
}

static inline f16 futrts_asin16(f16 x) {
  return asinf(x);
}

static inline f16 futrts_atan16(f16 x) {
  return atanf(x);
}

static inline f16 futrts_cosh16(f16 x) {
  return coshf(x);
}

static inline f16 futrts_sinh16(f16 x) {
  return sinhf(x);
}

static inline f16 futrts_tanh16(f16 x) {
  return tanhf(x);
}

static inline f16 futrts_acosh16(f16 x) {
  return acoshf(x);
}

static inline f16 futrts_asinh16(f16 x) {
  return asinhf(x);
}

static inline f16 futrts_atanh16(f16 x) {
  return atanhf(x);
}

static inline f16 futrts_atan2_16(f16 x, f16 y) {
  return atan2f(x, y);
}

static inline f16 futrts_hypot16(f16 x, f16 y) {
  return hypotf(x, y);
}

static inline f16 futrts_gamma16(f16 x) {
  return tgammaf(x);
}

static inline f16 futrts_lgamma16(f16 x) {
  return lgammaf(x);
}

static inline f16 futrts_erf16(f16 x) {
  return erff(x);
}

static inline f16 futrts_erfc16(f16 x) {
  return erfcf(x);
}

static inline f16 fmod16(f16 x, f16 y) {
  return fmodf(x, y);
}

static inline f16 futrts_round16(f16 x) {
  return rintf(x);
}

static inline f16 futrts_floor16(f16 x) {
  return hfloor(x);
}

static inline f16 futrts_ceil16(f16 x) {
  return hceil(x);
}

static inline f16 futrts_lerp16(f16 v0, f16 v1, f16 t) {
  return v0 + (v1 - v0) * t;
}

static inline f16 futrts_mad16(f16 a, f16 b, f16 c) {
  return a * b + c;
}

static inline f16 futrts_fma16(f16 a, f16 b, f16 c) {
  return fmaf(a, b, c);
}

#endif

// The CUDA __half type cannot be put in unions for some reason, so we
// use bespoke conversion functions instead.
#ifdef __CUDA_ARCH__
static inline int16_t futrts_to_bits16(f16 x) {
  return __half_as_ushort(x);
}
static inline f16 futrts_from_bits16(int16_t x) {
  return __ushort_as_half(x);
}
#elif ISPC

static inline int16_t futrts_to_bits16(f16 x) {
  varying int16_t y = *((varying int16_t * uniform)&x);
  return y;
}

static inline f16 futrts_from_bits16(int16_t x) {
  varying f16 y = *((varying f16 * uniform)&x);
  return y;
}
#else
static inline int16_t futrts_to_bits16(f16 x) {
  union {
    f16 f;
    int16_t t;
  } p;

  p.f = x;
  return p.t;
}

static inline f16 futrts_from_bits16(int16_t x) {
  union {
    int16_t f;
    f16 t;
  } p;

  p.f = x;
  return p.t;
}
#endif

#else // No native f16 - emulate.

static inline f16 fabs16(f16 x) {
  return fabs32(x);
}

static inline f16 fmax16(f16 x, f16 y) {
  return fmax32(x, y);
}

static inline f16 fmin16(f16 x, f16 y) {
  return fmin32(x, y);
}

static inline f16 fpow16(f16 x, f16 y) {
  return fpow32(x, y);
}

static inline bool futrts_isnan16(f16 x) {
  return futrts_isnan32(x);
}

static inline bool futrts_isinf16(f16 x) {
  return futrts_isinf32(x);
}

static inline f16 futrts_log16(f16 x) {
  return futrts_log32(x);
}

static inline f16 futrts_log2_16(f16 x) {
  return futrts_log2_32(x);
}

static inline f16 futrts_log10_16(f16 x) {
  return futrts_log10_32(x);
}

static inline f16 futrts_sqrt16(f16 x) {
  return futrts_sqrt32(x);
}

static inline f16 futrts_cbrt16(f16 x) {
  return futrts_cbrt32(x);
}

static inline f16 futrts_exp16(f16 x) {
  return futrts_exp32(x);
}

static inline f16 futrts_cos16(f16 x) {
  return futrts_cos32(x);
}

static inline f16 futrts_sin16(f16 x) {
  return futrts_sin32(x);
}

static inline f16 futrts_tan16(f16 x) {
  return futrts_tan32(x);
}

static inline f16 futrts_acos16(f16 x) {
  return futrts_acos32(x);
}

static inline f16 futrts_asin16(f16 x) {
  return futrts_asin32(x);
}

static inline f16 futrts_atan16(f16 x) {
  return futrts_atan32(x);
}

static inline f16 futrts_cosh16(f16 x) {
  return futrts_cosh32(x);
}

static inline f16 futrts_sinh16(f16 x) {
  return futrts_sinh32(x);
}

static inline f16 futrts_tanh16(f16 x) {
  return futrts_tanh32(x);
}

static inline f16 futrts_acosh16(f16 x) {
  return futrts_acosh32(x);
}

static inline f16 futrts_asinh16(f16 x) {
  return futrts_asinh32(x);
}

static inline f16 futrts_atanh16(f16 x) {
  return futrts_atanh32(x);
}

static inline f16 futrts_atan2_16(f16 x, f16 y) {
  return futrts_atan2_32(x, y);
}

static inline f16 futrts_hypot16(f16 x, f16 y) {
  return futrts_hypot32(x, y);
}

static inline f16 futrts_gamma16(f16 x) {
  return futrts_gamma32(x);
}

static inline f16 futrts_lgamma16(f16 x) {
  return futrts_lgamma32(x);
}

static inline f16 futrts_erf16(f16 x) {
  return futrts_erf32(x);
}

static inline f16 futrts_erfc16(f16 x) {
  return futrts_erfc32(x);
}

static inline f16 fmod16(f16 x, f16 y) {
  return fmod32(x, y);
}

static inline f16 futrts_round16(f16 x) {
  return futrts_round32(x);
}

static inline f16 futrts_floor16(f16 x) {
  return futrts_floor32(x);
}

static inline f16 futrts_ceil16(f16 x) {
  return futrts_ceil32(x);
}

static inline f16 futrts_lerp16(f16 v0, f16 v1, f16 t) {
  return futrts_lerp32(v0, v1, t);
}

static inline f16 futrts_mad16(f16 a, f16 b, f16 c) {
  return futrts_mad32(a, b, c);
}

static inline f16 futrts_fma16(f16 a, f16 b, f16 c) {
  return futrts_fma32(a, b, c);
}

// Even when we are using an OpenCL that does not support cl_khr_fp16,
// it must still support vload_half for actually creating a
// half-precision number, which can then be efficiently converted to a
// float.  Similarly for vstore_half.
#ifdef __OPENCL_VERSION__

static inline int16_t futrts_to_bits16(f16 x) {
  int16_t y;
  // Violating strict aliasing here.
  vstore_half((float)x, 0, (half*)&y);
  return y;
}

static inline f16 futrts_from_bits16(int16_t x) {
  return (f16)vload_half(0, (half*)&x);
}

#else

static inline int16_t futrts_to_bits16(f16 x) {
  return (int16_t)float2halfbits(x);
}

static inline f16 futrts_from_bits16(int16_t x) {
  return halfbits2float((uint16_t)x);
}

static inline f16 fsignum16(f16 x) {
  return futrts_isnan16(x) ? x : (x > 0 ? 1 : 0) - (x < 0 ? 1 : 0);
}

#endif

#endif

static inline float fpconv_f16_f16(f16 x) {
  return x;
}

static inline float fpconv_f16_f32(f16 x) {
  return x;
}

static inline f16 fpconv_f32_f16(float x) {
  return (f16) x;
}

#ifdef FUTHARK_F64_ENABLED

static inline double fpconv_f16_f64(f16 x) {
  return (double) x;
}

#if ISPC
static inline f16 fpconv_f64_f16(double x) {
  return (f16) ((float)x);
}
#else
static inline f16 fpconv_f64_f16(double x) {
  return (f16) x;
}
#endif
#endif


// End of scalar_f16.h.

// Start of context_prototypes.h
//
// Prototypes for the functions in prototypes.h that need to be
// available very early.

struct futhark_context_config;
struct futhark_context;

static void set_error(struct futhark_context* ctx, char *error);

// End of of context_prototypes.h

static int init_constants(struct futhark_context *);
static int free_constants(struct futhark_context *);
struct memblock {
    int *references;
    unsigned char *mem;
    int64_t size;
    const char *desc;
};
struct futhark_context_config {
    int debugging;
    int in_use;
    const char *cache_fname;
};
struct futhark_context_config *futhark_context_config_new(void)
{
    struct futhark_context_config *cfg =
                                  (struct futhark_context_config *) malloc(sizeof(struct futhark_context_config));
    
    if (cfg == NULL)
        return NULL;
    cfg->in_use = 0;
    cfg->debugging = 0;
    cfg->cache_fname = NULL;
    return cfg;
}
void futhark_context_config_free(struct futhark_context_config *cfg)
{
    assert(!cfg->in_use);
    free(cfg);
}
void futhark_context_config_set_debugging(struct futhark_context_config *cfg,
                                          int detail)
{
    cfg->debugging = detail;
}
void futhark_context_config_set_profiling(struct futhark_context_config *cfg,
                                          int flag)
{
    (void) cfg;
    (void) flag;
}
void futhark_context_config_set_logging(struct futhark_context_config *cfg,
                                        int detail)
{
    // Does nothing for this backend.
    (void) cfg;
    (void) detail;
}
struct futhark_context {
    struct futhark_context_config *cfg;
    int detail_memory;
    int debugging;
    int profiling;
    int logging;
    lock_t lock;
    char *error;
    lock_t error_lock;
    FILE *log;
    int profiling_paused;
    int64_t peak_mem_usage_default;
    int64_t cur_mem_usage_default;
    struct {
        int dummy;
    } constants;
};
struct futhark_context *futhark_context_new(struct futhark_context_config *cfg)
{
    assert(!cfg->in_use);
    
    struct futhark_context *ctx =
                           (struct futhark_context *) malloc(sizeof(struct futhark_context));
    
    if (ctx == NULL)
        return NULL;
    ctx->cfg = cfg;
    ctx->cfg->in_use = 1;
    ctx->detail_memory = cfg->debugging;
    ctx->debugging = cfg->debugging;
    ctx->profiling = cfg->debugging;
    ctx->logging = cfg->debugging;
    ctx->error = NULL;
    create_lock(&ctx->error_lock);
    ctx->log = stderr;
    create_lock(&ctx->lock);
    ctx->peak_mem_usage_default = 0;
    ctx->cur_mem_usage_default = 0;
    init_constants(ctx);
    return ctx;
}
void futhark_context_free(struct futhark_context *ctx)
{
    free_constants(ctx);
    free_lock(&ctx->lock);
    ctx->cfg->in_use = 0;
    free(ctx);
}
int futhark_context_sync(struct futhark_context *ctx)
{
    (void) ctx;
    return 0;
}
static const char *tuning_param_names[0];
static const char *tuning_param_vars[0];
static const char *tuning_param_classes[0];
int futhark_context_config_set_tuning_param(struct futhark_context_config *cfg,
                                            const char *param_name,
                                            size_t param_value)
{
    (void) cfg;
    (void) param_name;
    (void) param_value;
    return 1;
}
int memblock_unref(struct futhark_context *ctx, struct memblock *block, const
                   char *desc)
{
    if (block->references != NULL) {
        *block->references -= 1;
        if (ctx->detail_memory)
            fprintf(ctx->log,
                    "Unreferencing block %s (allocated as %s) in %s: %d references remaining.\n",
                    desc, block->desc, "default space", *block->references);
        if (*block->references == 0) {
            ctx->cur_mem_usage_default -= block->size;
            free(block->mem);
            free(block->references);
            if (ctx->detail_memory)
                fprintf(ctx->log,
                        "%lld bytes freed (now allocated: %lld bytes)\n",
                        (long long) block->size,
                        (long long) ctx->cur_mem_usage_default);
        }
        block->references = NULL;
    }
    return 0;
}
int memblock_alloc(struct futhark_context *ctx, struct memblock *block,
                   int64_t size, const char *desc)
{
    if (size < 0)
        futhark_panic(1,
                      "Negative allocation of %lld bytes attempted for %s in %s.\n",
                      (long long) size, desc, "default space",
                      ctx->cur_mem_usage_default);
    
    int ret = memblock_unref(ctx, block, desc);
    
    if (ret != FUTHARK_SUCCESS)
        return ret;
    if (ctx->detail_memory)
        fprintf(ctx->log,
                "Allocating %lld bytes for %s in %s (then allocated: %lld bytes)",
                (long long) size, desc, "default space",
                (long long) ctx->cur_mem_usage_default + size);
    if (ctx->cur_mem_usage_default > ctx->peak_mem_usage_default) {
        ctx->peak_mem_usage_default = ctx->cur_mem_usage_default;
        if (ctx->detail_memory)
            fprintf(ctx->log, " (new peak).\n");
    } else if (ctx->detail_memory)
        fprintf(ctx->log, ".\n");
    block->mem = (unsigned char *) malloc((size_t) size);
    if (ctx->error == NULL) {
        block->references = (int *) malloc(sizeof(int));
        *block->references = 1;
        block->size = size;
        block->desc = desc;
        ctx->cur_mem_usage_default += size;
        return FUTHARK_SUCCESS;
    } else {
        // We are naively assuming that any memory allocation error is due to OOM.
        lock_lock(&ctx->error_lock);
        
        char *old_error = ctx->error;
        
        ctx->error =
            msgprintf("Failed to allocate memory in %s.\nAttempted allocation: %12lld bytes\nCurrently allocated:  %12lld bytes\n%s",
                      "default space", (long long) size,
                      (long long) ctx->cur_mem_usage_default, old_error);
        free(old_error);
        lock_unlock(&ctx->error_lock);
        return FUTHARK_OUT_OF_MEMORY;
    }
}
int memblock_set(struct futhark_context *ctx, struct memblock *lhs,
                 struct memblock *rhs, const char *lhs_desc)
{
    int ret = memblock_unref(ctx, lhs, lhs_desc);
    
    if (rhs->references != NULL)
        (*rhs->references)++;
    *lhs = *rhs;
    return ret;
}
void futhark_context_config_set_cache_file(struct futhark_context_config *cfg,
                                           const char *f)
{
    cfg->cache_fname = f;
}
int futhark_get_tuning_param_count(void)
{
    return sizeof(tuning_param_names) / sizeof(tuning_param_names[0]);
}
const char *futhark_get_tuning_param_name(int i)
{
    return tuning_param_names[i];
}
const char *futhark_get_tuning_param_class(int i)
{
    return tuning_param_classes[i];
}
char *futhark_context_report(struct futhark_context *ctx)
{
    if (futhark_context_sync(ctx) != 0)
        return NULL;
    
    struct str_builder builder;
    
    str_builder_init(&builder);
    { }
    if (ctx->profiling) { }
    return builder.str;
}
char *futhark_context_get_error(struct futhark_context *ctx)
{
    char *error = ctx->error;
    
    ctx->error = NULL;
    return error;
}
void futhark_context_set_logging_file(struct futhark_context *ctx, FILE *f)
{
    ctx->log = f;
}
void futhark_context_pause_profiling(struct futhark_context *ctx)
{
    ctx->profiling_paused = 1;
}
void futhark_context_unpause_profiling(struct futhark_context *ctx)
{
    ctx->profiling_paused = 0;
}
int futhark_context_clear_caches(struct futhark_context *ctx)
{
    lock_lock(&ctx->lock);
    ctx->peak_mem_usage_default = 0;
    lock_unlock(&ctx->lock);
    return ctx->error != NULL;
}

// Start of context.h

// Eventually it would be nice to move the context definition in here
// instead of generating it in the compiler.  For now it defines
// various helper functions that must be available.

// Internal functions.

static void set_error(struct futhark_context* ctx, char *error) {
  lock_lock(&ctx->error_lock);
  if (ctx->error == NULL) {
    ctx->error = error;
  } else {
    free(error);
  }
  lock_unlock(&ctx->error_lock);
}

// XXX: should be static, but used in ispc_util.h
void lexical_realloc_error(struct futhark_context* ctx, size_t new_size) {
  set_error(ctx,
            msgprintf("Failed to allocate memory.\nAttempted allocation: %12lld bytes\n",
                      (long long) new_size));
}

static int lexical_realloc(struct futhark_context *ctx,
                           unsigned char **ptr,
                           int64_t *old_size,
                           int64_t new_size) {
  unsigned char *new = realloc(*ptr, (size_t)new_size);
  if (new == NULL) {
    lexical_realloc_error(ctx, new_size);
    return FUTHARK_OUT_OF_MEMORY;
  } else {
    *ptr = new;
    *old_size = new_size;
    return FUTHARK_SUCCESS;
  }
}

// End of context.h

static int futrts_entry_convolve2d_b_bench(struct futhark_context *ctx,
                                           struct memblock *mem_out_p_14764,
                                           struct memblock *mem_out_p_14765,
                                           struct memblock *mem_out_p_14766,
                                           struct memblock out_grad_mem_14222,
                                           struct memblock conv_input_mem_14223,
                                           struct memblock kernels_mem_14224,
                                           int64_t o_11780, int64_t q_11781,
                                           int64_t r_11782, int64_t n_11783,
                                           int64_t m_11784, int64_t l_11785,
                                           int64_t p_11786, int64_t k_11787);
static int futrts_entry_convolve2d_b_test(struct futhark_context *ctx,
                                          struct memblock *mem_out_p_14776,
                                          struct memblock *mem_out_p_14777,
                                          struct memblock *mem_out_p_14778,
                                          struct memblock out_grad_mem_14222,
                                          struct memblock conv_input_mem_14223,
                                          struct memblock kernels_mem_14224,
                                          int64_t o_11750, int64_t q_11751,
                                          int64_t r_11752, int64_t n_11753,
                                          int64_t m_11754, int64_t l_11755,
                                          int64_t p_11756, int64_t k_11757,
                                          int64_t valid_num_11761,
                                          int64_t full_num_11762);
static int futrts_entry_convolve2d_test(struct futhark_context *ctx,
                                        struct memblock *mem_out_p_14788,
                                        int64_t *out_prim_out_14789,
                                        int64_t *out_prim_out_14790,
                                        struct memblock imgs_mem_14222,
                                        struct memblock kernels_mem_14223,
                                        struct memblock biases_mem_14224,
                                        int64_t n_10711, int64_t m_10712,
                                        int64_t l_10713, int64_t p_10714,
                                        int64_t k_10715, int64_t o_10716,
                                        int64_t padding_10720);

static int init_constants(struct futhark_context *ctx)
{
    (void) ctx;
    
    int err = 0;
    
    
  cleanup:
    return err;
}
static int free_constants(struct futhark_context *ctx)
{
    (void) ctx;
    return 0;
}
struct futhark_f64_1d {
    struct memblock mem;
    int64_t shape[1];
};
struct futhark_f64_1d *futhark_new_f64_1d(struct futhark_context *ctx, const
                                          double *data, int64_t dim0)
{
    struct futhark_f64_1d *bad = NULL;
    struct futhark_f64_1d *arr =
                          (struct futhark_f64_1d *) malloc(sizeof(struct futhark_f64_1d));
    
    if (arr == NULL)
        return bad;
    lock_lock(&ctx->lock);
    arr->mem.references = NULL;
    if (memblock_alloc(ctx, &arr->mem, dim0 * 8, "arr->mem"))
        return NULL;
    arr->shape[0] = dim0;
    if ((size_t) dim0 * 8 > 0)
        memmove(arr->mem.mem + 0, data + 0, (size_t) dim0 * 8);
    lock_unlock(&ctx->lock);
    return arr;
}
struct futhark_f64_1d *futhark_new_raw_f64_1d(struct futhark_context *ctx, const
                                              unsigned char *data,
                                              int64_t offset, int64_t dim0)
{
    struct futhark_f64_1d *bad = NULL;
    struct futhark_f64_1d *arr =
                          (struct futhark_f64_1d *) malloc(sizeof(struct futhark_f64_1d));
    
    if (arr == NULL)
        return bad;
    lock_lock(&ctx->lock);
    arr->mem.references = NULL;
    if (memblock_alloc(ctx, &arr->mem, dim0 * 8, "arr->mem"))
        return NULL;
    arr->shape[0] = dim0;
    if ((size_t) dim0 * 8 > 0)
        memmove(arr->mem.mem + 0, data + offset, (size_t) dim0 * 8);
    lock_unlock(&ctx->lock);
    return arr;
}
int futhark_free_f64_1d(struct futhark_context *ctx, struct futhark_f64_1d *arr)
{
    lock_lock(&ctx->lock);
    if (memblock_unref(ctx, &arr->mem, "arr->mem") != 0)
        return 1;
    lock_unlock(&ctx->lock);
    free(arr);
    return 0;
}
int futhark_values_f64_1d(struct futhark_context *ctx,
                          struct futhark_f64_1d *arr, double *data)
{
    lock_lock(&ctx->lock);
    if ((size_t) arr->shape[0] * 8 > 0)
        memmove(data + 0, arr->mem.mem + 0, (size_t) arr->shape[0] * 8);
    lock_unlock(&ctx->lock);
    return 0;
}
unsigned char *futhark_values_raw_f64_1d(struct futhark_context *ctx,
                                         struct futhark_f64_1d *arr)
{
    (void) ctx;
    return arr->mem.mem;
}
const int64_t *futhark_shape_f64_1d(struct futhark_context *ctx,
                                    struct futhark_f64_1d *arr)
{
    (void) ctx;
    return arr->shape;
}
struct futhark_f64_3d {
    struct memblock mem;
    int64_t shape[3];
};
struct futhark_f64_3d *futhark_new_f64_3d(struct futhark_context *ctx, const
                                          double *data, int64_t dim0,
                                          int64_t dim1, int64_t dim2)
{
    struct futhark_f64_3d *bad = NULL;
    struct futhark_f64_3d *arr =
                          (struct futhark_f64_3d *) malloc(sizeof(struct futhark_f64_3d));
    
    if (arr == NULL)
        return bad;
    lock_lock(&ctx->lock);
    arr->mem.references = NULL;
    if (memblock_alloc(ctx, &arr->mem, dim0 * dim1 * dim2 * 8, "arr->mem"))
        return NULL;
    arr->shape[0] = dim0;
    arr->shape[1] = dim1;
    arr->shape[2] = dim2;
    if ((size_t) (dim0 * dim1 * dim2) * 8 > 0)
        memmove(arr->mem.mem + 0, data + 0, (size_t) (dim0 * dim1 * dim2) * 8);
    lock_unlock(&ctx->lock);
    return arr;
}
struct futhark_f64_3d *futhark_new_raw_f64_3d(struct futhark_context *ctx, const
                                              unsigned char *data,
                                              int64_t offset, int64_t dim0,
                                              int64_t dim1, int64_t dim2)
{
    struct futhark_f64_3d *bad = NULL;
    struct futhark_f64_3d *arr =
                          (struct futhark_f64_3d *) malloc(sizeof(struct futhark_f64_3d));
    
    if (arr == NULL)
        return bad;
    lock_lock(&ctx->lock);
    arr->mem.references = NULL;
    if (memblock_alloc(ctx, &arr->mem, dim0 * dim1 * dim2 * 8, "arr->mem"))
        return NULL;
    arr->shape[0] = dim0;
    arr->shape[1] = dim1;
    arr->shape[2] = dim2;
    if ((size_t) (dim0 * dim1 * dim2) * 8 > 0)
        memmove(arr->mem.mem + 0, data + offset, (size_t) (dim0 * dim1 * dim2) *
                8);
    lock_unlock(&ctx->lock);
    return arr;
}
int futhark_free_f64_3d(struct futhark_context *ctx, struct futhark_f64_3d *arr)
{
    lock_lock(&ctx->lock);
    if (memblock_unref(ctx, &arr->mem, "arr->mem") != 0)
        return 1;
    lock_unlock(&ctx->lock);
    free(arr);
    return 0;
}
int futhark_values_f64_3d(struct futhark_context *ctx,
                          struct futhark_f64_3d *arr, double *data)
{
    lock_lock(&ctx->lock);
    if ((size_t) (arr->shape[0] * arr->shape[1] * arr->shape[2]) * 8 > 0)
        memmove(data + 0, arr->mem.mem + 0, (size_t) (arr->shape[0] *
                                                      arr->shape[1] *
                                                      arr->shape[2]) * 8);
    lock_unlock(&ctx->lock);
    return 0;
}
unsigned char *futhark_values_raw_f64_3d(struct futhark_context *ctx,
                                         struct futhark_f64_3d *arr)
{
    (void) ctx;
    return arr->mem.mem;
}
const int64_t *futhark_shape_f64_3d(struct futhark_context *ctx,
                                    struct futhark_f64_3d *arr)
{
    (void) ctx;
    return arr->shape;
}
struct futhark_f64_4d {
    struct memblock mem;
    int64_t shape[4];
};
struct futhark_f64_4d *futhark_new_f64_4d(struct futhark_context *ctx, const
                                          double *data, int64_t dim0,
                                          int64_t dim1, int64_t dim2,
                                          int64_t dim3)
{
    struct futhark_f64_4d *bad = NULL;
    struct futhark_f64_4d *arr =
                          (struct futhark_f64_4d *) malloc(sizeof(struct futhark_f64_4d));
    
    if (arr == NULL)
        return bad;
    lock_lock(&ctx->lock);
    arr->mem.references = NULL;
    if (memblock_alloc(ctx, &arr->mem, dim0 * dim1 * dim2 * dim3 * 8,
                       "arr->mem"))
        return NULL;
    arr->shape[0] = dim0;
    arr->shape[1] = dim1;
    arr->shape[2] = dim2;
    arr->shape[3] = dim3;
    if ((size_t) (dim0 * dim1 * dim2 * dim3) * 8 > 0)
        memmove(arr->mem.mem + 0, data + 0, (size_t) (dim0 * dim1 * dim2 *
                                                      dim3) * 8);
    lock_unlock(&ctx->lock);
    return arr;
}
struct futhark_f64_4d *futhark_new_raw_f64_4d(struct futhark_context *ctx, const
                                              unsigned char *data,
                                              int64_t offset, int64_t dim0,
                                              int64_t dim1, int64_t dim2,
                                              int64_t dim3)
{
    struct futhark_f64_4d *bad = NULL;
    struct futhark_f64_4d *arr =
                          (struct futhark_f64_4d *) malloc(sizeof(struct futhark_f64_4d));
    
    if (arr == NULL)
        return bad;
    lock_lock(&ctx->lock);
    arr->mem.references = NULL;
    if (memblock_alloc(ctx, &arr->mem, dim0 * dim1 * dim2 * dim3 * 8,
                       "arr->mem"))
        return NULL;
    arr->shape[0] = dim0;
    arr->shape[1] = dim1;
    arr->shape[2] = dim2;
    arr->shape[3] = dim3;
    if ((size_t) (dim0 * dim1 * dim2 * dim3) * 8 > 0)
        memmove(arr->mem.mem + 0, data + offset, (size_t) (dim0 * dim1 * dim2 *
                                                           dim3) * 8);
    lock_unlock(&ctx->lock);
    return arr;
}
int futhark_free_f64_4d(struct futhark_context *ctx, struct futhark_f64_4d *arr)
{
    lock_lock(&ctx->lock);
    if (memblock_unref(ctx, &arr->mem, "arr->mem") != 0)
        return 1;
    lock_unlock(&ctx->lock);
    free(arr);
    return 0;
}
int futhark_values_f64_4d(struct futhark_context *ctx,
                          struct futhark_f64_4d *arr, double *data)
{
    lock_lock(&ctx->lock);
    if ((size_t) (arr->shape[0] * arr->shape[1] * arr->shape[2] *
                  arr->shape[3]) * 8 > 0)
        memmove(data + 0, arr->mem.mem + 0, (size_t) (arr->shape[0] *
                                                      arr->shape[1] *
                                                      arr->shape[2] *
                                                      arr->shape[3]) * 8);
    lock_unlock(&ctx->lock);
    return 0;
}
unsigned char *futhark_values_raw_f64_4d(struct futhark_context *ctx,
                                         struct futhark_f64_4d *arr)
{
    (void) ctx;
    return arr->mem.mem;
}
const int64_t *futhark_shape_f64_4d(struct futhark_context *ctx,
                                    struct futhark_f64_4d *arr)
{
    (void) ctx;
    return arr->shape;
}

static int futrts_entry_convolve2d_b_bench(struct futhark_context *ctx,
                                           struct memblock *mem_out_p_14764,
                                           struct memblock *mem_out_p_14765,
                                           struct memblock *mem_out_p_14766,
                                           struct memblock out_grad_mem_14222,
                                           struct memblock conv_input_mem_14223,
                                           struct memblock kernels_mem_14224,
                                           int64_t o_11780, int64_t q_11781,
                                           int64_t r_11782, int64_t n_11783,
                                           int64_t m_11784, int64_t l_11785,
                                           int64_t p_11786, int64_t k_11787)
{
    (void) ctx;
    
    int err = 0;
    int64_t mem_14230_cached_sizze_14767 = 0;
    unsigned char *mem_14230 = NULL;
    int64_t mem_14271_cached_sizze_14768 = 0;
    unsigned char *mem_14271 = NULL;
    int64_t mem_14301_cached_sizze_14769 = 0;
    unsigned char *mem_14301 = NULL;
    int64_t mem_14334_cached_sizze_14770 = 0;
    unsigned char *mem_14334 = NULL;
    int64_t mem_14348_cached_sizze_14771 = 0;
    unsigned char *mem_14348 = NULL;
    int64_t mem_14394_cached_sizze_14772 = 0;
    unsigned char *mem_14394 = NULL;
    int64_t mem_14505_cached_sizze_14773 = 0;
    unsigned char *mem_14505 = NULL;
    int64_t mem_14566_cached_sizze_14774 = 0;
    unsigned char *mem_14566 = NULL;
    int64_t mem_14612_cached_sizze_14775 = 0;
    unsigned char *mem_14612 = NULL;
    struct memblock mem_14624;
    
    mem_14624.references = NULL;
    
    struct memblock mem_14617;
    
    mem_14617.references = NULL;
    
    struct memblock mem_14389;
    
    mem_14389.references = NULL;
    
    struct memblock mem_out_14736;
    
    mem_out_14736.references = NULL;
    
    struct memblock mem_out_14735;
    
    mem_out_14735.references = NULL;
    
    struct memblock mem_out_14734;
    
    mem_out_14734.references = NULL;
    
    int64_t x_13279 = sub64(n_11783, q_11781);
    int64_t new_n_13280 = add64((int64_t) 1, x_13279);
    int64_t x_13282 = sub64(m_11784, q_11781);
    int64_t new_m_13283 = add64((int64_t) 1, x_13282);
    int64_t total_13284 = mul64(q_11781, r_11782);
    int64_t x_13287 = new_n_13280 * new_m_13283;
    bool dim_match_13288 = k_11787 == new_m_13283;
    int64_t k_total_13293 = mul64(q_11781, q_11781);
    bool bounds_invalid_upwards_13294 = slt64(new_n_13280, (int64_t) 0);
    bool valid_13295 = !bounds_invalid_upwards_13294;
    bool range_valid_c_13296;
    
    if (!valid_13295) {
        set_error(ctx,
                  msgprintf("Error: %s%lld%s%lld%s%lld%s\n\nBacktrace:\n%s",
                            "Range ", (long long) (int64_t) 0, "..",
                            (long long) (int64_t) 1, "..<",
                            (long long) new_n_13280, " is invalid.",
                            "-> #0  /prelude/array.fut:95:3-10\n   #1  /prelude/array.fut:208:28-33\n   #2  ../layers/conv2d.fut:13:26-162\n   #3  /prelude/soacs.fut:59:3-10\n   #4  /prelude/array.fut:208:3-34\n   #5  conv2d_test.fut:67:3-46\n   #6  conv2d_test.fut:66:1-67:46\n"));
        err = FUTHARK_PROGRAM_ERROR;
        goto cleanup;
    }
    
    bool bounds_invalid_upwards_13298 = slt64(new_m_13283, (int64_t) 0);
    bool valid_13299 = !bounds_invalid_upwards_13298;
    bool range_valid_c_13300;
    
    if (!valid_13299) {
        set_error(ctx,
                  msgprintf("Error: %s%lld%s%lld%s%lld%s\n\nBacktrace:\n%s",
                            "Range ", (long long) (int64_t) 0, "..",
                            (long long) (int64_t) 1, "..<",
                            (long long) new_m_13283, " is invalid.",
                            "-> #0  /prelude/array.fut:95:3-10\n   #1  /prelude/array.fut:208:3-34\n   #2  ../layers/conv2d.fut:13:26-162\n   #3  /prelude/soacs.fut:59:3-10\n   #4  /prelude/array.fut:208:3-34\n   #5  conv2d_test.fut:67:3-46\n   #6  conv2d_test.fut:66:1-67:46\n"));
        err = FUTHARK_PROGRAM_ERROR;
        goto cleanup;
    }
    
    bool empty_slice_13302 = q_11781 == (int64_t) 0;
    int64_t m_13303 = sub64(q_11781, (int64_t) 1);
    bool dim_match_13306 = total_13284 == k_total_13293;
    bool empty_or_match_cert_13307;
    
    if (!dim_match_13306) {
        set_error(ctx, msgprintf("Error: %s%lld%s%lld%s\n\nBacktrace:\n%s",
                                 "Value of (core language) shape (",
                                 (long long) k_total_13293,
                                 ") cannot match shape of type `[",
                                 (long long) total_13284, "]f64`.",
                                 "-> #0  ../layers/conv2d.fut:13:60-161\n   #1  /prelude/soacs.fut:59:3-10\n   #2  /prelude/array.fut:200:3-17\n   #3  /prelude/functional.fut:39:59-65\n   #4  /prelude/soacs.fut:59:3-10\n   #5  /prelude/array.fut:208:3-34\n   #6  ../layers/conv2d.fut:13:26-162\n   #7  /prelude/soacs.fut:59:3-10\n   #8  /prelude/array.fut:208:3-34\n   #9  conv2d_test.fut:67:3-46\n   #10 conv2d_test.fut:66:1-67:46\n"));
        err = FUTHARK_PROGRAM_ERROR;
        goto cleanup;
    }
    
    bool dim_match_13310 = p_11786 == new_n_13280;
    bool match_13311 = dim_match_13288 && dim_match_13310;
    bool empty_or_match_cert_13312;
    
    if (!match_13311) {
        set_error(ctx,
                  msgprintf("Error: %s%lld%s%lld%s%lld%s%lld%s\n\nBacktrace:\n%s",
                            "Value of (core language) shape (",
                            (long long) new_n_13280, ", ",
                            (long long) new_m_13283,
                            ") cannot match shape of type `[",
                            (long long) p_11786, "][", (long long) k_11787,
                            "]f64`.",
                            "-> #0  ../layers/conv2d.fut:34:48-129\n   #1  /prelude/soacs.fut:59:3-10\n   #2  /prelude/array.fut:200:3-17\n   #3  /prelude/functional.fut:39:59-65\n   #4  /prelude/soacs.fut:59:3-10\n   #5  /prelude/array.fut:208:3-34\n   #6  conv2d_test.fut:67:3-46\n   #7  conv2d_test.fut:66:1-67:46\n"));
        err = FUTHARK_PROGRAM_ERROR;
        goto cleanup;
    }
    
    int64_t binop_x_14225 = o_11780 * l_11785;
    int64_t binop_x_14226 = p_11786 * binop_x_14225;
    int64_t binop_x_14227 = k_11787 * binop_x_14226;
    int64_t binop_y_14228 = (int64_t) 8 * binop_x_14227;
    int64_t bytes_14229 = smax64((int64_t) 0, binop_y_14228);
    
    if (mem_14230_cached_sizze_14767 < bytes_14229) {
        err = lexical_realloc(ctx, &mem_14230, &mem_14230_cached_sizze_14767,
                              bytes_14229);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    
    int64_t binop_y_14136 = new_m_13283 * total_13284;
    int64_t binop_x_14245 = p_11786 * k_11787;
    int64_t ixfun_arg_14246 = l_11785 * binop_x_14245;
    int64_t binop_x_14268 = total_13284 * x_13287;
    int64_t binop_y_14269 = (int64_t) 8 * binop_x_14268;
    int64_t bytes_14270 = smax64((int64_t) 0, binop_y_14269);
    
    if (mem_14271_cached_sizze_14768 < bytes_14270) {
        err = lexical_realloc(ctx, &mem_14271, &mem_14271_cached_sizze_14768,
                              bytes_14270);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    
    int64_t ixfun_arg_14283 = new_m_13283 * total_13284;
    int64_t binop_y_14299 = (int64_t) 8 * k_total_13293;
    int64_t bytes_14300 = smax64((int64_t) 0, binop_y_14299);
    
    if (mem_14301_cached_sizze_14769 < bytes_14300) {
        err = lexical_realloc(ctx, &mem_14301, &mem_14301_cached_sizze_14769,
                              bytes_14300);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    
    int64_t binop_y_14332 = (int64_t) 8 * x_13287;
    int64_t bytes_14333 = smax64((int64_t) 0, binop_y_14332);
    
    if (mem_14334_cached_sizze_14770 < bytes_14333) {
        err = lexical_realloc(ctx, &mem_14334, &mem_14334_cached_sizze_14770,
                              bytes_14333);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_14348_cached_sizze_14771 < bytes_14333) {
        err = lexical_realloc(ctx, &mem_14348, &mem_14348_cached_sizze_14771,
                              bytes_14333);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    for (int64_t i_13891 = 0; i_13891 < o_11780; i_13891++) {
        for (int64_t i_13887 = 0; i_13887 < l_11785; i_13887++) {
            for (int64_t i_13877 = 0; i_13877 < new_n_13280; i_13877++) {
                int64_t j_13376 = add64(q_11781, i_13877);
                int64_t i_p_m_t_s_13377 = add64(m_13303, i_13877);
                bool zzero_leq_i_p_m_t_s_13378 = sle64((int64_t) 0,
                                                       i_p_m_t_s_13377);
                bool i_p_m_t_s_leq_w_13379 = slt64(i_p_m_t_s_13377, n_11783);
                bool i_lte_j_13381 = sle64(i_13877, j_13376);
                bool y_13383 = zzero_leq_i_p_m_t_s_13378 &&
                     i_p_m_t_s_leq_w_13379;
                bool y_13384 = i_lte_j_13381 && y_13383;
                bool ok_or_empty_13386 = empty_slice_13302 || y_13384;
                
                for (int64_t i_13873 = 0; i_13873 < new_m_13283; i_13873++) {
                    int64_t j_13389 = add64(q_11781, i_13873);
                    int64_t i_p_m_t_s_13390 = add64(m_13303, i_13873);
                    bool zzero_leq_i_p_m_t_s_13391 = sle64((int64_t) 0,
                                                           i_p_m_t_s_13390);
                    bool i_p_m_t_s_leq_w_13392 = slt64(i_p_m_t_s_13390,
                                                       m_11784);
                    bool i_lte_j_13394 = sle64(i_13873, j_13389);
                    bool y_13396 = zzero_leq_i_p_m_t_s_13391 &&
                         i_p_m_t_s_leq_w_13392;
                    bool y_13397 = i_lte_j_13394 && y_13396;
                    bool ok_or_empty_13399 = empty_slice_13302 || y_13397;
                    bool index_ok_13400 = ok_or_empty_13386 &&
                         ok_or_empty_13399;
                    bool index_certs_13401;
                    
                    if (!index_ok_13400) {
                        set_error(ctx,
                                  msgprintf("Error: %s%lld%s%lld%s%lld%s%lld%s%lld%s%lld%s\n\nBacktrace:\n%s",
                                            "Index [", (long long) i_13877, ":",
                                            (long long) j_13376, ", ",
                                            (long long) i_13873, ":",
                                            (long long) j_13389,
                                            "] out of bounds for array of shape [",
                                            (long long) n_11783, "][",
                                            (long long) m_11784, "].",
                                            "-> #0  ../layers/conv2d.fut:13:90-124\n   #1  ../layers/conv2d.fut:13:69-146\n   #2  /prelude/soacs.fut:59:3-10\n   #3  /prelude/array.fut:200:3-17\n   #4  /prelude/functional.fut:39:59-65\n   #5  /prelude/soacs.fut:59:3-10\n   #6  /prelude/array.fut:208:3-34\n   #7  ../layers/conv2d.fut:13:26-162\n   #8  /prelude/soacs.fut:59:3-10\n   #9  /prelude/array.fut:208:3-34\n   #10 conv2d_test.fut:67:3-46\n   #11 conv2d_test.fut:66:1-67:46\n"));
                        err = FUTHARK_PROGRAM_ERROR;
                        goto cleanup;
                    }
                    for (int64_t i_14741 = 0; i_14741 < k_total_13293;
                         i_14741++) {
                        double tmp_14742 =
                               ((double *) conv_input_mem_14223.mem)[i_13887 *
                                                                     (m_11784 *
                                                                      n_11783) +
                                                                     m_11784 *
                                                                     i_13877 +
                                                                     i_13873 +
                                                                     (squot64(i_14741,
                                                                              q_11781) *
                                                                      m_11784 +
                                                                      (i_14741 -
                                                                       squot64(i_14741,
                                                                               q_11781) *
                                                                       q_11781))];
                        
                        ((double *) mem_14301)[i_14741] = tmp_14742;
                    }
                    if (k_total_13293 * (int64_t) 8 > 0)
                        memmove(mem_14271 + (i_13877 * ixfun_arg_14283 +
                                             i_13873 * total_13284) *
                                (int64_t) 8, mem_14301 + (int64_t) 0,
                                k_total_13293 * (int64_t) 8);
                }
            }
            for (int64_t i_13883 = 0; i_13883 < x_13287; i_13883++) {
                int64_t binop_x_14134 = total_13284 * i_13883;
                double defunc_2_reduce_res_13649;
                double redout_13879 = 0.0;
                
                for (int64_t i_13880 = 0; i_13880 < total_13284; i_13880++) {
                    int64_t new_index_13945 = squot64(i_13880, r_11782);
                    int64_t binop_y_13947 = r_11782 * new_index_13945;
                    int64_t new_index_13948 = i_13880 - binop_y_13947;
                    double x_13620 =
                           ((double *) out_grad_mem_14222.mem)[i_13891 *
                                                               (r_11782 *
                                                                q_11781) +
                                                               new_index_13945 *
                                                               r_11782 +
                                                               new_index_13948];
                    int64_t binop_x_14135 = i_13880 + binop_x_14134;
                    int64_t new_index_14137 = squot64(binop_x_14135,
                                                      binop_y_14136);
                    int64_t binop_y_14145 = binop_y_14136 * new_index_14137;
                    int64_t binop_x_14146 = binop_x_14135 - binop_y_14145;
                    int64_t new_index_14147 = squot64(binop_x_14146,
                                                      total_13284);
                    int64_t binop_y_14167 = total_13284 * new_index_14147;
                    int64_t new_index_14168 = binop_x_14146 - binop_y_14167;
                    double x_13621 = ((double *) mem_14271)[new_index_14137 *
                                                            ixfun_arg_14283 +
                                                            new_index_14147 *
                                                            total_13284 +
                                                            new_index_14168];
                    double defunc_1_f_res_13622 = x_13620 * x_13621;
                    double defunc_1_op_res_13416 = defunc_1_f_res_13622 +
                           redout_13879;
                    double redout_tmp_14744 = defunc_1_op_res_13416;
                    
                    redout_13879 = redout_tmp_14744;
                }
                defunc_2_reduce_res_13649 = redout_13879;
                ((double *) mem_14334)[i_13883] = defunc_2_reduce_res_13649;
            }
            if (new_n_13280 * new_m_13283 * (int64_t) 8 > 0)
                memmove(mem_14348 + (int64_t) 0, mem_14334 + (int64_t) 0,
                        new_n_13280 * new_m_13283 * (int64_t) 8);
            for (int64_t i_14745 = 0; i_14745 < new_n_13280; i_14745++) {
                for (int64_t i_14746 = 0; i_14746 < new_m_13283; i_14746++) {
                    double tmp_14747 = ((double *) mem_14348)[i_14745 *
                                                              new_m_13283 +
                                                              i_14746];
                    
                    ((double *) mem_14230)[i_13891 * ixfun_arg_14246 + i_13887 *
                                           binop_x_14245 + (i_14745 * k_11787 +
                                                            i_14746)] =
                        tmp_14747;
                }
            }
        }
    }
    
    bool empty_slice_13421 = o_11780 == (int64_t) 0;
    int64_t m_13422 = sub64(o_11780, (int64_t) 1);
    bool zzero_leq_i_p_m_t_s_13423 = sle64((int64_t) 0, m_13422);
    bool i_p_m_t_s_leq_w_13424 = slt64(m_13422, o_11780);
    bool i_lte_j_13425 = sle64((int64_t) 0, o_11780);
    bool y_13426 = zzero_leq_i_p_m_t_s_13423 && i_p_m_t_s_leq_w_13424;
    bool y_13427 = i_lte_j_13425 && y_13426;
    bool ok_or_empty_13428 = empty_slice_13421 || y_13427;
    bool empty_slice_13429 = l_11785 == (int64_t) 0;
    int64_t m_13430 = sub64(l_11785, (int64_t) 1);
    bool zzero_leq_i_p_m_t_s_13431 = sle64((int64_t) 0, m_13430);
    bool i_p_m_t_s_leq_w_13432 = slt64(m_13430, l_11785);
    bool i_lte_j_13433 = sle64((int64_t) 0, l_11785);
    bool y_13434 = zzero_leq_i_p_m_t_s_13431 && i_p_m_t_s_leq_w_13432;
    bool y_13435 = i_lte_j_13433 && y_13434;
    bool ok_or_empty_13436 = empty_slice_13429 || y_13435;
    int64_t w_minus_1_13437 = sub64(p_11786, (int64_t) 1);
    int64_t w_minus_1_13438 = sub64(k_11787, (int64_t) 1);
    bool index_ok_13439 = ok_or_empty_13428 && ok_or_empty_13436;
    bool index_certs_13440;
    
    if (!index_ok_13439) {
        set_error(ctx,
                  msgprintf("Error: %s%lld%s%lld%s%lld%s%lld%s%lld%s%lld%s\n\nBacktrace:\n%s",
                            "Index [", (long long) (int64_t) 0, ":, ",
                            (long long) (int64_t) 0,
                            ":, , ] out of bounds for array of shape [",
                            (long long) o_11780, "][", (long long) l_11785,
                            "][", (long long) p_11786, "][",
                            (long long) k_11787, "].",
                            "-> #0  ../layers/conv2d.fut:35:51-72\n   #1  conv2d_test.fut:67:3-46\n   #2  conv2d_test.fut:66:1-67:46\n"));
        err = FUTHARK_PROGRAM_ERROR;
        goto cleanup;
    }
    
    int64_t x_13447 = add64((int64_t) 2, r_11782);
    int64_t x_13448 = sub64(x_13447, p_11786);
    int64_t new_m_13449 = add64((int64_t) 1, x_13448);
    int64_t x_13444 = add64((int64_t) 2, q_11781);
    int64_t x_13445 = sub64(x_13444, p_11786);
    int64_t new_n_13446 = add64((int64_t) 1, x_13445);
    int64_t flat_dim_13545 = new_n_13446 * new_m_13449;
    int64_t k_total_13500 = mul64(p_11786, p_11786);
    int64_t flat_dim_13512 = o_11780 * k_total_13500;
    int64_t x_13450 = mul64(o_11780, p_11786);
    int64_t total_13451 = mul64(k_11787, x_13450);
    bool dim_match_13513 = total_13451 == flat_dim_13512;
    bool empty_or_match_cert_13514;
    
    if (!dim_match_13513) {
        set_error(ctx, msgprintf("Error: %s%lld%s%lld%s\n\nBacktrace:\n%s",
                                 "Value of (core language) shape (",
                                 (long long) flat_dim_13512,
                                 ") cannot match shape of type `[",
                                 (long long) total_13451, "]f64`.",
                                 "-> #0  ../layers/conv2d.fut:13:60-161\n   #1  /prelude/soacs.fut:59:3-10\n   #2  /prelude/array.fut:200:3-17\n   #3  /prelude/functional.fut:39:59-65\n   #4  /prelude/soacs.fut:59:3-10\n   #5  /prelude/array.fut:208:3-34\n   #6  ../layers/conv2d.fut:13:26-162\n   #7  ../layers/conv2d.fut:26:17-54\n   #8  conv2d_test.fut:67:3-46\n   #9  conv2d_test.fut:66:1-67:46\n"));
        err = FUTHARK_PROGRAM_ERROR;
        goto cleanup;
    }
    
    bool empty_slice_13509 = p_11786 == (int64_t) 0;
    bool bounds_invalid_upwards_13505 = slt64(new_m_13449, (int64_t) 0);
    bool valid_13506 = !bounds_invalid_upwards_13505;
    bool range_valid_c_13507;
    
    if (!valid_13506) {
        set_error(ctx,
                  msgprintf("Error: %s%lld%s%lld%s%lld%s\n\nBacktrace:\n%s",
                            "Range ", (long long) (int64_t) 0, "..",
                            (long long) (int64_t) 1, "..<",
                            (long long) new_m_13449, " is invalid.",
                            "-> #0  /prelude/array.fut:95:3-10\n   #1  /prelude/array.fut:208:3-34\n   #2  ../layers/conv2d.fut:13:26-162\n   #3  ../layers/conv2d.fut:26:17-54\n   #4  conv2d_test.fut:67:3-46\n   #5  conv2d_test.fut:66:1-67:46\n"));
        err = FUTHARK_PROGRAM_ERROR;
        goto cleanup;
    }
    
    bool bounds_invalid_upwards_13501 = slt64(new_n_13446, (int64_t) 0);
    bool valid_13502 = !bounds_invalid_upwards_13501;
    bool range_valid_c_13503;
    
    if (!valid_13502) {
        set_error(ctx,
                  msgprintf("Error: %s%lld%s%lld%s%lld%s\n\nBacktrace:\n%s",
                            "Range ", (long long) (int64_t) 0, "..",
                            (long long) (int64_t) 1, "..<",
                            (long long) new_n_13446, " is invalid.",
                            "-> #0  /prelude/array.fut:95:3-10\n   #1  /prelude/array.fut:208:28-33\n   #2  ../layers/conv2d.fut:13:26-162\n   #3  ../layers/conv2d.fut:26:17-54\n   #4  conv2d_test.fut:67:3-46\n   #5  conv2d_test.fut:66:1-67:46\n"));
        err = FUTHARK_PROGRAM_ERROR;
        goto cleanup;
    }
    
    int64_t y_13467 = add64((int64_t) 1, r_11782);
    int64_t y_13466 = add64((int64_t) 1, q_11781);
    int64_t binop_y_14387 = (int64_t) 8 * o_11780;
    int64_t bytes_14388 = smax64((int64_t) 0, binop_y_14387);
    
    if (memblock_alloc(ctx, &mem_14389, bytes_14388, "mem_14389")) {
        err = 1;
        goto cleanup;
    }
    
    int64_t binop_x_14390 = o_11780 * x_13444;
    int64_t binop_x_14391 = x_13447 * binop_x_14390;
    int64_t binop_y_14392 = (int64_t) 8 * binop_x_14391;
    int64_t bytes_14393 = smax64((int64_t) 0, binop_y_14392);
    
    if (mem_14394_cached_sizze_14772 < bytes_14393) {
        err = lexical_realloc(ctx, &mem_14394, &mem_14394_cached_sizze_14772,
                              bytes_14393);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    
    int64_t ixfun_arg_14411 = x_13444 * x_13447;
    
    for (int64_t i_13907 = 0; i_13907 < o_11780; i_13907++) {
        for (int64_t i_13899 = 0; i_13899 < x_13444; i_13899++) {
            bool cond_13585 = slt64(i_13899, (int64_t) 1);
            bool cond_f_res_13586 = sle64(y_13466, i_13899);
            bool x_13587 = !cond_13585;
            bool y_13588 = cond_f_res_13586 && x_13587;
            bool cond_13589 = cond_13585 || y_13588;
            bool x_13590 = !cond_13589;
            
            for (int64_t i_13895 = 0; i_13895 < x_13447; i_13895++) {
                bool cond_f_res_13593 = slt64(i_13895, (int64_t) 1);
                bool y_13594 = x_13590 && cond_f_res_13593;
                bool cond_13595 = cond_13589 || y_13594;
                bool cond_f_res_13596 = sle64(y_13467, i_13895);
                bool x_13597 = !cond_13595;
                bool y_13598 = cond_f_res_13596 && x_13597;
                bool cond_13599 = cond_13595 || y_13598;
                double defunc_0_f_res_13600;
                
                if (cond_13599 == 1) {
                    defunc_0_f_res_13600 = 0.0;
                } else {
                    int64_t i_13601 = sub64(i_13899, (int64_t) 1);
                    bool x_13602 = sle64((int64_t) 0, i_13601);
                    bool y_13603 = slt64(i_13601, q_11781);
                    bool bounds_check_13604 = x_13602 && y_13603;
                    int64_t i_13605 = sub64(i_13895, (int64_t) 1);
                    bool x_13606 = sle64((int64_t) 0, i_13605);
                    bool y_13607 = slt64(i_13605, r_11782);
                    bool bounds_check_13608 = x_13606 && y_13607;
                    bool index_ok_13609 = bounds_check_13604 &&
                         bounds_check_13608;
                    bool index_certs_13610;
                    
                    if (!index_ok_13609) {
                        set_error(ctx,
                                  msgprintf("Error: %s%lld%s%lld%s%lld%s%lld%s\n\nBacktrace:\n%s",
                                            "Index [", (long long) i_13601,
                                            ", ", (long long) i_13605,
                                            "] out of bounds for array of shape [",
                                            (long long) q_11781, "][",
                                            (long long) r_11782, "].",
                                            "-> #0  ../layers/conv2d.fut:7:91-116\n   #1  /prelude/soacs.fut:59:3-10\n   #2  /prelude/array.fut:200:3-17\n   #3  /prelude/functional.fut:39:59-65\n   #4  /prelude/soacs.fut:59:3-10\n   #5  /prelude/array.fut:208:3-34\n   #6  ../layers/conv2d.fut:6:22-7:117\n   #7  ../layers/conv2d.fut:6:6-7:123\n   #8  ../layers/conv2d.fut:22:7-30\n   #9  conv2d_test.fut:67:3-46\n   #10 conv2d_test.fut:66:1-67:46\n"));
                        err = FUTHARK_PROGRAM_ERROR;
                        goto cleanup;
                    }
                    
                    double defunc_0_f_res_f_res_13611 =
                           ((double *) out_grad_mem_14222.mem)[i_13907 *
                                                               (r_11782 *
                                                                q_11781) +
                                                               i_13601 *
                                                               r_11782 +
                                                               i_13605];
                    
                    defunc_0_f_res_13600 = defunc_0_f_res_f_res_13611;
                }
                ((double *) mem_14394)[i_13907 * ixfun_arg_14411 + i_13899 *
                                       x_13447 + i_13895] =
                    defunc_0_f_res_13600;
            }
        }
        
        int64_t binop_x_14099 = total_13284 * i_13907;
        double defunc_2_reduce_res_13658;
        double redout_13901 = 0.0;
        
        for (int64_t i_13902 = 0; i_13902 < total_13284; i_13902++) {
            int64_t binop_x_14100 = i_13902 + binop_x_14099;
            int64_t new_index_14102 = squot64(binop_x_14100, total_13284);
            int64_t binop_y_14110 = total_13284 * new_index_14102;
            int64_t binop_x_14111 = binop_x_14100 - binop_y_14110;
            int64_t new_index_14112 = squot64(binop_x_14111, r_11782);
            int64_t binop_y_14132 = r_11782 * new_index_14112;
            int64_t new_index_14133 = binop_x_14111 - binop_y_14132;
            double x_13617 =
                   ((double *) out_grad_mem_14222.mem)[new_index_14102 *
                                                       (r_11782 * q_11781) +
                                                       new_index_14112 *
                                                       r_11782 +
                                                       new_index_14133];
            double defunc_1_op_res_13616 = x_13617 + redout_13901;
            double redout_tmp_14752 = defunc_1_op_res_13616;
            
            redout_13901 = redout_tmp_14752;
        }
        defunc_2_reduce_res_13658 = redout_13901;
        ((double *) mem_14389.mem)[i_13907] = defunc_2_reduce_res_13658;
    }
    
    int64_t binop_x_14502 = total_13451 * flat_dim_13545;
    int64_t binop_y_14503 = (int64_t) 8 * binop_x_14502;
    int64_t bytes_14504 = smax64((int64_t) 0, binop_y_14503);
    
    if (mem_14505_cached_sizze_14773 < bytes_14504) {
        err = lexical_realloc(ctx, &mem_14505, &mem_14505_cached_sizze_14773,
                              bytes_14504);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    
    int64_t ixfun_arg_14517 = new_m_13449 * total_13451;
    
    for (int64_t i_13916 = 0; i_13916 < new_n_13446; i_13916++) {
        int64_t j_13517 = add64(p_11786, i_13916);
        int64_t i_p_m_t_s_13518 = add64(w_minus_1_13437, i_13916);
        bool zzero_leq_i_p_m_t_s_13519 = sle64((int64_t) 0, i_p_m_t_s_13518);
        bool i_p_m_t_s_leq_w_13520 = slt64(i_p_m_t_s_13518, x_13444);
        bool i_lte_j_13522 = sle64(i_13916, j_13517);
        bool y_13524 = zzero_leq_i_p_m_t_s_13519 && i_p_m_t_s_leq_w_13520;
        bool y_13525 = i_lte_j_13522 && y_13524;
        bool ok_or_empty_13527 = empty_slice_13509 || y_13525;
        
        for (int64_t i_13912 = 0; i_13912 < new_m_13449; i_13912++) {
            int64_t j_13530 = add64(p_11786, i_13912);
            int64_t i_p_m_t_s_13531 = add64(w_minus_1_13437, i_13912);
            bool zzero_leq_i_p_m_t_s_13532 = sle64((int64_t) 0,
                                                   i_p_m_t_s_13531);
            bool i_p_m_t_s_leq_w_13533 = slt64(i_p_m_t_s_13531, x_13447);
            bool i_lte_j_13535 = sle64(i_13912, j_13530);
            bool y_13537 = zzero_leq_i_p_m_t_s_13532 && i_p_m_t_s_leq_w_13533;
            bool y_13538 = i_lte_j_13535 && y_13537;
            bool ok_or_empty_13540 = empty_slice_13509 || y_13538;
            bool index_ok_13541 = ok_or_empty_13527 && ok_or_empty_13540;
            bool index_certs_13542;
            
            if (!index_ok_13541) {
                set_error(ctx,
                          msgprintf("Error: %s%lld%s%lld%s%lld%s%lld%s%lld%s%lld%s\n\nBacktrace:\n%s",
                                    "Index [", (long long) i_13916, ":",
                                    (long long) j_13517, ", ",
                                    (long long) i_13912, ":",
                                    (long long) j_13530,
                                    "] out of bounds for array of shape [",
                                    (long long) x_13444, "][",
                                    (long long) x_13447, "].",
                                    "-> #0  ../layers/conv2d.fut:13:90-124\n   #1  ../layers/conv2d.fut:13:69-146\n   #2  /prelude/soacs.fut:59:3-10\n   #3  /prelude/array.fut:200:3-17\n   #4  /prelude/functional.fut:39:59-65\n   #5  /prelude/soacs.fut:59:3-10\n   #6  /prelude/array.fut:208:3-34\n   #7  ../layers/conv2d.fut:13:26-162\n   #8  ../layers/conv2d.fut:26:17-54\n   #9  conv2d_test.fut:67:3-46\n   #10 conv2d_test.fut:66:1-67:46\n"));
                err = FUTHARK_PROGRAM_ERROR;
                goto cleanup;
            }
            for (int64_t i_14755 = 0; i_14755 < total_13451; i_14755++) {
                double tmp_14756 = ((double *) mem_14394)[x_13447 * i_13916 +
                                                          i_13912 +
                                                          (squot64(i_14755,
                                                                   p_11786 *
                                                                   p_11786) *
                                                           ixfun_arg_14411 +
                                                           squot64(i_14755 -
                                                                   squot64(i_14755,
                                                                           p_11786 *
                                                                           p_11786) *
                                                                   (p_11786 *
                                                                    p_11786),
                                                                   p_11786) *
                                                           x_13447 + (i_14755 -
                                                                      squot64(i_14755,
                                                                              p_11786 *
                                                                              p_11786) *
                                                                      (p_11786 *
                                                                       p_11786) -
                                                                      squot64(i_14755 -
                                                                              squot64(i_14755,
                                                                                      p_11786 *
                                                                                      p_11786) *
                                                                              (p_11786 *
                                                                               p_11786),
                                                                              p_11786) *
                                                                      p_11786))];
                
                ((double *) mem_14505)[i_13916 * ixfun_arg_14517 + i_13912 *
                                       total_13451 + i_14755] = tmp_14756;
            }
        }
    }
    
    int64_t binop_x_14563 = l_11785 * flat_dim_13545;
    int64_t binop_y_14564 = (int64_t) 8 * binop_x_14563;
    int64_t bytes_14565 = smax64((int64_t) 0, binop_y_14564);
    
    if (mem_14566_cached_sizze_14774 < bytes_14565) {
        err = lexical_realloc(ctx, &mem_14566, &mem_14566_cached_sizze_14774,
                              bytes_14565);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    
    int64_t binop_y_13973 = p_11786 * k_11787;
    int64_t binop_y_14062 = new_m_13449 * total_13451;
    
    for (int64_t i_13926 = 0; i_13926 < l_11785; i_13926++) {
        int64_t binop_x_13957 = total_13451 * i_13926;
        
        for (int64_t i_13922 = 0; i_13922 < flat_dim_13545; i_13922++) {
            int64_t binop_x_14060 = total_13451 * i_13922;
            double defunc_2_reduce_res_13654;
            double redout_13918 = 0.0;
            
            for (int64_t i_13919 = 0; i_13919 < total_13451; i_13919++) {
                int64_t binop_x_13958 = i_13919 + binop_x_13957;
                int64_t new_index_13961 = squot64(binop_x_13958, total_13451);
                int64_t binop_y_13971 = total_13451 * new_index_13961;
                int64_t binop_x_13972 = binop_x_13958 - binop_y_13971;
                int64_t new_index_13974 = squot64(binop_x_13972, binop_y_13973);
                int64_t binop_y_14000 = binop_y_13973 * new_index_13974;
                int64_t binop_x_14001 = binop_x_13972 - binop_y_14000;
                int64_t new_index_14002 = squot64(binop_x_14001, k_11787);
                int64_t binop_y_14058 = k_11787 * new_index_14002;
                int64_t new_index_14059 = binop_x_14001 - binop_y_14058;
                int64_t binop_y_14095 = (int64_t) -1 * new_index_14002;
                int64_t slice_14096 = w_minus_1_13437 + binop_y_14095;
                int64_t binop_y_14097 = (int64_t) -1 * new_index_14059;
                int64_t slice_14098 = w_minus_1_13438 + binop_y_14097;
                double x_13637 =
                       ((double *) kernels_mem_14224.mem)[new_index_13974 *
                                                          (k_11787 * p_11786 *
                                                           l_11785) +
                                                          new_index_13961 *
                                                          (k_11787 * p_11786) +
                                                          slice_14096 *
                                                          k_11787 +
                                                          slice_14098];
                int64_t binop_x_14061 = i_13919 + binop_x_14060;
                int64_t new_index_14063 = squot64(binop_x_14061, binop_y_14062);
                int64_t binop_y_14071 = binop_y_14062 * new_index_14063;
                int64_t binop_x_14072 = binop_x_14061 - binop_y_14071;
                int64_t new_index_14073 = squot64(binop_x_14072, total_13451);
                int64_t binop_y_14093 = total_13451 * new_index_14073;
                int64_t new_index_14094 = binop_x_14072 - binop_y_14093;
                double x_13638 = ((double *) mem_14505)[new_index_14063 *
                                                        ixfun_arg_14517 +
                                                        new_index_14073 *
                                                        total_13451 +
                                                        new_index_14094];
                double defunc_1_f_res_13639 = x_13637 * x_13638;
                double defunc_1_op_res_13561 = defunc_1_f_res_13639 +
                       redout_13918;
                double redout_tmp_14759 = defunc_1_op_res_13561;
                
                redout_13918 = redout_tmp_14759;
            }
            defunc_2_reduce_res_13654 = redout_13918;
            ((double *) mem_14566)[i_13926 * flat_dim_13545 + i_13922] =
                defunc_2_reduce_res_13654;
        }
    }
    
    int64_t binop_x_14608 = l_11785 * new_n_13446;
    int64_t binop_x_14609 = new_m_13449 * binop_x_14608;
    int64_t binop_y_14610 = (int64_t) 8 * binop_x_14609;
    int64_t bytes_14611 = smax64((int64_t) 0, binop_y_14610);
    
    if (mem_14612_cached_sizze_14775 < bytes_14611) {
        err = lexical_realloc(ctx, &mem_14612, &mem_14612_cached_sizze_14775,
                              bytes_14611);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (l_11785 * new_n_13446 * new_m_13449 * (int64_t) 8 > 0)
        memmove(mem_14612 + (int64_t) 0, mem_14566 + (int64_t) 0, l_11785 *
                new_n_13446 * new_m_13449 * (int64_t) 8);
    
    bool dim_match_13567 = n_11783 == new_n_13446;
    bool dim_match_13568 = m_11784 == new_m_13449;
    bool match_13569 = dim_match_13567 && dim_match_13568;
    bool empty_or_match_cert_13570;
    
    if (!match_13569) {
        set_error(ctx,
                  msgprintf("Error: %s%lld%s%lld%s%lld%s%lld%s%lld%s%lld%s\n\nBacktrace:\n%s",
                            "Value of (core language) shape (",
                            (long long) l_11785, ", ", (long long) new_n_13446,
                            ", ", (long long) new_m_13449,
                            ") cannot match shape of type `[",
                            (long long) l_11785, "][", (long long) n_11783,
                            "][", (long long) m_11784, "]f64`.",
                            "-> #0  ../layers/conv2d.fut:35:20-117\n   #1  conv2d_test.fut:67:3-46\n   #2  conv2d_test.fut:66:1-67:46\n"));
        err = FUTHARK_PROGRAM_ERROR;
        goto cleanup;
    }
    
    int64_t binop_x_14613 = n_11783 * l_11785;
    int64_t binop_x_14614 = m_11784 * binop_x_14613;
    int64_t binop_y_14615 = (int64_t) 8 * binop_x_14614;
    int64_t bytes_14616 = smax64((int64_t) 0, binop_y_14615);
    
    if (memblock_alloc(ctx, &mem_14617, bytes_14616, "mem_14617")) {
        err = 1;
        goto cleanup;
    }
    if (l_11785 * n_11783 * m_11784 * (int64_t) 8 > 0)
        memmove(mem_14617.mem + (int64_t) 0, mem_14612 + (int64_t) 0, l_11785 *
                n_11783 * m_11784 * (int64_t) 8);
    if (memblock_alloc(ctx, &mem_14624, bytes_14229, "mem_14624")) {
        err = 1;
        goto cleanup;
    }
    if (o_11780 * l_11785 * p_11786 * k_11787 * (int64_t) 8 > 0)
        memmove(mem_14624.mem + (int64_t) 0, mem_14230 + (int64_t) 0, o_11780 *
                l_11785 * p_11786 * k_11787 * (int64_t) 8);
    if (memblock_set(ctx, &mem_out_14734, &mem_14617, "mem_14617") != 0)
        return 1;
    if (memblock_set(ctx, &mem_out_14735, &mem_14624, "mem_14624") != 0)
        return 1;
    if (memblock_set(ctx, &mem_out_14736, &mem_14389, "mem_14389") != 0)
        return 1;
    (*mem_out_p_14764).references = NULL;
    if (memblock_set(ctx, &*mem_out_p_14764, &mem_out_14734, "mem_out_14734") !=
        0)
        return 1;
    (*mem_out_p_14765).references = NULL;
    if (memblock_set(ctx, &*mem_out_p_14765, &mem_out_14735, "mem_out_14735") !=
        0)
        return 1;
    (*mem_out_p_14766).references = NULL;
    if (memblock_set(ctx, &*mem_out_p_14766, &mem_out_14736, "mem_out_14736") !=
        0)
        return 1;
    
  cleanup:
    {
        free(mem_14230);
        free(mem_14271);
        free(mem_14301);
        free(mem_14334);
        free(mem_14348);
        free(mem_14394);
        free(mem_14505);
        free(mem_14566);
        free(mem_14612);
        if (memblock_unref(ctx, &mem_14624, "mem_14624") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_14617, "mem_14617") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_14389, "mem_14389") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_out_14736, "mem_out_14736") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_out_14735, "mem_out_14735") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_out_14734, "mem_out_14734") != 0)
            return 1;
    }
    return err;
}
static int futrts_entry_convolve2d_b_test(struct futhark_context *ctx,
                                          struct memblock *mem_out_p_14776,
                                          struct memblock *mem_out_p_14777,
                                          struct memblock *mem_out_p_14778,
                                          struct memblock out_grad_mem_14222,
                                          struct memblock conv_input_mem_14223,
                                          struct memblock kernels_mem_14224,
                                          int64_t o_11750, int64_t q_11751,
                                          int64_t r_11752, int64_t n_11753,
                                          int64_t m_11754, int64_t l_11755,
                                          int64_t p_11756, int64_t k_11757,
                                          int64_t valid_num_11761,
                                          int64_t full_num_11762)
{
    (void) ctx;
    
    int err = 0;
    int64_t mem_14230_cached_sizze_14779 = 0;
    unsigned char *mem_14230 = NULL;
    int64_t mem_14274_cached_sizze_14780 = 0;
    unsigned char *mem_14274 = NULL;
    int64_t mem_14331_cached_sizze_14781 = 0;
    unsigned char *mem_14331 = NULL;
    int64_t mem_14361_cached_sizze_14782 = 0;
    unsigned char *mem_14361 = NULL;
    int64_t mem_14394_cached_sizze_14783 = 0;
    unsigned char *mem_14394 = NULL;
    int64_t mem_14408_cached_sizze_14784 = 0;
    unsigned char *mem_14408 = NULL;
    int64_t mem_14561_cached_sizze_14785 = 0;
    unsigned char *mem_14561 = NULL;
    int64_t mem_14622_cached_sizze_14786 = 0;
    unsigned char *mem_14622 = NULL;
    int64_t mem_14668_cached_sizze_14787 = 0;
    unsigned char *mem_14668 = NULL;
    struct memblock mem_14693;
    
    mem_14693.references = NULL;
    
    struct memblock mem_14686;
    
    mem_14686.references = NULL;
    
    struct memblock mem_14671;
    
    mem_14671.references = NULL;
    
    struct memblock mem_14451;
    
    mem_14451.references = NULL;
    
    struct memblock ext_mem_14556;
    
    ext_mem_14556.references = NULL;
    
    struct memblock mem_14319;
    
    mem_14319.references = NULL;
    
    struct memblock ext_mem_14326;
    
    ext_mem_14326.references = NULL;
    
    struct memblock mem_14270;
    
    mem_14270.references = NULL;
    
    struct memblock mem_out_14736;
    
    mem_out_14736.references = NULL;
    
    struct memblock mem_out_14735;
    
    mem_out_14735.references = NULL;
    
    struct memblock mem_out_14734;
    
    mem_out_14734.references = NULL;
    
    int64_t y_13277 = mul64((int64_t) 2, valid_num_11761);
    int64_t x_13278 = add64(n_11753, y_13277);
    int64_t x_13279 = sub64(x_13278, q_11751);
    int64_t new_n_13280 = add64((int64_t) 1, x_13279);
    int64_t x_13281 = add64(m_11754, y_13277);
    int64_t x_13282 = sub64(x_13281, q_11751);
    int64_t new_m_13283 = add64((int64_t) 1, x_13282);
    int64_t total_13284 = mul64(q_11751, r_11752);
    bool cond_13285 = valid_num_11761 == (int64_t) 0;
    bool cond_13286 = !cond_13285;
    int64_t x_13287 = new_n_13280 * new_m_13283;
    bool dim_match_13288 = k_11757 == new_m_13283;
    int64_t y_13291 = add64(n_11753, valid_num_11761);
    int64_t y_13292 = add64(m_11754, valid_num_11761);
    int64_t k_total_13293 = mul64(q_11751, q_11751);
    bool bounds_invalid_upwards_13294 = slt64(new_n_13280, (int64_t) 0);
    bool valid_13295 = !bounds_invalid_upwards_13294;
    bool range_valid_c_13296;
    
    if (!valid_13295) {
        set_error(ctx,
                  msgprintf("Error: %s%lld%s%lld%s%lld%s\n\nBacktrace:\n%s",
                            "Range ", (long long) (int64_t) 0, "..",
                            (long long) (int64_t) 1, "..<",
                            (long long) new_n_13280, " is invalid.",
                            "-> #0  /prelude/array.fut:95:3-10\n   #1  /prelude/array.fut:208:28-33\n   #2  ../layers/conv2d.fut:13:26-162\n   #3  /prelude/soacs.fut:59:3-10\n   #4  /prelude/array.fut:208:3-34\n   #5  conv2d_test.fut:64:3-61\n   #6  conv2d_test.fut:63:1-64:61\n"));
        err = FUTHARK_PROGRAM_ERROR;
        goto cleanup;
    }
    
    bool bounds_invalid_upwards_13298 = slt64(new_m_13283, (int64_t) 0);
    bool valid_13299 = !bounds_invalid_upwards_13298;
    bool range_valid_c_13300;
    
    if (!valid_13299) {
        set_error(ctx,
                  msgprintf("Error: %s%lld%s%lld%s%lld%s\n\nBacktrace:\n%s",
                            "Range ", (long long) (int64_t) 0, "..",
                            (long long) (int64_t) 1, "..<",
                            (long long) new_m_13283, " is invalid.",
                            "-> #0  /prelude/array.fut:95:3-10\n   #1  /prelude/array.fut:208:3-34\n   #2  ../layers/conv2d.fut:13:26-162\n   #3  /prelude/soacs.fut:59:3-10\n   #4  /prelude/array.fut:208:3-34\n   #5  conv2d_test.fut:64:3-61\n   #6  conv2d_test.fut:63:1-64:61\n"));
        err = FUTHARK_PROGRAM_ERROR;
        goto cleanup;
    }
    
    bool empty_slice_13302 = q_11751 == (int64_t) 0;
    int64_t m_13303 = sub64(q_11751, (int64_t) 1);
    bool dim_match_13306 = total_13284 == k_total_13293;
    bool empty_or_match_cert_13307;
    
    if (!dim_match_13306) {
        set_error(ctx, msgprintf("Error: %s%lld%s%lld%s\n\nBacktrace:\n%s",
                                 "Value of (core language) shape (",
                                 (long long) k_total_13293,
                                 ") cannot match shape of type `[",
                                 (long long) total_13284, "]f64`.",
                                 "-> #0  ../layers/conv2d.fut:13:60-161\n   #1  /prelude/soacs.fut:59:3-10\n   #2  /prelude/array.fut:200:3-17\n   #3  /prelude/functional.fut:39:59-65\n   #4  /prelude/soacs.fut:59:3-10\n   #5  /prelude/array.fut:208:3-34\n   #6  ../layers/conv2d.fut:13:26-162\n   #7  /prelude/soacs.fut:59:3-10\n   #8  /prelude/array.fut:208:3-34\n   #9  conv2d_test.fut:64:3-61\n   #10 conv2d_test.fut:63:1-64:61\n"));
        err = FUTHARK_PROGRAM_ERROR;
        goto cleanup;
    }
    
    bool dim_match_13310 = p_11756 == new_n_13280;
    bool match_13311 = dim_match_13288 && dim_match_13310;
    bool empty_or_match_cert_13312;
    
    if (!match_13311) {
        set_error(ctx,
                  msgprintf("Error: %s%lld%s%lld%s%lld%s%lld%s\n\nBacktrace:\n%s",
                            "Value of (core language) shape (",
                            (long long) new_n_13280, ", ",
                            (long long) new_m_13283,
                            ") cannot match shape of type `[",
                            (long long) p_11756, "][", (long long) k_11757,
                            "]f64`.",
                            "-> #0  ../layers/conv2d.fut:34:48-129\n   #1  /prelude/soacs.fut:59:3-10\n   #2  /prelude/array.fut:200:3-17\n   #3  /prelude/functional.fut:39:59-65\n   #4  /prelude/soacs.fut:59:3-10\n   #5  /prelude/array.fut:208:3-34\n   #6  conv2d_test.fut:64:3-61\n   #7  conv2d_test.fut:63:1-64:61\n"));
        err = FUTHARK_PROGRAM_ERROR;
        goto cleanup;
    }
    
    int64_t imgs_padded_13313;
    
    if (cond_13286 == 1) {
        imgs_padded_13313 = x_13278;
    } else {
        imgs_padded_13313 = n_11753;
    }
    
    int64_t imgs_padded_13314;
    
    if (cond_13286 == 1) {
        imgs_padded_13314 = x_13281;
    } else {
        imgs_padded_13314 = m_11754;
    }
    
    bool bounds_invalid_upwards_13315 = slt64(x_13278, (int64_t) 0);
    bool bounds_invalid_upwards_13316 = slt64(x_13281, (int64_t) 0);
    bool valid_13317 = !bounds_invalid_upwards_13315;
    bool valid_13318 = !bounds_invalid_upwards_13316;
    bool protect_assert_disj_13319 = cond_13285 || valid_13317;
    bool range_valid_c_13320;
    
    if (!protect_assert_disj_13319) {
        set_error(ctx,
                  msgprintf("Error: %s%lld%s%lld%s%lld%s\n\nBacktrace:\n%s",
                            "Range ", (long long) (int64_t) 0, "..",
                            (long long) (int64_t) 1, "..<", (long long) x_13278,
                            " is invalid.",
                            "-> #0  /prelude/array.fut:95:3-10\n   #1  ../layers/conv2d.fut:6:6-7:123\n   #2  /prelude/soacs.fut:59:3-10\n   #3  /prelude/array.fut:208:3-34\n   #4  conv2d_test.fut:64:3-61\n   #5  conv2d_test.fut:63:1-64:61\n"));
        err = FUTHARK_PROGRAM_ERROR;
        goto cleanup;
    }
    
    bool protect_assert_disj_13321 = cond_13285 || valid_13318;
    bool range_valid_c_13322;
    
    if (!protect_assert_disj_13321) {
        set_error(ctx,
                  msgprintf("Error: %s%lld%s%lld%s%lld%s\n\nBacktrace:\n%s",
                            "Range ", (long long) (int64_t) 0, "..",
                            (long long) (int64_t) 1, "..<", (long long) x_13281,
                            " is invalid.",
                            "-> #0  /prelude/array.fut:95:3-10\n   #1  ../layers/conv2d.fut:6:6-7:123\n   #2  /prelude/soacs.fut:59:3-10\n   #3  /prelude/array.fut:208:3-34\n   #4  conv2d_test.fut:64:3-61\n   #5  conv2d_test.fut:63:1-64:61\n"));
        err = FUTHARK_PROGRAM_ERROR;
        goto cleanup;
    }
    
    int64_t binop_x_14225 = o_11750 * l_11755;
    int64_t binop_x_14226 = p_11756 * binop_x_14225;
    int64_t binop_x_14227 = k_11757 * binop_x_14226;
    int64_t binop_y_14228 = (int64_t) 8 * binop_x_14227;
    int64_t bytes_14229 = smax64((int64_t) 0, binop_y_14228);
    
    if (mem_14230_cached_sizze_14779 < bytes_14229) {
        err = lexical_realloc(ctx, &mem_14230, &mem_14230_cached_sizze_14779,
                              bytes_14229);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    
    int64_t binop_y_14140 = new_m_13283 * total_13284;
    int64_t binop_x_14245 = p_11756 * k_11757;
    int64_t ixfun_arg_14246 = l_11755 * binop_x_14245;
    int64_t binop_x_14267 = n_11753 * m_11754;
    int64_t binop_y_14268 = (int64_t) 8 * binop_x_14267;
    int64_t bytes_14269 = smax64((int64_t) 0, binop_y_14268);
    
    if (memblock_alloc(ctx, &mem_14270, bytes_14269, "mem_14270")) {
        err = 1;
        goto cleanup;
    }
    
    int64_t ext_14324;
    
    if (cond_13286 == 1) {
        ext_14324 = x_13281;
    } else {
        ext_14324 = m_11754;
    }
    
    int64_t ext_14323;
    
    if (cond_13286 == 1) {
        ext_14323 = x_13278;
    } else {
        ext_14323 = n_11753;
    }
    
    int64_t ext_14322;
    
    if (cond_13286 == 1) {
        ext_14322 = x_13281;
    } else {
        ext_14322 = m_11754;
    }
    
    int64_t ixfun_ext_14320 = n_11753 * m_11754;
    int64_t binop_x_14271 = x_13278 * x_13281;
    int64_t binop_y_14272 = (int64_t) 8 * binop_x_14271;
    int64_t bytes_14273 = smax64((int64_t) 0, binop_y_14272);
    int64_t ixfun_ext_14321 = x_13278 * x_13281;
    int64_t binop_x_14328 = total_13284 * x_13287;
    int64_t binop_y_14329 = (int64_t) 8 * binop_x_14328;
    int64_t bytes_14330 = smax64((int64_t) 0, binop_y_14329);
    
    if (mem_14331_cached_sizze_14781 < bytes_14330) {
        err = lexical_realloc(ctx, &mem_14331, &mem_14331_cached_sizze_14781,
                              bytes_14330);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    
    int64_t ixfun_arg_14343 = new_m_13283 * total_13284;
    int64_t binop_y_14359 = (int64_t) 8 * k_total_13293;
    int64_t bytes_14360 = smax64((int64_t) 0, binop_y_14359);
    
    if (mem_14361_cached_sizze_14782 < bytes_14360) {
        err = lexical_realloc(ctx, &mem_14361, &mem_14361_cached_sizze_14782,
                              bytes_14360);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    
    int64_t binop_y_14392 = (int64_t) 8 * x_13287;
    int64_t bytes_14393 = smax64((int64_t) 0, binop_y_14392);
    
    if (mem_14394_cached_sizze_14783 < bytes_14393) {
        err = lexical_realloc(ctx, &mem_14394, &mem_14394_cached_sizze_14783,
                              bytes_14393);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_14408_cached_sizze_14784 < bytes_14393) {
        err = lexical_realloc(ctx, &mem_14408, &mem_14408_cached_sizze_14784,
                              bytes_14393);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    
    int64_t ext_14325;
    
    if (cond_13286 == 1) {
        ext_14325 = ixfun_ext_14321;
    } else {
        ext_14325 = ixfun_ext_14320;
    }
    for (int64_t i_13899 = 0; i_13899 < o_11750; i_13899++) {
        for (int64_t i_13895 = 0; i_13895 < l_11755; i_13895++) {
            for (int64_t i_14739 = 0; i_14739 < (int64_t) 1; i_14739++) {
                if (n_11753 * m_11754 * (int64_t) 8 > 0)
                    memmove(mem_14270.mem + i_14739 * (m_11754 * n_11753) *
                            (int64_t) 8, conv_input_mem_14223.mem + i_13895 *
                            (m_11754 * n_11753) * (int64_t) 8, n_11753 *
                            m_11754 * (int64_t) 8);
            }
            if (cond_13286 == 1) {
                if (mem_14274_cached_sizze_14780 < bytes_14273) {
                    err = lexical_realloc(ctx, &mem_14274,
                                          &mem_14274_cached_sizze_14780,
                                          bytes_14273);
                    if (err != FUTHARK_SUCCESS)
                        goto cleanup;
                }
                for (int64_t i_13877 = 0; i_13877 < x_13278; i_13877++) {
                    bool cond_13774 = slt64(i_13877, valid_num_11761);
                    bool cond_f_res_13775 = sle64(y_13291, i_13877);
                    bool x_13776 = !cond_13774;
                    bool y_13777 = cond_f_res_13775 && x_13776;
                    bool cond_13778 = cond_13774 || y_13777;
                    bool x_13779 = !cond_13778;
                    
                    for (int64_t i_13873 = 0; i_13873 < x_13281; i_13873++) {
                        bool cond_f_res_13782 = slt64(i_13873, valid_num_11761);
                        bool y_13783 = x_13779 && cond_f_res_13782;
                        bool cond_13784 = cond_13778 || y_13783;
                        bool cond_f_res_13785 = sle64(y_13292, i_13873);
                        bool x_13786 = !cond_13784;
                        bool y_13787 = cond_f_res_13785 && x_13786;
                        bool cond_13788 = cond_13784 || y_13787;
                        double defunc_0_f_res_13789;
                        
                        if (cond_13788 == 1) {
                            defunc_0_f_res_13789 = 0.0;
                        } else {
                            int64_t i_13790 = sub64(i_13877, valid_num_11761);
                            bool x_13791 = sle64((int64_t) 0, i_13790);
                            bool y_13792 = slt64(i_13790, n_11753);
                            bool bounds_check_13793 = x_13791 && y_13792;
                            int64_t i_13794 = sub64(i_13873, valid_num_11761);
                            bool x_13795 = sle64((int64_t) 0, i_13794);
                            bool y_13796 = slt64(i_13794, m_11754);
                            bool bounds_check_13797 = x_13795 && y_13796;
                            bool index_ok_13798 = bounds_check_13793 &&
                                 bounds_check_13797;
                            bool index_certs_13799;
                            
                            if (!index_ok_13798) {
                                set_error(ctx,
                                          msgprintf("Error: %s%lld%s%lld%s%lld%s%lld%s\n\nBacktrace:\n%s",
                                                    "Index [",
                                                    (long long) i_13790, ", ",
                                                    (long long) i_13794,
                                                    "] out of bounds for array of shape [",
                                                    (long long) n_11753, "][",
                                                    (long long) m_11754, "].",
                                                    "-> #0  ../layers/conv2d.fut:7:91-116\n   #1  /prelude/soacs.fut:59:3-10\n   #2  /prelude/array.fut:200:3-17\n   #3  /prelude/functional.fut:39:59-65\n   #4  /prelude/soacs.fut:59:3-10\n   #5  /prelude/array.fut:208:3-34\n   #6  ../layers/conv2d.fut:6:22-7:117\n   #7  ../layers/conv2d.fut:6:6-7:123\n   #8  /prelude/soacs.fut:59:3-10\n   #9  /prelude/array.fut:208:3-34\n   #10 conv2d_test.fut:64:3-61\n   #11 conv2d_test.fut:63:1-64:61\n"));
                                err = FUTHARK_PROGRAM_ERROR;
                                goto cleanup;
                            }
                            
                            double defunc_0_f_res_f_res_13800 =
                                   ((double *) conv_input_mem_14223.mem)[i_13895 *
                                                                         (m_11754 *
                                                                          n_11753) +
                                                                         i_13790 *
                                                                         m_11754 +
                                                                         i_13794];
                            
                            defunc_0_f_res_13789 = defunc_0_f_res_f_res_13800;
                        }
                        ((double *) mem_14274)[i_13877 * x_13281 + i_13873] =
                            defunc_0_f_res_13789;
                    }
                }
                if (memblock_alloc(ctx, &mem_14319, bytes_14273, "mem_14319")) {
                    err = 1;
                    goto cleanup;
                }
                for (int64_t i_14742 = 0; i_14742 < (int64_t) 1; i_14742++) {
                    if (x_13278 * x_13281 * (int64_t) 8 > 0)
                        memmove(mem_14319.mem + i_14742 * (x_13281 * x_13278) *
                                (int64_t) 8, mem_14274 + (int64_t) 0, x_13278 *
                                x_13281 * (int64_t) 8);
                }
                if (memblock_set(ctx, &ext_mem_14326, &mem_14319,
                                 "mem_14319") != 0)
                    return 1;
            } else if (memblock_set(ctx, &ext_mem_14326, &mem_14270,
                                    "mem_14270") != 0)
                return 1;
            for (int64_t i_13885 = 0; i_13885 < new_n_13280; i_13885++) {
                int64_t j_13376 = add64(q_11751, i_13885);
                int64_t i_p_m_t_s_13377 = add64(m_13303, i_13885);
                bool zzero_leq_i_p_m_t_s_13378 = sle64((int64_t) 0,
                                                       i_p_m_t_s_13377);
                bool i_p_m_t_s_leq_w_13379 = slt64(i_p_m_t_s_13377,
                                                   imgs_padded_13313);
                bool i_lte_j_13381 = sle64(i_13885, j_13376);
                bool y_13383 = zzero_leq_i_p_m_t_s_13378 &&
                     i_p_m_t_s_leq_w_13379;
                bool y_13384 = i_lte_j_13381 && y_13383;
                bool ok_or_empty_13386 = empty_slice_13302 || y_13384;
                
                for (int64_t i_13881 = 0; i_13881 < new_m_13283; i_13881++) {
                    int64_t j_13389 = add64(q_11751, i_13881);
                    int64_t i_p_m_t_s_13390 = add64(m_13303, i_13881);
                    bool zzero_leq_i_p_m_t_s_13391 = sle64((int64_t) 0,
                                                           i_p_m_t_s_13390);
                    bool i_p_m_t_s_leq_w_13392 = slt64(i_p_m_t_s_13390,
                                                       imgs_padded_13314);
                    bool i_lte_j_13394 = sle64(i_13881, j_13389);
                    bool y_13396 = zzero_leq_i_p_m_t_s_13391 &&
                         i_p_m_t_s_leq_w_13392;
                    bool y_13397 = i_lte_j_13394 && y_13396;
                    bool ok_or_empty_13399 = empty_slice_13302 || y_13397;
                    bool index_ok_13400 = ok_or_empty_13386 &&
                         ok_or_empty_13399;
                    bool index_certs_13401;
                    
                    if (!index_ok_13400) {
                        set_error(ctx,
                                  msgprintf("Error: %s%lld%s%lld%s%lld%s%lld%s%lld%s%lld%s\n\nBacktrace:\n%s",
                                            "Index [", (long long) i_13885, ":",
                                            (long long) j_13376, ", ",
                                            (long long) i_13881, ":",
                                            (long long) j_13389,
                                            "] out of bounds for array of shape [",
                                            (long long) imgs_padded_13313, "][",
                                            (long long) imgs_padded_13314, "].",
                                            "-> #0  ../layers/conv2d.fut:13:90-124\n   #1  ../layers/conv2d.fut:13:69-146\n   #2  /prelude/soacs.fut:59:3-10\n   #3  /prelude/array.fut:200:3-17\n   #4  /prelude/functional.fut:39:59-65\n   #5  /prelude/soacs.fut:59:3-10\n   #6  /prelude/array.fut:208:3-34\n   #7  ../layers/conv2d.fut:13:26-162\n   #8  /prelude/soacs.fut:59:3-10\n   #9  /prelude/array.fut:208:3-34\n   #10 conv2d_test.fut:64:3-61\n   #11 conv2d_test.fut:63:1-64:61\n"));
                        err = FUTHARK_PROGRAM_ERROR;
                        goto cleanup;
                    }
                    for (int64_t i_14745 = 0; i_14745 < k_total_13293;
                         i_14745++) {
                        double tmp_14746 =
                               ((double *) ext_mem_14326.mem)[ext_14324 *
                                                              i_13885 +
                                                              i_13881 +
                                                              (squot64(i_14745,
                                                                       q_11751) *
                                                               ext_14324 +
                                                               (i_14745 -
                                                                squot64(i_14745,
                                                                        q_11751) *
                                                                q_11751))];
                        
                        ((double *) mem_14361)[i_14745] = tmp_14746;
                    }
                    if (k_total_13293 * (int64_t) 8 > 0)
                        memmove(mem_14331 + (i_13885 * ixfun_arg_14343 +
                                             i_13881 * total_13284) *
                                (int64_t) 8, mem_14361 + (int64_t) 0,
                                k_total_13293 * (int64_t) 8);
                }
            }
            if (memblock_unref(ctx, &ext_mem_14326, "ext_mem_14326") != 0)
                return 1;
            for (int64_t i_13891 = 0; i_13891 < x_13287; i_13891++) {
                int64_t binop_x_14138 = total_13284 * i_13891;
                double defunc_2_reduce_res_13806;
                double redout_13887 = 0.0;
                
                for (int64_t i_13888 = 0; i_13888 < total_13284; i_13888++) {
                    int64_t new_index_13945 = squot64(i_13888, r_11752);
                    int64_t binop_y_13947 = r_11752 * new_index_13945;
                    int64_t new_index_13948 = i_13888 - binop_y_13947;
                    double x_13619 =
                           ((double *) out_grad_mem_14222.mem)[i_13899 *
                                                               (r_11752 *
                                                                q_11751) +
                                                               new_index_13945 *
                                                               r_11752 +
                                                               new_index_13948];
                    int64_t binop_x_14139 = i_13888 + binop_x_14138;
                    int64_t new_index_14141 = squot64(binop_x_14139,
                                                      binop_y_14140);
                    int64_t binop_y_14149 = binop_y_14140 * new_index_14141;
                    int64_t binop_x_14150 = binop_x_14139 - binop_y_14149;
                    int64_t new_index_14151 = squot64(binop_x_14150,
                                                      total_13284);
                    int64_t binop_y_14171 = total_13284 * new_index_14151;
                    int64_t new_index_14172 = binop_x_14150 - binop_y_14171;
                    double x_13620 = ((double *) mem_14331)[new_index_14141 *
                                                            ixfun_arg_14343 +
                                                            new_index_14151 *
                                                            total_13284 +
                                                            new_index_14172];
                    double defunc_1_f_res_13621 = x_13619 * x_13620;
                    double defunc_1_op_res_13416 = defunc_1_f_res_13621 +
                           redout_13887;
                    double redout_tmp_14748 = defunc_1_op_res_13416;
                    
                    redout_13887 = redout_tmp_14748;
                }
                defunc_2_reduce_res_13806 = redout_13887;
                ((double *) mem_14394)[i_13891] = defunc_2_reduce_res_13806;
            }
            if (new_n_13280 * new_m_13283 * (int64_t) 8 > 0)
                memmove(mem_14408 + (int64_t) 0, mem_14394 + (int64_t) 0,
                        new_n_13280 * new_m_13283 * (int64_t) 8);
            for (int64_t i_14749 = 0; i_14749 < new_n_13280; i_14749++) {
                for (int64_t i_14750 = 0; i_14750 < new_m_13283; i_14750++) {
                    double tmp_14751 = ((double *) mem_14408)[i_14749 *
                                                              new_m_13283 +
                                                              i_14750];
                    
                    ((double *) mem_14230)[i_13899 * ixfun_arg_14246 + i_13895 *
                                           binop_x_14245 + (i_14749 * k_11757 +
                                                            i_14750)] =
                        tmp_14751;
                }
            }
        }
    }
    if (memblock_unref(ctx, &mem_14270, "mem_14270") != 0)
        return 1;
    
    bool empty_slice_13421 = o_11750 == (int64_t) 0;
    int64_t m_13422 = sub64(o_11750, (int64_t) 1);
    bool zzero_leq_i_p_m_t_s_13423 = sle64((int64_t) 0, m_13422);
    bool i_p_m_t_s_leq_w_13424 = slt64(m_13422, o_11750);
    bool i_lte_j_13425 = sle64((int64_t) 0, o_11750);
    bool y_13426 = zzero_leq_i_p_m_t_s_13423 && i_p_m_t_s_leq_w_13424;
    bool y_13427 = i_lte_j_13425 && y_13426;
    bool ok_or_empty_13428 = empty_slice_13421 || y_13427;
    bool empty_slice_13429 = l_11755 == (int64_t) 0;
    int64_t m_13430 = sub64(l_11755, (int64_t) 1);
    bool zzero_leq_i_p_m_t_s_13431 = sle64((int64_t) 0, m_13430);
    bool i_p_m_t_s_leq_w_13432 = slt64(m_13430, l_11755);
    bool i_lte_j_13433 = sle64((int64_t) 0, l_11755);
    bool y_13434 = zzero_leq_i_p_m_t_s_13431 && i_p_m_t_s_leq_w_13432;
    bool y_13435 = i_lte_j_13433 && y_13434;
    bool ok_or_empty_13436 = empty_slice_13429 || y_13435;
    int64_t w_minus_1_13437 = sub64(p_11756, (int64_t) 1);
    int64_t w_minus_1_13438 = sub64(k_11757, (int64_t) 1);
    bool index_ok_13439 = ok_or_empty_13428 && ok_or_empty_13436;
    bool index_certs_13440;
    
    if (!index_ok_13439) {
        set_error(ctx,
                  msgprintf("Error: %s%lld%s%lld%s%lld%s%lld%s%lld%s%lld%s\n\nBacktrace:\n%s",
                            "Index [", (long long) (int64_t) 0, ":, ",
                            (long long) (int64_t) 0,
                            ":, , ] out of bounds for array of shape [",
                            (long long) o_11750, "][", (long long) l_11755,
                            "][", (long long) p_11756, "][",
                            (long long) k_11757, "].",
                            "-> #0  ../layers/conv2d.fut:35:51-72\n   #1  conv2d_test.fut:64:3-61\n   #2  conv2d_test.fut:63:1-64:61\n"));
        err = FUTHARK_PROGRAM_ERROR;
        goto cleanup;
    }
    
    int64_t y_13443 = mul64((int64_t) 2, full_num_11762);
    int64_t x_13447 = add64(r_11752, y_13443);
    int64_t x_13448 = sub64(x_13447, p_11756);
    int64_t new_m_13449 = add64((int64_t) 1, x_13448);
    int64_t x_13444 = add64(q_11751, y_13443);
    int64_t x_13445 = sub64(x_13444, p_11756);
    int64_t new_n_13446 = add64((int64_t) 1, x_13445);
    int64_t flat_dim_13545 = new_n_13446 * new_m_13449;
    int64_t k_total_13500 = mul64(p_11756, p_11756);
    int64_t flat_dim_13512 = o_11750 * k_total_13500;
    int64_t x_13450 = mul64(o_11750, p_11756);
    int64_t total_13451 = mul64(k_11757, x_13450);
    bool dim_match_13513 = total_13451 == flat_dim_13512;
    bool empty_or_match_cert_13514;
    
    if (!dim_match_13513) {
        set_error(ctx, msgprintf("Error: %s%lld%s%lld%s\n\nBacktrace:\n%s",
                                 "Value of (core language) shape (",
                                 (long long) flat_dim_13512,
                                 ") cannot match shape of type `[",
                                 (long long) total_13451, "]f64`.",
                                 "-> #0  ../layers/conv2d.fut:13:60-161\n   #1  /prelude/soacs.fut:59:3-10\n   #2  /prelude/array.fut:200:3-17\n   #3  /prelude/functional.fut:39:59-65\n   #4  /prelude/soacs.fut:59:3-10\n   #5  /prelude/array.fut:208:3-34\n   #6  ../layers/conv2d.fut:13:26-162\n   #7  ../layers/conv2d.fut:26:17-54\n   #8  conv2d_test.fut:64:3-61\n   #9  conv2d_test.fut:63:1-64:61\n"));
        err = FUTHARK_PROGRAM_ERROR;
        goto cleanup;
    }
    
    bool empty_slice_13509 = p_11756 == (int64_t) 0;
    bool bounds_invalid_upwards_13505 = slt64(new_m_13449, (int64_t) 0);
    bool valid_13506 = !bounds_invalid_upwards_13505;
    bool range_valid_c_13507;
    
    if (!valid_13506) {
        set_error(ctx,
                  msgprintf("Error: %s%lld%s%lld%s%lld%s\n\nBacktrace:\n%s",
                            "Range ", (long long) (int64_t) 0, "..",
                            (long long) (int64_t) 1, "..<",
                            (long long) new_m_13449, " is invalid.",
                            "-> #0  /prelude/array.fut:95:3-10\n   #1  /prelude/array.fut:208:3-34\n   #2  ../layers/conv2d.fut:13:26-162\n   #3  ../layers/conv2d.fut:26:17-54\n   #4  conv2d_test.fut:64:3-61\n   #5  conv2d_test.fut:63:1-64:61\n"));
        err = FUTHARK_PROGRAM_ERROR;
        goto cleanup;
    }
    
    bool bounds_invalid_upwards_13501 = slt64(new_n_13446, (int64_t) 0);
    bool valid_13502 = !bounds_invalid_upwards_13501;
    bool range_valid_c_13503;
    
    if (!valid_13502) {
        set_error(ctx,
                  msgprintf("Error: %s%lld%s%lld%s%lld%s\n\nBacktrace:\n%s",
                            "Range ", (long long) (int64_t) 0, "..",
                            (long long) (int64_t) 1, "..<",
                            (long long) new_n_13446, " is invalid.",
                            "-> #0  /prelude/array.fut:95:3-10\n   #1  /prelude/array.fut:208:28-33\n   #2  ../layers/conv2d.fut:13:26-162\n   #3  ../layers/conv2d.fut:26:17-54\n   #4  conv2d_test.fut:64:3-61\n   #5  conv2d_test.fut:63:1-64:61\n"));
        err = FUTHARK_PROGRAM_ERROR;
        goto cleanup;
    }
    
    bool cond_13452 = full_num_11762 == (int64_t) 0;
    bool cond_13453 = !cond_13452;
    int64_t imgs_padded_13455;
    
    if (cond_13453 == 1) {
        imgs_padded_13455 = x_13447;
    } else {
        imgs_padded_13455 = r_11752;
    }
    
    int64_t imgs_padded_13454;
    
    if (cond_13453 == 1) {
        imgs_padded_13454 = x_13444;
    } else {
        imgs_padded_13454 = q_11751;
    }
    
    int64_t binop_x_14447 = o_11750 * x_13444;
    int64_t binop_x_14448 = x_13447 * binop_x_14447;
    int64_t binop_y_14449 = (int64_t) 8 * binop_x_14448;
    int64_t bytes_14450 = smax64((int64_t) 0, binop_y_14449);
    int64_t ext_14553;
    
    if (cond_13453 == 1) {
        ext_14553 = x_13447;
    } else {
        ext_14553 = r_11752;
    }
    
    int64_t ext_14550;
    
    if (cond_13453 == 1) {
        ext_14550 = x_13444;
    } else {
        ext_14550 = q_11751;
    }
    
    int64_t ext_14549;
    
    if (cond_13453 == 1) {
        ext_14549 = x_13447;
    } else {
        ext_14549 = r_11752;
    }
    
    int64_t ext_14554;
    
    if (cond_13453 == 1) {
        bool bounds_invalid_upwards_13816 = slt64(x_13444, (int64_t) 0);
        bool valid_13817 = !bounds_invalid_upwards_13816;
        bool range_valid_c_13818;
        
        if (!valid_13817) {
            set_error(ctx,
                      msgprintf("Error: %s%lld%s%lld%s%lld%s\n\nBacktrace:\n%s",
                                "Range ", (long long) (int64_t) 0, "..",
                                (long long) (int64_t) 1, "..<",
                                (long long) x_13444, " is invalid.",
                                "-> #0  /prelude/array.fut:95:3-10\n   #1  ../layers/conv2d.fut:6:6-7:123\n   #2  ../layers/conv2d.fut:22:7-30\n   #3  conv2d_test.fut:64:3-61\n   #4  conv2d_test.fut:63:1-64:61\n"));
            err = FUTHARK_PROGRAM_ERROR;
            goto cleanup;
        }
        
        bool bounds_invalid_upwards_13820 = slt64(x_13447, (int64_t) 0);
        bool valid_13821 = !bounds_invalid_upwards_13820;
        bool range_valid_c_13822;
        
        if (!valid_13821) {
            set_error(ctx,
                      msgprintf("Error: %s%lld%s%lld%s%lld%s\n\nBacktrace:\n%s",
                                "Range ", (long long) (int64_t) 0, "..",
                                (long long) (int64_t) 1, "..<",
                                (long long) x_13447, " is invalid.",
                                "-> #0  /prelude/array.fut:95:3-10\n   #1  ../layers/conv2d.fut:6:6-7:123\n   #2  ../layers/conv2d.fut:22:7-30\n   #3  conv2d_test.fut:64:3-61\n   #4  conv2d_test.fut:63:1-64:61\n"));
            err = FUTHARK_PROGRAM_ERROR;
            goto cleanup;
        }
        
        int64_t y_13824 = add64(q_11751, full_num_11762);
        int64_t y_13825 = add64(r_11752, full_num_11762);
        
        if (memblock_alloc(ctx, &mem_14451, bytes_14450, "mem_14451")) {
            err = 1;
            goto cleanup;
        }
        
        int64_t ixfun_arg_14463 = x_13444 * x_13447;
        
        for (int64_t i_13911 = 0; i_13911 < o_11750; i_13911++) {
            for (int64_t i_13907 = 0; i_13907 < x_13444; i_13907++) {
                bool cond_13830 = slt64(i_13907, full_num_11762);
                bool cond_f_res_13831 = sle64(y_13824, i_13907);
                bool x_13832 = !cond_13830;
                bool y_13833 = cond_f_res_13831 && x_13832;
                bool cond_13834 = cond_13830 || y_13833;
                bool x_13835 = !cond_13834;
                
                for (int64_t i_13903 = 0; i_13903 < x_13447; i_13903++) {
                    bool cond_f_res_13838 = slt64(i_13903, full_num_11762);
                    bool y_13839 = x_13835 && cond_f_res_13838;
                    bool cond_13840 = cond_13834 || y_13839;
                    bool cond_f_res_13841 = sle64(y_13825, i_13903);
                    bool x_13842 = !cond_13840;
                    bool y_13843 = cond_f_res_13841 && x_13842;
                    bool cond_13844 = cond_13840 || y_13843;
                    double defunc_0_f_res_13845;
                    
                    if (cond_13844 == 1) {
                        defunc_0_f_res_13845 = 0.0;
                    } else {
                        int64_t i_13846 = sub64(i_13907, full_num_11762);
                        bool x_13847 = sle64((int64_t) 0, i_13846);
                        bool y_13848 = slt64(i_13846, q_11751);
                        bool bounds_check_13849 = x_13847 && y_13848;
                        int64_t i_13850 = sub64(i_13903, full_num_11762);
                        bool x_13851 = sle64((int64_t) 0, i_13850);
                        bool y_13852 = slt64(i_13850, r_11752);
                        bool bounds_check_13853 = x_13851 && y_13852;
                        bool index_ok_13854 = bounds_check_13849 &&
                             bounds_check_13853;
                        bool index_certs_13855;
                        
                        if (!index_ok_13854) {
                            set_error(ctx,
                                      msgprintf("Error: %s%lld%s%lld%s%lld%s%lld%s\n\nBacktrace:\n%s",
                                                "Index [", (long long) i_13846,
                                                ", ", (long long) i_13850,
                                                "] out of bounds for array of shape [",
                                                (long long) q_11751, "][",
                                                (long long) r_11752, "].",
                                                "-> #0  ../layers/conv2d.fut:7:91-116\n   #1  /prelude/soacs.fut:59:3-10\n   #2  /prelude/array.fut:200:3-17\n   #3  /prelude/functional.fut:39:59-65\n   #4  /prelude/soacs.fut:59:3-10\n   #5  /prelude/array.fut:208:3-34\n   #6  ../layers/conv2d.fut:6:22-7:117\n   #7  ../layers/conv2d.fut:6:6-7:123\n   #8  ../layers/conv2d.fut:22:7-30\n   #9  conv2d_test.fut:64:3-61\n   #10 conv2d_test.fut:63:1-64:61\n"));
                            err = FUTHARK_PROGRAM_ERROR;
                            goto cleanup;
                        }
                        
                        double defunc_0_f_res_f_res_13856 =
                               ((double *) out_grad_mem_14222.mem)[i_13911 *
                                                                   (r_11752 *
                                                                    q_11751) +
                                                                   i_13846 *
                                                                   r_11752 +
                                                                   i_13850];
                        
                        defunc_0_f_res_13845 = defunc_0_f_res_f_res_13856;
                    }
                    ((double *) mem_14451.mem)[i_13911 * ixfun_arg_14463 +
                                               i_13907 * x_13447 + i_13903] =
                        defunc_0_f_res_13845;
                }
            }
        }
        if (memblock_set(ctx, &ext_mem_14556, &mem_14451, "mem_14451") != 0)
            return 1;
        ext_14554 = ixfun_arg_14463;
    } else {
        int64_t ixfun_ext_14548 = q_11751 * r_11752;
        
        if (memblock_set(ctx, &ext_mem_14556, &out_grad_mem_14222,
                         "out_grad_mem_14222") != 0)
            return 1;
        ext_14554 = ixfun_ext_14548;
    }
    
    int64_t binop_x_14558 = total_13451 * flat_dim_13545;
    int64_t binop_y_14559 = (int64_t) 8 * binop_x_14558;
    int64_t bytes_14560 = smax64((int64_t) 0, binop_y_14559);
    
    if (mem_14561_cached_sizze_14785 < bytes_14560) {
        err = lexical_realloc(ctx, &mem_14561, &mem_14561_cached_sizze_14785,
                              bytes_14560);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    
    int64_t ixfun_arg_14573 = new_m_13449 * total_13451;
    
    for (int64_t i_13919 = 0; i_13919 < new_n_13446; i_13919++) {
        int64_t j_13517 = add64(p_11756, i_13919);
        int64_t i_p_m_t_s_13518 = add64(w_minus_1_13437, i_13919);
        bool zzero_leq_i_p_m_t_s_13519 = sle64((int64_t) 0, i_p_m_t_s_13518);
        bool i_p_m_t_s_leq_w_13520 = slt64(i_p_m_t_s_13518, imgs_padded_13454);
        bool i_lte_j_13522 = sle64(i_13919, j_13517);
        bool y_13524 = zzero_leq_i_p_m_t_s_13519 && i_p_m_t_s_leq_w_13520;
        bool y_13525 = i_lte_j_13522 && y_13524;
        bool ok_or_empty_13527 = empty_slice_13509 || y_13525;
        
        for (int64_t i_13915 = 0; i_13915 < new_m_13449; i_13915++) {
            int64_t j_13530 = add64(p_11756, i_13915);
            int64_t i_p_m_t_s_13531 = add64(w_minus_1_13437, i_13915);
            bool zzero_leq_i_p_m_t_s_13532 = sle64((int64_t) 0,
                                                   i_p_m_t_s_13531);
            bool i_p_m_t_s_leq_w_13533 = slt64(i_p_m_t_s_13531,
                                               imgs_padded_13455);
            bool i_lte_j_13535 = sle64(i_13915, j_13530);
            bool y_13537 = zzero_leq_i_p_m_t_s_13532 && i_p_m_t_s_leq_w_13533;
            bool y_13538 = i_lte_j_13535 && y_13537;
            bool ok_or_empty_13540 = empty_slice_13509 || y_13538;
            bool index_ok_13541 = ok_or_empty_13527 && ok_or_empty_13540;
            bool index_certs_13542;
            
            if (!index_ok_13541) {
                set_error(ctx,
                          msgprintf("Error: %s%lld%s%lld%s%lld%s%lld%s%lld%s%lld%s\n\nBacktrace:\n%s",
                                    "Index [", (long long) i_13919, ":",
                                    (long long) j_13517, ", ",
                                    (long long) i_13915, ":",
                                    (long long) j_13530,
                                    "] out of bounds for array of shape [",
                                    (long long) imgs_padded_13454, "][",
                                    (long long) imgs_padded_13455, "].",
                                    "-> #0  ../layers/conv2d.fut:13:90-124\n   #1  ../layers/conv2d.fut:13:69-146\n   #2  /prelude/soacs.fut:59:3-10\n   #3  /prelude/array.fut:200:3-17\n   #4  /prelude/functional.fut:39:59-65\n   #5  /prelude/soacs.fut:59:3-10\n   #6  /prelude/array.fut:208:3-34\n   #7  ../layers/conv2d.fut:13:26-162\n   #8  ../layers/conv2d.fut:26:17-54\n   #9  conv2d_test.fut:64:3-61\n   #10 conv2d_test.fut:63:1-64:61\n"));
                err = FUTHARK_PROGRAM_ERROR;
                goto cleanup;
            }
            for (int64_t i_14757 = 0; i_14757 < total_13451; i_14757++) {
                double tmp_14758 = ((double *) ext_mem_14556.mem)[ext_14553 *
                                                                  i_13919 +
                                                                  i_13915 +
                                                                  (squot64(i_14757,
                                                                           p_11756 *
                                                                           p_11756) *
                                                                   ext_14554 +
                                                                   squot64(i_14757 -
                                                                           squot64(i_14757,
                                                                                   p_11756 *
                                                                                   p_11756) *
                                                                           (p_11756 *
                                                                            p_11756),
                                                                           p_11756) *
                                                                   ext_14553 +
                                                                   (i_14757 -
                                                                    squot64(i_14757,
                                                                            p_11756 *
                                                                            p_11756) *
                                                                    (p_11756 *
                                                                     p_11756) -
                                                                    squot64(i_14757 -
                                                                            squot64(i_14757,
                                                                                    p_11756 *
                                                                                    p_11756) *
                                                                            (p_11756 *
                                                                             p_11756),
                                                                            p_11756) *
                                                                    p_11756))];
                
                ((double *) mem_14561)[i_13919 * ixfun_arg_14573 + i_13915 *
                                       total_13451 + i_14757] = tmp_14758;
            }
        }
    }
    if (memblock_unref(ctx, &ext_mem_14556, "ext_mem_14556") != 0)
        return 1;
    
    int64_t binop_x_14619 = l_11755 * flat_dim_13545;
    int64_t binop_y_14620 = (int64_t) 8 * binop_x_14619;
    int64_t bytes_14621 = smax64((int64_t) 0, binop_y_14620);
    
    if (mem_14622_cached_sizze_14786 < bytes_14621) {
        err = lexical_realloc(ctx, &mem_14622, &mem_14622_cached_sizze_14786,
                              bytes_14621);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    
    int64_t binop_y_14012 = p_11756 * k_11757;
    int64_t binop_y_14101 = new_m_13449 * total_13451;
    
    for (int64_t i_13929 = 0; i_13929 < l_11755; i_13929++) {
        int64_t binop_x_13996 = total_13451 * i_13929;
        
        for (int64_t i_13925 = 0; i_13925 < flat_dim_13545; i_13925++) {
            int64_t binop_x_14099 = total_13451 * i_13925;
            double defunc_2_reduce_res_13811;
            double redout_13921 = 0.0;
            
            for (int64_t i_13922 = 0; i_13922 < total_13451; i_13922++) {
                int64_t binop_x_13997 = i_13922 + binop_x_13996;
                int64_t new_index_14000 = squot64(binop_x_13997, total_13451);
                int64_t binop_y_14010 = total_13451 * new_index_14000;
                int64_t binop_x_14011 = binop_x_13997 - binop_y_14010;
                int64_t new_index_14013 = squot64(binop_x_14011, binop_y_14012);
                int64_t binop_y_14039 = binop_y_14012 * new_index_14013;
                int64_t binop_x_14040 = binop_x_14011 - binop_y_14039;
                int64_t new_index_14041 = squot64(binop_x_14040, k_11757);
                int64_t binop_y_14097 = k_11757 * new_index_14041;
                int64_t new_index_14098 = binop_x_14040 - binop_y_14097;
                int64_t binop_y_14134 = (int64_t) -1 * new_index_14041;
                int64_t slice_14135 = w_minus_1_13437 + binop_y_14134;
                int64_t binop_y_14136 = (int64_t) -1 * new_index_14098;
                int64_t slice_14137 = w_minus_1_13438 + binop_y_14136;
                double x_13711 =
                       ((double *) kernels_mem_14224.mem)[new_index_14013 *
                                                          (k_11757 * p_11756 *
                                                           l_11755) +
                                                          new_index_14000 *
                                                          (k_11757 * p_11756) +
                                                          slice_14135 *
                                                          k_11757 +
                                                          slice_14137];
                int64_t binop_x_14100 = i_13922 + binop_x_14099;
                int64_t new_index_14102 = squot64(binop_x_14100, binop_y_14101);
                int64_t binop_y_14110 = binop_y_14101 * new_index_14102;
                int64_t binop_x_14111 = binop_x_14100 - binop_y_14110;
                int64_t new_index_14112 = squot64(binop_x_14111, total_13451);
                int64_t binop_y_14132 = total_13451 * new_index_14112;
                int64_t new_index_14133 = binop_x_14111 - binop_y_14132;
                double x_13712 = ((double *) mem_14561)[new_index_14102 *
                                                        ixfun_arg_14573 +
                                                        new_index_14112 *
                                                        total_13451 +
                                                        new_index_14133];
                double defunc_1_f_res_13713 = x_13711 * x_13712;
                double defunc_1_op_res_13561 = defunc_1_f_res_13713 +
                       redout_13921;
                double redout_tmp_14761 = defunc_1_op_res_13561;
                
                redout_13921 = redout_tmp_14761;
            }
            defunc_2_reduce_res_13811 = redout_13921;
            ((double *) mem_14622)[i_13929 * flat_dim_13545 + i_13925] =
                defunc_2_reduce_res_13811;
        }
    }
    
    int64_t binop_x_14664 = l_11755 * new_n_13446;
    int64_t binop_x_14665 = new_m_13449 * binop_x_14664;
    int64_t binop_y_14666 = (int64_t) 8 * binop_x_14665;
    int64_t bytes_14667 = smax64((int64_t) 0, binop_y_14666);
    
    if (mem_14668_cached_sizze_14787 < bytes_14667) {
        err = lexical_realloc(ctx, &mem_14668, &mem_14668_cached_sizze_14787,
                              bytes_14667);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (l_11755 * new_n_13446 * new_m_13449 * (int64_t) 8 > 0)
        memmove(mem_14668 + (int64_t) 0, mem_14622 + (int64_t) 0, l_11755 *
                new_n_13446 * new_m_13449 * (int64_t) 8);
    
    bool dim_match_13567 = n_11753 == new_n_13446;
    bool dim_match_13568 = m_11754 == new_m_13449;
    bool match_13569 = dim_match_13567 && dim_match_13568;
    bool empty_or_match_cert_13570;
    
    if (!match_13569) {
        set_error(ctx,
                  msgprintf("Error: %s%lld%s%lld%s%lld%s%lld%s%lld%s%lld%s\n\nBacktrace:\n%s",
                            "Value of (core language) shape (",
                            (long long) l_11755, ", ", (long long) new_n_13446,
                            ", ", (long long) new_m_13449,
                            ") cannot match shape of type `[",
                            (long long) l_11755, "][", (long long) n_11753,
                            "][", (long long) m_11754, "]f64`.",
                            "-> #0  ../layers/conv2d.fut:35:20-117\n   #1  conv2d_test.fut:64:3-61\n   #2  conv2d_test.fut:63:1-64:61\n"));
        err = FUTHARK_PROGRAM_ERROR;
        goto cleanup;
    }
    
    int64_t binop_y_14669 = (int64_t) 8 * o_11750;
    int64_t bytes_14670 = smax64((int64_t) 0, binop_y_14669);
    
    if (memblock_alloc(ctx, &mem_14671, bytes_14670, "mem_14671")) {
        err = 1;
        goto cleanup;
    }
    for (int64_t i_13935 = 0; i_13935 < o_11750; i_13935++) {
        int64_t binop_x_13961 = total_13284 * i_13935;
        double defunc_2_reduce_res_13863;
        double redout_13931 = 0.0;
        
        for (int64_t i_13932 = 0; i_13932 < total_13284; i_13932++) {
            int64_t binop_x_13962 = i_13932 + binop_x_13961;
            int64_t new_index_13964 = squot64(binop_x_13962, total_13284);
            int64_t binop_y_13972 = total_13284 * new_index_13964;
            int64_t binop_x_13973 = binop_x_13962 - binop_y_13972;
            int64_t new_index_13974 = squot64(binop_x_13973, r_11752);
            int64_t binop_y_13994 = r_11752 * new_index_13974;
            int64_t new_index_13995 = binop_x_13973 - binop_y_13994;
            double x_13579 =
                   ((double *) out_grad_mem_14222.mem)[new_index_13964 *
                                                       (r_11752 * q_11751) +
                                                       new_index_13974 *
                                                       r_11752 +
                                                       new_index_13995];
            double defunc_1_op_res_13578 = x_13579 + redout_13931;
            double redout_tmp_14763 = defunc_1_op_res_13578;
            
            redout_13931 = redout_tmp_14763;
        }
        defunc_2_reduce_res_13863 = redout_13931;
        ((double *) mem_14671.mem)[i_13935] = defunc_2_reduce_res_13863;
    }
    
    int64_t binop_x_14682 = n_11753 * l_11755;
    int64_t binop_x_14683 = m_11754 * binop_x_14682;
    int64_t binop_y_14684 = (int64_t) 8 * binop_x_14683;
    int64_t bytes_14685 = smax64((int64_t) 0, binop_y_14684);
    
    if (memblock_alloc(ctx, &mem_14686, bytes_14685, "mem_14686")) {
        err = 1;
        goto cleanup;
    }
    if (l_11755 * n_11753 * m_11754 * (int64_t) 8 > 0)
        memmove(mem_14686.mem + (int64_t) 0, mem_14668 + (int64_t) 0, l_11755 *
                n_11753 * m_11754 * (int64_t) 8);
    if (memblock_alloc(ctx, &mem_14693, bytes_14229, "mem_14693")) {
        err = 1;
        goto cleanup;
    }
    if (o_11750 * l_11755 * p_11756 * k_11757 * (int64_t) 8 > 0)
        memmove(mem_14693.mem + (int64_t) 0, mem_14230 + (int64_t) 0, o_11750 *
                l_11755 * p_11756 * k_11757 * (int64_t) 8);
    if (memblock_set(ctx, &mem_out_14734, &mem_14686, "mem_14686") != 0)
        return 1;
    if (memblock_set(ctx, &mem_out_14735, &mem_14693, "mem_14693") != 0)
        return 1;
    if (memblock_set(ctx, &mem_out_14736, &mem_14671, "mem_14671") != 0)
        return 1;
    (*mem_out_p_14776).references = NULL;
    if (memblock_set(ctx, &*mem_out_p_14776, &mem_out_14734, "mem_out_14734") !=
        0)
        return 1;
    (*mem_out_p_14777).references = NULL;
    if (memblock_set(ctx, &*mem_out_p_14777, &mem_out_14735, "mem_out_14735") !=
        0)
        return 1;
    (*mem_out_p_14778).references = NULL;
    if (memblock_set(ctx, &*mem_out_p_14778, &mem_out_14736, "mem_out_14736") !=
        0)
        return 1;
    
  cleanup:
    {
        free(mem_14230);
        free(mem_14274);
        free(mem_14331);
        free(mem_14361);
        free(mem_14394);
        free(mem_14408);
        free(mem_14561);
        free(mem_14622);
        free(mem_14668);
        if (memblock_unref(ctx, &mem_14693, "mem_14693") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_14686, "mem_14686") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_14671, "mem_14671") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_14451, "mem_14451") != 0)
            return 1;
        if (memblock_unref(ctx, &ext_mem_14556, "ext_mem_14556") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_14319, "mem_14319") != 0)
            return 1;
        if (memblock_unref(ctx, &ext_mem_14326, "ext_mem_14326") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_14270, "mem_14270") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_out_14736, "mem_out_14736") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_out_14735, "mem_out_14735") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_out_14734, "mem_out_14734") != 0)
            return 1;
    }
    return err;
}
static int futrts_entry_convolve2d_test(struct futhark_context *ctx,
                                        struct memblock *mem_out_p_14788,
                                        int64_t *out_prim_out_14789,
                                        int64_t *out_prim_out_14790,
                                        struct memblock imgs_mem_14222,
                                        struct memblock kernels_mem_14223,
                                        struct memblock biases_mem_14224,
                                        int64_t n_10711, int64_t m_10712,
                                        int64_t l_10713, int64_t p_10714,
                                        int64_t k_10715, int64_t o_10716,
                                        int64_t padding_10720)
{
    (void) ctx;
    
    int err = 0;
    int64_t mem_14339_cached_sizze_14791 = 0;
    unsigned char *mem_14339 = NULL;
    int64_t mem_14400_cached_sizze_14792 = 0;
    unsigned char *mem_14400 = NULL;
    struct memblock mem_14446;
    
    mem_14446.references = NULL;
    
    struct memblock mem_14229;
    
    mem_14229.references = NULL;
    
    struct memblock ext_mem_14334;
    
    ext_mem_14334.references = NULL;
    
    struct memblock mem_out_14734;
    
    mem_out_14734.references = NULL;
    
    int64_t prim_out_14735;
    int64_t prim_out_14736;
    int64_t y_13101 = mul64((int64_t) 2, padding_10720);
    int64_t x_13102 = add64(n_10711, y_13101);
    int64_t x_13103 = sub64(x_13102, p_10714);
    int64_t new_n_13104 = add64((int64_t) 1, x_13103);
    int64_t x_13106 = add64(m_10712, y_13101);
    int64_t x_13107 = sub64(x_13106, p_10714);
    int64_t new_m_13108 = add64((int64_t) 1, x_13107);
    int64_t x_13109 = mul64(l_10713, p_10714);
    int64_t total_13110 = mul64(k_10715, x_13109);
    bool cond_13111 = padding_10720 == (int64_t) 0;
    bool cond_13112 = !cond_13111;
    int64_t imgs_padded_13113;
    
    if (cond_13112 == 1) {
        imgs_padded_13113 = x_13102;
    } else {
        imgs_padded_13113 = n_10711;
    }
    
    int64_t imgs_padded_13114;
    
    if (cond_13112 == 1) {
        imgs_padded_13114 = x_13106;
    } else {
        imgs_padded_13114 = m_10712;
    }
    
    int64_t binop_x_14225 = l_10713 * x_13102;
    int64_t binop_x_14226 = x_13106 * binop_x_14225;
    int64_t binop_y_14227 = (int64_t) 8 * binop_x_14226;
    int64_t bytes_14228 = smax64((int64_t) 0, binop_y_14227);
    int64_t ext_14331;
    
    if (cond_13112 == 1) {
        ext_14331 = x_13106;
    } else {
        ext_14331 = m_10712;
    }
    
    int64_t ext_14328;
    
    if (cond_13112 == 1) {
        ext_14328 = x_13102;
    } else {
        ext_14328 = n_10711;
    }
    
    int64_t ext_14327;
    
    if (cond_13112 == 1) {
        ext_14327 = x_13106;
    } else {
        ext_14327 = m_10712;
    }
    
    int64_t ext_14332;
    
    if (cond_13112 == 1) {
        bool bounds_invalid_upwards_13671 = slt64(x_13102, (int64_t) 0);
        bool valid_13672 = !bounds_invalid_upwards_13671;
        bool range_valid_c_13673;
        
        if (!valid_13672) {
            set_error(ctx,
                      msgprintf("Error: %s%lld%s%lld%s%lld%s\n\nBacktrace:\n%s",
                                "Range ", (long long) (int64_t) 0, "..",
                                (long long) (int64_t) 1, "..<",
                                (long long) x_13102, " is invalid.",
                                "-> #0  /prelude/array.fut:95:3-10\n   #1  ../layers/conv2d.fut:6:6-7:123\n   #2  ../layers/conv2d.fut:22:7-30\n   #3  conv2d_test.fut:61:3-40\n   #4  conv2d_test.fut:60:1-61:40\n"));
            err = FUTHARK_PROGRAM_ERROR;
            goto cleanup;
        }
        
        bool bounds_invalid_upwards_13675 = slt64(x_13106, (int64_t) 0);
        bool valid_13676 = !bounds_invalid_upwards_13675;
        bool range_valid_c_13677;
        
        if (!valid_13676) {
            set_error(ctx,
                      msgprintf("Error: %s%lld%s%lld%s%lld%s\n\nBacktrace:\n%s",
                                "Range ", (long long) (int64_t) 0, "..",
                                (long long) (int64_t) 1, "..<",
                                (long long) x_13106, " is invalid.",
                                "-> #0  /prelude/array.fut:95:3-10\n   #1  ../layers/conv2d.fut:6:6-7:123\n   #2  ../layers/conv2d.fut:22:7-30\n   #3  conv2d_test.fut:61:3-40\n   #4  conv2d_test.fut:60:1-61:40\n"));
            err = FUTHARK_PROGRAM_ERROR;
            goto cleanup;
        }
        
        int64_t y_13679 = add64(n_10711, padding_10720);
        int64_t y_13680 = add64(m_10712, padding_10720);
        
        if (memblock_alloc(ctx, &mem_14229, bytes_14228, "mem_14229")) {
            err = 1;
            goto cleanup;
        }
        
        int64_t ixfun_arg_14241 = x_13102 * x_13106;
        
        for (int64_t i_13881 = 0; i_13881 < l_10713; i_13881++) {
            for (int64_t i_13877 = 0; i_13877 < x_13102; i_13877++) {
                bool cond_13685 = slt64(i_13877, padding_10720);
                bool cond_f_res_13686 = sle64(y_13679, i_13877);
                bool x_13687 = !cond_13685;
                bool y_13688 = cond_f_res_13686 && x_13687;
                bool cond_13689 = cond_13685 || y_13688;
                bool x_13690 = !cond_13689;
                
                for (int64_t i_13873 = 0; i_13873 < x_13106; i_13873++) {
                    bool cond_f_res_13693 = slt64(i_13873, padding_10720);
                    bool y_13694 = x_13690 && cond_f_res_13693;
                    bool cond_13695 = cond_13689 || y_13694;
                    bool cond_f_res_13696 = sle64(y_13680, i_13873);
                    bool x_13697 = !cond_13695;
                    bool y_13698 = cond_f_res_13696 && x_13697;
                    bool cond_13699 = cond_13695 || y_13698;
                    double defunc_0_f_res_13700;
                    
                    if (cond_13699 == 1) {
                        defunc_0_f_res_13700 = 0.0;
                    } else {
                        int64_t i_13701 = sub64(i_13877, padding_10720);
                        bool x_13702 = sle64((int64_t) 0, i_13701);
                        bool y_13703 = slt64(i_13701, n_10711);
                        bool bounds_check_13704 = x_13702 && y_13703;
                        int64_t i_13705 = sub64(i_13873, padding_10720);
                        bool x_13706 = sle64((int64_t) 0, i_13705);
                        bool y_13707 = slt64(i_13705, m_10712);
                        bool bounds_check_13708 = x_13706 && y_13707;
                        bool index_ok_13709 = bounds_check_13704 &&
                             bounds_check_13708;
                        bool index_certs_13710;
                        
                        if (!index_ok_13709) {
                            set_error(ctx,
                                      msgprintf("Error: %s%lld%s%lld%s%lld%s%lld%s\n\nBacktrace:\n%s",
                                                "Index [", (long long) i_13701,
                                                ", ", (long long) i_13705,
                                                "] out of bounds for array of shape [",
                                                (long long) n_10711, "][",
                                                (long long) m_10712, "].",
                                                "-> #0  ../layers/conv2d.fut:7:91-116\n   #1  /prelude/soacs.fut:59:3-10\n   #2  /prelude/array.fut:200:3-17\n   #3  /prelude/functional.fut:39:59-65\n   #4  /prelude/soacs.fut:59:3-10\n   #5  /prelude/array.fut:208:3-34\n   #6  ../layers/conv2d.fut:6:22-7:117\n   #7  ../layers/conv2d.fut:6:6-7:123\n   #8  ../layers/conv2d.fut:22:7-30\n   #9  conv2d_test.fut:61:3-40\n   #10 conv2d_test.fut:60:1-61:40\n"));
                            err = FUTHARK_PROGRAM_ERROR;
                            goto cleanup;
                        }
                        
                        double defunc_0_f_res_f_res_13711 =
                               ((double *) imgs_mem_14222.mem)[i_13881 *
                                                               (m_10712 *
                                                                n_10711) +
                                                               i_13701 *
                                                               m_10712 +
                                                               i_13705];
                        
                        defunc_0_f_res_13700 = defunc_0_f_res_f_res_13711;
                    }
                    ((double *) mem_14229.mem)[i_13881 * ixfun_arg_14241 +
                                               i_13877 * x_13106 + i_13873] =
                        defunc_0_f_res_13700;
                }
            }
        }
        if (memblock_set(ctx, &ext_mem_14334, &mem_14229, "mem_14229") != 0)
            return 1;
        ext_14332 = ixfun_arg_14241;
    } else {
        int64_t ixfun_ext_14326 = n_10711 * m_10712;
        
        if (memblock_set(ctx, &ext_mem_14334, &imgs_mem_14222,
                         "imgs_mem_14222") != 0)
            return 1;
        ext_14332 = ixfun_ext_14326;
    }
    
    int64_t k_total_13161 = mul64(p_10714, p_10714);
    bool bounds_invalid_upwards_13162 = slt64(new_n_13104, (int64_t) 0);
    bool valid_13163 = !bounds_invalid_upwards_13162;
    bool range_valid_c_13164;
    
    if (!valid_13163) {
        set_error(ctx,
                  msgprintf("Error: %s%lld%s%lld%s%lld%s\n\nBacktrace:\n%s",
                            "Range ", (long long) (int64_t) 0, "..",
                            (long long) (int64_t) 1, "..<",
                            (long long) new_n_13104, " is invalid.",
                            "-> #0  /prelude/array.fut:95:3-10\n   #1  /prelude/array.fut:208:28-33\n   #2  ../layers/conv2d.fut:13:26-162\n   #3  ../layers/conv2d.fut:26:17-54\n   #4  conv2d_test.fut:61:3-40\n   #5  conv2d_test.fut:60:1-61:40\n"));
        err = FUTHARK_PROGRAM_ERROR;
        goto cleanup;
    }
    
    bool bounds_invalid_upwards_13166 = slt64(new_m_13108, (int64_t) 0);
    bool valid_13167 = !bounds_invalid_upwards_13166;
    bool range_valid_c_13168;
    
    if (!valid_13167) {
        set_error(ctx,
                  msgprintf("Error: %s%lld%s%lld%s%lld%s\n\nBacktrace:\n%s",
                            "Range ", (long long) (int64_t) 0, "..",
                            (long long) (int64_t) 1, "..<",
                            (long long) new_m_13108, " is invalid.",
                            "-> #0  /prelude/array.fut:95:3-10\n   #1  /prelude/array.fut:208:3-34\n   #2  ../layers/conv2d.fut:13:26-162\n   #3  ../layers/conv2d.fut:26:17-54\n   #4  conv2d_test.fut:61:3-40\n   #5  conv2d_test.fut:60:1-61:40\n"));
        err = FUTHARK_PROGRAM_ERROR;
        goto cleanup;
    }
    
    bool empty_slice_13170 = p_10714 == (int64_t) 0;
    int64_t m_13171 = sub64(p_10714, (int64_t) 1);
    int64_t flat_dim_13208 = l_10713 * k_total_13161;
    bool dim_match_13210 = total_13110 == flat_dim_13208;
    bool empty_or_match_cert_13211;
    
    if (!dim_match_13210) {
        set_error(ctx, msgprintf("Error: %s%lld%s%lld%s\n\nBacktrace:\n%s",
                                 "Value of (core language) shape (",
                                 (long long) flat_dim_13208,
                                 ") cannot match shape of type `[",
                                 (long long) total_13110, "]f64`.",
                                 "-> #0  ../layers/conv2d.fut:13:60-161\n   #1  /prelude/soacs.fut:59:3-10\n   #2  /prelude/array.fut:200:3-17\n   #3  /prelude/functional.fut:39:59-65\n   #4  /prelude/soacs.fut:59:3-10\n   #5  /prelude/array.fut:208:3-34\n   #6  ../layers/conv2d.fut:13:26-162\n   #7  ../layers/conv2d.fut:26:17-54\n   #8  conv2d_test.fut:61:3-40\n   #9  conv2d_test.fut:60:1-61:40\n"));
        err = FUTHARK_PROGRAM_ERROR;
        goto cleanup;
    }
    
    int64_t binop_x_14335 = new_n_13104 * new_m_13108;
    int64_t binop_x_14336 = total_13110 * binop_x_14335;
    int64_t binop_y_14337 = (int64_t) 8 * binop_x_14336;
    int64_t bytes_14338 = smax64((int64_t) 0, binop_y_14337);
    
    if (mem_14339_cached_sizze_14791 < bytes_14338) {
        err = lexical_realloc(ctx, &mem_14339, &mem_14339_cached_sizze_14791,
                              bytes_14338);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    
    int64_t ixfun_arg_14351 = new_m_13108 * total_13110;
    
    for (int64_t i_13889 = 0; i_13889 < new_n_13104; i_13889++) {
        int64_t j_13174 = add64(p_10714, i_13889);
        int64_t i_p_m_t_s_13175 = add64(m_13171, i_13889);
        bool zzero_leq_i_p_m_t_s_13176 = sle64((int64_t) 0, i_p_m_t_s_13175);
        bool i_p_m_t_s_leq_w_13177 = slt64(i_p_m_t_s_13175, imgs_padded_13113);
        bool i_lte_j_13179 = sle64(i_13889, j_13174);
        bool y_13181 = zzero_leq_i_p_m_t_s_13176 && i_p_m_t_s_leq_w_13177;
        bool y_13182 = i_lte_j_13179 && y_13181;
        bool ok_or_empty_13184 = empty_slice_13170 || y_13182;
        
        for (int64_t i_13885 = 0; i_13885 < new_m_13108; i_13885++) {
            int64_t j_13187 = add64(p_10714, i_13885);
            int64_t i_p_m_t_s_13188 = add64(m_13171, i_13885);
            bool zzero_leq_i_p_m_t_s_13189 = sle64((int64_t) 0,
                                                   i_p_m_t_s_13188);
            bool i_p_m_t_s_leq_w_13190 = slt64(i_p_m_t_s_13188,
                                               imgs_padded_13114);
            bool i_lte_j_13192 = sle64(i_13885, j_13187);
            bool y_13194 = zzero_leq_i_p_m_t_s_13189 && i_p_m_t_s_leq_w_13190;
            bool y_13195 = i_lte_j_13192 && y_13194;
            bool ok_or_empty_13197 = empty_slice_13170 || y_13195;
            bool index_ok_13198 = ok_or_empty_13184 && ok_or_empty_13197;
            bool index_certs_13199;
            
            if (!index_ok_13198) {
                set_error(ctx,
                          msgprintf("Error: %s%lld%s%lld%s%lld%s%lld%s%lld%s%lld%s\n\nBacktrace:\n%s",
                                    "Index [", (long long) i_13889, ":",
                                    (long long) j_13174, ", ",
                                    (long long) i_13885, ":",
                                    (long long) j_13187,
                                    "] out of bounds for array of shape [",
                                    (long long) imgs_padded_13113, "][",
                                    (long long) imgs_padded_13114, "].",
                                    "-> #0  ../layers/conv2d.fut:13:90-124\n   #1  ../layers/conv2d.fut:13:69-146\n   #2  /prelude/soacs.fut:59:3-10\n   #3  /prelude/array.fut:200:3-17\n   #4  /prelude/functional.fut:39:59-65\n   #5  /prelude/soacs.fut:59:3-10\n   #6  /prelude/array.fut:208:3-34\n   #7  ../layers/conv2d.fut:13:26-162\n   #8  ../layers/conv2d.fut:26:17-54\n   #9  conv2d_test.fut:61:3-40\n   #10 conv2d_test.fut:60:1-61:40\n"));
                err = FUTHARK_PROGRAM_ERROR;
                goto cleanup;
            }
            for (int64_t i_14742 = 0; i_14742 < total_13110; i_14742++) {
                double tmp_14743 = ((double *) ext_mem_14334.mem)[ext_14331 *
                                                                  i_13889 +
                                                                  i_13885 +
                                                                  (squot64(i_14742,
                                                                           p_10714 *
                                                                           p_10714) *
                                                                   ext_14332 +
                                                                   squot64(i_14742 -
                                                                           squot64(i_14742,
                                                                                   p_10714 *
                                                                                   p_10714) *
                                                                           (p_10714 *
                                                                            p_10714),
                                                                           p_10714) *
                                                                   ext_14331 +
                                                                   (i_14742 -
                                                                    squot64(i_14742,
                                                                            p_10714 *
                                                                            p_10714) *
                                                                    (p_10714 *
                                                                     p_10714) -
                                                                    squot64(i_14742 -
                                                                            squot64(i_14742,
                                                                                    p_10714 *
                                                                                    p_10714) *
                                                                            (p_10714 *
                                                                             p_10714),
                                                                            p_10714) *
                                                                    p_10714))];
                
                ((double *) mem_14339)[i_13889 * ixfun_arg_14351 + i_13885 *
                                       total_13110 + i_14742] = tmp_14743;
            }
        }
    }
    if (memblock_unref(ctx, &ext_mem_14334, "ext_mem_14334") != 0)
        return 1;
    
    int64_t binop_x_14397 = o_10716 * binop_x_14335;
    int64_t binop_y_14398 = (int64_t) 8 * binop_x_14397;
    int64_t bytes_14399 = smax64((int64_t) 0, binop_y_14398);
    
    if (mem_14400_cached_sizze_14792 < bytes_14399) {
        err = lexical_realloc(ctx, &mem_14400, &mem_14400_cached_sizze_14792,
                              bytes_14399);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    
    int64_t binop_y_13961 = p_10714 * k_10715;
    int64_t binop_y_14050 = new_m_13108 * total_13110;
    
    for (int64_t i_13899 = 0; i_13899 < o_10716; i_13899++) {
        double x_13582 = ((double *) biases_mem_14224.mem)[i_13899];
        int64_t binop_x_13945 = total_13110 * i_13899;
        
        for (int64_t i_13895 = 0; i_13895 < binop_x_14335; i_13895++) {
            int64_t binop_x_14048 = total_13110 * i_13895;
            double defunc_2_reduce_res_13718;
            double redout_13891 = 0.0;
            
            for (int64_t i_13892 = 0; i_13892 < total_13110; i_13892++) {
                int64_t binop_x_13946 = i_13892 + binop_x_13945;
                int64_t new_index_13949 = squot64(binop_x_13946, total_13110);
                int64_t binop_y_13959 = total_13110 * new_index_13949;
                int64_t binop_x_13960 = binop_x_13946 - binop_y_13959;
                int64_t new_index_13962 = squot64(binop_x_13960, binop_y_13961);
                int64_t binop_y_13988 = binop_y_13961 * new_index_13962;
                int64_t binop_x_13989 = binop_x_13960 - binop_y_13988;
                int64_t new_index_13990 = squot64(binop_x_13989, k_10715);
                int64_t binop_y_14046 = k_10715 * new_index_13990;
                int64_t new_index_14047 = binop_x_13989 - binop_y_14046;
                double x_13661 =
                       ((double *) kernels_mem_14223.mem)[new_index_13949 *
                                                          (k_10715 * p_10714 *
                                                           l_10713) +
                                                          new_index_13962 *
                                                          (k_10715 * p_10714) +
                                                          new_index_13990 *
                                                          k_10715 +
                                                          new_index_14047];
                int64_t binop_x_14049 = i_13892 + binop_x_14048;
                int64_t new_index_14051 = squot64(binop_x_14049, binop_y_14050);
                int64_t binop_y_14059 = binop_y_14050 * new_index_14051;
                int64_t binop_x_14060 = binop_x_14049 - binop_y_14059;
                int64_t new_index_14061 = squot64(binop_x_14060, total_13110);
                int64_t binop_y_14081 = total_13110 * new_index_14061;
                int64_t new_index_14082 = binop_x_14060 - binop_y_14081;
                double x_13662 = ((double *) mem_14339)[new_index_14051 *
                                                        ixfun_arg_14351 +
                                                        new_index_14061 *
                                                        total_13110 +
                                                        new_index_14082];
                double defunc_1_f_res_13663 = x_13661 * x_13662;
                double defunc_1_op_res_13656 = defunc_1_f_res_13663 +
                       redout_13891;
                double redout_tmp_14746 = defunc_1_op_res_13656;
                
                redout_13891 = redout_tmp_14746;
            }
            defunc_2_reduce_res_13718 = redout_13891;
            
            double defunc_0_f_res_13659 = x_13582 + defunc_2_reduce_res_13718;
            
            ((double *) mem_14400)[i_13899 * binop_x_14335 + i_13895] =
                defunc_0_f_res_13659;
        }
    }
    
    int64_t binop_x_14442 = o_10716 * new_n_13104;
    int64_t binop_x_14443 = new_m_13108 * binop_x_14442;
    int64_t binop_y_14444 = (int64_t) 8 * binop_x_14443;
    int64_t bytes_14445 = smax64((int64_t) 0, binop_y_14444);
    
    if (memblock_alloc(ctx, &mem_14446, bytes_14445, "mem_14446")) {
        err = 1;
        goto cleanup;
    }
    if (o_10716 * new_n_13104 * new_m_13108 * (int64_t) 8 > 0)
        memmove(mem_14446.mem + (int64_t) 0, mem_14400 + (int64_t) 0, o_10716 *
                new_n_13104 * new_m_13108 * (int64_t) 8);
    if (memblock_set(ctx, &mem_out_14734, &mem_14446, "mem_14446") != 0)
        return 1;
    prim_out_14735 = new_n_13104;
    prim_out_14736 = new_m_13108;
    (*mem_out_p_14788).references = NULL;
    if (memblock_set(ctx, &*mem_out_p_14788, &mem_out_14734, "mem_out_14734") !=
        0)
        return 1;
    *out_prim_out_14789 = prim_out_14735;
    *out_prim_out_14790 = prim_out_14736;
    
  cleanup:
    {
        free(mem_14339);
        free(mem_14400);
        if (memblock_unref(ctx, &mem_14446, "mem_14446") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_14229, "mem_14229") != 0)
            return 1;
        if (memblock_unref(ctx, &ext_mem_14334, "ext_mem_14334") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_out_14734, "mem_out_14734") != 0)
            return 1;
    }
    return err;
}

int futhark_entry_convolve2d_b_bench(struct futhark_context *ctx,
                                     struct futhark_f64_3d **out0,
                                     struct futhark_f64_4d **out1,
                                     struct futhark_f64_1d **out2, const
                                     struct futhark_f64_3d *in0, const
                                     struct futhark_f64_3d *in1, const
                                     struct futhark_f64_4d *in2)
{
    int64_t o_11780;
    int64_t q_11781;
    int64_t r_11782;
    int64_t n_11783;
    int64_t m_11784;
    int64_t l_11785;
    int64_t p_11786;
    int64_t k_11787;
    int ret = 0;
    
    lock_lock(&ctx->lock);
    
    struct memblock mem_out_14736;
    
    mem_out_14736.references = NULL;
    
    struct memblock mem_out_14735;
    
    mem_out_14735.references = NULL;
    
    struct memblock mem_out_14734;
    
    mem_out_14734.references = NULL;
    
    struct memblock kernels_mem_14224;
    
    kernels_mem_14224.references = NULL;
    
    struct memblock conv_input_mem_14223;
    
    conv_input_mem_14223.references = NULL;
    
    struct memblock out_grad_mem_14222;
    
    out_grad_mem_14222.references = NULL;
    out_grad_mem_14222 = in0->mem;
    o_11780 = in0->shape[0];
    q_11781 = in0->shape[1];
    r_11782 = in0->shape[2];
    conv_input_mem_14223 = in1->mem;
    l_11785 = in1->shape[0];
    n_11783 = in1->shape[1];
    m_11784 = in1->shape[2];
    kernels_mem_14224 = in2->mem;
    o_11780 = in2->shape[0];
    l_11785 = in2->shape[1];
    p_11786 = in2->shape[2];
    k_11787 = in2->shape[3];
    if (!((o_11780 == in0->shape[0] && (q_11781 == in0->shape[1] && r_11782 ==
                                        in0->shape[2])) && ((l_11785 ==
                                                             in1->shape[0] &&
                                                             (n_11783 ==
                                                              in1->shape[1] &&
                                                              m_11784 ==
                                                              in1->shape[2])) &&
                                                            (o_11780 ==
                                                             in2->shape[0] &&
                                                             (l_11785 ==
                                                              in2->shape[1] &&
                                                              (p_11786 ==
                                                               in2->shape[2] &&
                                                               k_11787 ==
                                                               in2->shape[3])))))) {
        ret = 1;
        set_error(ctx,
                  msgprintf("Error: entry point arguments have invalid sizes.\n"));
    }
    if (ret == 0) {
        ret = futrts_entry_convolve2d_b_bench(ctx, &mem_out_14734,
                                              &mem_out_14735, &mem_out_14736,
                                              out_grad_mem_14222,
                                              conv_input_mem_14223,
                                              kernels_mem_14224, o_11780,
                                              q_11781, r_11782, n_11783,
                                              m_11784, l_11785, p_11786,
                                              k_11787);
        if (ret == 0) {
            assert((*out0 =
                    (struct futhark_f64_3d *) malloc(sizeof(struct futhark_f64_3d))) !=
                NULL);
            (*out0)->mem = mem_out_14734;
            (*out0)->shape[0] = l_11785;
            (*out0)->shape[1] = n_11783;
            (*out0)->shape[2] = m_11784;
            assert((*out1 =
                    (struct futhark_f64_4d *) malloc(sizeof(struct futhark_f64_4d))) !=
                NULL);
            (*out1)->mem = mem_out_14735;
            (*out1)->shape[0] = o_11780;
            (*out1)->shape[1] = l_11785;
            (*out1)->shape[2] = p_11786;
            (*out1)->shape[3] = k_11787;
            assert((*out2 =
                    (struct futhark_f64_1d *) malloc(sizeof(struct futhark_f64_1d))) !=
                NULL);
            (*out2)->mem = mem_out_14736;
            (*out2)->shape[0] = o_11780;
        }
    }
    lock_unlock(&ctx->lock);
    return ret;
}
int futhark_entry_convolve2d_b_test(struct futhark_context *ctx,
                                    struct futhark_f64_3d **out0,
                                    struct futhark_f64_4d **out1,
                                    struct futhark_f64_1d **out2, const
                                    struct futhark_f64_3d *in0, const
                                    struct futhark_f64_3d *in1, const
                                    struct futhark_f64_4d *in2, const
                                    int64_t in3, const int64_t in4)
{
    int64_t o_11750;
    int64_t q_11751;
    int64_t r_11752;
    int64_t n_11753;
    int64_t m_11754;
    int64_t l_11755;
    int64_t p_11756;
    int64_t k_11757;
    int64_t valid_num_11761;
    int64_t full_num_11762;
    int ret = 0;
    
    lock_lock(&ctx->lock);
    
    struct memblock mem_out_14736;
    
    mem_out_14736.references = NULL;
    
    struct memblock mem_out_14735;
    
    mem_out_14735.references = NULL;
    
    struct memblock mem_out_14734;
    
    mem_out_14734.references = NULL;
    
    struct memblock kernels_mem_14224;
    
    kernels_mem_14224.references = NULL;
    
    struct memblock conv_input_mem_14223;
    
    conv_input_mem_14223.references = NULL;
    
    struct memblock out_grad_mem_14222;
    
    out_grad_mem_14222.references = NULL;
    out_grad_mem_14222 = in0->mem;
    o_11750 = in0->shape[0];
    q_11751 = in0->shape[1];
    r_11752 = in0->shape[2];
    conv_input_mem_14223 = in1->mem;
    l_11755 = in1->shape[0];
    n_11753 = in1->shape[1];
    m_11754 = in1->shape[2];
    kernels_mem_14224 = in2->mem;
    o_11750 = in2->shape[0];
    l_11755 = in2->shape[1];
    p_11756 = in2->shape[2];
    k_11757 = in2->shape[3];
    valid_num_11761 = in3;
    full_num_11762 = in4;
    if (!((o_11750 == in0->shape[0] && (q_11751 == in0->shape[1] && r_11752 ==
                                        in0->shape[2])) && ((l_11755 ==
                                                             in1->shape[0] &&
                                                             (n_11753 ==
                                                              in1->shape[1] &&
                                                              m_11754 ==
                                                              in1->shape[2])) &&
                                                            (o_11750 ==
                                                             in2->shape[0] &&
                                                             (l_11755 ==
                                                              in2->shape[1] &&
                                                              (p_11756 ==
                                                               in2->shape[2] &&
                                                               k_11757 ==
                                                               in2->shape[3])))))) {
        ret = 1;
        set_error(ctx,
                  msgprintf("Error: entry point arguments have invalid sizes.\n"));
    }
    if (ret == 0) {
        ret = futrts_entry_convolve2d_b_test(ctx, &mem_out_14734,
                                             &mem_out_14735, &mem_out_14736,
                                             out_grad_mem_14222,
                                             conv_input_mem_14223,
                                             kernels_mem_14224, o_11750,
                                             q_11751, r_11752, n_11753, m_11754,
                                             l_11755, p_11756, k_11757,
                                             valid_num_11761, full_num_11762);
        if (ret == 0) {
            assert((*out0 =
                    (struct futhark_f64_3d *) malloc(sizeof(struct futhark_f64_3d))) !=
                NULL);
            (*out0)->mem = mem_out_14734;
            (*out0)->shape[0] = l_11755;
            (*out0)->shape[1] = n_11753;
            (*out0)->shape[2] = m_11754;
            assert((*out1 =
                    (struct futhark_f64_4d *) malloc(sizeof(struct futhark_f64_4d))) !=
                NULL);
            (*out1)->mem = mem_out_14735;
            (*out1)->shape[0] = o_11750;
            (*out1)->shape[1] = l_11755;
            (*out1)->shape[2] = p_11756;
            (*out1)->shape[3] = k_11757;
            assert((*out2 =
                    (struct futhark_f64_1d *) malloc(sizeof(struct futhark_f64_1d))) !=
                NULL);
            (*out2)->mem = mem_out_14736;
            (*out2)->shape[0] = o_11750;
        }
    }
    lock_unlock(&ctx->lock);
    return ret;
}
int futhark_entry_convolve2d_test(struct futhark_context *ctx,
                                  struct futhark_f64_3d **out0, const
                                  struct futhark_f64_3d *in0, const
                                  struct futhark_f64_4d *in1, const
                                  struct futhark_f64_1d *in2, const int64_t in3)
{
    int64_t n_10711;
    int64_t m_10712;
    int64_t l_10713;
    int64_t p_10714;
    int64_t k_10715;
    int64_t o_10716;
    int64_t padding_10720;
    int64_t prim_out_14735;
    int64_t prim_out_14736;
    int ret = 0;
    
    lock_lock(&ctx->lock);
    
    struct memblock mem_out_14734;
    
    mem_out_14734.references = NULL;
    
    struct memblock biases_mem_14224;
    
    biases_mem_14224.references = NULL;
    
    struct memblock kernels_mem_14223;
    
    kernels_mem_14223.references = NULL;
    
    struct memblock imgs_mem_14222;
    
    imgs_mem_14222.references = NULL;
    imgs_mem_14222 = in0->mem;
    l_10713 = in0->shape[0];
    n_10711 = in0->shape[1];
    m_10712 = in0->shape[2];
    kernels_mem_14223 = in1->mem;
    o_10716 = in1->shape[0];
    l_10713 = in1->shape[1];
    p_10714 = in1->shape[2];
    k_10715 = in1->shape[3];
    biases_mem_14224 = in2->mem;
    o_10716 = in2->shape[0];
    padding_10720 = in3;
    if (!((l_10713 == in0->shape[0] && (n_10711 == in0->shape[1] && m_10712 ==
                                        in0->shape[2])) && ((o_10716 ==
                                                             in1->shape[0] &&
                                                             (l_10713 ==
                                                              in1->shape[1] &&
                                                              (p_10714 ==
                                                               in1->shape[2] &&
                                                               k_10715 ==
                                                               in1->shape[3]))) &&
                                                            o_10716 ==
                                                            in2->shape[0]))) {
        ret = 1;
        set_error(ctx,
                  msgprintf("Error: entry point arguments have invalid sizes.\n"));
    }
    if (ret == 0) {
        ret = futrts_entry_convolve2d_test(ctx, &mem_out_14734, &prim_out_14735,
                                           &prim_out_14736, imgs_mem_14222,
                                           kernels_mem_14223, biases_mem_14224,
                                           n_10711, m_10712, l_10713, p_10714,
                                           k_10715, o_10716, padding_10720);
        if (ret == 0) {
            assert((*out0 =
                    (struct futhark_f64_3d *) malloc(sizeof(struct futhark_f64_3d))) !=
                NULL);
            (*out0)->mem = mem_out_14734;
            (*out0)->shape[0] = o_10716;
            (*out0)->shape[1] = prim_out_14735;
            (*out0)->shape[2] = prim_out_14736;
        }
    }
    lock_unlock(&ctx->lock);
    return ret;
}
  
