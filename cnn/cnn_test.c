
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
int futhark_context_config_set_tuning_param(struct futhark_context_config *cfg, const char *param_name, size_t new_value);
struct futhark_context;
struct futhark_context *futhark_context_new(struct futhark_context_config *cfg);
void futhark_context_free(struct futhark_context *cfg);
void futhark_context_config_set_debugging(struct futhark_context_config *cfg, int flag);
void futhark_context_config_set_profiling(struct futhark_context_config *cfg, int flag);
void futhark_context_config_set_logging(struct futhark_context_config *cfg, int flag);
int futhark_get_tuning_param_count(void);
const char *futhark_get_tuning_param_name(int);
const char *futhark_get_tuning_param_class(int);

// Arrays
struct futhark_f64_1d;
struct futhark_f64_1d *futhark_new_f64_1d(struct futhark_context *ctx, const double *data, int64_t dim0);
struct futhark_f64_1d *futhark_new_raw_f64_1d(struct futhark_context *ctx, const unsigned char *data, int64_t offset, int64_t dim0);
int futhark_free_f64_1d(struct futhark_context *ctx, struct futhark_f64_1d *arr);
int futhark_values_f64_1d(struct futhark_context *ctx, struct futhark_f64_1d *arr, double *data);
unsigned char *futhark_values_raw_f64_1d(struct futhark_context *ctx, struct futhark_f64_1d *arr);
const int64_t *futhark_shape_f64_1d(struct futhark_context *ctx, struct futhark_f64_1d *arr);
struct futhark_f64_2d;
struct futhark_f64_2d *futhark_new_f64_2d(struct futhark_context *ctx, const double *data, int64_t dim0, int64_t dim1);
struct futhark_f64_2d *futhark_new_raw_f64_2d(struct futhark_context *ctx, const unsigned char *data, int64_t offset, int64_t dim0, int64_t dim1);
int futhark_free_f64_2d(struct futhark_context *ctx, struct futhark_f64_2d *arr);
int futhark_values_f64_2d(struct futhark_context *ctx, struct futhark_f64_2d *arr, double *data);
unsigned char *futhark_values_raw_f64_2d(struct futhark_context *ctx, struct futhark_f64_2d *arr);
const int64_t *futhark_shape_f64_2d(struct futhark_context *ctx, struct futhark_f64_2d *arr);
struct futhark_f64_3d;
struct futhark_f64_3d *futhark_new_f64_3d(struct futhark_context *ctx, const double *data, int64_t dim0, int64_t dim1, int64_t dim2);
struct futhark_f64_3d *futhark_new_raw_f64_3d(struct futhark_context *ctx, const unsigned char *data, int64_t offset, int64_t dim0, int64_t dim1, int64_t dim2);
int futhark_free_f64_3d(struct futhark_context *ctx, struct futhark_f64_3d *arr);
int futhark_values_f64_3d(struct futhark_context *ctx, struct futhark_f64_3d *arr, double *data);
unsigned char *futhark_values_raw_f64_3d(struct futhark_context *ctx, struct futhark_f64_3d *arr);
const int64_t *futhark_shape_f64_3d(struct futhark_context *ctx, struct futhark_f64_3d *arr);
struct futhark_f64_4d;
struct futhark_f64_4d *futhark_new_f64_4d(struct futhark_context *ctx, const double *data, int64_t dim0, int64_t dim1, int64_t dim2, int64_t dim3);
struct futhark_f64_4d *futhark_new_raw_f64_4d(struct futhark_context *ctx, const unsigned char *data, int64_t offset, int64_t dim0, int64_t dim1, int64_t dim2, int64_t dim3);
int futhark_free_f64_4d(struct futhark_context *ctx, struct futhark_f64_4d *arr);
int futhark_values_f64_4d(struct futhark_context *ctx, struct futhark_f64_4d *arr, double *data);
unsigned char *futhark_values_raw_f64_4d(struct futhark_context *ctx, struct futhark_f64_4d *arr);
const int64_t *futhark_shape_f64_4d(struct futhark_context *ctx, struct futhark_f64_4d *arr);

// Opaque values



// Entry points
int futhark_entry_bench_cnn(struct futhark_context *ctx, struct futhark_f64_1d **out0, const struct futhark_f64_3d *in0, const struct futhark_f64_2d *in1, const int64_t in2);
int futhark_entry_bench_cnn_futhark_ad(struct futhark_context *ctx, struct futhark_f64_4d **out0, struct futhark_f64_1d **out1, struct futhark_f64_4d **out2, struct futhark_f64_1d **out3, struct futhark_f64_2d **out4, struct futhark_f64_1d **out5, struct futhark_f64_2d **out6, struct futhark_f64_1d **out7, struct futhark_f64_2d **out8, struct futhark_f64_1d **out9, const struct futhark_f64_3d *in0, const struct futhark_f64_2d *in1, const int64_t in2);
int futhark_entry_test_cnn_futhark_ad(struct futhark_context *ctx, struct futhark_f64_3d **out0, const struct futhark_f64_3d *in0, const struct futhark_f64_2d *in1);

// Miscellaneous
int futhark_context_sync(struct futhark_context *ctx);
void futhark_context_config_set_cache_file(struct futhark_context_config *cfg, const char *f);
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
static char *strclone(const char *str);

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


static char *strclone(const char *str) {
  size_t size = strlen(str) + 1;
  char *copy = (char*) malloc(size);
  if (copy == NULL) {
    return NULL;
  }

  memcpy(copy, str, size);
  return copy;
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

static uint16_t halfbitsnextafter(uint16_t from, uint16_t to) {
  int fabs = from & 0x7FFF, tabs = to & 0x7FFF;
  if(fabs > 0x7C00 || tabs > 0x7C00) {
    return ((from&0x7FFF)>0x7C00) ? (from|0x200) : (to|0x200);
  }
  if(from == to || !(fabs|tabs)) {
    return to;
  }
  if(!fabs) {
    return (to&0x8000)+1;
  }
  unsigned int out =
    from +
    (((from>>15)^(unsigned int)((from^(0x8000|(0x8000-(from>>15))))<(to^(0x8000|(0x8000-(to>>15))))))<<1)
    - 1;
  return out;
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
// Start of free_list.h.

typedef uintptr_t fl_mem;

// An entry in the free list.  May be invalid, to avoid having to
// deallocate entries as soon as they are removed.  There is also a
// tag, to help with memory reuse.
struct free_list_entry {
  size_t size;
  fl_mem mem;
  const char *tag;
  unsigned char valid;
};

struct free_list {
  struct free_list_entry *entries; // Pointer to entries.
  int capacity;                    // Number of entries.
  int used;                        // Number of valid entries.
  lock_t lock;                     // Thread safety.
};

static void free_list_init(struct free_list *l) {
  l->capacity = 30; // Picked arbitrarily.
  l->used = 0;
  l->entries = (struct free_list_entry*) malloc(sizeof(struct free_list_entry) * l->capacity);
  for (int i = 0; i < l->capacity; i++) {
    l->entries[i].valid = 0;
  }
  create_lock(&l->lock);
}

// Remove invalid entries from the free list.
static void free_list_pack(struct free_list *l) {
  lock_lock(&l->lock);
  int p = 0;
  for (int i = 0; i < l->capacity; i++) {
    if (l->entries[i].valid) {
      l->entries[p] = l->entries[i];
      if (i > p) {
        l->entries[i].valid = 0;
      }
      p++;
    }
  }

  // Now p is the number of used elements.  We don't want it to go
  // less than the default capacity (although in practice it's OK as
  // long as it doesn't become 1).
  if (p < 30) {
    p = 30;
  }
  l->entries = realloc(l->entries, p * sizeof(struct free_list_entry));
  l->capacity = p;
  lock_unlock(&l->lock);
}

static void free_list_destroy(struct free_list *l) {
  assert(l->used == 0);
  free(l->entries);
  free_lock(&l->lock);
}

// Not part of the interface, so no locking.
static int free_list_find_invalid(struct free_list *l) {
  int i;
  for (i = 0; i < l->capacity; i++) {
    if (!l->entries[i].valid) {
      break;
    }
  }
  return i;
}

static void free_list_insert(struct free_list *l, size_t size, fl_mem mem, const char *tag) {
  lock_lock(&l->lock);
  int i = free_list_find_invalid(l);

  if (i == l->capacity) {
    // List is full; so we have to grow it.
    int new_capacity = l->capacity * 2 * sizeof(struct free_list_entry);
    l->entries = realloc(l->entries, new_capacity);
    for (int j = 0; j < l->capacity; j++) {
      l->entries[j+l->capacity].valid = 0;
    }
    l->capacity *= 2;
  }

  // Now 'i' points to the first invalid entry.
  l->entries[i].valid = 1;
  l->entries[i].size = size;
  l->entries[i].mem = mem;
  l->entries[i].tag = tag;

  l->used++;
  lock_unlock(&l->lock);
}

// Determine whether this entry in the free list is acceptable for
// satisfying the request.  Not public, so no locking.
static bool free_list_acceptable(size_t size, const char* tag, struct free_list_entry *entry) {
  // We check not just the hard requirement (is the entry acceptable
  // and big enough?) but also put a cap on how much wasted space
  // (internal fragmentation) we allow.  This is necessarily a
  // heuristic, and a crude one.

  if (!entry->valid) {
    return false;
  }

  if (size > entry->size) {
    return false;
  }

  // We know the block fits.  Now the question is whether it is too
  // big.  Our policy is as follows:
  //
  // 1) We don't care about wasted space below 4096 bytes (to avoid
  // churn in tiny allocations).
  //
  // 2) If the tag matches, we allow _any_ amount of wasted space.
  //
  // 3) Otherwise we allow up to 50% wasted space.

  if (entry->size < 4096) {
    return true;
  }

  if (entry->tag == tag) {
    return true;
  }

  if (entry->size < size * 2) {
    return true;
  }

  return false;
}

// Find and remove a memory block of the indicated tag, or if that
// does not exist, another memory block with exactly the desired size.
// Returns 0 on success.
static int free_list_find(struct free_list *l, size_t size, const char *tag,
                          size_t *size_out, fl_mem *mem_out) {
  lock_lock(&l->lock);
  int size_match = -1;
  int i;
  int ret = 1;
  for (i = 0; i < l->capacity; i++) {
    if (free_list_acceptable(size, tag, &l->entries[i]) &&
        (size_match < 0 || l->entries[i].size < l->entries[size_match].size)) {
      // If this entry is valid, has sufficient size, and is smaller than the
      // best entry found so far, use this entry.
      size_match = i;
    }
  }

  if (size_match >= 0) {
    l->entries[size_match].valid = 0;
    *size_out = l->entries[size_match].size;
    *mem_out = l->entries[size_match].mem;
    l->used--;
    ret = 0;
  }
  lock_unlock(&l->lock);
  return ret;
}

// Remove the first block in the free list.  Returns 0 if a block was
// removed, and nonzero if the free list was already empty.
static int free_list_first(struct free_list *l, fl_mem *mem_out) {
  lock_lock(&l->lock);
  int ret = 1;
  for (int i = 0; i < l->capacity; i++) {
    if (l->entries[i].valid) {
      l->entries[i].valid = 0;
      *mem_out = l->entries[i].mem;
      l->used--;
      ret = 0;
      break;
    }
  }
  lock_unlock(&l->lock);
  return ret;
}

// End of free_list.h.
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
int futhark_get_tuning_param_count(void);
const char* futhark_get_tuning_param_name(int i);
const char* futhark_get_tuning_param_class(int i);

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
  const char** tuning_params;
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
    return;
  }

  int bad = 0;
  int values = 0;
  for (int i = 1; arg_exists(args, i); i+=2, values++) {
    const char *vname = get_arg(args, i);
    const char *type = get_arg(args, i+1);

    const struct type *t = get_type(s, type);
    struct variable *v = create_variable(s, vname, t);

    if (v == NULL) {
      bad = 1;
      failure();
      printf("Variable already exists: %s\n", vname);
      break;
    }

    errno = 0;
    if (t->restore(t->aux, f, s->ctx, value_ptr(&v->value)) != 0) {
      bad = 1;
      failure();
      printf("Failed to restore variable %s.\n"
             "Possibly malformed data in %s (errno: %s)\n",
             vname, fname, strerror(errno));
      drop_variable(v);
      break;
    }
  }

  if (!bad && end_of_input(f) != 0) {
    failure();
    printf("Expected EOF after reading %d values from %s\n",
           values, fname);
  }

  fclose(f);

  if (!bad) {
    int err = futhark_context_sync(s->ctx);
    error_check(s, err);
  }
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

void cmd_tuning_params(struct server_state *s, const char *args[]) {
  const char *name = get_arg(args, 0);
  struct entry_point *e = get_entry_point(s, name);

  if (e == NULL) {
    failure();
    printf("Unknown entry point: %s\n", name);
    return;
  }

  const char **params = e->tuning_params;
  for (int i = 0; params[i] != NULL; i++) {
    printf("%s\n", params[i]);
  }
}

void cmd_tuning_param_class(struct server_state *s, const char *args[]) {
  (void)s;
  const char *param = get_arg(args, 0);

  int n = futhark_get_tuning_param_count();

  for (int i = 0; i < n; i++) {
    if (strcmp(futhark_get_tuning_param_name(i), param) == 0) {
      printf("%s\n", futhark_get_tuning_param_class(i));
      return;
    }
  }

  failure();
  printf("Unknown tuning parameter: %s\n", param);
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
  } else if (strcmp(command, "tuning_params") == 0) {
    cmd_tuning_params(s, tokens+1);
  } else if (strcmp(command, "tuning_param_class") == 0) {
    cmd_tuning_param_class(s, tokens+1);
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
  int err = futhark_context_sync(ctx);
  *(void**)p = arr;
  free(data);
  return err;
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
const struct type type_ZMZNZMZNf64;
const struct type type_ZMZNf64;
void *futhark_new_f64_4d_wrap(struct futhark_context *ctx, const void *p, const int64_t *shape)
{
    return futhark_new_f64_4d(ctx, p, shape[0], shape[1], shape[2], shape[3]);
}
const struct array_aux type_ZMZNZMZNZMZNZMZNf64_aux = {.name ="[][][][]f64", .rank =4, .info =&f64_info, .new =(array_new_fn) futhark_new_f64_4d_wrap, .free =(array_free_fn) futhark_free_f64_4d, .shape =(array_shape_fn) futhark_shape_f64_4d, .values =(array_values_fn) futhark_values_f64_4d};
const struct type type_ZMZNZMZNZMZNZMZNf64 = {.name ="[][][][]f64", .restore =(restore_fn) restore_array, .store =(store_fn) store_array, .free =(free_fn) free_array, .aux =&type_ZMZNZMZNZMZNZMZNf64_aux};
void *futhark_new_f64_3d_wrap(struct futhark_context *ctx, const void *p, const int64_t *shape)
{
    return futhark_new_f64_3d(ctx, p, shape[0], shape[1], shape[2]);
}
const struct array_aux type_ZMZNZMZNZMZNf64_aux = {.name ="[][][]f64", .rank =3, .info =&f64_info, .new =(array_new_fn) futhark_new_f64_3d_wrap, .free =(array_free_fn) futhark_free_f64_3d, .shape =(array_shape_fn) futhark_shape_f64_3d, .values =(array_values_fn) futhark_values_f64_3d};
const struct type type_ZMZNZMZNZMZNf64 = {.name ="[][][]f64", .restore =(restore_fn) restore_array, .store =(store_fn) store_array, .free =(free_fn) free_array, .aux =&type_ZMZNZMZNZMZNf64_aux};
void *futhark_new_f64_2d_wrap(struct futhark_context *ctx, const void *p, const int64_t *shape)
{
    return futhark_new_f64_2d(ctx, p, shape[0], shape[1]);
}
const struct array_aux type_ZMZNZMZNf64_aux = {.name ="[][]f64", .rank =2, .info =&f64_info, .new =(array_new_fn) futhark_new_f64_2d_wrap, .free =(array_free_fn) futhark_free_f64_2d, .shape =(array_shape_fn) futhark_shape_f64_2d, .values =(array_values_fn) futhark_values_f64_2d};
const struct type type_ZMZNZMZNf64 = {.name ="[][]f64", .restore =(restore_fn) restore_array, .store =(store_fn) store_array, .free =(free_fn) free_array, .aux =&type_ZMZNZMZNf64_aux};
void *futhark_new_f64_1d_wrap(struct futhark_context *ctx, const void *p, const int64_t *shape)
{
    return futhark_new_f64_1d(ctx, p, shape[0]);
}
const struct array_aux type_ZMZNf64_aux = {.name ="[]f64", .rank =1, .info =&f64_info, .new =(array_new_fn) futhark_new_f64_1d_wrap, .free =(array_free_fn) futhark_free_f64_1d, .shape =(array_shape_fn) futhark_shape_f64_1d, .values =(array_values_fn) futhark_values_f64_1d};
const struct type type_ZMZNf64 = {.name ="[]f64", .restore =(restore_fn) restore_array, .store =(store_fn) store_array, .free =(free_fn) free_array, .aux =&type_ZMZNf64_aux};
const struct type *bench_cnn_out_types[] = {&type_ZMZNf64, NULL};
bool bench_cnn_out_unique[] = {false};
const struct type *bench_cnn_in_types[] = {&type_ZMZNZMZNZMZNf64, &type_ZMZNZMZNf64, &type_i64, NULL};
bool bench_cnn_in_unique[] = {false, false, false};
const char *bench_cnn_tuning_params[] = {NULL};
int call_bench_cnn(struct futhark_context *ctx, void **outs, void **ins)
{
    struct futhark_f64_1d * *out0 = outs[0];
    struct futhark_f64_3d * in0 = *(struct futhark_f64_3d * *) ins[0];
    struct futhark_f64_2d * in1 = *(struct futhark_f64_2d * *) ins[1];
    int64_t in2 = *(int64_t *) ins[2];
    
    return futhark_entry_bench_cnn(ctx, out0, in0, in1, in2);
}
const struct type *bench_cnn_futhark_ad_out_types[] = {&type_ZMZNZMZNZMZNZMZNf64, &type_ZMZNf64, &type_ZMZNZMZNZMZNZMZNf64, &type_ZMZNf64, &type_ZMZNZMZNf64, &type_ZMZNf64, &type_ZMZNZMZNf64, &type_ZMZNf64, &type_ZMZNZMZNf64, &type_ZMZNf64, NULL};
bool bench_cnn_futhark_ad_out_unique[] = {false, false, false, false, false, false, false, false, false, false};
const struct type *bench_cnn_futhark_ad_in_types[] = {&type_ZMZNZMZNZMZNf64, &type_ZMZNZMZNf64, &type_i64, NULL};
bool bench_cnn_futhark_ad_in_unique[] = {false, false, false};
const char *bench_cnn_futhark_ad_tuning_params[] = {NULL};
int call_bench_cnn_futhark_ad(struct futhark_context *ctx, void **outs, void **ins)
{
    struct futhark_f64_4d * *out0 = outs[0];
    struct futhark_f64_1d * *out1 = outs[1];
    struct futhark_f64_4d * *out2 = outs[2];
    struct futhark_f64_1d * *out3 = outs[3];
    struct futhark_f64_2d * *out4 = outs[4];
    struct futhark_f64_1d * *out5 = outs[5];
    struct futhark_f64_2d * *out6 = outs[6];
    struct futhark_f64_1d * *out7 = outs[7];
    struct futhark_f64_2d * *out8 = outs[8];
    struct futhark_f64_1d * *out9 = outs[9];
    struct futhark_f64_3d * in0 = *(struct futhark_f64_3d * *) ins[0];
    struct futhark_f64_2d * in1 = *(struct futhark_f64_2d * *) ins[1];
    int64_t in2 = *(int64_t *) ins[2];
    
    return futhark_entry_bench_cnn_futhark_ad(ctx, out0, out1, out2, out3, out4, out5, out6, out7, out8, out9, in0, in1, in2);
}
const struct type *test_cnn_futhark_ad_out_types[] = {&type_ZMZNZMZNZMZNf64, NULL};
bool test_cnn_futhark_ad_out_unique[] = {false};
const struct type *test_cnn_futhark_ad_in_types[] = {&type_ZMZNZMZNZMZNf64, &type_ZMZNZMZNf64, NULL};
bool test_cnn_futhark_ad_in_unique[] = {false, false};
const char *test_cnn_futhark_ad_tuning_params[] = {NULL};
int call_test_cnn_futhark_ad(struct futhark_context *ctx, void **outs, void **ins)
{
    struct futhark_f64_3d * *out0 = outs[0];
    struct futhark_f64_3d * in0 = *(struct futhark_f64_3d * *) ins[0];
    struct futhark_f64_2d * in1 = *(struct futhark_f64_2d * *) ins[1];
    
    return futhark_entry_test_cnn_futhark_ad(ctx, out0, in0, in1);
}
const struct type *types[] = {&type_i8, &type_i16, &type_i32, &type_i64, &type_u8, &type_u16, &type_u32, &type_u64, &type_f16, &type_f32, &type_f64, &type_bool, &type_ZMZNZMZNZMZNZMZNf64, &type_ZMZNZMZNZMZNf64, &type_ZMZNZMZNf64, &type_ZMZNf64, NULL};
struct entry_point entry_points[] = {{.name ="bench_cnn", .f =call_bench_cnn, .tuning_params =bench_cnn_tuning_params, .in_types =bench_cnn_in_types, .out_types =bench_cnn_out_types, .in_unique =bench_cnn_in_unique, .out_unique =bench_cnn_out_unique}, {.name ="bench_cnn_futhark_ad", .f =call_bench_cnn_futhark_ad, .tuning_params =bench_cnn_futhark_ad_tuning_params, .in_types =bench_cnn_futhark_ad_in_types, .out_types =bench_cnn_futhark_ad_out_types, .in_unique =bench_cnn_futhark_ad_in_unique, .out_unique =bench_cnn_futhark_ad_out_unique}, {.name ="test_cnn_futhark_ad", .f =call_test_cnn_futhark_ad, .tuning_params =test_cnn_futhark_ad_tuning_params, .in_types =test_cnn_futhark_ad_in_types, .out_types =test_cnn_futhark_ad_out_types, .in_unique =test_cnn_futhark_ad_in_unique, .out_unique =test_cnn_futhark_ad_out_unique}, {.name =NULL}};
struct futhark_prog prog = {.types =types, .entry_points =entry_points};
int parse_options(struct futhark_context_config *cfg, int argc, char *const argv[])
{
    int ch;
    static struct option long_options[] = {{"debugging", no_argument, NULL, 1}, {"log", no_argument, NULL, 2}, {"help", no_argument, NULL, 3}, {"print-params", no_argument, NULL, 4}, {"param", required_argument, NULL, 5}, {"tuning", required_argument, NULL, 6}, {"cache-file", required_argument, NULL, 7}, {0, 0, 0, 0}};
    static char *option_descriptions = "  -D/--debugging     Perform possibly expensive internal correctness checks and verbose logging.\n  -L/--log           Print various low-overhead logging information while running.\n  -h/--help          Print help information and exit.\n  --print-params     Print all tuning parameters that can be set with --param or --tuning.\n  --param ASSIGNMENT Set a tuning parameter to the given value.\n  --tuning FILE      Read size=value assignments from the given file.\n  --cache-file FILE  Store program cache here.\n";
    
    while ((ch = getopt_long(argc, argv, ":DLh", long_options, NULL)) != -1) {
        if (ch == 1 || ch == 'D')
            futhark_context_config_set_debugging(cfg, 1);
        if (ch == 2 || ch == 'L')
            futhark_context_config_set_logging(cfg, 1);
        if (ch == 3 || ch == 'h') {
            printf("Usage: %s [OPTIONS]...\nOptions:\n\n%s\nFor more information, consult the Futhark User's Guide or the man pages.\n", fut_progname, option_descriptions);
            exit(0);
        }
        if (ch == 4) {
            int n = futhark_get_tuning_param_count();
            
            for (int i = 0; i < n; i++)
                printf("%s (%s)\n", futhark_get_tuning_param_name(i), futhark_get_tuning_param_class(i));
            exit(0);
        }
        if (ch == 5) {
            char *name = optarg;
            char *equals = strstr(optarg, "=");
            char *value_str = equals != NULL ? equals + 1 : optarg;
            int value = atoi(value_str);
            
            if (equals != NULL) {
                *equals = 0;
                if (futhark_context_config_set_tuning_param(cfg, name, value) != 0)
                    futhark_panic(1, "Unknown size: %s\n", name);
            } else
                futhark_panic(1, "Invalid argument for size option: %s\n", optarg);
        }
        if (ch == 6) {
            char *ret = load_tuning_file(optarg, cfg, (int (*)(void *, const char *, size_t)) futhark_context_config_set_tuning_param);
            
            if (ret != NULL)
                futhark_panic(1, "When loading tuning from '%s': %s\n", optarg, ret);
        }
        if (ch == 7)
            futhark_context_config_set_cache_file(cfg, optarg);
        if (ch == ':')
            futhark_panic(-1, "Missing argument for option %s\n", argv[optind - 1]);
        if (ch == '?') {
            fprintf(stderr, "Usage: %s [OPTIONS]...\nOptions:\n\n%s\n", fut_progname, "  -D/--debugging     Perform possibly expensive internal correctness checks and verbose logging.\n  -L/--log           Print various low-overhead logging information while running.\n  -h/--help          Print help information and exit.\n  --print-params     Print all tuning parameters that can be set with --param or --tuning.\n  --param ASSIGNMENT Set a tuning parameter to the given value.\n  --tuning FILE      Read size=value assignments from the given file.\n  --cache-file FILE  Store program cache here.\n");
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
static uint8_t  futrts_umul_hi8 ( uint8_t a,  uint8_t b) { return mul_hi(a, b); }
static uint16_t futrts_umul_hi16(uint16_t a, uint16_t b) { return mul_hi(a, b); }
static uint32_t futrts_umul_hi32(uint32_t a, uint32_t b) { return mul_hi(a, b); }
static uint64_t futrts_umul_hi64(uint64_t a, uint64_t b) { return mul_hi(a, b); }
static uint8_t  futrts_smul_hi8 ( int8_t a,  int8_t b) { return mul_hi(a, b); }
static uint16_t futrts_smul_hi16(int16_t a, int16_t b) { return mul_hi(a, b); }
static uint32_t futrts_smul_hi32(int32_t a, int32_t b) { return mul_hi(a, b); }
static uint64_t futrts_smul_hi64(int64_t a, int64_t b) { return mul_hi(a, b); }
#elif defined(__CUDA_ARCH__)
static  uint8_t futrts_umul_hi8(uint8_t a, uint8_t b) { return ((uint16_t)a) * ((uint16_t)b) >> 8; }
static uint16_t futrts_umul_hi16(uint16_t a, uint16_t b) { return ((uint32_t)a) * ((uint32_t)b) >> 16; }
static uint32_t futrts_umul_hi32(uint32_t a, uint32_t b) { return __umulhi(a, b); }
static uint64_t futrts_umul_hi64(uint64_t a, uint64_t b) { return __umul64hi(a, b); }
static  uint8_t futrts_smul_hi8 ( int8_t a, int8_t b) { return ((int16_t)a) * ((int16_t)b) >> 8; }
static uint16_t futrts_smul_hi16(int16_t a, int16_t b) { return ((int32_t)a) * ((int32_t)b) >> 16; }
static uint32_t futrts_smul_hi32(int32_t a, int32_t b) { return __mulhi(a, b); }
static uint64_t futrts_smul_hi64(int64_t a, int64_t b) { return __mul64hi(a, b); }
#elif ISPC
static uint8_t futrts_umul_hi8(uint8_t a, uint8_t b) { return ((uint16_t)a) * ((uint16_t)b) >> 8; }
static uint16_t futrts_umul_hi16(uint16_t a, uint16_t b) { return ((uint32_t)a) * ((uint32_t)b) >> 16; }
static uint32_t futrts_umul_hi32(uint32_t a, uint32_t b) { return ((uint64_t)a) * ((uint64_t)b) >> 32; }
static uint64_t futrts_umul_hi64(uint64_t a, uint64_t b) {
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

  uint64_t l = p1h + p2l + p3l;
  uint64_t m = (p2 >> 32) + (p3 >> 32);
  uint64_t h = (l >> 32) + m + p4;

  return h;
}
static  int8_t futrts_smul_hi8 ( int8_t a,  int8_t b) { return ((uint16_t)a) * ((uint16_t)b) >> 8; }
static int16_t futrts_smul_hi16(int16_t a, int16_t b) { return ((uint32_t)a) * ((uint32_t)b) >> 16; }
static int32_t futrts_smul_hi32(int32_t a, int32_t b) { return ((uint64_t)a) * ((uint64_t)b) >> 32; }
static int64_t futrts_smul_hi64(int64_t a, int64_t b) {
  uint64_t ah = a >> 32;
  uint64_t al = a & 0xffffffff;
  uint64_t bh = b >> 32;
  uint64_t bl = b & 0xffffffff;

  uint64_t p1 =  al * bl;
  int64_t  p2 = al * bh;
  int64_t  p3 = ah * bl;
  uint64_t p4 =  ah * bh;

  uint64_t p1h = p1 >> 32;
  uint64_t p2h = p2 >> 32;
  uint64_t p3h = p3 >> 32;
  uint64_t p2l = p2 & 0xffffffff;
  uint64_t p3l = p3 & 0xffffffff;

  uint64_t l = p1h + p2l + p3l;
  uint64_t m = (p2 >> 32) + (p3 >> 32);
  uint64_t h = (l >> 32) + m + p4;

  return h;
}

#else // Not OpenCL, ISPC, or CUDA, but plain C.
static uint8_t futrts_umul_hi8(uint8_t a, uint8_t b) { return ((uint16_t)a) * ((uint16_t)b) >> 8; }
static uint16_t futrts_umul_hi16(uint16_t a, uint16_t b) { return ((uint32_t)a) * ((uint32_t)b) >> 16; }
static uint32_t futrts_umul_hi32(uint32_t a, uint32_t b) { return ((uint64_t)a) * ((uint64_t)b) >> 32; }
static uint64_t futrts_umul_hi64(uint64_t a, uint64_t b) { return ((__uint128_t)a) * ((__uint128_t)b) >> 64; }
static int8_t futrts_smul_hi8(int8_t a, int8_t b) { return ((int16_t)a) * ((int16_t)b) >> 8; }
static int16_t futrts_smul_hi16(int16_t a, int16_t b) { return ((int32_t)a) * ((int32_t)b) >> 16; }
static int32_t futrts_smul_hi32(int32_t a, int32_t b) { return ((int64_t)a) * ((int64_t)b) >> 32; }
static int64_t futrts_smul_hi64(int64_t a, int64_t b) { return ((__int128_t)a) * ((__int128_t)b) >> 64; }
#endif

#if defined(__OPENCL_VERSION__)
static  uint8_t futrts_umad_hi8 ( uint8_t a,  uint8_t b,  uint8_t c) { return mad_hi(a, b, c); }
static uint16_t futrts_umad_hi16(uint16_t a, uint16_t b, uint16_t c) { return mad_hi(a, b, c); }
static uint32_t futrts_umad_hi32(uint32_t a, uint32_t b, uint32_t c) { return mad_hi(a, b, c); }
static uint64_t futrts_umad_hi64(uint64_t a, uint64_t b, uint64_t c) { return mad_hi(a, b, c); }
static  uint8_t futrts_smad_hi8( int8_t a,  int8_t b,   int8_t c) { return mad_hi(a, b, c); }
static uint16_t futrts_smad_hi16(int16_t a, int16_t b, int16_t c) { return mad_hi(a, b, c); }
static uint32_t futrts_smad_hi32(int32_t a, int32_t b, int32_t c) { return mad_hi(a, b, c); }
static uint64_t futrts_smad_hi64(int64_t a, int64_t b, int64_t c) { return mad_hi(a, b, c); }
#else // Not OpenCL

static  uint8_t futrts_umad_hi8( uint8_t a,  uint8_t b,  uint8_t c) { return futrts_umul_hi8(a, b) + c; }
static uint16_t futrts_umad_hi16(uint16_t a, uint16_t b, uint16_t c) { return futrts_umul_hi16(a, b) + c; }
static uint32_t futrts_umad_hi32(uint32_t a, uint32_t b, uint32_t c) { return futrts_umul_hi32(a, b) + c; }
static uint64_t futrts_umad_hi64(uint64_t a, uint64_t b, uint64_t c) { return futrts_umul_hi64(a, b) + c; }
static  uint8_t futrts_smad_hi8 ( int8_t a,  int8_t b,  int8_t c) { return futrts_smul_hi8(a, b) + c; }
static uint16_t futrts_smad_hi16(int16_t a, int16_t b, int16_t c) { return futrts_smul_hi16(a, b) + c; }
static uint32_t futrts_smad_hi32(int32_t a, int32_t b, int32_t c) { return futrts_smul_hi32(a, b) + c; }
static uint64_t futrts_smad_hi64(int64_t a, int64_t b, int64_t c) { return futrts_smul_hi64(a, b) + c; }
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

static inline float futrts_log1p_32(float x) {
  return log1p(x);
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

static inline float futrts_nextafter32(float x, float y) {
  return nextafter(x, y);
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

static inline float futrts_log1p_32(float x) {
  if(x == -1.0f || (futrts_isinf32(x) && x > 0.0f)) return x / 0.0f;
  float y = 1.0f + x;
  float z = y - 1.0f;
  return log(y) - (z-x)/y;
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

extern "C" unmasked uniform float nextafterf(uniform float x, uniform float y);
static inline float futrts_nextafter32(float x, float y) {
  float res;
  foreach_active (i) {
    uniform float r = nextafterf(extract(x, i), extract(y, i));
    res = insert(res, i, r);
  }
  return res;
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

static inline float futrts_log1p_32(float x) {
  return log1pf(x);
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

static inline float futrts_nextafter32(float x, float y) {
  return nextafterf(x, y);
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

static inline double futrts_log1p_64(double x) {
  if(x == -1.0d || (futrts_isinf64(x) && x > 0.0d)) return x / 0.0d;
  double y = 1.0d + x;
  double z = y - 1.0d;
  return log(y) - (z-x)/y;
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

extern "C" unmasked uniform double nextafter(uniform float x, uniform double y);
static inline float futrts_nextafter64(double x, double y) {
  double res;
  foreach_active (i) {
    uniform double r = nextafter(extract(x, i), extract(y, i));
    res = insert(res, i, r);
  }
  return res;
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

static inline double futrts_log1p_64(double x) {
  return log1p(x);
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

static inline float futrts_nextafter64(float x, float y) {
  return nextafter(x, y);
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

static inline f16 futrts_log1p_16(f16 x) {
  return log1p(x);
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

static inline f16 futrts_nextafter16(f16 x, f16 y) {
  return nextafter(x, y);
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

static inline f16 futrts_log1p_16(f16 x) {
  if(x == -1.0f16 || (futrts_isinf16(x) && x > 0.0f16)) return x / 0.0f16;
  f16 y = 1.0f16 + x;
  f16 z = y - 1.0f16;
  return log(y) - (z-x)/y;
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

static inline f16 futrts_nextafter16(f16 x, f16 y) {
  return (float16)futrts_nextafter32((float)x, (float) y);
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

static inline f16 futrts_log1p_16(f16 x) {
  return (f16)log1pf((float)x);
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

static inline f16 futrts_nextafter16(f16 x, f16 y) {
  return __ushort_as_half(halfbitsnextafter(__half_as_ushort(x), __half_as_ushort(y)));
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

static inline f16 futrts_log1p_16(f16 x) {
  return futrts_log1p_32(x);
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

static inline f16 futrts_nextafter16(f16 x, f16 y) {
  return halfbits2float(halfbitsnextafter(float2halfbits(x), float2halfbits(y)));
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
// Prototypes for the functions in context.h, or that will be called
// from those functions, that need to be available very early.

struct futhark_context_config;
struct futhark_context;

static void set_error(struct futhark_context* ctx, char *error);

// These are called in context/config new/free functions and contain
// shared setup.  They are generated by the compiler itself.
static int init_constants(struct futhark_context*);
static int free_constants(struct futhark_context*);
static void setup_program(struct futhark_context* ctx);
static void teardown_program(struct futhark_context *ctx);

// Allocate host memory.  Must be freed with host_free().
static void host_alloc(struct futhark_context* ctx, size_t size, const char* tag, size_t* size_out, void** mem_out);
// Allocate memory allocated with host_alloc().
static void host_free(struct futhark_context* ctx, size_t size, const char* tag, void* mem);

// Functions that must be defined by the backend.
static void backend_context_config_setup(struct futhark_context_config* cfg);
static void backend_context_config_teardown(struct futhark_context_config* cfg);
static int backend_context_setup(struct futhark_context *ctx);
static void backend_context_teardown(struct futhark_context *ctx);

// End of of context_prototypes.h

struct memblock {
    int *references;
    unsigned char *mem;
    int64_t size;
    const char *desc;
};
struct constants {
    int dummy;
    struct memblock mem_46702;
    struct memblock mem_46714;
    struct memblock mem_46726;
    struct memblock mem_46738;
    struct memblock mem_46750;
    struct memblock mem_46762;
    struct memblock mem_46774;
    struct memblock mem_46786;
    struct memblock mem_46798;
    struct memblock mem_46810;
};
struct tuning_params { };
static const int num_tuning_params = 0;
static const char *tuning_param_names[] = {NULL};
static const char *tuning_param_vars[] = {NULL};
static const char *tuning_param_classes[] = {NULL};
static int64_t tuning_param_defaults[] = {0};
// Start of backends/c.h

struct futhark_context_config {
  int in_use;
  int debugging;
  int profiling;
  int logging;
  const char *cache_fname;
  int num_tuning_params;
  int64_t *tuning_params;
  const char** tuning_param_names;
  const char** tuning_param_vars;
  const char** tuning_param_classes;
};

static void backend_context_config_setup(struct futhark_context_config* cfg) {
  (void)cfg;
}

static void backend_context_config_teardown(struct futhark_context_config* cfg) {
  (void)cfg;
}

int futhark_context_config_set_tuning_param(struct futhark_context_config* cfg, const char *param_name, size_t param_value) {
  (void)cfg; (void)param_name; (void)param_value;
  return 1;
}

struct futhark_context {
  struct futhark_context_config* cfg;
  int detail_memory;
  int debugging;
  int profiling;
  int profiling_paused;
  int logging;
  lock_t lock;
  char *error;
  lock_t error_lock;
  FILE *log;
  struct constants *constants;
  struct free_list free_list;
  int64_t peak_mem_usage_default;
  int64_t cur_mem_usage_default;
  struct program* program;
};

int backend_context_setup(struct futhark_context* ctx) {
  (void)ctx;
  return 0;
}

void backend_context_teardown(struct futhark_context* ctx) {
  (void)ctx;
}

int futhark_context_sync(struct futhark_context* ctx) {
  (void)ctx;
  return 0;
}

// End of backends/c.h

struct program { };
static void setup_program(struct futhark_context *ctx)
{
    (void) ctx;
    
    int error = 0;
    
    (void) error;
    ctx->program = malloc(sizeof(struct program));
}
static void teardown_program(struct futhark_context *ctx)
{
    (void) ctx;
    
    int error = 0;
    
    (void) error;
    free(ctx->program);
}
static void set_tuning_params(struct futhark_context *ctx)
{
    (void) ctx;
}
int memblock_unref(struct futhark_context *ctx, struct memblock *block, const char *desc)
{
    if (block->references != NULL) {
        *block->references -= 1;
        if (ctx->detail_memory)
            fprintf(ctx->log, "Unreferencing block %s (allocated as %s) in %s: %d references remaining.\n", desc, block->desc, "default space", *block->references);
        if (*block->references == 0) {
            ctx->cur_mem_usage_default -= block->size;
            host_free(ctx, (size_t) block->size, desc, (void *) block->mem);
            free(block->references);
            if (ctx->detail_memory)
                fprintf(ctx->log, "%lld bytes freed (now allocated: %lld bytes)\n", (long long) block->size, (long long) ctx->cur_mem_usage_default);
        }
        block->references = NULL;
    }
    return 0;
}
int memblock_alloc(struct futhark_context *ctx, struct memblock *block, int64_t size, const char *desc)
{
    if (size < 0)
        futhark_panic(1, "Negative allocation of %lld bytes attempted for %s in %s.\n", (long long) size, desc, "default space", ctx->cur_mem_usage_default);
    
    int ret = memblock_unref(ctx, block, desc);
    
    if (ret != FUTHARK_SUCCESS)
        return ret;
    if (ctx->detail_memory)
        fprintf(ctx->log, "Allocating %lld bytes for %s in %s (then allocated: %lld bytes)", (long long) size, desc, "default space", (long long) ctx->cur_mem_usage_default + size);
    if (ctx->cur_mem_usage_default > ctx->peak_mem_usage_default) {
        ctx->peak_mem_usage_default = ctx->cur_mem_usage_default;
        if (ctx->detail_memory)
            fprintf(ctx->log, " (new peak).\n");
    } else if (ctx->detail_memory)
        fprintf(ctx->log, ".\n");
    host_alloc(ctx, (size_t) size, desc, (size_t *) &size, (void *) &block->mem);
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
        
        ctx->error = msgprintf("Failed to allocate memory in %s.\nAttempted allocation: %12lld bytes\nCurrently allocated:  %12lld bytes\n%s", "default space", (long long) size, (long long) ctx->cur_mem_usage_default, old_error);
        free(old_error);
        lock_unlock(&ctx->error_lock);
        return FUTHARK_OUT_OF_MEMORY;
    }
}
int memblock_set(struct futhark_context *ctx, struct memblock *lhs, struct memblock *rhs, const char *lhs_desc)
{
    int ret = memblock_unref(ctx, lhs, lhs_desc);
    
    if (rhs->references != NULL)
        (*rhs->references)++;
    *lhs = *rhs;
    return ret;
}
void futhark_context_config_set_debugging(struct futhark_context_config *cfg, int flag)
{
    cfg->profiling = cfg->logging = cfg->debugging = flag;
}
void futhark_context_config_set_profiling(struct futhark_context_config *cfg, int flag)
{
    cfg->profiling = flag;
}
void futhark_context_config_set_logging(struct futhark_context_config *cfg, int flag)
{
    cfg->logging = flag;
}
void futhark_context_config_set_cache_file(struct futhark_context_config *cfg, const char *f)
{
    cfg->cache_fname = f;
}
int futhark_get_tuning_param_count(void)
{
    return num_tuning_params;
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

static void free_all_in_free_list(struct futhark_context* ctx) {
  fl_mem mem;
  free_list_pack(&ctx->free_list);
  while (free_list_first(&ctx->free_list, (fl_mem*)&mem) == 0) {
    free((void*)mem);
  }
}

static int is_small_alloc(size_t size) {
  return size < 1024*1024;
}

static void host_alloc(struct futhark_context* ctx,
                       size_t size, const char* tag, size_t* size_out, void** mem_out) {
  if (is_small_alloc(size) || free_list_find(&ctx->free_list, size, tag, size_out, (fl_mem*)mem_out) != 0) {
    *size_out = size;
    *mem_out = malloc(size);
  }
}

static void host_free(struct futhark_context* ctx,
                      size_t size, const char* tag, void* mem) {
  // Small allocations are handled by malloc()s own free list.  The
  // threshold here is kind of arbitrary, but seems to work OK.
  // Larger allocations are mmap()ed/munmapped() every time, which is
  // very slow, and Futhark programs tend to use a few very large
  // allocations.
  if (is_small_alloc(size)) {
    free(mem);
  } else {
    free_list_insert(&ctx->free_list, size, (fl_mem)mem, tag);
  }
}

struct futhark_context_config* futhark_context_config_new(void) {
  struct futhark_context_config* cfg = malloc(sizeof(struct futhark_context_config));
  if (cfg == NULL) {
    return NULL;
  }
  cfg->in_use = 0;
  cfg->debugging = 0;
  cfg->profiling = 0;
  cfg->logging = 0;
  cfg->cache_fname = NULL;
  cfg->num_tuning_params = num_tuning_params;
  cfg->tuning_params = malloc(cfg->num_tuning_params * sizeof(int64_t));
  memcpy(cfg->tuning_params, tuning_param_defaults,
         cfg->num_tuning_params * sizeof(int64_t));
  cfg->tuning_param_names = tuning_param_names;
  cfg->tuning_param_vars = tuning_param_vars;
  cfg->tuning_param_classes = tuning_param_classes;
  backend_context_config_setup(cfg);
  return cfg;
}

void futhark_context_config_free(struct futhark_context_config* cfg) {
  assert(!cfg->in_use);
  backend_context_config_teardown(cfg);
  free(cfg->tuning_params);
  free(cfg);
}

struct futhark_context* futhark_context_new(struct futhark_context_config* cfg) {
  struct futhark_context* ctx = malloc(sizeof(struct futhark_context));
  if (ctx == NULL) {
    return NULL;
  }
  assert(!cfg->in_use);
  ctx->cfg = cfg;
  ctx->cfg->in_use = 1;
  create_lock(&ctx->error_lock);
  create_lock(&ctx->lock);
  free_list_init(&ctx->free_list);
  ctx->peak_mem_usage_default = 0;
  ctx->cur_mem_usage_default = 0;
  ctx->constants = malloc(sizeof(struct constants));
  ctx->detail_memory = cfg->debugging;
  ctx->debugging = cfg->debugging;
  ctx->logging = cfg->logging;
  ctx->profiling = cfg->profiling;
  ctx->profiling_paused = 0;
  ctx->error = NULL;
  ctx->log = stderr;
  if (backend_context_setup(ctx) == 0) {
    set_tuning_params(ctx);
    setup_program(ctx);
    init_constants(ctx);
    (void)futhark_context_clear_caches(ctx);
    (void)futhark_context_sync(ctx);
  }
  return ctx;
}

void futhark_context_free(struct futhark_context* ctx) {
  free_constants(ctx);
  teardown_program(ctx);
  backend_context_teardown(ctx);
  free_all_in_free_list(ctx);
  free_list_destroy(&ctx->free_list);
  free(ctx->constants);
  free_lock(&ctx->lock);
  free_lock(&ctx->error_lock);
  ctx->cfg->in_use = 0;
  free(ctx);
}

// End of context.h

static int futrts_entry_bench_cnn(struct futhark_context *ctx, struct memblock *mem_out_p_48540, int64_t *out_prim_out_48541, struct memblock x_train_mem_46821, struct memblock y_train_mem_46822, int64_t l_37763, int64_t m_37764, int64_t n_37765, int64_t epochs_37768);
static int futrts_entry_bench_cnn_futhark_ad(struct futhark_context *ctx, struct memblock *mem_out_p_48543, struct memblock *mem_out_p_48544, struct memblock *mem_out_p_48545, struct memblock *mem_out_p_48546, struct memblock *mem_out_p_48547, struct memblock *mem_out_p_48548, struct memblock *mem_out_p_48549, struct memblock *mem_out_p_48550, struct memblock *mem_out_p_48551, struct memblock *mem_out_p_48552, struct memblock x_train_mem_46821, struct memblock y_train_mem_46822, int64_t l_38230, int64_t m_38231, int64_t n_38232, int64_t epochs_38235);
static int futrts_entry_test_cnn_futhark_ad(struct futhark_context *ctx, struct memblock *mem_out_p_48591, struct memblock x_train_mem_46821, struct memblock y_train_mem_46822, int64_t l_31478, int64_t m_31479, int64_t n_31480);

static int init_constants(struct futhark_context *ctx)
{
    (void) ctx;
    
    int err = 0;
    
    #define mem_46702 (ctx->constants->mem_46702)
    #define mem_46714 (ctx->constants->mem_46714)
    #define mem_46726 (ctx->constants->mem_46726)
    #define mem_46738 (ctx->constants->mem_46738)
    #define mem_46750 (ctx->constants->mem_46750)
    #define mem_46762 (ctx->constants->mem_46762)
    #define mem_46774 (ctx->constants->mem_46774)
    #define mem_46786 (ctx->constants->mem_46786)
    #define mem_46798 (ctx->constants->mem_46798)
    #define mem_46810 (ctx->constants->mem_46810)
    
    struct memblock mem_46650;
    
    mem_46650.references = NULL;
    
    struct memblock mem_46648;
    
    mem_46648.references = NULL;
    
    struct memblock mem_46646;
    
    mem_46646.references = NULL;
    
    struct memblock mem_46644;
    
    mem_46644.references = NULL;
    
    struct memblock mem_46642;
    
    mem_46642.references = NULL;
    
    struct memblock mem_46630;
    
    mem_46630.references = NULL;
    mem_46702.references = NULL;
    mem_46714.references = NULL;
    mem_46726.references = NULL;
    mem_46738.references = NULL;
    mem_46750.references = NULL;
    mem_46762.references = NULL;
    mem_46774.references = NULL;
    mem_46786.references = NULL;
    mem_46798.references = NULL;
    mem_46810.references = NULL;
    if (memblock_alloc(ctx, &mem_46630, (int64_t) 20, "mem_46630")) {
        err = 1;
        goto cleanup;
    }
    for (int64_t i_45379 = 0; i_45379 < (int64_t) 5; i_45379++) {
        int32_t i64_res_42878 = sext_i64_i32(i_45379);
        int32_t arg_42879 = lshr32(i64_res_42878, 16);
        int32_t arg_42880 = i64_res_42878 ^ arg_42879;
        int32_t x_42881 = mul32(73244475, arg_42880);
        int32_t arg_42882 = lshr32(x_42881, 16);
        int32_t arg_42883 = x_42881 ^ arg_42882;
        int32_t x_42884 = mul32(73244475, arg_42883);
        int32_t arg_42885 = lshr32(x_42884, 16);
        int32_t x_42886 = x_42884 ^ arg_42885;
        int32_t unsign_arg_42887 = 1822209471 ^ x_42886;
        int32_t unsign_arg_42889 = mul32(48271, unsign_arg_42887);
        int32_t unsign_arg_42890 = umod32(unsign_arg_42889, 2147483647);
        bool zgze_res_42891 = ule32(2147000000, unsign_arg_42890);
        bool defunc_0_f_res_f_res_42892;
        int32_t defunc_0_f_res_f_res_42893;
        int32_t defunc_0_f_res_f_res_42894;
        bool loop_while_42895;
        int32_t rng_42896;
        int32_t x_42897;
        
        loop_while_42895 = zgze_res_42891;
        rng_42896 = unsign_arg_42890;
        x_42897 = unsign_arg_42890;
        while (loop_while_42895) {
            int32_t unsign_arg_42898 = mul32(48271, rng_42896);
            int32_t unsign_arg_42899 = umod32(unsign_arg_42898, 2147483647);
            bool zgze_res_42900 = ule32(2147000000, unsign_arg_42899);
            bool loop_while_tmp_48507 = zgze_res_42900;
            int32_t rng_tmp_48508 = unsign_arg_42899;
            int32_t x_tmp_48509 = unsign_arg_42899;
            
            loop_while_42895 = loop_while_tmp_48507;
            rng_42896 = rng_tmp_48508;
            x_42897 = x_tmp_48509;
        }
        defunc_0_f_res_f_res_42892 = loop_while_42895;
        defunc_0_f_res_f_res_42893 = rng_42896;
        defunc_0_f_res_f_res_42894 = x_42897;
        
        int32_t unsign_arg_42901 = umod32(defunc_0_f_res_f_res_42894, 1000000);
        int64_t to_i64_res_42902 = zext_i32_i64(unsign_arg_42901);
        int32_t defunc_0_f_res_42904 = sext_i64_i32(to_i64_res_42902);
        
        ((int32_t *) mem_46630.mem)[i_45379] = defunc_0_f_res_42904;
    }
    
    int32_t mk_conv_wandb_arg_38274 = ((int32_t *) mem_46630.mem)[(int64_t) 0];
    int32_t unsign_arg_41866 = 5460 ^ mk_conv_wandb_arg_38274;
    int32_t unsign_arg_41867 = mul32(48271, unsign_arg_41866);
    int32_t unsign_arg_41868 = umod32(unsign_arg_41867, 2147483647);
    int32_t unsign_arg_41869 = mul32(48271, unsign_arg_41868);
    int32_t unsign_arg_41870 = umod32(unsign_arg_41869, 2147483647);
    int32_t mk_dense_wandb_arg_38286 = ((int32_t *) mem_46630.mem)[(int64_t) 4];
    int32_t unsign_arg_42316 = 5460 ^ mk_dense_wandb_arg_38286;
    int32_t unsign_arg_42317 = mul32(48271, unsign_arg_42316);
    int32_t unsign_arg_42318 = umod32(unsign_arg_42317, 2147483647);
    int32_t unsign_arg_42319 = mul32(48271, unsign_arg_42318);
    int32_t unsign_arg_42320 = umod32(unsign_arg_42319, 2147483647);
    int32_t mk_dense_wandb_arg_38283 = ((int32_t *) mem_46630.mem)[(int64_t) 3];
    int32_t unsign_arg_42207 = 5460 ^ mk_dense_wandb_arg_38283;
    int32_t unsign_arg_42208 = mul32(48271, unsign_arg_42207);
    int32_t unsign_arg_42209 = umod32(unsign_arg_42208, 2147483647);
    int32_t unsign_arg_42210 = mul32(48271, unsign_arg_42209);
    int32_t unsign_arg_42211 = umod32(unsign_arg_42210, 2147483647);
    int32_t mk_dense_wandb_arg_38280 = ((int32_t *) mem_46630.mem)[(int64_t) 2];
    int32_t unsign_arg_42098 = 5460 ^ mk_dense_wandb_arg_38280;
    int32_t unsign_arg_42099 = mul32(48271, unsign_arg_42098);
    int32_t unsign_arg_42100 = umod32(unsign_arg_42099, 2147483647);
    int32_t unsign_arg_42101 = mul32(48271, unsign_arg_42100);
    int32_t unsign_arg_42102 = umod32(unsign_arg_42101, 2147483647);
    int32_t mk_conv_wandb_arg_38277 = ((int32_t *) mem_46630.mem)[(int64_t) 1];
    
    if (memblock_unref(ctx, &mem_46630, "mem_46630") != 0)
        return 1;
    
    int32_t unsign_arg_41983 = 5460 ^ mk_conv_wandb_arg_38277;
    int32_t unsign_arg_41984 = mul32(48271, unsign_arg_41983);
    int32_t unsign_arg_41985 = umod32(unsign_arg_41984, 2147483647);
    int32_t unsign_arg_41986 = mul32(48271, unsign_arg_41985);
    int32_t unsign_arg_41987 = umod32(unsign_arg_41986, 2147483647);
    
    if (memblock_alloc(ctx, &mem_46642, (int64_t) 8, "mem_46642")) {
        err = 1;
        goto cleanup;
    }
    if (memblock_alloc(ctx, &mem_46644, (int64_t) 8, "mem_46644")) {
        err = 1;
        goto cleanup;
    }
    if (memblock_alloc(ctx, &mem_46646, (int64_t) 8, "mem_46646")) {
        err = 1;
        goto cleanup;
    }
    if (memblock_alloc(ctx, &mem_46648, (int64_t) 8, "mem_46648")) {
        err = 1;
        goto cleanup;
    }
    if (memblock_alloc(ctx, &mem_46650, (int64_t) 8, "mem_46650")) {
        err = 1;
        goto cleanup;
    }
    for (int64_t i_45391 = 0; i_45391 < (int64_t) 2; i_45391++) {
        int32_t i64_res_43182 = sext_i64_i32(i_45391);
        int32_t arg_43183 = lshr32(i64_res_43182, 16);
        int32_t arg_43184 = i64_res_43182 ^ arg_43183;
        int32_t x_43185 = mul32(73244475, arg_43184);
        int32_t arg_43186 = lshr32(x_43185, 16);
        int32_t arg_43187 = x_43185 ^ arg_43186;
        int32_t x_43188 = mul32(73244475, arg_43187);
        int32_t arg_43189 = lshr32(x_43188, 16);
        int32_t x_43190 = x_43188 ^ arg_43189;
        int32_t unsign_arg_43191 = unsign_arg_41870 ^ x_43190;
        int32_t unsign_arg_43193 = mul32(48271, unsign_arg_43191);
        int32_t unsign_arg_43194 = umod32(unsign_arg_43193, 2147483647);
        bool zgze_res_43195 = ule32(2147000000, unsign_arg_43194);
        bool defunc_0_f_res_f_res_43196;
        int32_t defunc_0_f_res_f_res_43197;
        int32_t defunc_0_f_res_f_res_43198;
        bool loop_while_43199;
        int32_t rng_43200;
        int32_t x_43201;
        
        loop_while_43199 = zgze_res_43195;
        rng_43200 = unsign_arg_43194;
        x_43201 = unsign_arg_43194;
        while (loop_while_43199) {
            int32_t unsign_arg_43202 = mul32(48271, rng_43200);
            int32_t unsign_arg_43203 = umod32(unsign_arg_43202, 2147483647);
            bool zgze_res_43204 = ule32(2147000000, unsign_arg_43203);
            bool loop_while_tmp_48515 = zgze_res_43204;
            int32_t rng_tmp_48516 = unsign_arg_43203;
            int32_t x_tmp_48517 = unsign_arg_43203;
            
            loop_while_43199 = loop_while_tmp_48515;
            rng_43200 = rng_tmp_48516;
            x_43201 = x_tmp_48517;
        }
        defunc_0_f_res_f_res_43196 = loop_while_43199;
        defunc_0_f_res_f_res_43197 = rng_43200;
        defunc_0_f_res_f_res_43198 = x_43201;
        
        int32_t unsign_arg_43205 = umod32(defunc_0_f_res_f_res_43198, 1000000);
        int64_t to_i64_res_43206 = zext_i32_i64(unsign_arg_43205);
        int32_t defunc_0_f_res_43208 = sext_i64_i32(to_i64_res_43206);
        int32_t unsign_arg_43219 = unsign_arg_41987 ^ x_43190;
        int32_t unsign_arg_43221 = mul32(48271, unsign_arg_43219);
        int32_t unsign_arg_43222 = umod32(unsign_arg_43221, 2147483647);
        bool zgze_res_43223 = ule32(2147000000, unsign_arg_43222);
        bool defunc_0_f_res_f_res_43224;
        int32_t defunc_0_f_res_f_res_43225;
        int32_t defunc_0_f_res_f_res_43226;
        bool loop_while_43227;
        int32_t rng_43228;
        int32_t x_43229;
        
        loop_while_43227 = zgze_res_43223;
        rng_43228 = unsign_arg_43222;
        x_43229 = unsign_arg_43222;
        while (loop_while_43227) {
            int32_t unsign_arg_43230 = mul32(48271, rng_43228);
            int32_t unsign_arg_43231 = umod32(unsign_arg_43230, 2147483647);
            bool zgze_res_43232 = ule32(2147000000, unsign_arg_43231);
            bool loop_while_tmp_48518 = zgze_res_43232;
            int32_t rng_tmp_48519 = unsign_arg_43231;
            int32_t x_tmp_48520 = unsign_arg_43231;
            
            loop_while_43227 = loop_while_tmp_48518;
            rng_43228 = rng_tmp_48519;
            x_43229 = x_tmp_48520;
        }
        defunc_0_f_res_f_res_43224 = loop_while_43227;
        defunc_0_f_res_f_res_43225 = rng_43228;
        defunc_0_f_res_f_res_43226 = x_43229;
        
        int32_t unsign_arg_43233 = umod32(defunc_0_f_res_f_res_43226, 1000000);
        int64_t to_i64_res_43234 = zext_i32_i64(unsign_arg_43233);
        int32_t defunc_0_f_res_43236 = sext_i64_i32(to_i64_res_43234);
        int32_t unsign_arg_43248 = unsign_arg_42102 ^ x_43190;
        int32_t unsign_arg_43250 = mul32(48271, unsign_arg_43248);
        int32_t unsign_arg_43251 = umod32(unsign_arg_43250, 2147483647);
        bool zgze_res_43252 = ule32(2147000000, unsign_arg_43251);
        bool defunc_0_f_res_f_res_43253;
        int32_t defunc_0_f_res_f_res_43254;
        int32_t defunc_0_f_res_f_res_43255;
        bool loop_while_43256;
        int32_t rng_43257;
        int32_t x_43258;
        
        loop_while_43256 = zgze_res_43252;
        rng_43257 = unsign_arg_43251;
        x_43258 = unsign_arg_43251;
        while (loop_while_43256) {
            int32_t unsign_arg_43259 = mul32(48271, rng_43257);
            int32_t unsign_arg_43260 = umod32(unsign_arg_43259, 2147483647);
            bool zgze_res_43261 = ule32(2147000000, unsign_arg_43260);
            bool loop_while_tmp_48521 = zgze_res_43261;
            int32_t rng_tmp_48522 = unsign_arg_43260;
            int32_t x_tmp_48523 = unsign_arg_43260;
            
            loop_while_43256 = loop_while_tmp_48521;
            rng_43257 = rng_tmp_48522;
            x_43258 = x_tmp_48523;
        }
        defunc_0_f_res_f_res_43253 = loop_while_43256;
        defunc_0_f_res_f_res_43254 = rng_43257;
        defunc_0_f_res_f_res_43255 = x_43258;
        
        int32_t unsign_arg_43262 = umod32(defunc_0_f_res_f_res_43255, 1000000);
        int64_t to_i64_res_43263 = zext_i32_i64(unsign_arg_43262);
        int32_t defunc_0_f_res_43265 = sext_i64_i32(to_i64_res_43263);
        int32_t unsign_arg_43278 = unsign_arg_42211 ^ x_43190;
        int32_t unsign_arg_43280 = mul32(48271, unsign_arg_43278);
        int32_t unsign_arg_43281 = umod32(unsign_arg_43280, 2147483647);
        bool zgze_res_43282 = ule32(2147000000, unsign_arg_43281);
        bool defunc_0_f_res_f_res_43283;
        int32_t defunc_0_f_res_f_res_43284;
        int32_t defunc_0_f_res_f_res_43285;
        bool loop_while_43286;
        int32_t rng_43287;
        int32_t x_43288;
        
        loop_while_43286 = zgze_res_43282;
        rng_43287 = unsign_arg_43281;
        x_43288 = unsign_arg_43281;
        while (loop_while_43286) {
            int32_t unsign_arg_43289 = mul32(48271, rng_43287);
            int32_t unsign_arg_43290 = umod32(unsign_arg_43289, 2147483647);
            bool zgze_res_43291 = ule32(2147000000, unsign_arg_43290);
            bool loop_while_tmp_48524 = zgze_res_43291;
            int32_t rng_tmp_48525 = unsign_arg_43290;
            int32_t x_tmp_48526 = unsign_arg_43290;
            
            loop_while_43286 = loop_while_tmp_48524;
            rng_43287 = rng_tmp_48525;
            x_43288 = x_tmp_48526;
        }
        defunc_0_f_res_f_res_43283 = loop_while_43286;
        defunc_0_f_res_f_res_43284 = rng_43287;
        defunc_0_f_res_f_res_43285 = x_43288;
        
        int32_t unsign_arg_43292 = umod32(defunc_0_f_res_f_res_43285, 1000000);
        int64_t to_i64_res_43293 = zext_i32_i64(unsign_arg_43292);
        int32_t defunc_0_f_res_43295 = sext_i64_i32(to_i64_res_43293);
        int32_t unsign_arg_43309 = unsign_arg_42320 ^ x_43190;
        int32_t unsign_arg_43311 = mul32(48271, unsign_arg_43309);
        int32_t unsign_arg_43312 = umod32(unsign_arg_43311, 2147483647);
        bool zgze_res_43313 = ule32(2147000000, unsign_arg_43312);
        bool defunc_0_f_res_f_res_43314;
        int32_t defunc_0_f_res_f_res_43315;
        int32_t defunc_0_f_res_f_res_43316;
        bool loop_while_43317;
        int32_t rng_43318;
        int32_t x_43319;
        
        loop_while_43317 = zgze_res_43313;
        rng_43318 = unsign_arg_43312;
        x_43319 = unsign_arg_43312;
        while (loop_while_43317) {
            int32_t unsign_arg_43320 = mul32(48271, rng_43318);
            int32_t unsign_arg_43321 = umod32(unsign_arg_43320, 2147483647);
            bool zgze_res_43322 = ule32(2147000000, unsign_arg_43321);
            bool loop_while_tmp_48527 = zgze_res_43322;
            int32_t rng_tmp_48528 = unsign_arg_43321;
            int32_t x_tmp_48529 = unsign_arg_43321;
            
            loop_while_43317 = loop_while_tmp_48527;
            rng_43318 = rng_tmp_48528;
            x_43319 = x_tmp_48529;
        }
        defunc_0_f_res_f_res_43314 = loop_while_43317;
        defunc_0_f_res_f_res_43315 = rng_43318;
        defunc_0_f_res_f_res_43316 = x_43319;
        
        int32_t unsign_arg_43323 = umod32(defunc_0_f_res_f_res_43316, 1000000);
        int64_t to_i64_res_43324 = zext_i32_i64(unsign_arg_43323);
        int32_t defunc_0_f_res_43326 = sext_i64_i32(to_i64_res_43324);
        
        ((int32_t *) mem_46642.mem)[i_45391] = defunc_0_f_res_43326;
        ((int32_t *) mem_46644.mem)[i_45391] = defunc_0_f_res_43295;
        ((int32_t *) mem_46646.mem)[i_45391] = defunc_0_f_res_43265;
        ((int32_t *) mem_46648.mem)[i_45391] = defunc_0_f_res_43236;
        ((int32_t *) mem_46650.mem)[i_45391] = defunc_0_f_res_43208;
    }
    
    int32_t mk_conv_weights_arg_41906 = ((int32_t *) mem_46650.mem)[(int64_t) 0];
    int32_t unsign_arg_41911 = 5460 ^ mk_conv_weights_arg_41906;
    int32_t unsign_arg_41912 = mul32(48271, unsign_arg_41911);
    int32_t unsign_arg_41913 = umod32(unsign_arg_41912, 2147483647);
    int32_t unsign_arg_41917 = mul32(48271, unsign_arg_41913);
    int32_t unsign_arg_41918 = umod32(unsign_arg_41917, 2147483647);
    
    if (memblock_alloc(ctx, &mem_46702, (int64_t) 1200, "mem_46702")) {
        err = 1;
        goto cleanup;
    }
    for (int64_t i_45399 = 0; i_45399 < (int64_t) 150; i_45399++) {
        int32_t i64_res_42794 = sext_i64_i32(i_45399);
        int32_t arg_42795 = lshr32(i64_res_42794, 16);
        int32_t arg_42796 = i64_res_42794 ^ arg_42795;
        int32_t x_42797 = mul32(73244475, arg_42796);
        int32_t arg_42798 = lshr32(x_42797, 16);
        int32_t arg_42799 = x_42797 ^ arg_42798;
        int32_t x_42800 = mul32(73244475, arg_42799);
        int32_t arg_42801 = lshr32(x_42800, 16);
        int32_t x_42802 = x_42800 ^ arg_42801;
        int32_t unsign_arg_42803 = unsign_arg_41918 ^ x_42802;
        int32_t unsign_arg_42805 = mul32(48271, unsign_arg_42803);
        int32_t unsign_arg_42806 = umod32(unsign_arg_42805, 2147483647);
        double u64_res_42807 = uitofp_i32_f64(unsign_arg_42806);
        double zs_res_42808 = u64_res_42807 / 2.147483647e9;
        double zt_res_42809 = 0.4 * zs_res_42808;
        double zp_res_42810 = -0.2 + zt_res_42809;
        
        ((double *) mem_46702.mem)[i_45399] = zp_res_42810;
    }
    
    int32_t mk_conv_biases_arg_41951 = ((int32_t *) mem_46650.mem)[(int64_t) 1];
    
    if (memblock_unref(ctx, &mem_46650, "mem_46650") != 0)
        return 1;
    
    int32_t unsign_arg_41952 = 5460 ^ mk_conv_biases_arg_41951;
    int32_t unsign_arg_41953 = mul32(48271, unsign_arg_41952);
    int32_t unsign_arg_41954 = umod32(unsign_arg_41953, 2147483647);
    int32_t unsign_arg_41955 = mul32(48271, unsign_arg_41954);
    int32_t unsign_arg_41956 = umod32(unsign_arg_41955, 2147483647);
    
    if (memblock_alloc(ctx, &mem_46714, (int64_t) 48, "mem_46714")) {
        err = 1;
        goto cleanup;
    }
    for (int64_t i_45403 = 0; i_45403 < (int64_t) 6; i_45403++) {
        int32_t i64_res_42775 = sext_i64_i32(i_45403);
        int32_t arg_42776 = lshr32(i64_res_42775, 16);
        int32_t arg_42777 = i64_res_42775 ^ arg_42776;
        int32_t x_42778 = mul32(73244475, arg_42777);
        int32_t arg_42779 = lshr32(x_42778, 16);
        int32_t arg_42780 = x_42778 ^ arg_42779;
        int32_t x_42781 = mul32(73244475, arg_42780);
        int32_t arg_42782 = lshr32(x_42781, 16);
        int32_t x_42783 = x_42781 ^ arg_42782;
        int32_t unsign_arg_42784 = unsign_arg_41956 ^ x_42783;
        int32_t unsign_arg_42786 = mul32(48271, unsign_arg_42784);
        int32_t unsign_arg_42787 = umod32(unsign_arg_42786, 2147483647);
        double u64_res_42788 = uitofp_i32_f64(unsign_arg_42787);
        double zs_res_42789 = u64_res_42788 / 2.147483647e9;
        double zt_res_42790 = 0.4 * zs_res_42789;
        double zp_res_42791 = -0.2 + zt_res_42790;
        
        ((double *) mem_46714.mem)[i_45403] = zp_res_42791;
    }
    
    int32_t mk_conv_weights_arg_42023 = ((int32_t *) mem_46648.mem)[(int64_t) 0];
    int32_t unsign_arg_42028 = 5460 ^ mk_conv_weights_arg_42023;
    int32_t unsign_arg_42029 = mul32(48271, unsign_arg_42028);
    int32_t unsign_arg_42030 = umod32(unsign_arg_42029, 2147483647);
    int32_t unsign_arg_42034 = mul32(48271, unsign_arg_42030);
    int32_t unsign_arg_42035 = umod32(unsign_arg_42034, 2147483647);
    
    if (memblock_alloc(ctx, &mem_46726, (int64_t) 19200, "mem_46726")) {
        err = 1;
        goto cleanup;
    }
    for (int64_t i_45407 = 0; i_45407 < (int64_t) 2400; i_45407++) {
        int32_t i64_res_42709 = sext_i64_i32(i_45407);
        int32_t arg_42710 = lshr32(i64_res_42709, 16);
        int32_t arg_42711 = i64_res_42709 ^ arg_42710;
        int32_t x_42712 = mul32(73244475, arg_42711);
        int32_t arg_42713 = lshr32(x_42712, 16);
        int32_t arg_42714 = x_42712 ^ arg_42713;
        int32_t x_42715 = mul32(73244475, arg_42714);
        int32_t arg_42716 = lshr32(x_42715, 16);
        int32_t x_42717 = x_42715 ^ arg_42716;
        int32_t unsign_arg_42718 = unsign_arg_42035 ^ x_42717;
        int32_t unsign_arg_42720 = mul32(48271, unsign_arg_42718);
        int32_t unsign_arg_42721 = umod32(unsign_arg_42720, 2147483647);
        double u64_res_42722 = uitofp_i32_f64(unsign_arg_42721);
        double zs_res_42723 = u64_res_42722 / 2.147483647e9;
        double zt_res_42724 = 0.16329931618554522 * zs_res_42723;
        double zp_res_42725 = -8.164965809277261e-2 + zt_res_42724;
        
        ((double *) mem_46726.mem)[i_45407] = zp_res_42725;
    }
    
    int32_t mk_conv_biases_arg_42068 = ((int32_t *) mem_46648.mem)[(int64_t) 1];
    
    if (memblock_unref(ctx, &mem_46648, "mem_46648") != 0)
        return 1;
    
    int32_t unsign_arg_42069 = 5460 ^ mk_conv_biases_arg_42068;
    int32_t unsign_arg_42070 = mul32(48271, unsign_arg_42069);
    int32_t unsign_arg_42071 = umod32(unsign_arg_42070, 2147483647);
    int32_t unsign_arg_42072 = mul32(48271, unsign_arg_42071);
    int32_t unsign_arg_42073 = umod32(unsign_arg_42072, 2147483647);
    
    if (memblock_alloc(ctx, &mem_46738, (int64_t) 128, "mem_46738")) {
        err = 1;
        goto cleanup;
    }
    for (int64_t i_45411 = 0; i_45411 < (int64_t) 16; i_45411++) {
        int32_t i64_res_42690 = sext_i64_i32(i_45411);
        int32_t arg_42691 = lshr32(i64_res_42690, 16);
        int32_t arg_42692 = i64_res_42690 ^ arg_42691;
        int32_t x_42693 = mul32(73244475, arg_42692);
        int32_t arg_42694 = lshr32(x_42693, 16);
        int32_t arg_42695 = x_42693 ^ arg_42694;
        int32_t x_42696 = mul32(73244475, arg_42695);
        int32_t arg_42697 = lshr32(x_42696, 16);
        int32_t x_42698 = x_42696 ^ arg_42697;
        int32_t unsign_arg_42699 = unsign_arg_42073 ^ x_42698;
        int32_t unsign_arg_42701 = mul32(48271, unsign_arg_42699);
        int32_t unsign_arg_42702 = umod32(unsign_arg_42701, 2147483647);
        double u64_res_42703 = uitofp_i32_f64(unsign_arg_42702);
        double zs_res_42704 = u64_res_42703 / 2.147483647e9;
        double zt_res_42705 = 0.16329931618554522 * zs_res_42704;
        double zp_res_42706 = -8.164965809277261e-2 + zt_res_42705;
        
        ((double *) mem_46738.mem)[i_45411] = zp_res_42706;
    }
    
    int32_t mk_dense_weights_arg_42138 = ((int32_t *) mem_46646.mem)[(int64_t) 0];
    int32_t unsign_arg_42141 = 5460 ^ mk_dense_weights_arg_42138;
    int32_t unsign_arg_42142 = mul32(48271, unsign_arg_42141);
    int32_t unsign_arg_42143 = umod32(unsign_arg_42142, 2147483647);
    int32_t unsign_arg_42145 = mul32(48271, unsign_arg_42143);
    int32_t unsign_arg_42146 = umod32(unsign_arg_42145, 2147483647);
    
    if (memblock_alloc(ctx, &mem_46750, (int64_t) 384000, "mem_46750")) {
        err = 1;
        goto cleanup;
    }
    for (int64_t i_45415 = 0; i_45415 < (int64_t) 48000; i_45415++) {
        int32_t i64_res_42624 = sext_i64_i32(i_45415);
        int32_t arg_42625 = lshr32(i64_res_42624, 16);
        int32_t arg_42626 = i64_res_42624 ^ arg_42625;
        int32_t x_42627 = mul32(73244475, arg_42626);
        int32_t arg_42628 = lshr32(x_42627, 16);
        int32_t arg_42629 = x_42627 ^ arg_42628;
        int32_t x_42630 = mul32(73244475, arg_42629);
        int32_t arg_42631 = lshr32(x_42630, 16);
        int32_t x_42632 = x_42630 ^ arg_42631;
        int32_t unsign_arg_42633 = unsign_arg_42146 ^ x_42632;
        int32_t unsign_arg_42635 = mul32(48271, unsign_arg_42633);
        int32_t unsign_arg_42636 = umod32(unsign_arg_42635, 2147483647);
        double u64_res_42637 = uitofp_i32_f64(unsign_arg_42636);
        double zs_res_42638 = u64_res_42637 / 2.147483647e9;
        double zt_res_42639 = 0.1 * zs_res_42638;
        double zp_res_42640 = -5.0e-2 + zt_res_42639;
        
        ((double *) mem_46750.mem)[i_45415] = zp_res_42640;
    }
    
    int32_t mk_dense_biases_arg_42177 = ((int32_t *) mem_46646.mem)[(int64_t) 1];
    
    if (memblock_unref(ctx, &mem_46646, "mem_46646") != 0)
        return 1;
    
    int32_t unsign_arg_42178 = 5460 ^ mk_dense_biases_arg_42177;
    int32_t unsign_arg_42179 = mul32(48271, unsign_arg_42178);
    int32_t unsign_arg_42180 = umod32(unsign_arg_42179, 2147483647);
    int32_t unsign_arg_42181 = mul32(48271, unsign_arg_42180);
    int32_t unsign_arg_42182 = umod32(unsign_arg_42181, 2147483647);
    
    if (memblock_alloc(ctx, &mem_46762, (int64_t) 960, "mem_46762")) {
        err = 1;
        goto cleanup;
    }
    for (int64_t i_45419 = 0; i_45419 < (int64_t) 120; i_45419++) {
        int32_t i64_res_42605 = sext_i64_i32(i_45419);
        int32_t arg_42606 = lshr32(i64_res_42605, 16);
        int32_t arg_42607 = i64_res_42605 ^ arg_42606;
        int32_t x_42608 = mul32(73244475, arg_42607);
        int32_t arg_42609 = lshr32(x_42608, 16);
        int32_t arg_42610 = x_42608 ^ arg_42609;
        int32_t x_42611 = mul32(73244475, arg_42610);
        int32_t arg_42612 = lshr32(x_42611, 16);
        int32_t x_42613 = x_42611 ^ arg_42612;
        int32_t unsign_arg_42614 = unsign_arg_42182 ^ x_42613;
        int32_t unsign_arg_42616 = mul32(48271, unsign_arg_42614);
        int32_t unsign_arg_42617 = umod32(unsign_arg_42616, 2147483647);
        double u64_res_42618 = uitofp_i32_f64(unsign_arg_42617);
        double zs_res_42619 = u64_res_42618 / 2.147483647e9;
        double zt_res_42620 = 0.1 * zs_res_42619;
        double zp_res_42621 = -5.0e-2 + zt_res_42620;
        
        ((double *) mem_46762.mem)[i_45419] = zp_res_42621;
    }
    
    int32_t mk_dense_weights_arg_42247 = ((int32_t *) mem_46644.mem)[(int64_t) 0];
    int32_t unsign_arg_42250 = 5460 ^ mk_dense_weights_arg_42247;
    int32_t unsign_arg_42251 = mul32(48271, unsign_arg_42250);
    int32_t unsign_arg_42252 = umod32(unsign_arg_42251, 2147483647);
    int32_t unsign_arg_42254 = mul32(48271, unsign_arg_42252);
    int32_t unsign_arg_42255 = umod32(unsign_arg_42254, 2147483647);
    
    if (memblock_alloc(ctx, &mem_46774, (int64_t) 80640, "mem_46774")) {
        err = 1;
        goto cleanup;
    }
    for (int64_t i_45423 = 0; i_45423 < (int64_t) 10080; i_45423++) {
        int32_t i64_res_42539 = sext_i64_i32(i_45423);
        int32_t arg_42540 = lshr32(i64_res_42539, 16);
        int32_t arg_42541 = i64_res_42539 ^ arg_42540;
        int32_t x_42542 = mul32(73244475, arg_42541);
        int32_t arg_42543 = lshr32(x_42542, 16);
        int32_t arg_42544 = x_42542 ^ arg_42543;
        int32_t x_42545 = mul32(73244475, arg_42544);
        int32_t arg_42546 = lshr32(x_42545, 16);
        int32_t x_42547 = x_42545 ^ arg_42546;
        int32_t unsign_arg_42548 = unsign_arg_42255 ^ x_42547;
        int32_t unsign_arg_42550 = mul32(48271, unsign_arg_42548);
        int32_t unsign_arg_42551 = umod32(unsign_arg_42550, 2147483647);
        double u64_res_42552 = uitofp_i32_f64(unsign_arg_42551);
        double zs_res_42553 = u64_res_42552 / 2.147483647e9;
        double zt_res_42554 = 0.18257418583505536 * zs_res_42553;
        double zp_res_42555 = -9.128709291752768e-2 + zt_res_42554;
        
        ((double *) mem_46774.mem)[i_45423] = zp_res_42555;
    }
    
    int32_t mk_dense_biases_arg_42286 = ((int32_t *) mem_46644.mem)[(int64_t) 1];
    
    if (memblock_unref(ctx, &mem_46644, "mem_46644") != 0)
        return 1;
    
    int32_t unsign_arg_42287 = 5460 ^ mk_dense_biases_arg_42286;
    int32_t unsign_arg_42288 = mul32(48271, unsign_arg_42287);
    int32_t unsign_arg_42289 = umod32(unsign_arg_42288, 2147483647);
    int32_t unsign_arg_42290 = mul32(48271, unsign_arg_42289);
    int32_t unsign_arg_42291 = umod32(unsign_arg_42290, 2147483647);
    
    if (memblock_alloc(ctx, &mem_46786, (int64_t) 672, "mem_46786")) {
        err = 1;
        goto cleanup;
    }
    for (int64_t i_45427 = 0; i_45427 < (int64_t) 84; i_45427++) {
        int32_t i64_res_42520 = sext_i64_i32(i_45427);
        int32_t arg_42521 = lshr32(i64_res_42520, 16);
        int32_t arg_42522 = i64_res_42520 ^ arg_42521;
        int32_t x_42523 = mul32(73244475, arg_42522);
        int32_t arg_42524 = lshr32(x_42523, 16);
        int32_t arg_42525 = x_42523 ^ arg_42524;
        int32_t x_42526 = mul32(73244475, arg_42525);
        int32_t arg_42527 = lshr32(x_42526, 16);
        int32_t x_42528 = x_42526 ^ arg_42527;
        int32_t unsign_arg_42529 = unsign_arg_42291 ^ x_42528;
        int32_t unsign_arg_42531 = mul32(48271, unsign_arg_42529);
        int32_t unsign_arg_42532 = umod32(unsign_arg_42531, 2147483647);
        double u64_res_42533 = uitofp_i32_f64(unsign_arg_42532);
        double zs_res_42534 = u64_res_42533 / 2.147483647e9;
        double zt_res_42535 = 0.18257418583505536 * zs_res_42534;
        double zp_res_42536 = -9.128709291752768e-2 + zt_res_42535;
        
        ((double *) mem_46786.mem)[i_45427] = zp_res_42536;
    }
    
    int32_t mk_dense_weights_arg_42356 = ((int32_t *) mem_46642.mem)[(int64_t) 0];
    int32_t unsign_arg_42359 = 5460 ^ mk_dense_weights_arg_42356;
    int32_t unsign_arg_42360 = mul32(48271, unsign_arg_42359);
    int32_t unsign_arg_42361 = umod32(unsign_arg_42360, 2147483647);
    int32_t unsign_arg_42363 = mul32(48271, unsign_arg_42361);
    int32_t unsign_arg_42364 = umod32(unsign_arg_42363, 2147483647);
    
    if (memblock_alloc(ctx, &mem_46798, (int64_t) 6720, "mem_46798")) {
        err = 1;
        goto cleanup;
    }
    for (int64_t i_45431 = 0; i_45431 < (int64_t) 840; i_45431++) {
        int32_t i64_res_42454 = sext_i64_i32(i_45431);
        int32_t arg_42455 = lshr32(i64_res_42454, 16);
        int32_t arg_42456 = i64_res_42454 ^ arg_42455;
        int32_t x_42457 = mul32(73244475, arg_42456);
        int32_t arg_42458 = lshr32(x_42457, 16);
        int32_t arg_42459 = x_42457 ^ arg_42458;
        int32_t x_42460 = mul32(73244475, arg_42459);
        int32_t arg_42461 = lshr32(x_42460, 16);
        int32_t x_42462 = x_42460 ^ arg_42461;
        int32_t unsign_arg_42463 = unsign_arg_42364 ^ x_42462;
        int32_t unsign_arg_42465 = mul32(48271, unsign_arg_42463);
        int32_t unsign_arg_42466 = umod32(unsign_arg_42465, 2147483647);
        double u64_res_42467 = uitofp_i32_f64(unsign_arg_42466);
        double zs_res_42468 = u64_res_42467 / 2.147483647e9;
        double zt_res_42469 = 0.21821789023599236 * zs_res_42468;
        double zp_res_42470 = -0.10910894511799618 + zt_res_42469;
        
        ((double *) mem_46798.mem)[i_45431] = zp_res_42470;
    }
    
    int32_t mk_dense_biases_arg_42395 = ((int32_t *) mem_46642.mem)[(int64_t) 1];
    
    if (memblock_unref(ctx, &mem_46642, "mem_46642") != 0)
        return 1;
    
    int32_t unsign_arg_42396 = 5460 ^ mk_dense_biases_arg_42395;
    int32_t unsign_arg_42397 = mul32(48271, unsign_arg_42396);
    int32_t unsign_arg_42398 = umod32(unsign_arg_42397, 2147483647);
    int32_t unsign_arg_42399 = mul32(48271, unsign_arg_42398);
    int32_t unsign_arg_42400 = umod32(unsign_arg_42399, 2147483647);
    
    if (memblock_alloc(ctx, &mem_46810, (int64_t) 80, "mem_46810")) {
        err = 1;
        goto cleanup;
    }
    for (int64_t i_45435 = 0; i_45435 < (int64_t) 10; i_45435++) {
        int32_t i64_res_42435 = sext_i64_i32(i_45435);
        int32_t arg_42436 = lshr32(i64_res_42435, 16);
        int32_t arg_42437 = i64_res_42435 ^ arg_42436;
        int32_t x_42438 = mul32(73244475, arg_42437);
        int32_t arg_42439 = lshr32(x_42438, 16);
        int32_t arg_42440 = x_42438 ^ arg_42439;
        int32_t x_42441 = mul32(73244475, arg_42440);
        int32_t arg_42442 = lshr32(x_42441, 16);
        int32_t x_42443 = x_42441 ^ arg_42442;
        int32_t unsign_arg_42444 = unsign_arg_42400 ^ x_42443;
        int32_t unsign_arg_42446 = mul32(48271, unsign_arg_42444);
        int32_t unsign_arg_42447 = umod32(unsign_arg_42446, 2147483647);
        double u64_res_42448 = uitofp_i32_f64(unsign_arg_42447);
        double zs_res_42449 = u64_res_42448 / 2.147483647e9;
        double zt_res_42450 = 0.21821789023599236 * zs_res_42449;
        double zp_res_42451 = -0.10910894511799618 + zt_res_42450;
        
        ((double *) mem_46810.mem)[i_45435] = zp_res_42451;
    }
    if (memblock_unref(ctx, &mem_46650, "mem_46650") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_46648, "mem_46648") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_46646, "mem_46646") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_46644, "mem_46644") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_46642, "mem_46642") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_46630, "mem_46630") != 0)
        return 1;
    #undef mem_46702
    #undef mem_46714
    #undef mem_46726
    #undef mem_46738
    #undef mem_46750
    #undef mem_46762
    #undef mem_46774
    #undef mem_46786
    #undef mem_46798
    #undef mem_46810
    
  cleanup:
    return err;
}
static int free_constants(struct futhark_context *ctx)
{
    (void) ctx;
    if (memblock_unref(ctx, &ctx->constants->mem_46702, "ctx->constants->mem_46702") != 0)
        return 1;
    if (memblock_unref(ctx, &ctx->constants->mem_46714, "ctx->constants->mem_46714") != 0)
        return 1;
    if (memblock_unref(ctx, &ctx->constants->mem_46726, "ctx->constants->mem_46726") != 0)
        return 1;
    if (memblock_unref(ctx, &ctx->constants->mem_46738, "ctx->constants->mem_46738") != 0)
        return 1;
    if (memblock_unref(ctx, &ctx->constants->mem_46750, "ctx->constants->mem_46750") != 0)
        return 1;
    if (memblock_unref(ctx, &ctx->constants->mem_46762, "ctx->constants->mem_46762") != 0)
        return 1;
    if (memblock_unref(ctx, &ctx->constants->mem_46774, "ctx->constants->mem_46774") != 0)
        return 1;
    if (memblock_unref(ctx, &ctx->constants->mem_46786, "ctx->constants->mem_46786") != 0)
        return 1;
    if (memblock_unref(ctx, &ctx->constants->mem_46798, "ctx->constants->mem_46798") != 0)
        return 1;
    if (memblock_unref(ctx, &ctx->constants->mem_46810, "ctx->constants->mem_46810") != 0)
        return 1;
    return 0;
}
struct futhark_f64_1d {
    struct memblock mem;
    int64_t shape[1];
};
struct futhark_f64_1d *futhark_new_f64_1d(struct futhark_context *ctx, const double *data, int64_t dim0)
{
    struct futhark_f64_1d *bad = NULL;
    struct futhark_f64_1d *arr = (struct futhark_f64_1d *) malloc(sizeof(struct futhark_f64_1d));
    
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
struct futhark_f64_1d *futhark_new_raw_f64_1d(struct futhark_context *ctx, const unsigned char *data, int64_t offset, int64_t dim0)
{
    struct futhark_f64_1d *bad = NULL;
    struct futhark_f64_1d *arr = (struct futhark_f64_1d *) malloc(sizeof(struct futhark_f64_1d));
    
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
int futhark_values_f64_1d(struct futhark_context *ctx, struct futhark_f64_1d *arr, double *data)
{
    lock_lock(&ctx->lock);
    if ((size_t) arr->shape[0] * 8 > 0)
        memmove(data + 0, arr->mem.mem + 0, (size_t) arr->shape[0] * 8);
    lock_unlock(&ctx->lock);
    return 0;
}
unsigned char *futhark_values_raw_f64_1d(struct futhark_context *ctx, struct futhark_f64_1d *arr)
{
    (void) ctx;
    return arr->mem.mem;
}
const int64_t *futhark_shape_f64_1d(struct futhark_context *ctx, struct futhark_f64_1d *arr)
{
    (void) ctx;
    return arr->shape;
}
struct futhark_f64_2d {
    struct memblock mem;
    int64_t shape[2];
};
struct futhark_f64_2d *futhark_new_f64_2d(struct futhark_context *ctx, const double *data, int64_t dim0, int64_t dim1)
{
    struct futhark_f64_2d *bad = NULL;
    struct futhark_f64_2d *arr = (struct futhark_f64_2d *) malloc(sizeof(struct futhark_f64_2d));
    
    if (arr == NULL)
        return bad;
    lock_lock(&ctx->lock);
    arr->mem.references = NULL;
    if (memblock_alloc(ctx, &arr->mem, dim0 * dim1 * 8, "arr->mem"))
        return NULL;
    arr->shape[0] = dim0;
    arr->shape[1] = dim1;
    if ((size_t) (dim0 * dim1) * 8 > 0)
        memmove(arr->mem.mem + 0, data + 0, (size_t) (dim0 * dim1) * 8);
    lock_unlock(&ctx->lock);
    return arr;
}
struct futhark_f64_2d *futhark_new_raw_f64_2d(struct futhark_context *ctx, const unsigned char *data, int64_t offset, int64_t dim0, int64_t dim1)
{
    struct futhark_f64_2d *bad = NULL;
    struct futhark_f64_2d *arr = (struct futhark_f64_2d *) malloc(sizeof(struct futhark_f64_2d));
    
    if (arr == NULL)
        return bad;
    lock_lock(&ctx->lock);
    arr->mem.references = NULL;
    if (memblock_alloc(ctx, &arr->mem, dim0 * dim1 * 8, "arr->mem"))
        return NULL;
    arr->shape[0] = dim0;
    arr->shape[1] = dim1;
    if ((size_t) (dim0 * dim1) * 8 > 0)
        memmove(arr->mem.mem + 0, data + offset, (size_t) (dim0 * dim1) * 8);
    lock_unlock(&ctx->lock);
    return arr;
}
int futhark_free_f64_2d(struct futhark_context *ctx, struct futhark_f64_2d *arr)
{
    lock_lock(&ctx->lock);
    if (memblock_unref(ctx, &arr->mem, "arr->mem") != 0)
        return 1;
    lock_unlock(&ctx->lock);
    free(arr);
    return 0;
}
int futhark_values_f64_2d(struct futhark_context *ctx, struct futhark_f64_2d *arr, double *data)
{
    lock_lock(&ctx->lock);
    if ((size_t) (arr->shape[0] * arr->shape[1]) * 8 > 0)
        memmove(data + 0, arr->mem.mem + 0, (size_t) (arr->shape[0] * arr->shape[1]) * 8);
    lock_unlock(&ctx->lock);
    return 0;
}
unsigned char *futhark_values_raw_f64_2d(struct futhark_context *ctx, struct futhark_f64_2d *arr)
{
    (void) ctx;
    return arr->mem.mem;
}
const int64_t *futhark_shape_f64_2d(struct futhark_context *ctx, struct futhark_f64_2d *arr)
{
    (void) ctx;
    return arr->shape;
}
struct futhark_f64_3d {
    struct memblock mem;
    int64_t shape[3];
};
struct futhark_f64_3d *futhark_new_f64_3d(struct futhark_context *ctx, const double *data, int64_t dim0, int64_t dim1, int64_t dim2)
{
    struct futhark_f64_3d *bad = NULL;
    struct futhark_f64_3d *arr = (struct futhark_f64_3d *) malloc(sizeof(struct futhark_f64_3d));
    
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
struct futhark_f64_3d *futhark_new_raw_f64_3d(struct futhark_context *ctx, const unsigned char *data, int64_t offset, int64_t dim0, int64_t dim1, int64_t dim2)
{
    struct futhark_f64_3d *bad = NULL;
    struct futhark_f64_3d *arr = (struct futhark_f64_3d *) malloc(sizeof(struct futhark_f64_3d));
    
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
        memmove(arr->mem.mem + 0, data + offset, (size_t) (dim0 * dim1 * dim2) * 8);
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
int futhark_values_f64_3d(struct futhark_context *ctx, struct futhark_f64_3d *arr, double *data)
{
    lock_lock(&ctx->lock);
    if ((size_t) (arr->shape[0] * arr->shape[1] * arr->shape[2]) * 8 > 0)
        memmove(data + 0, arr->mem.mem + 0, (size_t) (arr->shape[0] * arr->shape[1] * arr->shape[2]) * 8);
    lock_unlock(&ctx->lock);
    return 0;
}
unsigned char *futhark_values_raw_f64_3d(struct futhark_context *ctx, struct futhark_f64_3d *arr)
{
    (void) ctx;
    return arr->mem.mem;
}
const int64_t *futhark_shape_f64_3d(struct futhark_context *ctx, struct futhark_f64_3d *arr)
{
    (void) ctx;
    return arr->shape;
}
struct futhark_f64_4d {
    struct memblock mem;
    int64_t shape[4];
};
struct futhark_f64_4d *futhark_new_f64_4d(struct futhark_context *ctx, const double *data, int64_t dim0, int64_t dim1, int64_t dim2, int64_t dim3)
{
    struct futhark_f64_4d *bad = NULL;
    struct futhark_f64_4d *arr = (struct futhark_f64_4d *) malloc(sizeof(struct futhark_f64_4d));
    
    if (arr == NULL)
        return bad;
    lock_lock(&ctx->lock);
    arr->mem.references = NULL;
    if (memblock_alloc(ctx, &arr->mem, dim0 * dim1 * dim2 * dim3 * 8, "arr->mem"))
        return NULL;
    arr->shape[0] = dim0;
    arr->shape[1] = dim1;
    arr->shape[2] = dim2;
    arr->shape[3] = dim3;
    if ((size_t) (dim0 * dim1 * dim2 * dim3) * 8 > 0)
        memmove(arr->mem.mem + 0, data + 0, (size_t) (dim0 * dim1 * dim2 * dim3) * 8);
    lock_unlock(&ctx->lock);
    return arr;
}
struct futhark_f64_4d *futhark_new_raw_f64_4d(struct futhark_context *ctx, const unsigned char *data, int64_t offset, int64_t dim0, int64_t dim1, int64_t dim2, int64_t dim3)
{
    struct futhark_f64_4d *bad = NULL;
    struct futhark_f64_4d *arr = (struct futhark_f64_4d *) malloc(sizeof(struct futhark_f64_4d));
    
    if (arr == NULL)
        return bad;
    lock_lock(&ctx->lock);
    arr->mem.references = NULL;
    if (memblock_alloc(ctx, &arr->mem, dim0 * dim1 * dim2 * dim3 * 8, "arr->mem"))
        return NULL;
    arr->shape[0] = dim0;
    arr->shape[1] = dim1;
    arr->shape[2] = dim2;
    arr->shape[3] = dim3;
    if ((size_t) (dim0 * dim1 * dim2 * dim3) * 8 > 0)
        memmove(arr->mem.mem + 0, data + offset, (size_t) (dim0 * dim1 * dim2 * dim3) * 8);
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
int futhark_values_f64_4d(struct futhark_context *ctx, struct futhark_f64_4d *arr, double *data)
{
    lock_lock(&ctx->lock);
    if ((size_t) (arr->shape[0] * arr->shape[1] * arr->shape[2] * arr->shape[3]) * 8 > 0)
        memmove(data + 0, arr->mem.mem + 0, (size_t) (arr->shape[0] * arr->shape[1] * arr->shape[2] * arr->shape[3]) * 8);
    lock_unlock(&ctx->lock);
    return 0;
}
unsigned char *futhark_values_raw_f64_4d(struct futhark_context *ctx, struct futhark_f64_4d *arr)
{
    (void) ctx;
    return arr->mem.mem;
}
const int64_t *futhark_shape_f64_4d(struct futhark_context *ctx, struct futhark_f64_4d *arr)
{
    (void) ctx;
    return arr->shape;
}

static int futrts_entry_bench_cnn(struct futhark_context *ctx, struct memblock *mem_out_p_48540, int64_t *out_prim_out_48541, struct memblock x_train_mem_46821, struct memblock y_train_mem_46822, int64_t l_37763, int64_t m_37764, int64_t n_37765, int64_t epochs_37768)
{
    (void) ctx;
    
    int err = 0;
    int64_t mem_46826_cached_sizze_48542 = 0;
    unsigned char *mem_46826 = NULL;
    struct memblock mem_46842;
    
    mem_46842.references = NULL;
    
    struct memblock mem_param_tmp_48368;
    
    mem_param_tmp_48368.references = NULL;
    
    struct memblock mem_46834;
    
    mem_46834.references = NULL;
    
    struct memblock mem_param_46831;
    
    mem_param_46831.references = NULL;
    
    struct memblock ext_mem_46839;
    
    ext_mem_46839.references = NULL;
    
    struct memblock mem_46824;
    
    mem_46824.references = NULL;
    
    struct memblock mem_out_48365;
    
    mem_out_48365.references = NULL;
    
    struct memblock mem_46702 = ctx->constants->mem_46702;
    struct memblock mem_46714 = ctx->constants->mem_46714;
    struct memblock mem_46726 = ctx->constants->mem_46726;
    struct memblock mem_46738 = ctx->constants->mem_46738;
    struct memblock mem_46750 = ctx->constants->mem_46750;
    struct memblock mem_46762 = ctx->constants->mem_46762;
    struct memblock mem_46774 = ctx->constants->mem_46774;
    struct memblock mem_46786 = ctx->constants->mem_46786;
    struct memblock mem_46798 = ctx->constants->mem_46798;
    struct memblock mem_46810 = ctx->constants->mem_46810;
    int64_t prim_out_48366;
    
    if (memblock_alloc(ctx, &mem_46824, (int64_t) 0, "mem_46824")) {
        err = 1;
        goto cleanup;
    }
    if (mem_46826_cached_sizze_48542 < (int64_t) 8) {
        err = lexical_realloc(ctx, &mem_46826, &mem_46826_cached_sizze_48542, (int64_t) 8);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    for (int64_t nest_i_48367 = 0; nest_i_48367 < (int64_t) 1; nest_i_48367++) {
        ((double *) mem_46826)[nest_i_48367] = NAN;
    }
    
    int64_t ext_46836;
    int64_t ext_46835;
    int64_t train_lenet_res_40335;
    int64_t loop_dz2083U_40348;
    int64_t ctx_param_ext_46829;
    int64_t ctx_param_ext_46830;
    
    if (memblock_set(ctx, &mem_param_46831, &mem_46824, "mem_46824") != 0)
        return 1;
    ctx_param_ext_46829 = (int64_t) 0;
    ctx_param_ext_46830 = (int64_t) 0;
    loop_dz2083U_40348 = (int64_t) 0;
    for (int64_t e_40347 = 0; e_40347 < epochs_37768; e_40347++) {
        int64_t conc_tmp_40909 = (int64_t) 1 + loop_dz2083U_40348;
        int64_t binop_y_46832 = (int64_t) 8 * conc_tmp_40909;
        int64_t bytes_46833 = smax64((int64_t) 0, binop_y_46832);
        
        if (memblock_alloc(ctx, &mem_46834, bytes_46833, "mem_46834")) {
            err = 1;
            goto cleanup;
        }
        
        int64_t tmp_offs_48373 = (int64_t) 0;
        
        if (loop_dz2083U_40348 * (int64_t) 8 > 0)
            memmove(mem_46834.mem + tmp_offs_48373 * (int64_t) 8, mem_param_46831.mem + (int64_t) 0, loop_dz2083U_40348 * (int64_t) 8);
        tmp_offs_48373 += loop_dz2083U_40348;
        if ((int64_t) 8 > 0)
            memmove(mem_46834.mem + tmp_offs_48373 * (int64_t) 8, mem_46826 + (int64_t) 0, (int64_t) 8);
        tmp_offs_48373 += (int64_t) 1;
        if (memblock_set(ctx, &mem_param_tmp_48368, &mem_46834, "mem_46834") != 0)
            return 1;
        
        int64_t ctx_param_ext_tmp_48369 = conc_tmp_40909;
        int64_t ctx_param_ext_tmp_48370 = conc_tmp_40909;
        int64_t loop_dz2083U_tmp_48371 = conc_tmp_40909;
        
        if (memblock_set(ctx, &mem_param_46831, &mem_param_tmp_48368, "mem_param_tmp_48368") != 0)
            return 1;
        ctx_param_ext_46829 = ctx_param_ext_tmp_48369;
        ctx_param_ext_46830 = ctx_param_ext_tmp_48370;
        loop_dz2083U_40348 = loop_dz2083U_tmp_48371;
    }
    if (memblock_set(ctx, &ext_mem_46839, &mem_param_46831, "mem_param_46831") != 0)
        return 1;
    ext_46836 = ctx_param_ext_46829;
    ext_46835 = ctx_param_ext_46830;
    train_lenet_res_40335 = loop_dz2083U_40348;
    if (memblock_unref(ctx, &mem_46824, "mem_46824") != 0)
        return 1;
    
    int64_t binop_y_46840 = (int64_t) 8 * train_lenet_res_40335;
    int64_t bytes_46841 = smax64((int64_t) 0, binop_y_46840);
    
    if (memblock_alloc(ctx, &mem_46842, bytes_46841, "mem_46842")) {
        err = 1;
        goto cleanup;
    }
    if (train_lenet_res_40335 * (int64_t) 8 > 0)
        memmove(mem_46842.mem + (int64_t) 0, ext_mem_46839.mem + (int64_t) 0, train_lenet_res_40335 * (int64_t) 8);
    if (memblock_unref(ctx, &ext_mem_46839, "ext_mem_46839") != 0)
        return 1;
    if (memblock_set(ctx, &mem_out_48365, &mem_46842, "mem_46842") != 0)
        return 1;
    prim_out_48366 = train_lenet_res_40335;
    if (memblock_set(ctx, &*mem_out_p_48540, &mem_out_48365, "mem_out_48365") != 0)
        return 1;
    *out_prim_out_48541 = prim_out_48366;
    
  cleanup:
    {
        free(mem_46826);
        if (memblock_unref(ctx, &mem_46842, "mem_46842") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_param_tmp_48368, "mem_param_tmp_48368") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_46834, "mem_46834") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_param_46831, "mem_param_46831") != 0)
            return 1;
        if (memblock_unref(ctx, &ext_mem_46839, "ext_mem_46839") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_46824, "mem_46824") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_out_48365, "mem_out_48365") != 0)
            return 1;
    }
    return err;
}
static int futrts_entry_bench_cnn_futhark_ad(struct futhark_context *ctx, struct memblock *mem_out_p_48543, struct memblock *mem_out_p_48544, struct memblock *mem_out_p_48545, struct memblock *mem_out_p_48546, struct memblock *mem_out_p_48547, struct memblock *mem_out_p_48548, struct memblock *mem_out_p_48549, struct memblock *mem_out_p_48550, struct memblock *mem_out_p_48551, struct memblock *mem_out_p_48552, struct memblock x_train_mem_46821, struct memblock y_train_mem_46822, int64_t l_38230, int64_t m_38231, int64_t n_38232, int64_t epochs_38235)
{
    (void) ctx;
    
    int err = 0;
    int64_t mem_46826_cached_sizze_48553 = 0;
    unsigned char *mem_46826 = NULL;
    int64_t mem_46871_cached_sizze_48554 = 0;
    unsigned char *mem_46871 = NULL;
    int64_t mem_46876_cached_sizze_48555 = 0;
    unsigned char *mem_46876 = NULL;
    int64_t mem_46937_cached_sizze_48556 = 0;
    unsigned char *mem_46937 = NULL;
    int64_t mem_46980_cached_sizze_48557 = 0;
    unsigned char *mem_46980 = NULL;
    int64_t mem_46993_cached_sizze_48558 = 0;
    unsigned char *mem_46993 = NULL;
    int64_t mem_47104_cached_sizze_48559 = 0;
    unsigned char *mem_47104 = NULL;
    int64_t mem_47156_cached_sizze_48560 = 0;
    unsigned char *mem_47156 = NULL;
    int64_t mem_47196_cached_sizze_48561 = 0;
    unsigned char *mem_47196 = NULL;
    int64_t mem_47209_cached_sizze_48562 = 0;
    unsigned char *mem_47209 = NULL;
    int64_t mem_47320_cached_sizze_48563 = 0;
    unsigned char *mem_47320 = NULL;
    int64_t mem_47332_cached_sizze_48564 = 0;
    unsigned char *mem_47332 = NULL;
    int64_t mem_47344_cached_sizze_48565 = 0;
    unsigned char *mem_47344 = NULL;
    int64_t mem_47356_cached_sizze_48566 = 0;
    unsigned char *mem_47356 = NULL;
    int64_t mem_47368_cached_sizze_48567 = 0;
    unsigned char *mem_47368 = NULL;
    int64_t mem_47370_cached_sizze_48568 = 0;
    unsigned char *mem_47370 = NULL;
    int64_t mem_47372_cached_sizze_48569 = 0;
    unsigned char *mem_47372 = NULL;
    int64_t mem_47387_cached_sizze_48570 = 0;
    unsigned char *mem_47387 = NULL;
    int64_t mem_47416_cached_sizze_48571 = 0;
    unsigned char *mem_47416 = NULL;
    int64_t mem_47418_cached_sizze_48572 = 0;
    unsigned char *mem_47418 = NULL;
    int64_t mem_47420_cached_sizze_48573 = 0;
    unsigned char *mem_47420 = NULL;
    int64_t mem_47435_cached_sizze_48574 = 0;
    unsigned char *mem_47435 = NULL;
    int64_t mem_47464_cached_sizze_48575 = 0;
    unsigned char *mem_47464 = NULL;
    int64_t mem_47466_cached_sizze_48576 = 0;
    unsigned char *mem_47466 = NULL;
    int64_t mem_47468_cached_sizze_48577 = 0;
    unsigned char *mem_47468 = NULL;
    int64_t mem_47483_cached_sizze_48578 = 0;
    unsigned char *mem_47483 = NULL;
    int64_t mem_47512_cached_sizze_48579 = 0;
    unsigned char *mem_47512 = NULL;
    int64_t mem_47525_cached_sizze_48580 = 0;
    unsigned char *mem_47525 = NULL;
    int64_t mem_47598_cached_sizze_48581 = 0;
    unsigned char *mem_47598 = NULL;
    int64_t mem_47600_cached_sizze_48582 = 0;
    unsigned char *mem_47600 = NULL;
    int64_t mem_47602_cached_sizze_48583 = 0;
    unsigned char *mem_47602 = NULL;
    int64_t mem_47617_cached_sizze_48584 = 0;
    unsigned char *mem_47617 = NULL;
    int64_t mem_47632_cached_sizze_48585 = 0;
    unsigned char *mem_47632 = NULL;
    int64_t mem_47636_cached_sizze_48586 = 0;
    unsigned char *mem_47636 = NULL;
    int64_t mem_47638_cached_sizze_48587 = 0;
    unsigned char *mem_47638 = NULL;
    int64_t mem_47651_cached_sizze_48588 = 0;
    unsigned char *mem_47651 = NULL;
    int64_t mem_47724_cached_sizze_48589 = 0;
    unsigned char *mem_47724 = NULL;
    int64_t mem_47741_cached_sizze_48590 = 0;
    unsigned char *mem_47741 = NULL;
    struct memblock mem_47762;
    
    mem_47762.references = NULL;
    
    struct memblock mem_47756;
    
    mem_47756.references = NULL;
    
    struct memblock mem_47726;
    
    mem_47726.references = NULL;
    
    struct memblock mem_47634;
    
    mem_47634.references = NULL;
    
    struct memblock mem_47510;
    
    mem_47510.references = NULL;
    
    struct memblock mem_47508;
    
    mem_47508.references = NULL;
    
    struct memblock mem_47462;
    
    mem_47462.references = NULL;
    
    struct memblock mem_47460;
    
    mem_47460.references = NULL;
    
    struct memblock mem_47414;
    
    mem_47414.references = NULL;
    
    struct memblock mem_47412;
    
    mem_47412.references = NULL;
    
    struct memblock mem_out_48374;
    
    mem_out_48374.references = NULL;
    
    struct memblock mem_out_48373;
    
    mem_out_48373.references = NULL;
    
    struct memblock mem_out_48372;
    
    mem_out_48372.references = NULL;
    
    struct memblock mem_out_48371;
    
    mem_out_48371.references = NULL;
    
    struct memblock mem_out_48370;
    
    mem_out_48370.references = NULL;
    
    struct memblock mem_out_48369;
    
    mem_out_48369.references = NULL;
    
    struct memblock mem_out_48368;
    
    mem_out_48368.references = NULL;
    
    struct memblock mem_out_48367;
    
    mem_out_48367.references = NULL;
    
    struct memblock mem_out_48366;
    
    mem_out_48366.references = NULL;
    
    struct memblock mem_out_48365;
    
    mem_out_48365.references = NULL;
    
    struct memblock mem_46702 = ctx->constants->mem_46702;
    struct memblock mem_46714 = ctx->constants->mem_46714;
    struct memblock mem_46726 = ctx->constants->mem_46726;
    struct memblock mem_46738 = ctx->constants->mem_46738;
    struct memblock mem_46750 = ctx->constants->mem_46750;
    struct memblock mem_46762 = ctx->constants->mem_46762;
    struct memblock mem_46774 = ctx->constants->mem_46774;
    struct memblock mem_46786 = ctx->constants->mem_46786;
    struct memblock mem_46798 = ctx->constants->mem_46798;
    struct memblock mem_46810 = ctx->constants->mem_46810;
    int64_t arg_41505 = add64((int64_t) 4, m_38231);
    int64_t arg_41506 = sub64(arg_41505, (int64_t) 5);
    int64_t new_n_41507 = add64((int64_t) 1, arg_41506);
    int64_t arg_41508 = add64((int64_t) 4, n_38232);
    int64_t arg_41509 = sub64(arg_41508, (int64_t) 5);
    int64_t new_m_41510 = add64((int64_t) 1, arg_41509);
    int64_t binop_x_46823 = arg_41505 * arg_41508;
    int64_t binop_y_46824 = (int64_t) 8 * binop_x_46823;
    int64_t bytes_46825 = smax64((int64_t) 0, binop_y_46824);
    int64_t binop_x_46872 = new_n_41507 * new_m_41510;
    int64_t binop_y_46874 = (int64_t) 200 * binop_x_46872;
    int64_t bytes_46875 = smax64((int64_t) 0, binop_y_46874);
    int64_t binop_y_46935 = (int64_t) 48 * binop_x_46872;
    int64_t bytes_46936 = smax64((int64_t) 0, binop_y_46935);
    bool y_38824 = slt64((int64_t) 0, l_38230);
    bool index_certs_38825;
    
    if (!y_38824) {
        set_error(ctx, msgprintf("Error: %s%lld%s%lld%s\n\nBacktrace:\n%s", "Index [", (long long) (int64_t) 0, "] out of bounds for array of shape [", (long long) l_38230, "].", "-> #0  cnn_test.fut:37:52-61\n   #1  /prelude/ad.fut:23:13-14\n   #2  cnn_test.fut:38:40-43\n   #3  cnn_test.fut:36:1-39:11\n"));
        err = FUTHARK_PROGRAM_ERROR;
        goto cleanup;
    }
    
    bool bounds_invalid_upwards_41512 = slt64(arg_41505, (int64_t) 0);
    bool valid_41513 = !bounds_invalid_upwards_41512;
    bool range_valid_c_41514;
    
    if (!valid_41513) {
        set_error(ctx, msgprintf("Error: %s%lld%s%lld%s%lld%s\n\nBacktrace:\n%s", "Range ", (long long) (int64_t) 0, "..", (long long) (int64_t) 1, "..<", (long long) arg_41505, " is invalid.", "-> #0  /prelude/array.fut:95:3-10\n   #1  ../layers/conv2d.fut:7:120-123\n   #2  ../layers/conv2d.fut:20:7-30\n   #3  ../lenet/lenet.fut:10:37-64\n   #4  cnn_test.fut:36:1-39:11\n"));
        err = FUTHARK_PROGRAM_ERROR;
        goto cleanup;
    }
    
    bool bounds_invalid_upwards_41516 = slt64(arg_41508, (int64_t) 0);
    bool valid_41517 = !bounds_invalid_upwards_41516;
    bool range_valid_c_41518;
    
    if (!valid_41517) {
        set_error(ctx, msgprintf("Error: %s%lld%s%lld%s%lld%s\n\nBacktrace:\n%s", "Range ", (long long) (int64_t) 0, "..", (long long) (int64_t) 1, "..<", (long long) arg_41508, " is invalid.", "-> #0  /prelude/array.fut:95:3-10\n   #1  ../layers/conv2d.fut:7:120-123\n   #2  ../layers/conv2d.fut:20:7-30\n   #3  ../lenet/lenet.fut:10:37-64\n   #4  cnn_test.fut:36:1-39:11\n"));
        err = FUTHARK_PROGRAM_ERROR;
        goto cleanup;
    }
    
    int64_t arg_41520 = add64((int64_t) 2, m_38231);
    int64_t arg_41521 = add64((int64_t) 2, n_38232);
    
    if (mem_46826_cached_sizze_48553 < bytes_46825) {
        err = lexical_realloc(ctx, &mem_46826, &mem_46826_cached_sizze_48553, bytes_46825);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    for (int64_t i_45443 = 0; i_45443 < arg_41505; i_45443++) {
        bool cond_41524 = slt64(i_45443, (int64_t) 2);
        bool cond_f_res_41525 = sle64(arg_41520, i_45443);
        bool x_41526 = !cond_41524;
        bool y_41527 = cond_f_res_41525 && x_41526;
        bool cond_41528 = cond_41524 || y_41527;
        bool x_41529 = !cond_41528;
        
        for (int64_t i_45439 = 0; i_45439 < arg_41508; i_45439++) {
            bool cond_f_res_41532 = slt64(i_45439, (int64_t) 2);
            bool y_41533 = x_41529 && cond_f_res_41532;
            bool cond_41534 = cond_41528 || y_41533;
            bool cond_f_res_41535 = sle64(arg_41521, i_45439);
            bool x_41536 = !cond_41534;
            bool y_41537 = cond_f_res_41535 && x_41536;
            bool cond_41538 = cond_41534 || y_41537;
            double defunc_0_f_res_41539;
            
            if (cond_41538 == 1) {
                defunc_0_f_res_41539 = 0.0;
            } else {
                int64_t i_41540 = sub64(i_45443, (int64_t) 2);
                int64_t i_41544 = sub64(i_45439, (int64_t) 2);
                double defunc_0_f_res_f_res_41550 = ((double *) x_train_mem_46821.mem)[i_41540 * n_38232 + i_41544];
                
                defunc_0_f_res_41539 = defunc_0_f_res_f_res_41550;
            }
            ((double *) mem_46826)[i_45443 * arg_41508 + i_45439] = defunc_0_f_res_41539;
        }
    }
    if (mem_46871_cached_sizze_48554 < bytes_46825) {
        err = lexical_realloc(ctx, &mem_46871, &mem_46871_cached_sizze_48554, bytes_46825);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    for (int64_t nest_i_48377 = 0; nest_i_48377 < (int64_t) 1; nest_i_48377++) {
        if (arg_41505 * arg_41508 * (int64_t) 8 > 0)
            memmove(mem_46871 + nest_i_48377 * (arg_41508 * arg_41505) * (int64_t) 8, mem_46826 + (int64_t) 0, arg_41505 * arg_41508 * (int64_t) 8);
    }
    
    bool bounds_invalid_upwards_41553 = slt64(new_n_41507, (int64_t) 0);
    bool valid_41554 = !bounds_invalid_upwards_41553;
    bool range_valid_c_41555;
    
    if (!valid_41554) {
        set_error(ctx, msgprintf("Error: %s%lld%s%lld%s%lld%s\n\nBacktrace:\n%s", "Range ", (long long) (int64_t) 0, "..", (long long) (int64_t) 1, "..<", (long long) new_n_41507, " is invalid.", "-> #0  /prelude/array.fut:95:3-10\n   #1  /prelude/array.fut:208:28-33\n   #2  ../layers/conv2d.fut:11:50-162\n   #3  ../layers/conv2d.fut:24:17-54\n   #4  ../lenet/lenet.fut:10:37-64\n   #5  cnn_test.fut:36:1-39:11\n"));
        err = FUTHARK_PROGRAM_ERROR;
        goto cleanup;
    }
    
    bool bounds_invalid_upwards_41557 = slt64(new_m_41510, (int64_t) 0);
    bool valid_41558 = !bounds_invalid_upwards_41557;
    bool range_valid_c_41559;
    
    if (!valid_41558) {
        set_error(ctx, msgprintf("Error: %s%lld%s%lld%s%lld%s\n\nBacktrace:\n%s", "Range ", (long long) (int64_t) 0, "..", (long long) (int64_t) 1, "..<", (long long) new_m_41510, " is invalid.", "-> #0  /prelude/array.fut:95:3-10\n   #1  /prelude/array.fut:208:27-34\n   #2  ../layers/conv2d.fut:11:50-162\n   #3  ../layers/conv2d.fut:24:17-54\n   #4  ../lenet/lenet.fut:10:37-64\n   #5  cnn_test.fut:36:1-39:11\n"));
        err = FUTHARK_PROGRAM_ERROR;
        goto cleanup;
    }
    if (mem_46876_cached_sizze_48555 < bytes_46875) {
        err = lexical_realloc(ctx, &mem_46876, &mem_46876_cached_sizze_48555, bytes_46875);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    
    int64_t ixfun_arg_46888 = (int64_t) 25 * new_m_41510;
    
    for (int64_t i_45451 = 0; i_45451 < new_n_41507; i_45451++) {
        int64_t j_41569 = add64((int64_t) 5, i_45451);
        int64_t i_p_m_t_s_41570 = add64((int64_t) 4, i_45451);
        bool zzero_leq_i_p_m_t_s_41571 = sle64((int64_t) 0, i_p_m_t_s_41570);
        bool i_p_m_t_s_leq_w_41572 = slt64(i_p_m_t_s_41570, arg_41505);
        bool i_lte_j_41574 = sle64(i_45451, j_41569);
        bool y_41576 = zzero_leq_i_p_m_t_s_41571 && i_p_m_t_s_leq_w_41572;
        bool y_41577 = i_lte_j_41574 && y_41576;
        
        for (int64_t i_45447 = 0; i_45447 < new_m_41510; i_45447++) {
            int64_t j_41582 = add64((int64_t) 5, i_45447);
            int64_t i_p_m_t_s_41583 = add64((int64_t) 4, i_45447);
            bool zzero_leq_i_p_m_t_s_41584 = sle64((int64_t) 0, i_p_m_t_s_41583);
            bool i_p_m_t_s_leq_w_41585 = slt64(i_p_m_t_s_41583, arg_41508);
            bool i_lte_j_41587 = sle64(i_45447, j_41582);
            bool y_41589 = zzero_leq_i_p_m_t_s_41584 && i_p_m_t_s_leq_w_41585;
            bool y_41590 = i_lte_j_41587 && y_41589;
            bool index_ok_41593 = y_41577 && y_41590;
            bool index_certs_41594;
            
            if (!index_ok_41593) {
                set_error(ctx, msgprintf("Error: %s%lld%s%lld%s%lld%s%lld%s%lld%s%lld%s\n\nBacktrace:\n%s", "Index [", (long long) i_45451, ":", (long long) j_41569, ", ", (long long) i_45447, ":", (long long) j_41582, "] out of bounds for array of shape [", (long long) arg_41505, "][", (long long) arg_41508, "].", "-> #0  ../layers/conv2d.fut:11:90-124\n   #1  ../layers/conv2d.fut:11:144-146\n   #2  /prelude/soacs.fut:59:9-10\n   #3  /prelude/array.fut:200:10-17\n   #4  /prelude/functional.fut:39:61-65\n   #5  /prelude/soacs.fut:59:9-10\n   #6  /prelude/array.fut:208:27-34\n   #7  ../layers/conv2d.fut:11:50-162\n   #8  ../layers/conv2d.fut:24:17-54\n   #9  ../lenet/lenet.fut:10:37-64\n   #10 cnn_test.fut:36:1-39:11\n"));
                err = FUTHARK_PROGRAM_ERROR;
                goto cleanup;
            }
            for (int64_t i_48380 = 0; i_48380 < (int64_t) 25; i_48380++) {
                double tmp_48381 = ((double *) mem_46871)[arg_41508 * i_45451 + i_45447 + (squot64(i_48380, (int64_t) 25) * (arg_41508 * arg_41505) + squot64(i_48380 - squot64(i_48380, (int64_t) 25) * (int64_t) 25, (int64_t) 5) * arg_41508 + (i_48380 - squot64(i_48380, (int64_t) 25) * (int64_t) 25 - squot64(i_48380 - squot64(i_48380, (int64_t) 25) * (int64_t) 25, (int64_t) 5) * (int64_t) 5))];
                
                ((double *) mem_46876)[i_45451 * ixfun_arg_46888 + i_45447 * (int64_t) 25 + i_48380] = tmp_48381;
            }
        }
    }
    
    bool dim_match_41626 = (int64_t) 28 == new_n_41507;
    bool dim_match_41627 = (int64_t) 28 == new_m_41510;
    bool match_41629 = dim_match_41626 && dim_match_41627;
    bool empty_or_match_cert_41630;
    
    if (!match_41629) {
        set_error(ctx, msgprintf("Error: %s%lld%s%lld%s%lld%s%lld%s%lld%s%lld%s\n\nBacktrace:\n%s", "Value of (core language) shape (", (long long) (int64_t) 6, ", ", (long long) new_n_41507, ", ", (long long) new_m_41510, ") cannot match shape of type `[", (long long) (int64_t) 6, "][", (long long) (int64_t) 28, "][", (long long) (int64_t) 28, "]f64`.", "-> #0  ../lenet/lenet.fut:10:37-82\n   #1  cnn_test.fut:36:1-39:11\n"));
        err = FUTHARK_PROGRAM_ERROR;
        goto cleanup;
    }
    if (mem_46937_cached_sizze_48556 < bytes_46936) {
        err = lexical_realloc(ctx, &mem_46937, &mem_46937_cached_sizze_48556, bytes_46936);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    for (int64_t i_45461 = 0; i_45461 < (int64_t) 6; i_45461++) {
        double x_43517 = ((double *) mem_46714.mem)[i_45461];
        int64_t binop_x_46198 = (int64_t) 25 * i_45461;
        
        for (int64_t i_45457 = 0; i_45457 < binop_x_46872; i_45457++) {
            int64_t binop_x_46200 = (int64_t) 25 * i_45457;
            double defunc_0_reduce_res_45126;
            double redout_45453 = 0.0;
            
            for (int64_t i_45454 = 0; i_45454 < (int64_t) 25; i_45454++) {
                int64_t new_index_46199 = i_45454 + binop_x_46198;
                double x_43547 = ((double *) mem_46702.mem)[new_index_46199];
                int64_t binop_x_46201 = i_45454 + binop_x_46200;
                int64_t new_index_46203 = squot64(binop_x_46201, ixfun_arg_46888);
                int64_t binop_y_46211 = new_index_46203 * ixfun_arg_46888;
                int64_t binop_x_46212 = binop_x_46201 - binop_y_46211;
                int64_t new_index_46213 = squot64(binop_x_46212, (int64_t) 25);
                int64_t binop_y_46233 = (int64_t) 25 * new_index_46213;
                int64_t new_index_46234 = binop_x_46212 - binop_y_46233;
                double x_43548 = ((double *) mem_46876)[new_index_46203 * ixfun_arg_46888 + new_index_46213 * (int64_t) 25 + new_index_46234];
                double defunc_0_f_res_43549 = x_43547 * x_43548;
                double defunc_0_op_res_43542 = defunc_0_f_res_43549 + redout_45453;
                double redout_tmp_48384 = defunc_0_op_res_43542;
                
                redout_45453 = redout_tmp_48384;
            }
            defunc_0_reduce_res_45126 = redout_45453;
            
            double defunc_0_f_res_43545 = x_43517 + defunc_0_reduce_res_45126;
            
            ((double *) mem_46937)[i_45461 * binop_x_46872 + i_45457] = defunc_0_f_res_43545;
        }
    }
    if (mem_46980_cached_sizze_48557 < (int64_t) 9408) {
        err = lexical_realloc(ctx, &mem_46980, &mem_46980_cached_sizze_48557, (int64_t) 9408);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_46993_cached_sizze_48558 < (int64_t) 6272) {
        err = lexical_realloc(ctx, &mem_46993, &mem_46993_cached_sizze_48558, (int64_t) 6272);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    for (int64_t i_45483 = 0; i_45483 < (int64_t) 6; i_45483++) {
        int64_t binop_x_46182 = (int64_t) 784 * i_45483;
        
        for (int64_t i_45469 = 0; i_45469 < (int64_t) 28; i_45469++) {
            int64_t binop_y_46183 = (int64_t) 28 * i_45469;
            int64_t binop_x_46184 = binop_x_46182 + binop_y_46183;
            
            for (int64_t i_45465 = 0; i_45465 < (int64_t) 28; i_45465++) {
                int64_t binop_x_46185 = i_45465 + binop_x_46184;
                int64_t new_index_46186 = squot64(binop_x_46185, binop_x_46872);
                int64_t binop_y_46196 = new_index_46186 * binop_x_46872;
                int64_t new_index_46197 = binop_x_46185 - binop_y_46196;
                double x_43476 = ((double *) mem_46937)[new_index_46186 * binop_x_46872 + new_index_46197];
                double max_res_43477 = fmax64(0.0, x_43476);
                
                ((double *) mem_46993)[i_45469 * (int64_t) 28 + i_45465] = max_res_43477;
            }
        }
        for (int64_t i_45479 = 0; i_45479 < (int64_t) 14; i_45479++) {
            int64_t i_43481 = mul64((int64_t) 2, i_45479);
            int64_t j_43482 = add64((int64_t) 2, i_43481);
            int64_t i_p_m_t_s_43483 = add64((int64_t) 1, i_43481);
            bool zzero_leq_i_p_m_t_s_43484 = sle64((int64_t) 0, i_p_m_t_s_43483);
            bool i_p_m_t_s_leq_w_43485 = slt64(i_p_m_t_s_43483, (int64_t) 28);
            bool zzero_lte_i_43486 = sle64((int64_t) 0, i_43481);
            bool i_lte_j_43487 = sle64(i_43481, j_43482);
            bool y_43488 = i_p_m_t_s_leq_w_43485 && zzero_lte_i_43486;
            bool y_43489 = zzero_leq_i_p_m_t_s_43484 && y_43488;
            bool y_43490 = i_lte_j_43487 && y_43489;
            bool forwards_ok_43491 = zzero_lte_i_43486 && y_43490;
            
            for (int64_t i_45475 = 0; i_45475 < (int64_t) 14; i_45475++) {
                int64_t i_43494 = mul64((int64_t) 2, i_45475);
                int64_t j_43495 = add64((int64_t) 2, i_43494);
                int64_t i_p_m_t_s_43496 = add64((int64_t) 1, i_43494);
                bool zzero_leq_i_p_m_t_s_43497 = sle64((int64_t) 0, i_p_m_t_s_43496);
                bool i_p_m_t_s_leq_w_43498 = slt64(i_p_m_t_s_43496, (int64_t) 28);
                bool zzero_lte_i_43499 = sle64((int64_t) 0, i_43494);
                bool i_lte_j_43500 = sle64(i_43494, j_43495);
                bool y_43501 = i_p_m_t_s_leq_w_43498 && zzero_lte_i_43499;
                bool y_43502 = zzero_leq_i_p_m_t_s_43497 && y_43501;
                bool y_43503 = i_lte_j_43500 && y_43502;
                bool forwards_ok_43504 = zzero_lte_i_43499 && y_43503;
                bool index_ok_43505 = forwards_ok_43491 && forwards_ok_43504;
                bool index_certs_43506;
                
                if (!index_ok_43505) {
                    set_error(ctx, msgprintf("Error: %s%lld%s%lld%s%lld%s%lld%s%lld%s%lld%s\n\nBacktrace:\n%s", "Index [", (long long) i_43481, ":", (long long) j_43482, ", ", (long long) i_43494, ":", (long long) j_43495, "] out of bounds for array of shape [", (long long) (int64_t) 28, "][", (long long) (int64_t) 28, "].", "-> #0  ../layers/avgpool.fut:7:18-80\n   #1  /prelude/soacs.fut:59:9-10\n   #2  /prelude/array.fut:200:10-17\n   #3  /prelude/functional.fut:39:61-65\n   #4  /prelude/soacs.fut:59:9-10\n   #5  /prelude/array.fut:208:27-34\n   #6  ../layers/avgpool.fut:6:29-8:49\n   #7  ../layers/avgpool.fut:8:73-76\n   #8  ../lenet/lenet.fut:12:37-66\n   #9  cnn_test.fut:36:1-39:11\n"));
                    err = FUTHARK_PROGRAM_ERROR;
                    goto cleanup;
                }
                
                double defunc_0_reduce_res_45129;
                double redout_45471 = 0.0;
                
                for (int64_t i_45472 = 0; i_45472 < (int64_t) 4; i_45472++) {
                    int64_t new_index_45859 = squot64(i_45472, (int64_t) 2);
                    int64_t binop_y_45861 = (int64_t) 2 * new_index_45859;
                    int64_t new_index_45862 = i_45472 - binop_y_45861;
                    int64_t slice_45863 = i_43481 + new_index_45859;
                    int64_t slice_45864 = i_43494 + new_index_45862;
                    double x_43513 = ((double *) mem_46993)[slice_45863 * (int64_t) 28 + slice_45864];
                    double defunc_0_op_res_43512 = x_43513 + redout_45471;
                    double redout_tmp_48390 = defunc_0_op_res_43512;
                    
                    redout_45471 = redout_tmp_48390;
                }
                defunc_0_reduce_res_45129 = redout_45471;
                
                double defunc_0_f_res_43514 = defunc_0_reduce_res_45129 / 4.0;
                
                ((double *) mem_46980)[i_45483 * (int64_t) 196 + i_45479 * (int64_t) 14 + i_45475] = defunc_0_f_res_43514;
            }
        }
    }
    if (mem_47104_cached_sizze_48559 < (int64_t) 120000) {
        err = lexical_realloc(ctx, &mem_47104, &mem_47104_cached_sizze_48559, (int64_t) 120000);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    for (int64_t i_45491 = 0; i_45491 < (int64_t) 10; i_45491++) {
        int64_t j_41696 = add64((int64_t) 5, i_45491);
        int64_t i_p_m_t_s_41697 = add64((int64_t) 4, i_45491);
        bool zzero_leq_i_p_m_t_s_41698 = sle64((int64_t) 0, i_p_m_t_s_41697);
        bool i_p_m_t_s_leq_w_41699 = slt64(i_p_m_t_s_41697, (int64_t) 14);
        bool i_lte_j_41701 = sle64(i_45491, j_41696);
        bool y_41703 = zzero_leq_i_p_m_t_s_41698 && i_p_m_t_s_leq_w_41699;
        bool y_41704 = i_lte_j_41701 && y_41703;
        
        for (int64_t i_45487 = 0; i_45487 < (int64_t) 10; i_45487++) {
            int64_t j_41709 = add64((int64_t) 5, i_45487);
            int64_t i_p_m_t_s_41710 = add64((int64_t) 4, i_45487);
            bool zzero_leq_i_p_m_t_s_41711 = sle64((int64_t) 0, i_p_m_t_s_41710);
            bool i_p_m_t_s_leq_w_41712 = slt64(i_p_m_t_s_41710, (int64_t) 14);
            bool i_lte_j_41714 = sle64(i_45487, j_41709);
            bool y_41716 = zzero_leq_i_p_m_t_s_41711 && i_p_m_t_s_leq_w_41712;
            bool y_41717 = i_lte_j_41714 && y_41716;
            bool index_ok_41720 = y_41704 && y_41717;
            bool index_certs_41721;
            
            if (!index_ok_41720) {
                set_error(ctx, msgprintf("Error: %s%lld%s%lld%s%lld%s%lld%s%lld%s%lld%s\n\nBacktrace:\n%s", "Index [", (long long) i_45491, ":", (long long) j_41696, ", ", (long long) i_45487, ":", (long long) j_41709, "] out of bounds for array of shape [", (long long) (int64_t) 14, "][", (long long) (int64_t) 14, "].", "-> #0  ../layers/conv2d.fut:11:90-124\n   #1  ../layers/conv2d.fut:11:144-146\n   #2  /prelude/soacs.fut:59:9-10\n   #3  /prelude/array.fut:200:10-17\n   #4  /prelude/functional.fut:39:61-65\n   #5  /prelude/soacs.fut:59:9-10\n   #6  /prelude/array.fut:208:27-34\n   #7  ../layers/conv2d.fut:11:50-162\n   #8  ../layers/conv2d.fut:24:17-54\n   #9  ../lenet/lenet.fut:13:38-68\n   #10 cnn_test.fut:36:1-39:11\n"));
                err = FUTHARK_PROGRAM_ERROR;
                goto cleanup;
            }
            for (int64_t i_48393 = 0; i_48393 < (int64_t) 150; i_48393++) {
                double tmp_48394 = ((double *) mem_46980)[(int64_t) 14 * i_45491 + i_45487 + (squot64(i_48393, (int64_t) 25) * (int64_t) 196 + squot64(i_48393 - squot64(i_48393, (int64_t) 25) * (int64_t) 25, (int64_t) 5) * (int64_t) 14 + (i_48393 - squot64(i_48393, (int64_t) 25) * (int64_t) 25 - squot64(i_48393 - squot64(i_48393, (int64_t) 25) * (int64_t) 25, (int64_t) 5) * (int64_t) 5))];
                
                ((double *) mem_47104)[i_45491 * (int64_t) 1500 + i_45487 * (int64_t) 150 + i_48393] = tmp_48394;
            }
        }
    }
    if (mem_47156_cached_sizze_48560 < (int64_t) 12800) {
        err = lexical_realloc(ctx, &mem_47156, &mem_47156_cached_sizze_48560, (int64_t) 12800);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    for (int64_t i_45501 = 0; i_45501 < (int64_t) 16; i_45501++) {
        double x_43455 = ((double *) mem_46738.mem)[i_45501];
        int64_t binop_x_46152 = (int64_t) 150 * i_45501;
        
        for (int64_t i_45497 = 0; i_45497 < (int64_t) 100; i_45497++) {
            int64_t binop_x_46154 = (int64_t) 150 * i_45497;
            double defunc_0_reduce_res_45135;
            double redout_45493 = 0.0;
            
            for (int64_t i_45494 = 0; i_45494 < (int64_t) 150; i_45494++) {
                int64_t new_index_46153 = i_45494 + binop_x_46152;
                double x_43575 = ((double *) mem_46726.mem)[new_index_46153];
                int64_t binop_x_46155 = i_45494 + binop_x_46154;
                int64_t new_index_46156 = squot64(binop_x_46155, (int64_t) 1500);
                int64_t binop_y_46162 = (int64_t) 1500 * new_index_46156;
                int64_t binop_x_46163 = binop_x_46155 - binop_y_46162;
                int64_t new_index_46164 = squot64(binop_x_46163, (int64_t) 150);
                int64_t binop_y_46180 = (int64_t) 150 * new_index_46164;
                int64_t new_index_46181 = binop_x_46163 - binop_y_46180;
                double x_43576 = ((double *) mem_47104)[new_index_46156 * (int64_t) 1500 + new_index_46164 * (int64_t) 150 + new_index_46181];
                double defunc_0_f_res_43577 = x_43575 * x_43576;
                double defunc_0_op_res_43570 = defunc_0_f_res_43577 + redout_45493;
                double redout_tmp_48397 = defunc_0_op_res_43570;
                
                redout_45493 = redout_tmp_48397;
            }
            defunc_0_reduce_res_45135 = redout_45493;
            
            double defunc_0_f_res_43573 = x_43455 + defunc_0_reduce_res_45135;
            
            ((double *) mem_47156)[i_45501 * (int64_t) 100 + i_45497] = defunc_0_f_res_43573;
        }
    }
    if (mem_47196_cached_sizze_48561 < (int64_t) 3200) {
        err = lexical_realloc(ctx, &mem_47196, &mem_47196_cached_sizze_48561, (int64_t) 3200);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_47209_cached_sizze_48562 < (int64_t) 800) {
        err = lexical_realloc(ctx, &mem_47209, &mem_47209_cached_sizze_48562, (int64_t) 800);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    for (int64_t i_45523 = 0; i_45523 < (int64_t) 16; i_45523++) {
        int64_t binop_x_46136 = (int64_t) 100 * i_45523;
        
        for (int64_t i_45509 = 0; i_45509 < (int64_t) 10; i_45509++) {
            int64_t binop_y_46137 = (int64_t) 10 * i_45509;
            int64_t binop_x_46138 = binop_x_46136 + binop_y_46137;
            
            for (int64_t i_45505 = 0; i_45505 < (int64_t) 10; i_45505++) {
                int64_t binop_x_46139 = i_45505 + binop_x_46138;
                int64_t new_index_46140 = squot64(binop_x_46139, (int64_t) 100);
                int64_t binop_y_46150 = (int64_t) 100 * new_index_46140;
                int64_t new_index_46151 = binop_x_46139 - binop_y_46150;
                double x_43414 = ((double *) mem_47156)[new_index_46140 * (int64_t) 100 + new_index_46151];
                double max_res_43415 = fmax64(0.0, x_43414);
                
                ((double *) mem_47209)[i_45509 * (int64_t) 10 + i_45505] = max_res_43415;
            }
        }
        for (int64_t i_45519 = 0; i_45519 < (int64_t) 5; i_45519++) {
            int64_t i_43419 = mul64((int64_t) 2, i_45519);
            int64_t j_43420 = add64((int64_t) 2, i_43419);
            int64_t i_p_m_t_s_43421 = add64((int64_t) 1, i_43419);
            bool zzero_leq_i_p_m_t_s_43422 = sle64((int64_t) 0, i_p_m_t_s_43421);
            bool i_p_m_t_s_leq_w_43423 = slt64(i_p_m_t_s_43421, (int64_t) 10);
            bool zzero_lte_i_43424 = sle64((int64_t) 0, i_43419);
            bool i_lte_j_43425 = sle64(i_43419, j_43420);
            bool y_43426 = i_p_m_t_s_leq_w_43423 && zzero_lte_i_43424;
            bool y_43427 = zzero_leq_i_p_m_t_s_43422 && y_43426;
            bool y_43428 = i_lte_j_43425 && y_43427;
            bool forwards_ok_43429 = zzero_lte_i_43424 && y_43428;
            
            for (int64_t i_45515 = 0; i_45515 < (int64_t) 5; i_45515++) {
                int64_t i_43432 = mul64((int64_t) 2, i_45515);
                int64_t j_43433 = add64((int64_t) 2, i_43432);
                int64_t i_p_m_t_s_43434 = add64((int64_t) 1, i_43432);
                bool zzero_leq_i_p_m_t_s_43435 = sle64((int64_t) 0, i_p_m_t_s_43434);
                bool i_p_m_t_s_leq_w_43436 = slt64(i_p_m_t_s_43434, (int64_t) 10);
                bool zzero_lte_i_43437 = sle64((int64_t) 0, i_43432);
                bool i_lte_j_43438 = sle64(i_43432, j_43433);
                bool y_43439 = i_p_m_t_s_leq_w_43436 && zzero_lte_i_43437;
                bool y_43440 = zzero_leq_i_p_m_t_s_43435 && y_43439;
                bool y_43441 = i_lte_j_43438 && y_43440;
                bool forwards_ok_43442 = zzero_lte_i_43437 && y_43441;
                bool index_ok_43443 = forwards_ok_43429 && forwards_ok_43442;
                bool index_certs_43444;
                
                if (!index_ok_43443) {
                    set_error(ctx, msgprintf("Error: %s%lld%s%lld%s%lld%s%lld%s%lld%s%lld%s\n\nBacktrace:\n%s", "Index [", (long long) i_43419, ":", (long long) j_43420, ", ", (long long) i_43432, ":", (long long) j_43433, "] out of bounds for array of shape [", (long long) (int64_t) 10, "][", (long long) (int64_t) 10, "].", "-> #0  ../layers/avgpool.fut:7:18-80\n   #1  /prelude/soacs.fut:59:9-10\n   #2  /prelude/array.fut:200:10-17\n   #3  /prelude/functional.fut:39:61-65\n   #4  /prelude/soacs.fut:59:9-10\n   #5  /prelude/array.fut:208:27-34\n   #6  ../layers/avgpool.fut:6:29-8:49\n   #7  ../layers/avgpool.fut:8:73-76\n   #8  ../lenet/lenet.fut:15:36-65\n   #9  cnn_test.fut:36:1-39:11\n"));
                    err = FUTHARK_PROGRAM_ERROR;
                    goto cleanup;
                }
                
                double defunc_0_reduce_res_45138;
                double redout_45511 = 0.0;
                
                for (int64_t i_45512 = 0; i_45512 < (int64_t) 4; i_45512++) {
                    int64_t new_index_45845 = squot64(i_45512, (int64_t) 2);
                    int64_t binop_y_45847 = (int64_t) 2 * new_index_45845;
                    int64_t new_index_45848 = i_45512 - binop_y_45847;
                    int64_t slice_45849 = i_43419 + new_index_45845;
                    int64_t slice_45850 = i_43432 + new_index_45848;
                    double x_43451 = ((double *) mem_47209)[slice_45849 * (int64_t) 10 + slice_45850];
                    double defunc_0_op_res_43450 = x_43451 + redout_45511;
                    double redout_tmp_48403 = defunc_0_op_res_43450;
                    
                    redout_45511 = redout_tmp_48403;
                }
                defunc_0_reduce_res_45138 = redout_45511;
                
                double defunc_0_f_res_43452 = defunc_0_reduce_res_45138 / 4.0;
                
                ((double *) mem_47196)[i_45523 * (int64_t) 25 + i_45519 * (int64_t) 5 + i_45515] = defunc_0_f_res_43452;
            }
        }
    }
    if (mem_47320_cached_sizze_48563 < (int64_t) 960) {
        err = lexical_realloc(ctx, &mem_47320, &mem_47320_cached_sizze_48563, (int64_t) 960);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    for (int64_t i_45529 = 0; i_45529 < (int64_t) 120; i_45529++) {
        double x_43396 = ((double *) mem_46762.mem)[i_45529];
        int64_t binop_x_46134 = (int64_t) 400 * i_45529;
        double defunc_0_reduce_res_45143;
        double redout_45525 = 0.0;
        
        for (int64_t i_45526 = 0; i_45526 < (int64_t) 400; i_45526++) {
            int64_t new_index_45831 = squot64(i_45526, (int64_t) 25);
            int64_t binop_y_45833 = (int64_t) 25 * new_index_45831;
            int64_t binop_x_45834 = i_45526 - binop_y_45833;
            int64_t new_index_45835 = squot64(binop_x_45834, (int64_t) 5);
            int64_t binop_y_45843 = (int64_t) 5 * new_index_45835;
            int64_t new_index_45844 = binop_x_45834 - binop_y_45843;
            double x_43589 = ((double *) mem_47196)[new_index_45831 * (int64_t) 25 + new_index_45835 * (int64_t) 5 + new_index_45844];
            int64_t new_index_46135 = i_45526 + binop_x_46134;
            double x_43590 = ((double *) mem_46750.mem)[new_index_46135];
            double defunc_0_f_res_43591 = x_43589 * x_43590;
            double defunc_0_op_res_43404 = defunc_0_f_res_43591 + redout_45525;
            double redout_tmp_48405 = defunc_0_op_res_43404;
            
            redout_45525 = redout_tmp_48405;
        }
        defunc_0_reduce_res_45143 = redout_45525;
        
        double defunc_0_f_res_43406 = x_43396 + defunc_0_reduce_res_45143;
        double max_res_43408 = fmax64(0.0, defunc_0_f_res_43406);
        
        ((double *) mem_47320)[i_45529] = max_res_43408;
    }
    if (mem_47332_cached_sizze_48564 < (int64_t) 672) {
        err = lexical_realloc(ctx, &mem_47332, &mem_47332_cached_sizze_48564, (int64_t) 672);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    for (int64_t i_45535 = 0; i_45535 < (int64_t) 84; i_45535++) {
        double x_43381 = ((double *) mem_46786.mem)[i_45535];
        int64_t binop_x_46132 = (int64_t) 120 * i_45535;
        double defunc_0_reduce_res_45144;
        double redout_45531 = 0.0;
        
        for (int64_t i_45532 = 0; i_45532 < (int64_t) 120; i_45532++) {
            double x_43595 = ((double *) mem_47320)[i_45532];
            int64_t new_index_46133 = i_45532 + binop_x_46132;
            double x_43596 = ((double *) mem_46774.mem)[new_index_46133];
            double defunc_0_f_res_43597 = x_43595 * x_43596;
            double defunc_0_op_res_43389 = defunc_0_f_res_43597 + redout_45531;
            double redout_tmp_48407 = defunc_0_op_res_43389;
            
            redout_45531 = redout_tmp_48407;
        }
        defunc_0_reduce_res_45144 = redout_45531;
        
        double defunc_0_f_res_43391 = x_43381 + defunc_0_reduce_res_45144;
        double max_res_43393 = fmax64(0.0, defunc_0_f_res_43391);
        
        ((double *) mem_47332)[i_45535] = max_res_43393;
    }
    if (mem_47344_cached_sizze_48565 < (int64_t) 80) {
        err = lexical_realloc(ctx, &mem_47344, &mem_47344_cached_sizze_48565, (int64_t) 80);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    
    double defunc_0_reduce_res_45202;
    double redout_45540 = 0.0;
    
    for (int64_t i_45542 = 0; i_45542 < (int64_t) 10; i_45542++) {
        double x_44915 = ((double *) mem_46810.mem)[i_45542];
        int64_t binop_x_46130 = (int64_t) 84 * i_45542;
        double defunc_0_reduce_res_45145;
        double redout_45537 = 0.0;
        
        for (int64_t i_45538 = 0; i_45538 < (int64_t) 84; i_45538++) {
            double x_44920 = ((double *) mem_47332)[i_45538];
            int64_t new_index_46131 = i_45538 + binop_x_46130;
            double x_44921 = ((double *) mem_46798.mem)[new_index_46131];
            double defunc_0_f_res_44922 = x_44920 * x_44921;
            double defunc_0_op_res_44919 = defunc_0_f_res_44922 + redout_45537;
            double redout_tmp_48410 = defunc_0_op_res_44919;
            
            redout_45537 = redout_tmp_48410;
        }
        defunc_0_reduce_res_45145 = redout_45537;
        
        double defunc_0_f_res_44923 = x_44915 + defunc_0_reduce_res_45145;
        double defunc_0_f_res_44924 = futrts_exp64(defunc_0_f_res_44923);
        double defunc_0_op_res_41856 = defunc_0_f_res_44924 + redout_45540;
        
        ((double *) mem_47344)[i_45542] = defunc_0_f_res_44924;
        
        double redout_tmp_48408 = defunc_0_op_res_41856;
        
        redout_45540 = redout_tmp_48408;
    }
    defunc_0_reduce_res_45202 = redout_45540;
    
    double binop_y_43786 = 1.0 / defunc_0_reduce_res_45202;
    double binop_y_43788 = defunc_0_reduce_res_45202 * defunc_0_reduce_res_45202;
    
    if (mem_47356_cached_sizze_48566 < (int64_t) 80) {
        err = lexical_realloc(ctx, &mem_47356, &mem_47356_cached_sizze_48566, (int64_t) 80);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    
    double defunc_0_reduce_res_contrib_sum_45204;
    double redout_45545 = 0.0;
    
    for (int64_t i_45547 = 0; i_45547 < (int64_t) 10; i_45547++) {
        double x_44900 = ((double *) mem_47344)[i_45547];
        double x_44901 = ((double *) y_train_mem_46822.mem)[i_45547];
        double defunc_0_f_res_44902 = x_44900 / defunc_0_reduce_res_45202;
        double arg_44903 = x_44901 - defunc_0_f_res_44902;
        double binop_y_44904 = 2.0 * arg_44903;
        double binop_x_adj_44905 = 0.1 * binop_y_44904;
        double binop_y_adj_44906 = -1.0 * binop_x_adj_44905;
        double binop_x_adj_44907 = binop_y_43786 * binop_y_adj_44906;
        double binop_y_44908 = x_44900 / binop_y_43788;
        double binop_y_44909 = 0.0 - binop_y_44908;
        double binop_y_adj_44910 = binop_y_adj_44906 * binop_y_44909;
        double binlam_res_43797 = binop_y_adj_44910 + redout_45545;
        
        ((double *) mem_47356)[i_45547] = binop_x_adj_44907;
        
        double redout_tmp_48411 = binlam_res_43797;
        
        redout_45545 = redout_tmp_48411;
    }
    defunc_0_reduce_res_contrib_sum_45204 = redout_45545;
    if (mem_47368_cached_sizze_48567 < (int64_t) 672) {
        err = lexical_realloc(ctx, &mem_47368, &mem_47368_cached_sizze_48567, (int64_t) 672);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    for (int64_t nest_i_48413 = 0; nest_i_48413 < (int64_t) 84; nest_i_48413++) {
        ((double *) mem_47368)[nest_i_48413] = 0.0;
    }
    if (mem_47370_cached_sizze_48568 < (int64_t) 6720) {
        err = lexical_realloc(ctx, &mem_47370, &mem_47370_cached_sizze_48568, (int64_t) 6720);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_47372_cached_sizze_48569 < (int64_t) 80) {
        err = lexical_realloc(ctx, &mem_47372, &mem_47372_cached_sizze_48569, (int64_t) 80);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_47387_cached_sizze_48570 < (int64_t) 672) {
        err = lexical_realloc(ctx, &mem_47387, &mem_47387_cached_sizze_48570, (int64_t) 672);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (memblock_alloc(ctx, &mem_47412, (int64_t) 6720, "mem_47412")) {
        err = 1;
        goto cleanup;
    }
    if (memblock_alloc(ctx, &mem_47414, (int64_t) 80, "mem_47414")) {
        err = 1;
        goto cleanup;
    }
    
    bool acc_cert_p_43820;
    
    for (int64_t i_45561 = 0; i_45561 < (int64_t) 10; i_45561++) {
        double x_43804 = ((double *) mem_46810.mem)[i_45561];
        double map_adj_p_43802 = ((double *) mem_47356)[i_45561];
        double defunc_0_f_res_adj_43823 = map_adj_p_43802 + defunc_0_reduce_res_contrib_sum_45204;
        int64_t binop_x_46128 = (int64_t) 84 * i_45561;
        double defunc_0_reduce_res_45146;
        double redout_45549 = 0.0;
        
        for (int64_t i_45550 = 0; i_45550 < (int64_t) 84; i_45550++) {
            double x_44960 = ((double *) mem_47332)[i_45550];
            int64_t new_index_46129 = i_45550 + binop_x_46128;
            double x_44961 = ((double *) mem_46798.mem)[new_index_46129];
            double defunc_0_f_res_44962 = x_44960 * x_44961;
            double defunc_0_op_res_43808 = defunc_0_f_res_44962 + redout_45549;
            double redout_tmp_48417 = defunc_0_op_res_43808;
            
            redout_45549 = redout_tmp_48417;
        }
        defunc_0_reduce_res_45146 = redout_45549;
        
        double defunc_0_f_res_43812 = x_43804 + defunc_0_reduce_res_45146;
        double binop_y_43826 = futrts_exp64(defunc_0_f_res_43812);
        double contrib_43827 = defunc_0_f_res_adj_43823 * binop_y_43826;
        
        for (int64_t i_45554 = 0; i_45554 < (int64_t) 84; i_45554++) {
            double x_44950 = ((double *) mem_47332)[i_45554];
            int64_t new_index_46127 = i_45554 + binop_x_46128;
            double x_44951 = ((double *) mem_46798.mem)[new_index_46127];
            double binop_x_adj_44954 = contrib_43827 * x_44951;
            double binop_y_adj_44955 = contrib_43827 * x_44950;
            
            // UpdateAcc
            {
                int64_t idx_43819 = i_45554;
                
                if (sle64((int64_t) 0, i_45554) && slt64(i_45554, (int64_t) 84)) {
                    double x_43816;
                    double y_43817;
                    
                    x_43816 = ((double *) mem_47368)[i_45554];
                    y_43817 = binop_x_adj_44954;
                    
                    double binlam_res_43818 = x_43816 + y_43817;
                    
                    ((double *) mem_47368)[i_45554] = binlam_res_43818;
                }
            }
            ((double *) mem_47387)[i_45554] = binop_y_adj_44955;
        }
        if ((int64_t) 672 > 0)
            memmove(mem_47370 + i_45561 * (int64_t) 84 * (int64_t) 8, mem_47387 + (int64_t) 0, (int64_t) 672);
        ((double *) mem_47372)[i_45561] = contrib_43827;
    }
    if ((int64_t) 6720 > 0)
        memmove(mem_47412.mem + (int64_t) 0, mem_47370 + (int64_t) 0, (int64_t) 6720);
    if ((int64_t) 80 > 0)
        memmove(mem_47414.mem + (int64_t) 0, mem_47372 + (int64_t) 0, (int64_t) 80);
    if (mem_47416_cached_sizze_48571 < (int64_t) 960) {
        err = lexical_realloc(ctx, &mem_47416, &mem_47416_cached_sizze_48571, (int64_t) 960);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    for (int64_t nest_i_48420 = 0; nest_i_48420 < (int64_t) 120; nest_i_48420++) {
        ((double *) mem_47416)[nest_i_48420] = 0.0;
    }
    if (mem_47418_cached_sizze_48572 < (int64_t) 80640) {
        err = lexical_realloc(ctx, &mem_47418, &mem_47418_cached_sizze_48572, (int64_t) 80640);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_47420_cached_sizze_48573 < (int64_t) 672) {
        err = lexical_realloc(ctx, &mem_47420, &mem_47420_cached_sizze_48573, (int64_t) 672);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_47435_cached_sizze_48574 < (int64_t) 960) {
        err = lexical_realloc(ctx, &mem_47435, &mem_47435_cached_sizze_48574, (int64_t) 960);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (memblock_alloc(ctx, &mem_47460, (int64_t) 80640, "mem_47460")) {
        err = 1;
        goto cleanup;
    }
    if (memblock_alloc(ctx, &mem_47462, (int64_t) 672, "mem_47462")) {
        err = 1;
        goto cleanup;
    }
    
    bool acc_cert_p_43869;
    
    for (int64_t i_45576 = 0; i_45576 < (int64_t) 84; i_45576++) {
        double x_43853 = ((double *) mem_46786.mem)[i_45576];
        double map_adj_p_43851 = ((double *) mem_47368)[i_45576];
        int64_t binop_x_46124 = (int64_t) 120 * i_45576;
        double defunc_0_reduce_res_45152;
        double redout_45564 = 0.0;
        
        for (int64_t i_45565 = 0; i_45565 < (int64_t) 120; i_45565++) {
            double x_44985 = ((double *) mem_47320)[i_45565];
            int64_t new_index_46125 = i_45565 + binop_x_46124;
            double x_44986 = ((double *) mem_46774.mem)[new_index_46125];
            double defunc_0_f_res_44987 = x_44985 * x_44986;
            double defunc_0_op_res_43857 = defunc_0_f_res_44987 + redout_45564;
            double redout_tmp_48424 = defunc_0_op_res_43857;
            
            redout_45564 = redout_tmp_48424;
        }
        defunc_0_reduce_res_45152 = redout_45564;
        
        double defunc_0_f_res_43861 = x_43853 + defunc_0_reduce_res_45152;
        bool convop_x_43878 = 0.0 < defunc_0_f_res_43861;
        int32_t convop_x_43879 = btoi_bool_i32(convop_x_43878);
        double binop_y_43880 = sitofp_i32_f64(convop_x_43879);
        double binop_y_adj_43881 = map_adj_p_43851 * binop_y_43880;
        
        for (int64_t i_45569 = 0; i_45569 < (int64_t) 120; i_45569++) {
            double x_44975 = ((double *) mem_47320)[i_45569];
            int64_t new_index_46123 = i_45569 + binop_x_46124;
            double x_44976 = ((double *) mem_46774.mem)[new_index_46123];
            double binop_x_adj_44979 = binop_y_adj_43881 * x_44976;
            double binop_y_adj_44980 = binop_y_adj_43881 * x_44975;
            
            // UpdateAcc
            {
                int64_t idx_43868 = i_45569;
                
                if (sle64((int64_t) 0, i_45569) && slt64(i_45569, (int64_t) 120)) {
                    double x_43865;
                    double y_43866;
                    
                    x_43865 = ((double *) mem_47416)[i_45569];
                    y_43866 = binop_x_adj_44979;
                    
                    double binlam_res_43867 = x_43865 + y_43866;
                    
                    ((double *) mem_47416)[i_45569] = binlam_res_43867;
                }
            }
            ((double *) mem_47435)[i_45569] = binop_y_adj_44980;
        }
        if ((int64_t) 960 > 0)
            memmove(mem_47418 + i_45576 * (int64_t) 120 * (int64_t) 8, mem_47435 + (int64_t) 0, (int64_t) 960);
        ((double *) mem_47420)[i_45576] = binop_y_adj_43881;
    }
    if ((int64_t) 80640 > 0)
        memmove(mem_47460.mem + (int64_t) 0, mem_47418 + (int64_t) 0, (int64_t) 80640);
    if ((int64_t) 672 > 0)
        memmove(mem_47462.mem + (int64_t) 0, mem_47420 + (int64_t) 0, (int64_t) 672);
    if (mem_47464_cached_sizze_48575 < (int64_t) 3200) {
        err = lexical_realloc(ctx, &mem_47464, &mem_47464_cached_sizze_48575, (int64_t) 3200);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    for (int64_t nest_i_48427 = 0; nest_i_48427 < (int64_t) 400; nest_i_48427++) {
        ((double *) mem_47464)[nest_i_48427] = 0.0;
    }
    if (mem_47466_cached_sizze_48576 < (int64_t) 384000) {
        err = lexical_realloc(ctx, &mem_47466, &mem_47466_cached_sizze_48576, (int64_t) 384000);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_47468_cached_sizze_48577 < (int64_t) 960) {
        err = lexical_realloc(ctx, &mem_47468, &mem_47468_cached_sizze_48577, (int64_t) 960);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_47483_cached_sizze_48578 < (int64_t) 3200) {
        err = lexical_realloc(ctx, &mem_47483, &mem_47483_cached_sizze_48578, (int64_t) 3200);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (memblock_alloc(ctx, &mem_47508, (int64_t) 384000, "mem_47508")) {
        err = 1;
        goto cleanup;
    }
    if (memblock_alloc(ctx, &mem_47510, (int64_t) 960, "mem_47510")) {
        err = 1;
        goto cleanup;
    }
    
    bool acc_cert_p_43923;
    
    for (int64_t i_45591 = 0; i_45591 < (int64_t) 120; i_45591++) {
        double x_43907 = ((double *) mem_46762.mem)[i_45591];
        double map_adj_p_43905 = ((double *) mem_47416)[i_45591];
        int64_t binop_x_46120 = (int64_t) 400 * i_45591;
        double defunc_0_reduce_res_45158;
        double redout_45579 = 0.0;
        
        for (int64_t i_45580 = 0; i_45580 < (int64_t) 400; i_45580++) {
            int64_t new_index_45813 = squot64(i_45580, (int64_t) 25);
            int64_t binop_y_45815 = (int64_t) 25 * new_index_45813;
            int64_t binop_x_45816 = i_45580 - binop_y_45815;
            int64_t new_index_45817 = squot64(binop_x_45816, (int64_t) 5);
            int64_t binop_y_45825 = (int64_t) 5 * new_index_45817;
            int64_t new_index_45826 = binop_x_45816 - binop_y_45825;
            double x_45010 = ((double *) mem_47196)[new_index_45813 * (int64_t) 25 + new_index_45817 * (int64_t) 5 + new_index_45826];
            int64_t new_index_46121 = i_45580 + binop_x_46120;
            double x_45011 = ((double *) mem_46750.mem)[new_index_46121];
            double defunc_0_f_res_45012 = x_45010 * x_45011;
            double defunc_0_op_res_43911 = defunc_0_f_res_45012 + redout_45579;
            double redout_tmp_48431 = defunc_0_op_res_43911;
            
            redout_45579 = redout_tmp_48431;
        }
        defunc_0_reduce_res_45158 = redout_45579;
        
        double defunc_0_f_res_43915 = x_43907 + defunc_0_reduce_res_45158;
        bool convop_x_43932 = 0.0 < defunc_0_f_res_43915;
        int32_t convop_x_43933 = btoi_bool_i32(convop_x_43932);
        double binop_y_43934 = sitofp_i32_f64(convop_x_43933);
        double binop_y_adj_43935 = map_adj_p_43905 * binop_y_43934;
        
        for (int64_t i_45584 = 0; i_45584 < (int64_t) 400; i_45584++) {
            int64_t new_index_45797 = squot64(i_45584, (int64_t) 25);
            int64_t binop_y_45799 = (int64_t) 25 * new_index_45797;
            int64_t binop_x_45800 = i_45584 - binop_y_45799;
            int64_t new_index_45801 = squot64(binop_x_45800, (int64_t) 5);
            int64_t binop_y_45809 = (int64_t) 5 * new_index_45801;
            int64_t new_index_45810 = binop_x_45800 - binop_y_45809;
            double x_45000 = ((double *) mem_47196)[new_index_45797 * (int64_t) 25 + new_index_45801 * (int64_t) 5 + new_index_45810];
            int64_t new_index_46119 = i_45584 + binop_x_46120;
            double x_45001 = ((double *) mem_46750.mem)[new_index_46119];
            double binop_x_adj_45004 = binop_y_adj_43935 * x_45001;
            double binop_y_adj_45005 = binop_y_adj_43935 * x_45000;
            
            // UpdateAcc
            {
                int64_t idx_43922 = i_45584;
                
                if (sle64((int64_t) 0, i_45584) && slt64(i_45584, (int64_t) 400)) {
                    double x_43919;
                    double y_43920;
                    
                    x_43919 = ((double *) mem_47464)[i_45584];
                    y_43920 = binop_x_adj_45004;
                    
                    double binlam_res_43921 = x_43919 + y_43920;
                    
                    ((double *) mem_47464)[i_45584] = binlam_res_43921;
                }
            }
            ((double *) mem_47483)[i_45584] = binop_y_adj_45005;
        }
        if ((int64_t) 3200 > 0)
            memmove(mem_47466 + i_45591 * (int64_t) 400 * (int64_t) 8, mem_47483 + (int64_t) 0, (int64_t) 3200);
        ((double *) mem_47468)[i_45591] = binop_y_adj_43935;
    }
    if ((int64_t) 384000 > 0)
        memmove(mem_47508.mem + (int64_t) 0, mem_47466 + (int64_t) 0, (int64_t) 384000);
    if ((int64_t) 960 > 0)
        memmove(mem_47510.mem + (int64_t) 0, mem_47468 + (int64_t) 0, (int64_t) 960);
    if (mem_47512_cached_sizze_48579 < (int64_t) 12800) {
        err = lexical_realloc(ctx, &mem_47512, &mem_47512_cached_sizze_48579, (int64_t) 12800);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_47525_cached_sizze_48580 < (int64_t) 800) {
        err = lexical_realloc(ctx, &mem_47525, &mem_47525_cached_sizze_48580, (int64_t) 800);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    for (int64_t i_45612 = 0; i_45612 < (int64_t) 16; i_45612++) {
        for (int64_t nest_i_48435 = 0; nest_i_48435 < (int64_t) 10; nest_i_48435++) {
            for (int64_t nest_i_48436 = 0; nest_i_48436 < (int64_t) 10; nest_i_48436++) {
                ((double *) mem_47525)[nest_i_48435 * (int64_t) 10 + nest_i_48436] = 0.0;
            }
        }
        
        int64_t binop_x_46114 = (int64_t) 25 * i_45612;
        bool acc_cert_p_44055;
        
        for (int64_t i_45601 = 0; i_45601 < (int64_t) 5; i_45601++) {
            int64_t i_44014 = mul64((int64_t) 2, i_45601);
            int64_t binop_y_46115 = (int64_t) 5 * i_45601;
            int64_t binop_x_46116 = binop_x_46114 + binop_y_46115;
            
            for (int64_t i_45599 = 0; i_45599 < (int64_t) 5; i_45599++) {
                int64_t new_index_46117 = i_45599 + binop_x_46116;
                double map_adj_p_44059 = ((double *) mem_47464)[new_index_46117];
                int64_t i_44061 = mul64((int64_t) 2, i_45599);
                double binop_x_adj_44086 = 0.25 * map_adj_p_44059;
                
                for (int64_t i_45597 = 0; i_45597 < (int64_t) 2; i_45597++) {
                    int64_t index_44100 = i_44014 + i_45597;
                    
                    for (int64_t i_45595 = 0; i_45595 < (int64_t) 2; i_45595++) {
                        int64_t index_44101 = i_44061 + i_45595;
                        
                        // UpdateAcc
                        {
                            int64_t idx_44053 = index_44100;
                            int64_t idx_44054 = index_44101;
                            
                            if ((sle64((int64_t) 0, index_44100) && slt64(index_44100, (int64_t) 10)) && (sle64((int64_t) 0, index_44101) && slt64(index_44101, (int64_t) 10))) {
                                double x_44050;
                                double y_44051;
                                
                                x_44050 = ((double *) mem_47525)[index_44100 * (int64_t) 10 + index_44101];
                                y_44051 = binop_x_adj_44086;
                                
                                double binlam_res_44052 = x_44050 + y_44051;
                                
                                ((double *) mem_47525)[index_44100 * (int64_t) 10 + index_44101] = binlam_res_44052;
                            }
                        }
                    }
                }
            }
        }
        
        int64_t binop_x_46098 = (int64_t) 100 * i_45612;
        
        for (int64_t i_45608 = 0; i_45608 < (int64_t) 10; i_45608++) {
            int64_t binop_y_46099 = (int64_t) 10 * i_45608;
            int64_t binop_x_46100 = binop_x_46098 + binop_y_46099;
            
            for (int64_t i_45604 = 0; i_45604 < (int64_t) 10; i_45604++) {
                int64_t binop_x_46101 = i_45604 + binop_x_46100;
                int64_t new_index_46102 = squot64(binop_x_46101, (int64_t) 100);
                int64_t binop_y_46112 = (int64_t) 100 * new_index_46102;
                int64_t new_index_46113 = binop_x_46101 - binop_y_46112;
                double x_44202 = ((double *) mem_47156)[new_index_46102 * (int64_t) 100 + new_index_46113];
                double map_adj_p_44201 = ((double *) mem_47525)[i_45608 * (int64_t) 10 + i_45604];
                bool convop_x_44208 = 0.0 < x_44202;
                int32_t convop_x_44209 = btoi_bool_i32(convop_x_44208);
                double binop_y_44210 = sitofp_i32_f64(convop_x_44209);
                double binop_y_adj_44211 = map_adj_p_44201 * binop_y_44210;
                
                ((double *) mem_47512)[i_45612 * (int64_t) 100 + i_45608 * (int64_t) 10 + i_45604] = binop_y_adj_44211;
            }
        }
    }
    if (mem_47598_cached_sizze_48581 < (int64_t) 120000) {
        err = lexical_realloc(ctx, &mem_47598, &mem_47598_cached_sizze_48581, (int64_t) 120000);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    for (int64_t nest_i_48443 = 0; nest_i_48443 < (int64_t) 100; nest_i_48443++) {
        for (int64_t nest_i_48444 = 0; nest_i_48444 < (int64_t) 150; nest_i_48444++) {
            ((double *) mem_47598)[nest_i_48443 * (int64_t) 150 + nest_i_48444] = 0.0;
        }
    }
    if (mem_47600_cached_sizze_48582 < (int64_t) 19200) {
        err = lexical_realloc(ctx, &mem_47600, &mem_47600_cached_sizze_48582, (int64_t) 19200);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_47602_cached_sizze_48583 < (int64_t) 128) {
        err = lexical_realloc(ctx, &mem_47602, &mem_47602_cached_sizze_48583, (int64_t) 128);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_47617_cached_sizze_48584 < (int64_t) 1200) {
        err = lexical_realloc(ctx, &mem_47617, &mem_47617_cached_sizze_48584, (int64_t) 1200);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_47632_cached_sizze_48585 < (int64_t) 19200) {
        err = lexical_realloc(ctx, &mem_47632, &mem_47632_cached_sizze_48585, (int64_t) 19200);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (memblock_alloc(ctx, &mem_47634, (int64_t) 128, "mem_47634")) {
        err = 1;
        goto cleanup;
    }
    
    bool acc_cert_p_44239;
    
    for (int64_t i_45627 = 0; i_45627 < (int64_t) 16; i_45627++) {
        for (int64_t nest_i_48448 = 0; nest_i_48448 < (int64_t) 150; nest_i_48448++) {
            ((double *) mem_47617)[nest_i_48448] = 0.0;
        }
        
        int64_t binop_x_46070 = (int64_t) 100 * i_45627;
        double x_contrib_sum_45174;
        double redout_45614 = 0.0;
        
        for (int64_t i_45615 = 0; i_45615 < (int64_t) 100; i_45615++) {
            int64_t binop_x_46071 = i_45615 + binop_x_46070;
            int64_t new_index_46072 = squot64(binop_x_46071, (int64_t) 100);
            int64_t binop_y_46078 = (int64_t) 100 * new_index_46072;
            int64_t binop_x_46079 = binop_x_46071 - binop_y_46078;
            int64_t new_index_46080 = squot64(binop_x_46079, (int64_t) 10);
            int64_t binop_y_46096 = (int64_t) 10 * new_index_46080;
            int64_t new_index_46097 = binop_x_46079 - binop_y_46096;
            double x_44287 = ((double *) mem_47512)[new_index_46072 * (int64_t) 100 + new_index_46080 * (int64_t) 10 + new_index_46097];
            double binlam_res_44286 = x_44287 + redout_45614;
            double redout_tmp_48449 = binlam_res_44286;
            
            redout_45614 = redout_tmp_48449;
        }
        x_contrib_sum_45174 = redout_45614;
        
        int64_t binop_x_46040 = (int64_t) 150 * i_45627;
        bool acc_cert_p_44259;
        
        for (int64_t i_45621 = 0; i_45621 < (int64_t) 100; i_45621++) {
            int64_t binop_x_46013 = i_45621 + binop_x_46070;
            int64_t new_index_46014 = squot64(binop_x_46013, (int64_t) 100);
            int64_t binop_y_46020 = (int64_t) 100 * new_index_46014;
            int64_t binop_x_46021 = binop_x_46013 - binop_y_46020;
            int64_t new_index_46022 = squot64(binop_x_46021, (int64_t) 10);
            int64_t binop_y_46038 = (int64_t) 10 * new_index_46022;
            int64_t new_index_46039 = binop_x_46021 - binop_y_46038;
            double map_adj_p_45031 = ((double *) mem_47512)[new_index_46014 * (int64_t) 100 + new_index_46022 * (int64_t) 10 + new_index_46039];
            int64_t binop_x_46042 = (int64_t) 150 * i_45621;
            
            for (int64_t i_45618 = 0; i_45618 < (int64_t) 150; i_45618++) {
                int64_t new_index_46041 = i_45618 + binop_x_46040;
                double x_45069 = ((double *) mem_46726.mem)[new_index_46041];
                int64_t binop_x_46043 = i_45618 + binop_x_46042;
                int64_t new_index_46044 = squot64(binop_x_46043, (int64_t) 1500);
                int64_t binop_y_46050 = (int64_t) 1500 * new_index_46044;
                int64_t binop_x_46051 = binop_x_46043 - binop_y_46050;
                int64_t new_index_46052 = squot64(binop_x_46051, (int64_t) 150);
                int64_t binop_y_46068 = (int64_t) 150 * new_index_46052;
                int64_t new_index_46069 = binop_x_46051 - binop_y_46068;
                double x_45070 = ((double *) mem_47104)[new_index_46044 * (int64_t) 1500 + new_index_46052 * (int64_t) 150 + new_index_46069];
                double binop_x_adj_45073 = map_adj_p_45031 * x_45070;
                double binop_y_adj_45074 = map_adj_p_45031 * x_45069;
                
                // UpdateAcc
                {
                    int64_t idx_44237 = i_45621;
                    int64_t idx_44238 = i_45618;
                    
                    if ((sle64((int64_t) 0, i_45621) && slt64(i_45621, (int64_t) 100)) && (sle64((int64_t) 0, i_45618) && slt64(i_45618, (int64_t) 150))) {
                        double x_44234;
                        double y_44235;
                        
                        x_44234 = ((double *) mem_47598)[i_45621 * (int64_t) 150 + i_45618];
                        y_44235 = binop_y_adj_45074;
                        
                        double binlam_res_44236 = x_44234 + y_44235;
                        
                        ((double *) mem_47598)[i_45621 * (int64_t) 150 + i_45618] = binlam_res_44236;
                    }
                }
                // UpdateAcc
                {
                    int64_t idx_44258 = i_45618;
                    
                    if (sle64((int64_t) 0, i_45618) && slt64(i_45618, (int64_t) 150)) {
                        double x_44255;
                        double y_44256;
                        
                        x_44255 = ((double *) mem_47617)[i_45618];
                        y_44256 = binop_x_adj_45073;
                        
                        double binlam_res_44257 = x_44255 + y_44256;
                        
                        ((double *) mem_47617)[i_45618] = binlam_res_44257;
                    }
                }
            }
        }
        if ((int64_t) 1200 > 0)
            memmove(mem_47600 + i_45627 * (int64_t) 150 * (int64_t) 8, mem_47617 + (int64_t) 0, (int64_t) 1200);
        ((double *) mem_47602)[i_45627] = x_contrib_sum_45174;
    }
    if ((int64_t) 19200 > 0)
        memmove(mem_47632 + (int64_t) 0, mem_47600 + (int64_t) 0, (int64_t) 19200);
    if ((int64_t) 128 > 0)
        memmove(mem_47634.mem + (int64_t) 0, mem_47602 + (int64_t) 0, (int64_t) 128);
    if (mem_47636_cached_sizze_48586 < (int64_t) 9408) {
        err = lexical_realloc(ctx, &mem_47636, &mem_47636_cached_sizze_48586, (int64_t) 9408);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    for (int64_t nest_i_48454 = 0; nest_i_48454 < (int64_t) 6; nest_i_48454++) {
        for (int64_t nest_i_48455 = 0; nest_i_48455 < (int64_t) 14; nest_i_48455++) {
            for (int64_t nest_i_48456 = 0; nest_i_48456 < (int64_t) 14; nest_i_48456++) {
                ((double *) mem_47636)[nest_i_48454 * (int64_t) 196 + nest_i_48455 * (int64_t) 14 + nest_i_48456] = 0.0;
            }
        }
    }
    
    bool acc_cert_p_44355;
    
    for (int64_t i_45639 = 0; i_45639 < (int64_t) 10; i_45639++) {
        int64_t binop_x_45984 = (int64_t) 1500 * i_45639;
        
        for (int64_t i_45637 = 0; i_45637 < (int64_t) 10; i_45637++) {
            int64_t binop_y_45985 = (int64_t) 150 * i_45637;
            int64_t binop_x_45986 = binop_x_45984 + binop_y_45985;
            
            for (int64_t i_45635 = 0; i_45635 < (int64_t) 6; i_45635++) {
                int64_t binop_y_45987 = (int64_t) 25 * i_45635;
                int64_t binop_x_45988 = binop_x_45986 + binop_y_45987;
                
                for (int64_t i_45633 = 0; i_45633 < (int64_t) 5; i_45633++) {
                    int64_t index_44392 = i_45633 + i_45639;
                    int64_t binop_y_45989 = (int64_t) 5 * i_45633;
                    int64_t binop_x_45990 = binop_x_45988 + binop_y_45989;
                    
                    for (int64_t i_45631 = 0; i_45631 < (int64_t) 5; i_45631++) {
                        int64_t binop_x_45991 = i_45631 + binop_x_45990;
                        int64_t new_index_45992 = squot64(binop_x_45991, (int64_t) 150);
                        int64_t binop_y_46010 = (int64_t) 150 * new_index_45992;
                        int64_t new_index_46011 = binop_x_45991 - binop_y_46010;
                        double adj_reshape_p_p_p_44390 = ((double *) mem_47598)[new_index_45992 * (int64_t) 150 + new_index_46011];
                        int64_t index_44393 = i_45631 + i_45637;
                        
                        // UpdateAcc
                        {
                            int64_t idx_44350 = i_45635;
                            int64_t idx_44351 = index_44392;
                            int64_t idx_44352 = index_44393;
                            
                            if (((sle64((int64_t) 0, i_45635) && slt64(i_45635, (int64_t) 6)) && (sle64((int64_t) 0, index_44392) && slt64(index_44392, (int64_t) 14))) && (sle64((int64_t) 0, index_44393) && slt64(index_44393, (int64_t) 14))) {
                                double x_44347;
                                double y_44348;
                                
                                x_44347 = ((double *) mem_47636)[i_45635 * (int64_t) 196 + index_44392 * (int64_t) 14 + index_44393];
                                y_44348 = adj_reshape_p_p_p_44390;
                                
                                double binlam_res_44349 = x_44347 + y_44348;
                                
                                ((double *) mem_47636)[i_45635 * (int64_t) 196 + index_44392 * (int64_t) 14 + index_44393] = binlam_res_44349;
                            }
                        }
                    }
                }
            }
        }
    }
    if (mem_47638_cached_sizze_48587 < (int64_t) 37632) {
        err = lexical_realloc(ctx, &mem_47638, &mem_47638_cached_sizze_48587, (int64_t) 37632);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_47651_cached_sizze_48588 < (int64_t) 6272) {
        err = lexical_realloc(ctx, &mem_47651, &mem_47651_cached_sizze_48588, (int64_t) 6272);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    for (int64_t i_45658 = 0; i_45658 < (int64_t) 6; i_45658++) {
        for (int64_t nest_i_48463 = 0; nest_i_48463 < (int64_t) 28; nest_i_48463++) {
            for (int64_t nest_i_48464 = 0; nest_i_48464 < (int64_t) 28; nest_i_48464++) {
                ((double *) mem_47651)[nest_i_48463 * (int64_t) 28 + nest_i_48464] = 0.0;
            }
        }
        
        bool acc_cert_p_44580;
        
        for (int64_t i_45647 = 0; i_45647 < (int64_t) 14; i_45647++) {
            int64_t i_44539 = mul64((int64_t) 2, i_45647);
            
            for (int64_t i_45645 = 0; i_45645 < (int64_t) 14; i_45645++) {
                double map_adj_p_44584 = ((double *) mem_47636)[i_45658 * (int64_t) 196 + i_45647 * (int64_t) 14 + i_45645];
                int64_t i_44586 = mul64((int64_t) 2, i_45645);
                double binop_x_adj_44611 = 0.25 * map_adj_p_44584;
                
                for (int64_t i_45643 = 0; i_45643 < (int64_t) 2; i_45643++) {
                    int64_t index_44625 = i_44539 + i_45643;
                    
                    for (int64_t i_45641 = 0; i_45641 < (int64_t) 2; i_45641++) {
                        int64_t index_44626 = i_44586 + i_45641;
                        
                        // UpdateAcc
                        {
                            int64_t idx_44578 = index_44625;
                            int64_t idx_44579 = index_44626;
                            
                            if ((sle64((int64_t) 0, index_44625) && slt64(index_44625, (int64_t) 28)) && (sle64((int64_t) 0, index_44626) && slt64(index_44626, (int64_t) 28))) {
                                double x_44575;
                                double y_44576;
                                
                                x_44575 = ((double *) mem_47651)[index_44625 * (int64_t) 28 + index_44626];
                                y_44576 = binop_x_adj_44611;
                                
                                double binlam_res_44577 = x_44575 + y_44576;
                                
                                ((double *) mem_47651)[index_44625 * (int64_t) 28 + index_44626] = binlam_res_44577;
                            }
                        }
                    }
                }
            }
        }
        
        int64_t binop_x_45968 = (int64_t) 784 * i_45658;
        
        for (int64_t i_45654 = 0; i_45654 < (int64_t) 28; i_45654++) {
            int64_t binop_y_45969 = (int64_t) 28 * i_45654;
            int64_t binop_x_45970 = binop_x_45968 + binop_y_45969;
            
            for (int64_t i_45650 = 0; i_45650 < (int64_t) 28; i_45650++) {
                int64_t binop_x_45971 = i_45650 + binop_x_45970;
                int64_t new_index_45972 = squot64(binop_x_45971, binop_x_46872);
                int64_t binop_y_45982 = new_index_45972 * binop_x_46872;
                int64_t new_index_45983 = binop_x_45971 - binop_y_45982;
                double x_44727 = ((double *) mem_46937)[new_index_45972 * binop_x_46872 + new_index_45983];
                double map_adj_p_44726 = ((double *) mem_47651)[i_45654 * (int64_t) 28 + i_45650];
                bool convop_x_44733 = 0.0 < x_44727;
                int32_t convop_x_44734 = btoi_bool_i32(convop_x_44733);
                double binop_y_44735 = sitofp_i32_f64(convop_x_44734);
                double binop_y_adj_44736 = map_adj_p_44726 * binop_y_44735;
                
                ((double *) mem_47638)[i_45658 * (int64_t) 784 + i_45654 * (int64_t) 28 + i_45650] = binop_y_adj_44736;
            }
        }
    }
    if (mem_47724_cached_sizze_48589 < (int64_t) 1200) {
        err = lexical_realloc(ctx, &mem_47724, &mem_47724_cached_sizze_48589, (int64_t) 1200);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (memblock_alloc(ctx, &mem_47726, (int64_t) 48, "mem_47726")) {
        err = 1;
        goto cleanup;
    }
    if (mem_47741_cached_sizze_48590 < (int64_t) 200) {
        err = lexical_realloc(ctx, &mem_47741, &mem_47741_cached_sizze_48590, (int64_t) 200);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    for (int64_t i_45670 = 0; i_45670 < (int64_t) 6; i_45670++) {
        for (int64_t nest_i_48473 = 0; nest_i_48473 < (int64_t) 25; nest_i_48473++) {
            ((double *) mem_47741)[nest_i_48473] = 0.0;
        }
        
        int64_t binop_x_45940 = i_45670 * binop_x_46872;
        double x_contrib_sum_45191;
        double redout_45660 = 0.0;
        
        for (int64_t i_45661 = 0; i_45661 < binop_x_46872; i_45661++) {
            int64_t binop_x_45941 = i_45661 + binop_x_45940;
            int64_t new_index_45942 = squot64(binop_x_45941, (int64_t) 784);
            int64_t binop_y_45948 = (int64_t) 784 * new_index_45942;
            int64_t binop_x_45949 = binop_x_45941 - binop_y_45948;
            int64_t new_index_45950 = squot64(binop_x_45949, (int64_t) 28);
            int64_t binop_y_45966 = (int64_t) 28 * new_index_45950;
            int64_t new_index_45967 = binop_x_45949 - binop_y_45966;
            double x_44813 = ((double *) mem_47638)[new_index_45942 * (int64_t) 784 + new_index_45950 * (int64_t) 28 + new_index_45967];
            double binlam_res_44812 = x_44813 + redout_45660;
            double redout_tmp_48474 = binlam_res_44812;
            
            redout_45660 = redout_tmp_48474;
        }
        x_contrib_sum_45191 = redout_45660;
        
        bool acc_cert_p_44785;
        
        for (int64_t i_45665 = 0; i_45665 < binop_x_46872; i_45665++) {
            int64_t binop_x_45878 = i_45665 + binop_x_45940;
            int64_t new_index_45879 = squot64(binop_x_45878, (int64_t) 784);
            int64_t binop_y_45885 = (int64_t) 784 * new_index_45879;
            int64_t binop_x_45886 = binop_x_45878 - binop_y_45885;
            int64_t new_index_45887 = squot64(binop_x_45886, (int64_t) 28);
            int64_t binop_y_45903 = (int64_t) 28 * new_index_45887;
            int64_t new_index_45904 = binop_x_45886 - binop_y_45903;
            double map_adj_p_44768 = ((double *) mem_47638)[new_index_45879 * (int64_t) 784 + new_index_45887 * (int64_t) 28 + new_index_45904];
            int64_t binop_x_45905 = (int64_t) 25 * i_45665;
            
            for (int64_t i_45663 = 0; i_45663 < (int64_t) 25; i_45663++) {
                int64_t binop_x_45906 = i_45663 + binop_x_45905;
                int64_t new_index_45908 = squot64(binop_x_45906, ixfun_arg_46888);
                int64_t binop_y_45916 = new_index_45908 * ixfun_arg_46888;
                int64_t binop_x_45917 = binop_x_45906 - binop_y_45916;
                int64_t new_index_45918 = squot64(binop_x_45917, (int64_t) 25);
                int64_t binop_y_45938 = (int64_t) 25 * new_index_45918;
                int64_t new_index_45939 = binop_x_45917 - binop_y_45938;
                double x_45112 = ((double *) mem_46876)[new_index_45908 * ixfun_arg_46888 + new_index_45918 * (int64_t) 25 + new_index_45939];
                double binop_x_adj_45115 = map_adj_p_44768 * x_45112;
                
                // UpdateAcc
                {
                    int64_t idx_44784 = i_45663;
                    
                    if (sle64((int64_t) 0, i_45663) && slt64(i_45663, (int64_t) 25)) {
                        double x_44781;
                        double y_44782;
                        
                        x_44781 = ((double *) mem_47741)[i_45663];
                        y_44782 = binop_x_adj_45115;
                        
                        double binlam_res_44783 = x_44781 + y_44782;
                        
                        ((double *) mem_47741)[i_45663] = binlam_res_44783;
                    }
                }
            }
        }
        if ((int64_t) 200 > 0)
            memmove(mem_47724 + i_45670 * (int64_t) 25 * (int64_t) 8, mem_47741 + (int64_t) 0, (int64_t) 200);
        ((double *) mem_47726.mem)[i_45670] = x_contrib_sum_45191;
    }
    if (memblock_alloc(ctx, &mem_47756, (int64_t) 1200, "mem_47756")) {
        err = 1;
        goto cleanup;
    }
    if ((int64_t) 1200 > 0)
        memmove(mem_47756.mem + (int64_t) 0, mem_47724 + (int64_t) 0, (int64_t) 1200);
    if (memblock_alloc(ctx, &mem_47762, (int64_t) 19200, "mem_47762")) {
        err = 1;
        goto cleanup;
    }
    if ((int64_t) 19200 > 0)
        memmove(mem_47762.mem + (int64_t) 0, mem_47632 + (int64_t) 0, (int64_t) 19200);
    if (memblock_set(ctx, &mem_out_48365, &mem_47756, "mem_47756") != 0)
        return 1;
    if (memblock_set(ctx, &mem_out_48366, &mem_47726, "mem_47726") != 0)
        return 1;
    if (memblock_set(ctx, &mem_out_48367, &mem_47762, "mem_47762") != 0)
        return 1;
    if (memblock_set(ctx, &mem_out_48368, &mem_47634, "mem_47634") != 0)
        return 1;
    if (memblock_set(ctx, &mem_out_48369, &mem_47508, "mem_47508") != 0)
        return 1;
    if (memblock_set(ctx, &mem_out_48370, &mem_47510, "mem_47510") != 0)
        return 1;
    if (memblock_set(ctx, &mem_out_48371, &mem_47460, "mem_47460") != 0)
        return 1;
    if (memblock_set(ctx, &mem_out_48372, &mem_47462, "mem_47462") != 0)
        return 1;
    if (memblock_set(ctx, &mem_out_48373, &mem_47412, "mem_47412") != 0)
        return 1;
    if (memblock_set(ctx, &mem_out_48374, &mem_47414, "mem_47414") != 0)
        return 1;
    if (memblock_set(ctx, &*mem_out_p_48543, &mem_out_48365, "mem_out_48365") != 0)
        return 1;
    if (memblock_set(ctx, &*mem_out_p_48544, &mem_out_48366, "mem_out_48366") != 0)
        return 1;
    if (memblock_set(ctx, &*mem_out_p_48545, &mem_out_48367, "mem_out_48367") != 0)
        return 1;
    if (memblock_set(ctx, &*mem_out_p_48546, &mem_out_48368, "mem_out_48368") != 0)
        return 1;
    if (memblock_set(ctx, &*mem_out_p_48547, &mem_out_48369, "mem_out_48369") != 0)
        return 1;
    if (memblock_set(ctx, &*mem_out_p_48548, &mem_out_48370, "mem_out_48370") != 0)
        return 1;
    if (memblock_set(ctx, &*mem_out_p_48549, &mem_out_48371, "mem_out_48371") != 0)
        return 1;
    if (memblock_set(ctx, &*mem_out_p_48550, &mem_out_48372, "mem_out_48372") != 0)
        return 1;
    if (memblock_set(ctx, &*mem_out_p_48551, &mem_out_48373, "mem_out_48373") != 0)
        return 1;
    if (memblock_set(ctx, &*mem_out_p_48552, &mem_out_48374, "mem_out_48374") != 0)
        return 1;
    
  cleanup:
    {
        free(mem_46826);
        free(mem_46871);
        free(mem_46876);
        free(mem_46937);
        free(mem_46980);
        free(mem_46993);
        free(mem_47104);
        free(mem_47156);
        free(mem_47196);
        free(mem_47209);
        free(mem_47320);
        free(mem_47332);
        free(mem_47344);
        free(mem_47356);
        free(mem_47368);
        free(mem_47370);
        free(mem_47372);
        free(mem_47387);
        free(mem_47416);
        free(mem_47418);
        free(mem_47420);
        free(mem_47435);
        free(mem_47464);
        free(mem_47466);
        free(mem_47468);
        free(mem_47483);
        free(mem_47512);
        free(mem_47525);
        free(mem_47598);
        free(mem_47600);
        free(mem_47602);
        free(mem_47617);
        free(mem_47632);
        free(mem_47636);
        free(mem_47638);
        free(mem_47651);
        free(mem_47724);
        free(mem_47741);
        if (memblock_unref(ctx, &mem_47762, "mem_47762") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_47756, "mem_47756") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_47726, "mem_47726") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_47634, "mem_47634") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_47510, "mem_47510") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_47508, "mem_47508") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_47462, "mem_47462") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_47460, "mem_47460") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_47414, "mem_47414") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_47412, "mem_47412") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_out_48374, "mem_out_48374") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_out_48373, "mem_out_48373") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_out_48372, "mem_out_48372") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_out_48371, "mem_out_48371") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_out_48370, "mem_out_48370") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_out_48369, "mem_out_48369") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_out_48368, "mem_out_48368") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_out_48367, "mem_out_48367") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_out_48366, "mem_out_48366") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_out_48365, "mem_out_48365") != 0)
            return 1;
    }
    return err;
}
static int futrts_entry_test_cnn_futhark_ad(struct futhark_context *ctx, struct memblock *mem_out_p_48591, struct memblock x_train_mem_46821, struct memblock y_train_mem_46822, int64_t l_31478, int64_t m_31479, int64_t n_31480)
{
    (void) ctx;
    
    int err = 0;
    int64_t mem_46917_cached_sizze_48592 = 0;
    unsigned char *mem_46917 = NULL;
    int64_t mem_46962_cached_sizze_48593 = 0;
    unsigned char *mem_46962 = NULL;
    int64_t mem_46967_cached_sizze_48594 = 0;
    unsigned char *mem_46967 = NULL;
    int64_t mem_47028_cached_sizze_48595 = 0;
    unsigned char *mem_47028 = NULL;
    int64_t mem_47071_cached_sizze_48596 = 0;
    unsigned char *mem_47071 = NULL;
    int64_t mem_47084_cached_sizze_48597 = 0;
    unsigned char *mem_47084 = NULL;
    int64_t mem_47195_cached_sizze_48598 = 0;
    unsigned char *mem_47195 = NULL;
    int64_t mem_47247_cached_sizze_48599 = 0;
    unsigned char *mem_47247 = NULL;
    int64_t mem_47287_cached_sizze_48600 = 0;
    unsigned char *mem_47287 = NULL;
    int64_t mem_47300_cached_sizze_48601 = 0;
    unsigned char *mem_47300 = NULL;
    int64_t mem_47411_cached_sizze_48602 = 0;
    unsigned char *mem_47411 = NULL;
    int64_t mem_47423_cached_sizze_48603 = 0;
    unsigned char *mem_47423 = NULL;
    int64_t mem_47435_cached_sizze_48604 = 0;
    unsigned char *mem_47435 = NULL;
    int64_t mem_47447_cached_sizze_48605 = 0;
    unsigned char *mem_47447 = NULL;
    int64_t mem_47459_cached_sizze_48606 = 0;
    unsigned char *mem_47459 = NULL;
    int64_t mem_47461_cached_sizze_48607 = 0;
    unsigned char *mem_47461 = NULL;
    int64_t mem_47463_cached_sizze_48608 = 0;
    unsigned char *mem_47463 = NULL;
    int64_t mem_47478_cached_sizze_48609 = 0;
    unsigned char *mem_47478 = NULL;
    int64_t mem_47503_cached_sizze_48610 = 0;
    unsigned char *mem_47503 = NULL;
    int64_t mem_47505_cached_sizze_48611 = 0;
    unsigned char *mem_47505 = NULL;
    int64_t mem_47507_cached_sizze_48612 = 0;
    unsigned char *mem_47507 = NULL;
    int64_t mem_47509_cached_sizze_48613 = 0;
    unsigned char *mem_47509 = NULL;
    int64_t mem_47511_cached_sizze_48614 = 0;
    unsigned char *mem_47511 = NULL;
    int64_t mem_47526_cached_sizze_48615 = 0;
    unsigned char *mem_47526 = NULL;
    int64_t mem_47551_cached_sizze_48616 = 0;
    unsigned char *mem_47551 = NULL;
    int64_t mem_47553_cached_sizze_48617 = 0;
    unsigned char *mem_47553 = NULL;
    int64_t mem_47555_cached_sizze_48618 = 0;
    unsigned char *mem_47555 = NULL;
    int64_t mem_47557_cached_sizze_48619 = 0;
    unsigned char *mem_47557 = NULL;
    int64_t mem_47559_cached_sizze_48620 = 0;
    unsigned char *mem_47559 = NULL;
    int64_t mem_47574_cached_sizze_48621 = 0;
    unsigned char *mem_47574 = NULL;
    int64_t mem_47599_cached_sizze_48622 = 0;
    unsigned char *mem_47599 = NULL;
    int64_t mem_47601_cached_sizze_48623 = 0;
    unsigned char *mem_47601 = NULL;
    int64_t mem_47603_cached_sizze_48624 = 0;
    unsigned char *mem_47603 = NULL;
    int64_t mem_47616_cached_sizze_48625 = 0;
    unsigned char *mem_47616 = NULL;
    int64_t mem_47689_cached_sizze_48626 = 0;
    unsigned char *mem_47689 = NULL;
    int64_t mem_47691_cached_sizze_48627 = 0;
    unsigned char *mem_47691 = NULL;
    int64_t mem_47693_cached_sizze_48628 = 0;
    unsigned char *mem_47693 = NULL;
    int64_t mem_47708_cached_sizze_48629 = 0;
    unsigned char *mem_47708 = NULL;
    int64_t mem_47723_cached_sizze_48630 = 0;
    unsigned char *mem_47723 = NULL;
    int64_t mem_47725_cached_sizze_48631 = 0;
    unsigned char *mem_47725 = NULL;
    int64_t mem_47871_cached_sizze_48632 = 0;
    unsigned char *mem_47871 = NULL;
    int64_t mem_47873_cached_sizze_48633 = 0;
    unsigned char *mem_47873 = NULL;
    int64_t mem_47886_cached_sizze_48634 = 0;
    unsigned char *mem_47886 = NULL;
    int64_t mem_47961_cached_sizze_48635 = 0;
    unsigned char *mem_47961 = NULL;
    int64_t mem_47976_cached_sizze_48636 = 0;
    unsigned char *mem_47976 = NULL;
    int64_t mem_48007_cached_sizze_48637 = 0;
    unsigned char *mem_48007 = NULL;
    struct memblock mem_48308;
    
    mem_48308.references = NULL;
    
    struct memblock mem_param_tmp_48375;
    
    mem_param_tmp_48375.references = NULL;
    
    struct memblock mem_param_tmp_48374;
    
    mem_param_tmp_48374.references = NULL;
    
    struct memblock mem_param_tmp_48373;
    
    mem_param_tmp_48373.references = NULL;
    
    struct memblock mem_param_tmp_48372;
    
    mem_param_tmp_48372.references = NULL;
    
    struct memblock mem_param_tmp_48371;
    
    mem_param_tmp_48371.references = NULL;
    
    struct memblock mem_param_tmp_48370;
    
    mem_param_tmp_48370.references = NULL;
    
    struct memblock mem_param_tmp_48369;
    
    mem_param_tmp_48369.references = NULL;
    
    struct memblock mem_param_tmp_48368;
    
    mem_param_tmp_48368.references = NULL;
    
    struct memblock mem_param_tmp_48367;
    
    mem_param_tmp_48367.references = NULL;
    
    struct memblock mem_param_tmp_48366;
    
    mem_param_tmp_48366.references = NULL;
    
    struct memblock mem_48219;
    
    mem_48219.references = NULL;
    
    struct memblock mem_48179;
    
    mem_48179.references = NULL;
    
    struct memblock mem_48167;
    
    mem_48167.references = NULL;
    
    struct memblock mem_48127;
    
    mem_48127.references = NULL;
    
    struct memblock mem_48115;
    
    mem_48115.references = NULL;
    
    struct memblock mem_48075;
    
    mem_48075.references = NULL;
    
    struct memblock mem_48063;
    
    mem_48063.references = NULL;
    
    struct memblock mem_47991;
    
    mem_47991.references = NULL;
    
    struct memblock mem_47959;
    
    mem_47959.references = NULL;
    
    struct memblock mem_47727;
    
    mem_47727.references = NULL;
    
    struct memblock mem_param_46913;
    
    mem_param_46913.references = NULL;
    
    struct memblock mem_param_46908;
    
    mem_param_46908.references = NULL;
    
    struct memblock mem_param_46897;
    
    mem_param_46897.references = NULL;
    
    struct memblock mem_param_46892;
    
    mem_param_46892.references = NULL;
    
    struct memblock mem_param_46881;
    
    mem_param_46881.references = NULL;
    
    struct memblock mem_param_46876;
    
    mem_param_46876.references = NULL;
    
    struct memblock mem_param_46865;
    
    mem_param_46865.references = NULL;
    
    struct memblock mem_param_46860;
    
    mem_param_46860.references = NULL;
    
    struct memblock mem_param_46843;
    
    mem_param_46843.references = NULL;
    
    struct memblock mem_param_46838;
    
    mem_param_46838.references = NULL;
    
    struct memblock ext_mem_48297;
    
    ext_mem_48297.references = NULL;
    
    struct memblock ext_mem_48298;
    
    ext_mem_48298.references = NULL;
    
    struct memblock ext_mem_48299;
    
    ext_mem_48299.references = NULL;
    
    struct memblock ext_mem_48300;
    
    ext_mem_48300.references = NULL;
    
    struct memblock ext_mem_48301;
    
    ext_mem_48301.references = NULL;
    
    struct memblock ext_mem_48302;
    
    ext_mem_48302.references = NULL;
    
    struct memblock ext_mem_48303;
    
    ext_mem_48303.references = NULL;
    
    struct memblock ext_mem_48304;
    
    ext_mem_48304.references = NULL;
    
    struct memblock ext_mem_48305;
    
    ext_mem_48305.references = NULL;
    
    struct memblock ext_mem_48306;
    
    ext_mem_48306.references = NULL;
    
    struct memblock mem_46899;
    
    mem_46899.references = NULL;
    
    struct memblock mem_46883;
    
    mem_46883.references = NULL;
    
    struct memblock mem_46867;
    
    mem_46867.references = NULL;
    
    struct memblock mem_46845;
    
    mem_46845.references = NULL;
    
    struct memblock mem_46824;
    
    mem_46824.references = NULL;
    
    struct memblock mem_out_48365;
    
    mem_out_48365.references = NULL;
    
    struct memblock mem_46702 = ctx->constants->mem_46702;
    struct memblock mem_46714 = ctx->constants->mem_46714;
    struct memblock mem_46726 = ctx->constants->mem_46726;
    struct memblock mem_46738 = ctx->constants->mem_46738;
    struct memblock mem_46750 = ctx->constants->mem_46750;
    struct memblock mem_46762 = ctx->constants->mem_46762;
    struct memblock mem_46774 = ctx->constants->mem_46774;
    struct memblock mem_46786 = ctx->constants->mem_46786;
    struct memblock mem_46798 = ctx->constants->mem_46798;
    struct memblock mem_46810 = ctx->constants->mem_46810;
    int64_t arg_41505 = add64((int64_t) 4, m_31479);
    int64_t arg_41506 = sub64(arg_41505, (int64_t) 5);
    int64_t new_n_41507 = add64((int64_t) 1, arg_41506);
    int64_t arg_41508 = add64((int64_t) 4, n_31480);
    int64_t arg_41509 = sub64(arg_41508, (int64_t) 5);
    int64_t new_m_41510 = add64((int64_t) 1, arg_41509);
    int64_t flat_dim_41597 = new_n_41507 * new_m_41510;
    int64_t binop_x_46914 = arg_41505 * arg_41508;
    int64_t binop_y_46915 = (int64_t) 8 * binop_x_46914;
    int64_t bytes_46916 = smax64((int64_t) 0, binop_y_46915);
    int64_t binop_y_46965 = (int64_t) 200 * flat_dim_41597;
    int64_t bytes_46966 = smax64((int64_t) 0, binop_y_46965);
    int64_t binop_y_47026 = (int64_t) 48 * flat_dim_41597;
    int64_t bytes_47027 = smax64((int64_t) 0, binop_y_47026);
    
    if (memblock_alloc(ctx, &mem_46824, (int64_t) 1200, "mem_46824")) {
        err = 1;
        goto cleanup;
    }
    if ((int64_t) 1200 > 0)
        memmove(mem_46824.mem + (int64_t) 0, mem_46702.mem + (int64_t) 0, (int64_t) 1200);
    
    bool i_p_m_t_s_leq_w_40330 = slt64((int64_t) 9, l_31478);
    bool index_certs_40331;
    
    if (!i_p_m_t_s_leq_w_40330) {
        set_error(ctx, msgprintf("Error: %s%lld%s%lld%s\n\nBacktrace:\n%s", "Index [:", (long long) (int64_t) 10, "] out of bounds for array of shape [", (long long) l_31478, "].", "-> #0  cnn_test.fut:29:62-73\n   #1  cnn_test.fut:28:1-30:27\n"));
        err = FUTHARK_PROGRAM_ERROR;
        goto cleanup;
    }
    
    bool bounds_invalid_upwards_41512 = slt64(arg_41505, (int64_t) 0);
    bool valid_41513 = !bounds_invalid_upwards_41512;
    bool range_valid_c_41514;
    
    if (!valid_41513) {
        set_error(ctx, msgprintf("Error: %s%lld%s%lld%s%lld%s\n\nBacktrace:\n%s", "Range ", (long long) (int64_t) 0, "..", (long long) (int64_t) 1, "..<", (long long) arg_41505, " is invalid.", "-> #0  /prelude/array.fut:95:3-10\n   #1  ../layers/conv2d.fut:7:120-123\n   #2  ../layers/conv2d.fut:20:7-30\n   #3  ../lenet/lenet.fut:10:37-64\n"));
        err = FUTHARK_PROGRAM_ERROR;
        goto cleanup;
    }
    
    bool bounds_invalid_upwards_41516 = slt64(arg_41508, (int64_t) 0);
    bool valid_41517 = !bounds_invalid_upwards_41516;
    bool range_valid_c_41518;
    
    if (!valid_41517) {
        set_error(ctx, msgprintf("Error: %s%lld%s%lld%s%lld%s\n\nBacktrace:\n%s", "Range ", (long long) (int64_t) 0, "..", (long long) (int64_t) 1, "..<", (long long) arg_41508, " is invalid.", "-> #0  /prelude/array.fut:95:3-10\n   #1  ../layers/conv2d.fut:7:120-123\n   #2  ../layers/conv2d.fut:20:7-30\n   #3  ../lenet/lenet.fut:10:37-64\n"));
        err = FUTHARK_PROGRAM_ERROR;
        goto cleanup;
    }
    
    int64_t arg_41520 = add64((int64_t) 2, m_31479);
    int64_t arg_41521 = add64((int64_t) 2, n_31480);
    bool bounds_invalid_upwards_41553 = slt64(new_n_41507, (int64_t) 0);
    bool valid_41554 = !bounds_invalid_upwards_41553;
    bool range_valid_c_41555;
    
    if (!valid_41554) {
        set_error(ctx, msgprintf("Error: %s%lld%s%lld%s%lld%s\n\nBacktrace:\n%s", "Range ", (long long) (int64_t) 0, "..", (long long) (int64_t) 1, "..<", (long long) new_n_41507, " is invalid.", "-> #0  /prelude/array.fut:95:3-10\n   #1  /prelude/array.fut:208:28-33\n   #2  ../layers/conv2d.fut:11:50-162\n   #3  ../layers/conv2d.fut:24:17-54\n   #4  ../lenet/lenet.fut:10:37-64\n"));
        err = FUTHARK_PROGRAM_ERROR;
        goto cleanup;
    }
    
    bool bounds_invalid_upwards_41557 = slt64(new_m_41510, (int64_t) 0);
    bool valid_41558 = !bounds_invalid_upwards_41557;
    bool range_valid_c_41559;
    
    if (!valid_41558) {
        set_error(ctx, msgprintf("Error: %s%lld%s%lld%s%lld%s\n\nBacktrace:\n%s", "Range ", (long long) (int64_t) 0, "..", (long long) (int64_t) 1, "..<", (long long) new_m_41510, " is invalid.", "-> #0  /prelude/array.fut:95:3-10\n   #1  /prelude/array.fut:208:27-34\n   #2  ../layers/conv2d.fut:11:50-162\n   #3  ../layers/conv2d.fut:24:17-54\n   #4  ../lenet/lenet.fut:10:37-64\n"));
        err = FUTHARK_PROGRAM_ERROR;
        goto cleanup;
    }
    
    bool dim_match_41626 = (int64_t) 28 == new_n_41507;
    bool dim_match_41627 = (int64_t) 28 == new_m_41510;
    bool match_41629 = dim_match_41626 && dim_match_41627;
    bool empty_or_match_cert_41630;
    
    if (!match_41629) {
        set_error(ctx, msgprintf("Error: %s%lld%s%lld%s%lld%s%lld%s%lld%s%lld%s\n\nBacktrace:\n%s", "Value of (core language) shape (", (long long) (int64_t) 6, ", ", (long long) new_n_41507, ", ", (long long) new_m_41510, ") cannot match shape of type `[", (long long) (int64_t) 6, "][", (long long) (int64_t) 28, "][", (long long) (int64_t) 28, "]f64`.", "-> #0  ../lenet/lenet.fut:10:37-82\n"));
        err = FUTHARK_PROGRAM_ERROR;
        goto cleanup;
    }
    
    int64_t binop_y_46414 = (int64_t) 25 * new_m_41510;
    
    if (memblock_alloc(ctx, &mem_46845, (int64_t) 19200, "mem_46845")) {
        err = 1;
        goto cleanup;
    }
    if ((int64_t) 19200 > 0)
        memmove(mem_46845.mem + (int64_t) 0, mem_46726.mem + (int64_t) 0, (int64_t) 19200);
    if (memblock_alloc(ctx, &mem_46867, (int64_t) 384000, "mem_46867")) {
        err = 1;
        goto cleanup;
    }
    if ((int64_t) 384000 > 0)
        memmove(mem_46867.mem + (int64_t) 0, mem_46750.mem + (int64_t) 0, (int64_t) 384000);
    if (memblock_alloc(ctx, &mem_46883, (int64_t) 80640, "mem_46883")) {
        err = 1;
        goto cleanup;
    }
    if ((int64_t) 80640 > 0)
        memmove(mem_46883.mem + (int64_t) 0, mem_46774.mem + (int64_t) 0, (int64_t) 80640);
    if (memblock_alloc(ctx, &mem_46899, (int64_t) 6720, "mem_46899")) {
        err = 1;
        goto cleanup;
    }
    if ((int64_t) 6720 > 0)
        memmove(mem_46899.mem + (int64_t) 0, mem_46798.mem + (int64_t) 0, (int64_t) 6720);
    if (mem_46917_cached_sizze_48592 < bytes_46916) {
        err = lexical_realloc(ctx, &mem_46917, &mem_46917_cached_sizze_48592, bytes_46916);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_46962_cached_sizze_48593 < bytes_46916) {
        err = lexical_realloc(ctx, &mem_46962, &mem_46962_cached_sizze_48593, bytes_46916);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_46967_cached_sizze_48594 < bytes_46966) {
        err = lexical_realloc(ctx, &mem_46967, &mem_46967_cached_sizze_48594, bytes_46966);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_47028_cached_sizze_48595 < bytes_47027) {
        err = lexical_realloc(ctx, &mem_47028, &mem_47028_cached_sizze_48595, bytes_47027);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_47071_cached_sizze_48596 < (int64_t) 9408) {
        err = lexical_realloc(ctx, &mem_47071, &mem_47071_cached_sizze_48596, (int64_t) 9408);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_47084_cached_sizze_48597 < (int64_t) 6272) {
        err = lexical_realloc(ctx, &mem_47084, &mem_47084_cached_sizze_48597, (int64_t) 6272);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_47195_cached_sizze_48598 < (int64_t) 120000) {
        err = lexical_realloc(ctx, &mem_47195, &mem_47195_cached_sizze_48598, (int64_t) 120000);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_47247_cached_sizze_48599 < (int64_t) 12800) {
        err = lexical_realloc(ctx, &mem_47247, &mem_47247_cached_sizze_48599, (int64_t) 12800);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_47287_cached_sizze_48600 < (int64_t) 3200) {
        err = lexical_realloc(ctx, &mem_47287, &mem_47287_cached_sizze_48600, (int64_t) 3200);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_47300_cached_sizze_48601 < (int64_t) 800) {
        err = lexical_realloc(ctx, &mem_47300, &mem_47300_cached_sizze_48601, (int64_t) 800);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_47411_cached_sizze_48602 < (int64_t) 960) {
        err = lexical_realloc(ctx, &mem_47411, &mem_47411_cached_sizze_48602, (int64_t) 960);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_47423_cached_sizze_48603 < (int64_t) 672) {
        err = lexical_realloc(ctx, &mem_47423, &mem_47423_cached_sizze_48603, (int64_t) 672);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_47435_cached_sizze_48604 < (int64_t) 80) {
        err = lexical_realloc(ctx, &mem_47435, &mem_47435_cached_sizze_48604, (int64_t) 80);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_47447_cached_sizze_48605 < (int64_t) 80) {
        err = lexical_realloc(ctx, &mem_47447, &mem_47447_cached_sizze_48605, (int64_t) 80);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_47459_cached_sizze_48606 < (int64_t) 672) {
        err = lexical_realloc(ctx, &mem_47459, &mem_47459_cached_sizze_48606, (int64_t) 672);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_47461_cached_sizze_48607 < (int64_t) 6720) {
        err = lexical_realloc(ctx, &mem_47461, &mem_47461_cached_sizze_48607, (int64_t) 6720);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_47463_cached_sizze_48608 < (int64_t) 80) {
        err = lexical_realloc(ctx, &mem_47463, &mem_47463_cached_sizze_48608, (int64_t) 80);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_47478_cached_sizze_48609 < (int64_t) 672) {
        err = lexical_realloc(ctx, &mem_47478, &mem_47478_cached_sizze_48609, (int64_t) 672);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_47503_cached_sizze_48610 < (int64_t) 6720) {
        err = lexical_realloc(ctx, &mem_47503, &mem_47503_cached_sizze_48610, (int64_t) 6720);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_47505_cached_sizze_48611 < (int64_t) 80) {
        err = lexical_realloc(ctx, &mem_47505, &mem_47505_cached_sizze_48611, (int64_t) 80);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_47507_cached_sizze_48612 < (int64_t) 960) {
        err = lexical_realloc(ctx, &mem_47507, &mem_47507_cached_sizze_48612, (int64_t) 960);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_47509_cached_sizze_48613 < (int64_t) 80640) {
        err = lexical_realloc(ctx, &mem_47509, &mem_47509_cached_sizze_48613, (int64_t) 80640);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_47511_cached_sizze_48614 < (int64_t) 672) {
        err = lexical_realloc(ctx, &mem_47511, &mem_47511_cached_sizze_48614, (int64_t) 672);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_47526_cached_sizze_48615 < (int64_t) 960) {
        err = lexical_realloc(ctx, &mem_47526, &mem_47526_cached_sizze_48615, (int64_t) 960);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_47551_cached_sizze_48616 < (int64_t) 80640) {
        err = lexical_realloc(ctx, &mem_47551, &mem_47551_cached_sizze_48616, (int64_t) 80640);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_47553_cached_sizze_48617 < (int64_t) 672) {
        err = lexical_realloc(ctx, &mem_47553, &mem_47553_cached_sizze_48617, (int64_t) 672);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_47555_cached_sizze_48618 < (int64_t) 3200) {
        err = lexical_realloc(ctx, &mem_47555, &mem_47555_cached_sizze_48618, (int64_t) 3200);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_47557_cached_sizze_48619 < (int64_t) 384000) {
        err = lexical_realloc(ctx, &mem_47557, &mem_47557_cached_sizze_48619, (int64_t) 384000);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_47559_cached_sizze_48620 < (int64_t) 960) {
        err = lexical_realloc(ctx, &mem_47559, &mem_47559_cached_sizze_48620, (int64_t) 960);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_47574_cached_sizze_48621 < (int64_t) 3200) {
        err = lexical_realloc(ctx, &mem_47574, &mem_47574_cached_sizze_48621, (int64_t) 3200);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_47599_cached_sizze_48622 < (int64_t) 384000) {
        err = lexical_realloc(ctx, &mem_47599, &mem_47599_cached_sizze_48622, (int64_t) 384000);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_47601_cached_sizze_48623 < (int64_t) 960) {
        err = lexical_realloc(ctx, &mem_47601, &mem_47601_cached_sizze_48623, (int64_t) 960);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_47603_cached_sizze_48624 < (int64_t) 12800) {
        err = lexical_realloc(ctx, &mem_47603, &mem_47603_cached_sizze_48624, (int64_t) 12800);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_47616_cached_sizze_48625 < (int64_t) 800) {
        err = lexical_realloc(ctx, &mem_47616, &mem_47616_cached_sizze_48625, (int64_t) 800);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_47689_cached_sizze_48626 < (int64_t) 120000) {
        err = lexical_realloc(ctx, &mem_47689, &mem_47689_cached_sizze_48626, (int64_t) 120000);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_47691_cached_sizze_48627 < (int64_t) 19200) {
        err = lexical_realloc(ctx, &mem_47691, &mem_47691_cached_sizze_48627, (int64_t) 19200);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_47693_cached_sizze_48628 < (int64_t) 128) {
        err = lexical_realloc(ctx, &mem_47693, &mem_47693_cached_sizze_48628, (int64_t) 128);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_47708_cached_sizze_48629 < (int64_t) 1200) {
        err = lexical_realloc(ctx, &mem_47708, &mem_47708_cached_sizze_48629, (int64_t) 1200);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_47723_cached_sizze_48630 < (int64_t) 19200) {
        err = lexical_realloc(ctx, &mem_47723, &mem_47723_cached_sizze_48630, (int64_t) 19200);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_47725_cached_sizze_48631 < (int64_t) 128) {
        err = lexical_realloc(ctx, &mem_47725, &mem_47725_cached_sizze_48631, (int64_t) 128);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_47871_cached_sizze_48632 < (int64_t) 9408) {
        err = lexical_realloc(ctx, &mem_47871, &mem_47871_cached_sizze_48632, (int64_t) 9408);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_47873_cached_sizze_48633 < (int64_t) 37632) {
        err = lexical_realloc(ctx, &mem_47873, &mem_47873_cached_sizze_48633, (int64_t) 37632);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_47886_cached_sizze_48634 < (int64_t) 6272) {
        err = lexical_realloc(ctx, &mem_47886, &mem_47886_cached_sizze_48634, (int64_t) 6272);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_47961_cached_sizze_48635 < (int64_t) 1200) {
        err = lexical_realloc(ctx, &mem_47961, &mem_47961_cached_sizze_48635, (int64_t) 1200);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_47976_cached_sizze_48636 < (int64_t) 200) {
        err = lexical_realloc(ctx, &mem_47976, &mem_47976_cached_sizze_48636, (int64_t) 200);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_48007_cached_sizze_48637 < (int64_t) 200) {
        err = lexical_realloc(ctx, &mem_48007, &mem_48007_cached_sizze_48637, (int64_t) 200);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (memblock_set(ctx, &mem_param_46838, &mem_46824, "mem_46824") != 0)
        return 1;
    if (memblock_set(ctx, &mem_param_46843, &mem_46714, "mem_46714") != 0)
        return 1;
    if (memblock_set(ctx, &mem_param_46860, &mem_46845, "mem_46845") != 0)
        return 1;
    if (memblock_set(ctx, &mem_param_46865, &mem_46738, "mem_46738") != 0)
        return 1;
    if (memblock_set(ctx, &mem_param_46876, &mem_46867, "mem_46867") != 0)
        return 1;
    if (memblock_set(ctx, &mem_param_46881, &mem_46762, "mem_46762") != 0)
        return 1;
    if (memblock_set(ctx, &mem_param_46892, &mem_46883, "mem_46883") != 0)
        return 1;
    if (memblock_set(ctx, &mem_param_46897, &mem_46786, "mem_46786") != 0)
        return 1;
    if (memblock_set(ctx, &mem_param_46908, &mem_46899, "mem_46899") != 0)
        return 1;
    if (memblock_set(ctx, &mem_param_46913, &mem_46810, "mem_46810") != 0)
        return 1;
    for (int64_t i_40648 = 0; i_40648 < (int64_t) 10; i_40648++) {
        for (int64_t i_45443 = 0; i_45443 < arg_41505; i_45443++) {
            bool cond_41524 = slt64(i_45443, (int64_t) 2);
            bool cond_f_res_41525 = sle64(arg_41520, i_45443);
            bool x_41526 = !cond_41524;
            bool y_41527 = cond_f_res_41525 && x_41526;
            bool cond_41528 = cond_41524 || y_41527;
            bool x_41529 = !cond_41528;
            
            for (int64_t i_45439 = 0; i_45439 < arg_41508; i_45439++) {
                bool cond_f_res_41532 = slt64(i_45439, (int64_t) 2);
                bool y_41533 = x_41529 && cond_f_res_41532;
                bool cond_41534 = cond_41528 || y_41533;
                bool cond_f_res_41535 = sle64(arg_41521, i_45439);
                bool x_41536 = !cond_41534;
                bool y_41537 = cond_f_res_41535 && x_41536;
                bool cond_41538 = cond_41534 || y_41537;
                double defunc_0_f_res_41539;
                
                if (cond_41538 == 1) {
                    defunc_0_f_res_41539 = 0.0;
                } else {
                    int64_t i_41540 = sub64(i_45443, (int64_t) 2);
                    int64_t i_41544 = sub64(i_45439, (int64_t) 2);
                    double defunc_0_f_res_f_res_41550 = ((double *) x_train_mem_46821.mem)[i_40648 * (n_31480 * m_31479) + i_41540 * n_31480 + i_41544];
                    
                    defunc_0_f_res_41539 = defunc_0_f_res_f_res_41550;
                }
                ((double *) mem_46917)[i_45443 * arg_41508 + i_45439] = defunc_0_f_res_41539;
            }
        }
        for (int64_t nest_i_48388 = 0; nest_i_48388 < (int64_t) 1; nest_i_48388++) {
            if (arg_41505 * arg_41508 * (int64_t) 8 > 0)
                memmove(mem_46962 + nest_i_48388 * (arg_41508 * arg_41505) * (int64_t) 8, mem_46917 + (int64_t) 0, arg_41505 * arg_41508 * (int64_t) 8);
        }
        for (int64_t i_45451 = 0; i_45451 < new_n_41507; i_45451++) {
            int64_t j_41569 = add64((int64_t) 5, i_45451);
            int64_t i_p_m_t_s_41570 = add64((int64_t) 4, i_45451);
            bool zzero_leq_i_p_m_t_s_41571 = sle64((int64_t) 0, i_p_m_t_s_41570);
            bool i_p_m_t_s_leq_w_41572 = slt64(i_p_m_t_s_41570, arg_41505);
            bool i_lte_j_41574 = sle64(i_45451, j_41569);
            bool y_41576 = zzero_leq_i_p_m_t_s_41571 && i_p_m_t_s_leq_w_41572;
            bool y_41577 = i_lte_j_41574 && y_41576;
            
            for (int64_t i_45447 = 0; i_45447 < new_m_41510; i_45447++) {
                int64_t j_41582 = add64((int64_t) 5, i_45447);
                int64_t i_p_m_t_s_41583 = add64((int64_t) 4, i_45447);
                bool zzero_leq_i_p_m_t_s_41584 = sle64((int64_t) 0, i_p_m_t_s_41583);
                bool i_p_m_t_s_leq_w_41585 = slt64(i_p_m_t_s_41583, arg_41508);
                bool i_lte_j_41587 = sle64(i_45447, j_41582);
                bool y_41589 = zzero_leq_i_p_m_t_s_41584 && i_p_m_t_s_leq_w_41585;
                bool y_41590 = i_lte_j_41587 && y_41589;
                bool index_ok_41593 = y_41577 && y_41590;
                bool index_certs_41594;
                
                if (!index_ok_41593) {
                    set_error(ctx, msgprintf("Error: %s%lld%s%lld%s%lld%s%lld%s%lld%s%lld%s\n\nBacktrace:\n%s", "Index [", (long long) i_45451, ":", (long long) j_41569, ", ", (long long) i_45447, ":", (long long) j_41582, "] out of bounds for array of shape [", (long long) arg_41505, "][", (long long) arg_41508, "].", "-> #0  ../layers/conv2d.fut:11:90-124\n   #1  ../layers/conv2d.fut:11:144-146\n   #2  /prelude/soacs.fut:59:9-10\n   #3  /prelude/array.fut:200:10-17\n   #4  /prelude/functional.fut:39:61-65\n   #5  /prelude/soacs.fut:59:9-10\n   #6  /prelude/array.fut:208:27-34\n   #7  ../layers/conv2d.fut:11:50-162\n   #8  ../layers/conv2d.fut:24:17-54\n   #9  ../lenet/lenet.fut:10:37-64\n"));
                    err = FUTHARK_PROGRAM_ERROR;
                    goto cleanup;
                }
                for (int64_t i_48391 = 0; i_48391 < (int64_t) 25; i_48391++) {
                    double tmp_48392 = ((double *) mem_46962)[arg_41508 * i_45451 + i_45447 + (squot64(i_48391, (int64_t) 25) * (arg_41508 * arg_41505) + squot64(i_48391 - squot64(i_48391, (int64_t) 25) * (int64_t) 25, (int64_t) 5) * arg_41508 + (i_48391 - squot64(i_48391, (int64_t) 25) * (int64_t) 25 - squot64(i_48391 - squot64(i_48391, (int64_t) 25) * (int64_t) 25, (int64_t) 5) * (int64_t) 5))];
                    
                    ((double *) mem_46967)[i_45451 * binop_y_46414 + i_45447 * (int64_t) 25 + i_48391] = tmp_48392;
                }
            }
        }
        for (int64_t i_45461 = 0; i_45461 < (int64_t) 6; i_45461++) {
            double x_43517 = ((double *) mem_param_46843.mem)[i_45461];
            int64_t binop_x_46346 = (int64_t) 25 * i_45461;
            
            for (int64_t i_45457 = 0; i_45457 < flat_dim_41597; i_45457++) {
                int64_t binop_x_46412 = (int64_t) 25 * i_45457;
                double defunc_0_reduce_res_45273;
                double redout_45453 = 0.0;
                
                for (int64_t i_45454 = 0; i_45454 < (int64_t) 25; i_45454++) {
                    int64_t binop_x_46347 = i_45454 + binop_x_46346;
                    int64_t new_index_46348 = squot64(binop_x_46347, (int64_t) 25);
                    int64_t binop_y_46354 = (int64_t) 25 * new_index_46348;
                    int64_t binop_x_46355 = binop_x_46347 - binop_y_46354;
                    int64_t new_index_46356 = squot64(binop_x_46355, (int64_t) 25);
                    int64_t binop_y_46372 = (int64_t) 25 * new_index_46356;
                    int64_t binop_x_46373 = binop_x_46355 - binop_y_46372;
                    int64_t new_index_46374 = squot64(binop_x_46373, (int64_t) 5);
                    int64_t binop_y_46410 = (int64_t) 5 * new_index_46374;
                    int64_t new_index_46411 = binop_x_46373 - binop_y_46410;
                    double x_43547 = ((double *) mem_param_46838.mem)[new_index_46348 * (int64_t) 25 + new_index_46356 * (int64_t) 25 + new_index_46374 * (int64_t) 5 + new_index_46411];
                    int64_t binop_x_46413 = i_45454 + binop_x_46412;
                    int64_t new_index_46415 = squot64(binop_x_46413, binop_y_46414);
                    int64_t binop_y_46423 = binop_y_46414 * new_index_46415;
                    int64_t binop_x_46424 = binop_x_46413 - binop_y_46423;
                    int64_t new_index_46425 = squot64(binop_x_46424, (int64_t) 25);
                    int64_t binop_y_46445 = (int64_t) 25 * new_index_46425;
                    int64_t new_index_46446 = binop_x_46424 - binop_y_46445;
                    double x_43548 = ((double *) mem_46967)[new_index_46415 * binop_y_46414 + new_index_46425 * (int64_t) 25 + new_index_46446];
                    double defunc_0_f_res_43549 = x_43547 * x_43548;
                    double defunc_0_op_res_43542 = defunc_0_f_res_43549 + redout_45453;
                    double redout_tmp_48395 = defunc_0_op_res_43542;
                    
                    redout_45453 = redout_tmp_48395;
                }
                defunc_0_reduce_res_45273 = redout_45453;
                
                double defunc_0_f_res_43545 = x_43517 + defunc_0_reduce_res_45273;
                
                ((double *) mem_47028)[i_45461 * flat_dim_41597 + i_45457] = defunc_0_f_res_43545;
            }
        }
        for (int64_t i_45483 = 0; i_45483 < (int64_t) 6; i_45483++) {
            int64_t binop_x_46330 = (int64_t) 784 * i_45483;
            
            for (int64_t i_45469 = 0; i_45469 < (int64_t) 28; i_45469++) {
                int64_t binop_y_46331 = (int64_t) 28 * i_45469;
                int64_t binop_x_46332 = binop_x_46330 + binop_y_46331;
                
                for (int64_t i_45465 = 0; i_45465 < (int64_t) 28; i_45465++) {
                    int64_t binop_x_46333 = i_45465 + binop_x_46332;
                    int64_t new_index_46334 = squot64(binop_x_46333, flat_dim_41597);
                    int64_t binop_y_46344 = flat_dim_41597 * new_index_46334;
                    int64_t new_index_46345 = binop_x_46333 - binop_y_46344;
                    double x_43476 = ((double *) mem_47028)[new_index_46334 * flat_dim_41597 + new_index_46345];
                    double max_res_43477 = fmax64(0.0, x_43476);
                    
                    ((double *) mem_47084)[i_45469 * (int64_t) 28 + i_45465] = max_res_43477;
                }
            }
            for (int64_t i_45479 = 0; i_45479 < (int64_t) 14; i_45479++) {
                int64_t i_43481 = mul64((int64_t) 2, i_45479);
                int64_t j_43482 = add64((int64_t) 2, i_43481);
                int64_t i_p_m_t_s_43483 = add64((int64_t) 1, i_43481);
                bool zzero_leq_i_p_m_t_s_43484 = sle64((int64_t) 0, i_p_m_t_s_43483);
                bool i_p_m_t_s_leq_w_43485 = slt64(i_p_m_t_s_43483, (int64_t) 28);
                bool zzero_lte_i_43486 = sle64((int64_t) 0, i_43481);
                bool i_lte_j_43487 = sle64(i_43481, j_43482);
                bool y_43488 = i_p_m_t_s_leq_w_43485 && zzero_lte_i_43486;
                bool y_43489 = zzero_leq_i_p_m_t_s_43484 && y_43488;
                bool y_43490 = i_lte_j_43487 && y_43489;
                bool forwards_ok_43491 = zzero_lte_i_43486 && y_43490;
                
                for (int64_t i_45475 = 0; i_45475 < (int64_t) 14; i_45475++) {
                    int64_t i_43494 = mul64((int64_t) 2, i_45475);
                    int64_t j_43495 = add64((int64_t) 2, i_43494);
                    int64_t i_p_m_t_s_43496 = add64((int64_t) 1, i_43494);
                    bool zzero_leq_i_p_m_t_s_43497 = sle64((int64_t) 0, i_p_m_t_s_43496);
                    bool i_p_m_t_s_leq_w_43498 = slt64(i_p_m_t_s_43496, (int64_t) 28);
                    bool zzero_lte_i_43499 = sle64((int64_t) 0, i_43494);
                    bool i_lte_j_43500 = sle64(i_43494, j_43495);
                    bool y_43501 = i_p_m_t_s_leq_w_43498 && zzero_lte_i_43499;
                    bool y_43502 = zzero_leq_i_p_m_t_s_43497 && y_43501;
                    bool y_43503 = i_lte_j_43500 && y_43502;
                    bool forwards_ok_43504 = zzero_lte_i_43499 && y_43503;
                    bool index_ok_43505 = forwards_ok_43491 && forwards_ok_43504;
                    bool index_certs_43506;
                    
                    if (!index_ok_43505) {
                        set_error(ctx, msgprintf("Error: %s%lld%s%lld%s%lld%s%lld%s%lld%s%lld%s\n\nBacktrace:\n%s", "Index [", (long long) i_43481, ":", (long long) j_43482, ", ", (long long) i_43494, ":", (long long) j_43495, "] out of bounds for array of shape [", (long long) (int64_t) 28, "][", (long long) (int64_t) 28, "].", "-> #0  ../layers/avgpool.fut:7:18-80\n   #1  /prelude/soacs.fut:59:9-10\n   #2  /prelude/array.fut:200:10-17\n   #3  /prelude/functional.fut:39:61-65\n   #4  /prelude/soacs.fut:59:9-10\n   #5  /prelude/array.fut:208:27-34\n   #6  ../layers/avgpool.fut:6:29-8:49\n   #7  ../layers/avgpool.fut:8:73-76\n   #8  ../lenet/lenet.fut:12:37-66\n"));
                        err = FUTHARK_PROGRAM_ERROR;
                        goto cleanup;
                    }
                    
                    double defunc_0_reduce_res_45276;
                    double redout_45471 = 0.0;
                    
                    for (int64_t i_45472 = 0; i_45472 < (int64_t) 4; i_45472++) {
                        int64_t new_index_45859 = squot64(i_45472, (int64_t) 2);
                        int64_t binop_y_45861 = (int64_t) 2 * new_index_45859;
                        int64_t new_index_45862 = i_45472 - binop_y_45861;
                        int64_t slice_45863 = i_43481 + new_index_45859;
                        int64_t slice_45864 = i_43494 + new_index_45862;
                        double x_43513 = ((double *) mem_47084)[slice_45863 * (int64_t) 28 + slice_45864];
                        double defunc_0_op_res_43512 = x_43513 + redout_45471;
                        double redout_tmp_48401 = defunc_0_op_res_43512;
                        
                        redout_45471 = redout_tmp_48401;
                    }
                    defunc_0_reduce_res_45276 = redout_45471;
                    
                    double defunc_0_f_res_43514 = defunc_0_reduce_res_45276 / 4.0;
                    
                    ((double *) mem_47071)[i_45483 * (int64_t) 196 + i_45479 * (int64_t) 14 + i_45475] = defunc_0_f_res_43514;
                }
            }
        }
        for (int64_t i_45491 = 0; i_45491 < (int64_t) 10; i_45491++) {
            int64_t j_41696 = add64((int64_t) 5, i_45491);
            int64_t i_p_m_t_s_41697 = add64((int64_t) 4, i_45491);
            bool zzero_leq_i_p_m_t_s_41698 = sle64((int64_t) 0, i_p_m_t_s_41697);
            bool i_p_m_t_s_leq_w_41699 = slt64(i_p_m_t_s_41697, (int64_t) 14);
            bool i_lte_j_41701 = sle64(i_45491, j_41696);
            bool y_41703 = zzero_leq_i_p_m_t_s_41698 && i_p_m_t_s_leq_w_41699;
            bool y_41704 = i_lte_j_41701 && y_41703;
            
            for (int64_t i_45487 = 0; i_45487 < (int64_t) 10; i_45487++) {
                int64_t j_41709 = add64((int64_t) 5, i_45487);
                int64_t i_p_m_t_s_41710 = add64((int64_t) 4, i_45487);
                bool zzero_leq_i_p_m_t_s_41711 = sle64((int64_t) 0, i_p_m_t_s_41710);
                bool i_p_m_t_s_leq_w_41712 = slt64(i_p_m_t_s_41710, (int64_t) 14);
                bool i_lte_j_41714 = sle64(i_45487, j_41709);
                bool y_41716 = zzero_leq_i_p_m_t_s_41711 && i_p_m_t_s_leq_w_41712;
                bool y_41717 = i_lte_j_41714 && y_41716;
                bool index_ok_41720 = y_41704 && y_41717;
                bool index_certs_41721;
                
                if (!index_ok_41720) {
                    set_error(ctx, msgprintf("Error: %s%lld%s%lld%s%lld%s%lld%s%lld%s%lld%s\n\nBacktrace:\n%s", "Index [", (long long) i_45491, ":", (long long) j_41696, ", ", (long long) i_45487, ":", (long long) j_41709, "] out of bounds for array of shape [", (long long) (int64_t) 14, "][", (long long) (int64_t) 14, "].", "-> #0  ../layers/conv2d.fut:11:90-124\n   #1  ../layers/conv2d.fut:11:144-146\n   #2  /prelude/soacs.fut:59:9-10\n   #3  /prelude/array.fut:200:10-17\n   #4  /prelude/functional.fut:39:61-65\n   #5  /prelude/soacs.fut:59:9-10\n   #6  /prelude/array.fut:208:27-34\n   #7  ../layers/conv2d.fut:11:50-162\n   #8  ../layers/conv2d.fut:24:17-54\n   #9  ../lenet/lenet.fut:13:38-68\n"));
                    err = FUTHARK_PROGRAM_ERROR;
                    goto cleanup;
                }
                for (int64_t i_48404 = 0; i_48404 < (int64_t) 150; i_48404++) {
                    double tmp_48405 = ((double *) mem_47071)[(int64_t) 14 * i_45491 + i_45487 + (squot64(i_48404, (int64_t) 25) * (int64_t) 196 + squot64(i_48404 - squot64(i_48404, (int64_t) 25) * (int64_t) 25, (int64_t) 5) * (int64_t) 14 + (i_48404 - squot64(i_48404, (int64_t) 25) * (int64_t) 25 - squot64(i_48404 - squot64(i_48404, (int64_t) 25) * (int64_t) 25, (int64_t) 5) * (int64_t) 5))];
                    
                    ((double *) mem_47195)[i_45491 * (int64_t) 1500 + i_45487 * (int64_t) 150 + i_48404] = tmp_48405;
                }
            }
        }
        for (int64_t i_45501 = 0; i_45501 < (int64_t) 16; i_45501++) {
            double x_43455 = ((double *) mem_param_46865.mem)[i_45501];
            int64_t binop_x_46236 = (int64_t) 150 * i_45501;
            
            for (int64_t i_45497 = 0; i_45497 < (int64_t) 100; i_45497++) {
                int64_t binop_x_46302 = (int64_t) 150 * i_45497;
                double defunc_0_reduce_res_45282;
                double redout_45493 = 0.0;
                
                for (int64_t i_45494 = 0; i_45494 < (int64_t) 150; i_45494++) {
                    int64_t binop_x_46237 = i_45494 + binop_x_46236;
                    int64_t new_index_46238 = squot64(binop_x_46237, (int64_t) 150);
                    int64_t binop_y_46244 = (int64_t) 150 * new_index_46238;
                    int64_t binop_x_46245 = binop_x_46237 - binop_y_46244;
                    int64_t new_index_46246 = squot64(binop_x_46245, (int64_t) 25);
                    int64_t binop_y_46262 = (int64_t) 25 * new_index_46246;
                    int64_t binop_x_46263 = binop_x_46245 - binop_y_46262;
                    int64_t new_index_46264 = squot64(binop_x_46263, (int64_t) 5);
                    int64_t binop_y_46300 = (int64_t) 5 * new_index_46264;
                    int64_t new_index_46301 = binop_x_46263 - binop_y_46300;
                    double x_43575 = ((double *) mem_param_46860.mem)[new_index_46238 * (int64_t) 150 + new_index_46246 * (int64_t) 25 + new_index_46264 * (int64_t) 5 + new_index_46301];
                    int64_t binop_x_46303 = i_45494 + binop_x_46302;
                    int64_t new_index_46304 = squot64(binop_x_46303, (int64_t) 1500);
                    int64_t binop_y_46310 = (int64_t) 1500 * new_index_46304;
                    int64_t binop_x_46311 = binop_x_46303 - binop_y_46310;
                    int64_t new_index_46312 = squot64(binop_x_46311, (int64_t) 150);
                    int64_t binop_y_46328 = (int64_t) 150 * new_index_46312;
                    int64_t new_index_46329 = binop_x_46311 - binop_y_46328;
                    double x_43576 = ((double *) mem_47195)[new_index_46304 * (int64_t) 1500 + new_index_46312 * (int64_t) 150 + new_index_46329];
                    double defunc_0_f_res_43577 = x_43575 * x_43576;
                    double defunc_0_op_res_43570 = defunc_0_f_res_43577 + redout_45493;
                    double redout_tmp_48408 = defunc_0_op_res_43570;
                    
                    redout_45493 = redout_tmp_48408;
                }
                defunc_0_reduce_res_45282 = redout_45493;
                
                double defunc_0_f_res_43573 = x_43455 + defunc_0_reduce_res_45282;
                
                ((double *) mem_47247)[i_45501 * (int64_t) 100 + i_45497] = defunc_0_f_res_43573;
            }
        }
        for (int64_t i_45523 = 0; i_45523 < (int64_t) 16; i_45523++) {
            int64_t binop_x_46220 = (int64_t) 100 * i_45523;
            
            for (int64_t i_45509 = 0; i_45509 < (int64_t) 10; i_45509++) {
                int64_t binop_y_46221 = (int64_t) 10 * i_45509;
                int64_t binop_x_46222 = binop_x_46220 + binop_y_46221;
                
                for (int64_t i_45505 = 0; i_45505 < (int64_t) 10; i_45505++) {
                    int64_t binop_x_46223 = i_45505 + binop_x_46222;
                    int64_t new_index_46224 = squot64(binop_x_46223, (int64_t) 100);
                    int64_t binop_y_46234 = (int64_t) 100 * new_index_46224;
                    int64_t new_index_46235 = binop_x_46223 - binop_y_46234;
                    double x_43414 = ((double *) mem_47247)[new_index_46224 * (int64_t) 100 + new_index_46235];
                    double max_res_43415 = fmax64(0.0, x_43414);
                    
                    ((double *) mem_47300)[i_45509 * (int64_t) 10 + i_45505] = max_res_43415;
                }
            }
            for (int64_t i_45519 = 0; i_45519 < (int64_t) 5; i_45519++) {
                int64_t i_43419 = mul64((int64_t) 2, i_45519);
                int64_t j_43420 = add64((int64_t) 2, i_43419);
                int64_t i_p_m_t_s_43421 = add64((int64_t) 1, i_43419);
                bool zzero_leq_i_p_m_t_s_43422 = sle64((int64_t) 0, i_p_m_t_s_43421);
                bool i_p_m_t_s_leq_w_43423 = slt64(i_p_m_t_s_43421, (int64_t) 10);
                bool zzero_lte_i_43424 = sle64((int64_t) 0, i_43419);
                bool i_lte_j_43425 = sle64(i_43419, j_43420);
                bool y_43426 = i_p_m_t_s_leq_w_43423 && zzero_lte_i_43424;
                bool y_43427 = zzero_leq_i_p_m_t_s_43422 && y_43426;
                bool y_43428 = i_lte_j_43425 && y_43427;
                bool forwards_ok_43429 = zzero_lte_i_43424 && y_43428;
                
                for (int64_t i_45515 = 0; i_45515 < (int64_t) 5; i_45515++) {
                    int64_t i_43432 = mul64((int64_t) 2, i_45515);
                    int64_t j_43433 = add64((int64_t) 2, i_43432);
                    int64_t i_p_m_t_s_43434 = add64((int64_t) 1, i_43432);
                    bool zzero_leq_i_p_m_t_s_43435 = sle64((int64_t) 0, i_p_m_t_s_43434);
                    bool i_p_m_t_s_leq_w_43436 = slt64(i_p_m_t_s_43434, (int64_t) 10);
                    bool zzero_lte_i_43437 = sle64((int64_t) 0, i_43432);
                    bool i_lte_j_43438 = sle64(i_43432, j_43433);
                    bool y_43439 = i_p_m_t_s_leq_w_43436 && zzero_lte_i_43437;
                    bool y_43440 = zzero_leq_i_p_m_t_s_43435 && y_43439;
                    bool y_43441 = i_lte_j_43438 && y_43440;
                    bool forwards_ok_43442 = zzero_lte_i_43437 && y_43441;
                    bool index_ok_43443 = forwards_ok_43429 && forwards_ok_43442;
                    bool index_certs_43444;
                    
                    if (!index_ok_43443) {
                        set_error(ctx, msgprintf("Error: %s%lld%s%lld%s%lld%s%lld%s%lld%s%lld%s\n\nBacktrace:\n%s", "Index [", (long long) i_43419, ":", (long long) j_43420, ", ", (long long) i_43432, ":", (long long) j_43433, "] out of bounds for array of shape [", (long long) (int64_t) 10, "][", (long long) (int64_t) 10, "].", "-> #0  ../layers/avgpool.fut:7:18-80\n   #1  /prelude/soacs.fut:59:9-10\n   #2  /prelude/array.fut:200:10-17\n   #3  /prelude/functional.fut:39:61-65\n   #4  /prelude/soacs.fut:59:9-10\n   #5  /prelude/array.fut:208:27-34\n   #6  ../layers/avgpool.fut:6:29-8:49\n   #7  ../layers/avgpool.fut:8:73-76\n   #8  ../lenet/lenet.fut:15:36-65\n"));
                        err = FUTHARK_PROGRAM_ERROR;
                        goto cleanup;
                    }
                    
                    double defunc_0_reduce_res_45285;
                    double redout_45511 = 0.0;
                    
                    for (int64_t i_45512 = 0; i_45512 < (int64_t) 4; i_45512++) {
                        int64_t new_index_45845 = squot64(i_45512, (int64_t) 2);
                        int64_t binop_y_45847 = (int64_t) 2 * new_index_45845;
                        int64_t new_index_45848 = i_45512 - binop_y_45847;
                        int64_t slice_45849 = i_43419 + new_index_45845;
                        int64_t slice_45850 = i_43432 + new_index_45848;
                        double x_43451 = ((double *) mem_47300)[slice_45849 * (int64_t) 10 + slice_45850];
                        double defunc_0_op_res_43450 = x_43451 + redout_45511;
                        double redout_tmp_48414 = defunc_0_op_res_43450;
                        
                        redout_45511 = redout_tmp_48414;
                    }
                    defunc_0_reduce_res_45285 = redout_45511;
                    
                    double defunc_0_f_res_43452 = defunc_0_reduce_res_45285 / 4.0;
                    
                    ((double *) mem_47287)[i_45523 * (int64_t) 25 + i_45519 * (int64_t) 5 + i_45515] = defunc_0_f_res_43452;
                }
            }
        }
        for (int64_t i_45529 = 0; i_45529 < (int64_t) 120; i_45529++) {
            double x_43396 = ((double *) mem_param_46881.mem)[i_45529];
            double defunc_0_reduce_res_45290;
            double redout_45525 = 0.0;
            
            for (int64_t i_45526 = 0; i_45526 < (int64_t) 400; i_45526++) {
                int64_t new_index_45831 = squot64(i_45526, (int64_t) 25);
                int64_t binop_y_45833 = (int64_t) 25 * new_index_45831;
                int64_t binop_x_45834 = i_45526 - binop_y_45833;
                int64_t new_index_45835 = squot64(binop_x_45834, (int64_t) 5);
                int64_t binop_y_45843 = (int64_t) 5 * new_index_45835;
                int64_t new_index_45844 = binop_x_45834 - binop_y_45843;
                double x_43589 = ((double *) mem_47287)[new_index_45831 * (int64_t) 25 + new_index_45835 * (int64_t) 5 + new_index_45844];
                double x_43590 = ((double *) mem_param_46876.mem)[i_45529 * (int64_t) 400 + i_45526];
                double defunc_0_f_res_43591 = x_43589 * x_43590;
                double defunc_0_op_res_43404 = defunc_0_f_res_43591 + redout_45525;
                double redout_tmp_48416 = defunc_0_op_res_43404;
                
                redout_45525 = redout_tmp_48416;
            }
            defunc_0_reduce_res_45290 = redout_45525;
            
            double defunc_0_f_res_43406 = x_43396 + defunc_0_reduce_res_45290;
            double max_res_43408 = fmax64(0.0, defunc_0_f_res_43406);
            
            ((double *) mem_47411)[i_45529] = max_res_43408;
        }
        for (int64_t i_45535 = 0; i_45535 < (int64_t) 84; i_45535++) {
            double x_43381 = ((double *) mem_param_46897.mem)[i_45535];
            double defunc_0_reduce_res_45291;
            double redout_45531 = 0.0;
            
            for (int64_t i_45532 = 0; i_45532 < (int64_t) 120; i_45532++) {
                double x_43595 = ((double *) mem_47411)[i_45532];
                double x_43596 = ((double *) mem_param_46892.mem)[i_45535 * (int64_t) 120 + i_45532];
                double defunc_0_f_res_43597 = x_43595 * x_43596;
                double defunc_0_op_res_43389 = defunc_0_f_res_43597 + redout_45531;
                double redout_tmp_48418 = defunc_0_op_res_43389;
                
                redout_45531 = redout_tmp_48418;
            }
            defunc_0_reduce_res_45291 = redout_45531;
            
            double defunc_0_f_res_43391 = x_43381 + defunc_0_reduce_res_45291;
            double max_res_43393 = fmax64(0.0, defunc_0_f_res_43391);
            
            ((double *) mem_47423)[i_45535] = max_res_43393;
        }
        
        double defunc_0_reduce_res_45357;
        double redout_45540 = 0.0;
        
        for (int64_t i_45542 = 0; i_45542 < (int64_t) 10; i_45542++) {
            double x_44948 = ((double *) mem_param_46913.mem)[i_45542];
            double defunc_0_reduce_res_45292;
            double redout_45537 = 0.0;
            
            for (int64_t i_45538 = 0; i_45538 < (int64_t) 84; i_45538++) {
                double x_44953 = ((double *) mem_47423)[i_45538];
                double x_44954 = ((double *) mem_param_46908.mem)[i_45542 * (int64_t) 84 + i_45538];
                double defunc_0_f_res_44955 = x_44953 * x_44954;
                double defunc_0_op_res_44952 = defunc_0_f_res_44955 + redout_45537;
                double redout_tmp_48421 = defunc_0_op_res_44952;
                
                redout_45537 = redout_tmp_48421;
            }
            defunc_0_reduce_res_45292 = redout_45537;
            
            double defunc_0_f_res_44956 = x_44948 + defunc_0_reduce_res_45292;
            double defunc_0_f_res_44957 = futrts_exp64(defunc_0_f_res_44956);
            double defunc_0_op_res_41856 = defunc_0_f_res_44957 + redout_45540;
            
            ((double *) mem_47435)[i_45542] = defunc_0_f_res_44957;
            
            double redout_tmp_48419 = defunc_0_op_res_41856;
            
            redout_45540 = redout_tmp_48419;
        }
        defunc_0_reduce_res_45357 = redout_45540;
        
        double binop_y_43786 = 1.0 / defunc_0_reduce_res_45357;
        double binop_y_43788 = defunc_0_reduce_res_45357 * defunc_0_reduce_res_45357;
        double defunc_0_reduce_res_contrib_sum_45359;
        double redout_45545 = 0.0;
        
        for (int64_t i_45547 = 0; i_45547 < (int64_t) 10; i_45547++) {
            double x_44933 = ((double *) mem_47435)[i_45547];
            double x_44934 = ((double *) y_train_mem_46822.mem)[i_40648 * (int64_t) 10 + i_45547];
            double defunc_0_f_res_44935 = x_44933 / defunc_0_reduce_res_45357;
            double arg_44936 = x_44934 - defunc_0_f_res_44935;
            double binop_y_44937 = 2.0 * arg_44936;
            double binop_x_adj_44938 = 0.1 * binop_y_44937;
            double binop_y_adj_44939 = -1.0 * binop_x_adj_44938;
            double binop_x_adj_44940 = binop_y_43786 * binop_y_adj_44939;
            double binop_y_44941 = x_44933 / binop_y_43788;
            double binop_y_44942 = 0.0 - binop_y_44941;
            double binop_y_adj_44943 = binop_y_adj_44939 * binop_y_44942;
            double binlam_res_43797 = binop_y_adj_44943 + redout_45545;
            
            ((double *) mem_47447)[i_45547] = binop_x_adj_44940;
            
            double redout_tmp_48422 = binlam_res_43797;
            
            redout_45545 = redout_tmp_48422;
        }
        defunc_0_reduce_res_contrib_sum_45359 = redout_45545;
        for (int64_t nest_i_48424 = 0; nest_i_48424 < (int64_t) 84; nest_i_48424++) {
            ((double *) mem_47459)[nest_i_48424] = 0.0;
        }
        
        bool acc_cert_p_43820;
        
        for (int64_t i_45561 = 0; i_45561 < (int64_t) 10; i_45561++) {
            double x_43804 = ((double *) mem_param_46913.mem)[i_45561];
            double map_adj_p_43802 = ((double *) mem_47447)[i_45561];
            double defunc_0_f_res_adj_43823 = map_adj_p_43802 + defunc_0_reduce_res_contrib_sum_45359;
            double defunc_0_reduce_res_45293;
            double redout_45549 = 0.0;
            
            for (int64_t i_45550 = 0; i_45550 < (int64_t) 84; i_45550++) {
                double x_44993 = ((double *) mem_47423)[i_45550];
                double x_44994 = ((double *) mem_param_46908.mem)[i_45561 * (int64_t) 84 + i_45550];
                double defunc_0_f_res_44995 = x_44993 * x_44994;
                double defunc_0_op_res_43808 = defunc_0_f_res_44995 + redout_45549;
                double redout_tmp_48428 = defunc_0_op_res_43808;
                
                redout_45549 = redout_tmp_48428;
            }
            defunc_0_reduce_res_45293 = redout_45549;
            
            double defunc_0_f_res_43812 = x_43804 + defunc_0_reduce_res_45293;
            double binop_y_43826 = futrts_exp64(defunc_0_f_res_43812);
            double contrib_43827 = defunc_0_f_res_adj_43823 * binop_y_43826;
            
            for (int64_t i_45554 = 0; i_45554 < (int64_t) 84; i_45554++) {
                double x_44983 = ((double *) mem_47423)[i_45554];
                double x_44984 = ((double *) mem_param_46908.mem)[i_45561 * (int64_t) 84 + i_45554];
                double binop_x_adj_44987 = contrib_43827 * x_44984;
                double binop_y_adj_44988 = contrib_43827 * x_44983;
                
                // UpdateAcc
                {
                    int64_t idx_43819 = i_45554;
                    
                    if (sle64((int64_t) 0, i_45554) && slt64(i_45554, (int64_t) 84)) {
                        double x_43816;
                        double y_43817;
                        
                        x_43816 = ((double *) mem_47459)[i_45554];
                        y_43817 = binop_x_adj_44987;
                        
                        double binlam_res_43818 = x_43816 + y_43817;
                        
                        ((double *) mem_47459)[i_45554] = binlam_res_43818;
                    }
                }
                ((double *) mem_47478)[i_45554] = binop_y_adj_44988;
            }
            if ((int64_t) 672 > 0)
                memmove(mem_47461 + i_45561 * (int64_t) 84 * (int64_t) 8, mem_47478 + (int64_t) 0, (int64_t) 672);
            ((double *) mem_47463)[i_45561] = contrib_43827;
        }
        if ((int64_t) 6720 > 0)
            memmove(mem_47503 + (int64_t) 0, mem_47461 + (int64_t) 0, (int64_t) 6720);
        if ((int64_t) 80 > 0)
            memmove(mem_47505 + (int64_t) 0, mem_47463 + (int64_t) 0, (int64_t) 80);
        for (int64_t nest_i_48431 = 0; nest_i_48431 < (int64_t) 120; nest_i_48431++) {
            ((double *) mem_47507)[nest_i_48431] = 0.0;
        }
        
        bool acc_cert_p_43869;
        
        for (int64_t i_45576 = 0; i_45576 < (int64_t) 84; i_45576++) {
            double x_43853 = ((double *) mem_param_46897.mem)[i_45576];
            double map_adj_p_43851 = ((double *) mem_47459)[i_45576];
            double defunc_0_reduce_res_45299;
            double redout_45564 = 0.0;
            
            for (int64_t i_45565 = 0; i_45565 < (int64_t) 120; i_45565++) {
                double x_45018 = ((double *) mem_47411)[i_45565];
                double x_45019 = ((double *) mem_param_46892.mem)[i_45576 * (int64_t) 120 + i_45565];
                double defunc_0_f_res_45020 = x_45018 * x_45019;
                double defunc_0_op_res_43857 = defunc_0_f_res_45020 + redout_45564;
                double redout_tmp_48435 = defunc_0_op_res_43857;
                
                redout_45564 = redout_tmp_48435;
            }
            defunc_0_reduce_res_45299 = redout_45564;
            
            double defunc_0_f_res_43861 = x_43853 + defunc_0_reduce_res_45299;
            bool convop_x_43878 = 0.0 < defunc_0_f_res_43861;
            int32_t convop_x_43879 = btoi_bool_i32(convop_x_43878);
            double binop_y_43880 = sitofp_i32_f64(convop_x_43879);
            double binop_y_adj_43881 = map_adj_p_43851 * binop_y_43880;
            
            for (int64_t i_45569 = 0; i_45569 < (int64_t) 120; i_45569++) {
                double x_45008 = ((double *) mem_47411)[i_45569];
                double x_45009 = ((double *) mem_param_46892.mem)[i_45576 * (int64_t) 120 + i_45569];
                double binop_x_adj_45012 = binop_y_adj_43881 * x_45009;
                double binop_y_adj_45013 = binop_y_adj_43881 * x_45008;
                
                // UpdateAcc
                {
                    int64_t idx_43868 = i_45569;
                    
                    if (sle64((int64_t) 0, i_45569) && slt64(i_45569, (int64_t) 120)) {
                        double x_43865;
                        double y_43866;
                        
                        x_43865 = ((double *) mem_47507)[i_45569];
                        y_43866 = binop_x_adj_45012;
                        
                        double binlam_res_43867 = x_43865 + y_43866;
                        
                        ((double *) mem_47507)[i_45569] = binlam_res_43867;
                    }
                }
                ((double *) mem_47526)[i_45569] = binop_y_adj_45013;
            }
            if ((int64_t) 960 > 0)
                memmove(mem_47509 + i_45576 * (int64_t) 120 * (int64_t) 8, mem_47526 + (int64_t) 0, (int64_t) 960);
            ((double *) mem_47511)[i_45576] = binop_y_adj_43881;
        }
        if ((int64_t) 80640 > 0)
            memmove(mem_47551 + (int64_t) 0, mem_47509 + (int64_t) 0, (int64_t) 80640);
        if ((int64_t) 672 > 0)
            memmove(mem_47553 + (int64_t) 0, mem_47511 + (int64_t) 0, (int64_t) 672);
        for (int64_t nest_i_48438 = 0; nest_i_48438 < (int64_t) 400; nest_i_48438++) {
            ((double *) mem_47555)[nest_i_48438] = 0.0;
        }
        
        bool acc_cert_p_43923;
        
        for (int64_t i_45591 = 0; i_45591 < (int64_t) 120; i_45591++) {
            double x_43907 = ((double *) mem_param_46881.mem)[i_45591];
            double map_adj_p_43905 = ((double *) mem_47507)[i_45591];
            double defunc_0_reduce_res_45305;
            double redout_45579 = 0.0;
            
            for (int64_t i_45580 = 0; i_45580 < (int64_t) 400; i_45580++) {
                int64_t new_index_45813 = squot64(i_45580, (int64_t) 25);
                int64_t binop_y_45815 = (int64_t) 25 * new_index_45813;
                int64_t binop_x_45816 = i_45580 - binop_y_45815;
                int64_t new_index_45817 = squot64(binop_x_45816, (int64_t) 5);
                int64_t binop_y_45825 = (int64_t) 5 * new_index_45817;
                int64_t new_index_45826 = binop_x_45816 - binop_y_45825;
                double x_45043 = ((double *) mem_47287)[new_index_45813 * (int64_t) 25 + new_index_45817 * (int64_t) 5 + new_index_45826];
                double x_45044 = ((double *) mem_param_46876.mem)[i_45591 * (int64_t) 400 + i_45580];
                double defunc_0_f_res_45045 = x_45043 * x_45044;
                double defunc_0_op_res_43911 = defunc_0_f_res_45045 + redout_45579;
                double redout_tmp_48442 = defunc_0_op_res_43911;
                
                redout_45579 = redout_tmp_48442;
            }
            defunc_0_reduce_res_45305 = redout_45579;
            
            double defunc_0_f_res_43915 = x_43907 + defunc_0_reduce_res_45305;
            bool convop_x_43932 = 0.0 < defunc_0_f_res_43915;
            int32_t convop_x_43933 = btoi_bool_i32(convop_x_43932);
            double binop_y_43934 = sitofp_i32_f64(convop_x_43933);
            double binop_y_adj_43935 = map_adj_p_43905 * binop_y_43934;
            
            for (int64_t i_45584 = 0; i_45584 < (int64_t) 400; i_45584++) {
                int64_t new_index_45797 = squot64(i_45584, (int64_t) 25);
                int64_t binop_y_45799 = (int64_t) 25 * new_index_45797;
                int64_t binop_x_45800 = i_45584 - binop_y_45799;
                int64_t new_index_45801 = squot64(binop_x_45800, (int64_t) 5);
                int64_t binop_y_45809 = (int64_t) 5 * new_index_45801;
                int64_t new_index_45810 = binop_x_45800 - binop_y_45809;
                double x_45033 = ((double *) mem_47287)[new_index_45797 * (int64_t) 25 + new_index_45801 * (int64_t) 5 + new_index_45810];
                double x_45034 = ((double *) mem_param_46876.mem)[i_45591 * (int64_t) 400 + i_45584];
                double binop_x_adj_45037 = binop_y_adj_43935 * x_45034;
                double binop_y_adj_45038 = binop_y_adj_43935 * x_45033;
                
                // UpdateAcc
                {
                    int64_t idx_43922 = i_45584;
                    
                    if (sle64((int64_t) 0, i_45584) && slt64(i_45584, (int64_t) 400)) {
                        double x_43919;
                        double y_43920;
                        
                        x_43919 = ((double *) mem_47555)[i_45584];
                        y_43920 = binop_x_adj_45037;
                        
                        double binlam_res_43921 = x_43919 + y_43920;
                        
                        ((double *) mem_47555)[i_45584] = binlam_res_43921;
                    }
                }
                ((double *) mem_47574)[i_45584] = binop_y_adj_45038;
            }
            if ((int64_t) 3200 > 0)
                memmove(mem_47557 + i_45591 * (int64_t) 400 * (int64_t) 8, mem_47574 + (int64_t) 0, (int64_t) 3200);
            ((double *) mem_47559)[i_45591] = binop_y_adj_43935;
        }
        if ((int64_t) 384000 > 0)
            memmove(mem_47599 + (int64_t) 0, mem_47557 + (int64_t) 0, (int64_t) 384000);
        if ((int64_t) 960 > 0)
            memmove(mem_47601 + (int64_t) 0, mem_47559 + (int64_t) 0, (int64_t) 960);
        for (int64_t i_45612 = 0; i_45612 < (int64_t) 16; i_45612++) {
            for (int64_t nest_i_48446 = 0; nest_i_48446 < (int64_t) 10; nest_i_48446++) {
                for (int64_t nest_i_48447 = 0; nest_i_48447 < (int64_t) 10; nest_i_48447++) {
                    ((double *) mem_47616)[nest_i_48446 * (int64_t) 10 + nest_i_48447] = 0.0;
                }
            }
            
            int64_t binop_x_46216 = (int64_t) 25 * i_45612;
            bool acc_cert_p_44055;
            
            for (int64_t i_45601 = 0; i_45601 < (int64_t) 5; i_45601++) {
                int64_t i_44014 = mul64((int64_t) 2, i_45601);
                int64_t binop_y_46217 = (int64_t) 5 * i_45601;
                int64_t binop_x_46218 = binop_x_46216 + binop_y_46217;
                
                for (int64_t i_45599 = 0; i_45599 < (int64_t) 5; i_45599++) {
                    int64_t new_index_46219 = i_45599 + binop_x_46218;
                    double map_adj_p_44059 = ((double *) mem_47555)[new_index_46219];
                    int64_t i_44061 = mul64((int64_t) 2, i_45599);
                    double binop_x_adj_44086 = 0.25 * map_adj_p_44059;
                    
                    for (int64_t i_45597 = 0; i_45597 < (int64_t) 2; i_45597++) {
                        int64_t index_44100 = i_44014 + i_45597;
                        
                        for (int64_t i_45595 = 0; i_45595 < (int64_t) 2; i_45595++) {
                            int64_t index_44101 = i_44061 + i_45595;
                            
                            // UpdateAcc
                            {
                                int64_t idx_44053 = index_44100;
                                int64_t idx_44054 = index_44101;
                                
                                if ((sle64((int64_t) 0, index_44100) && slt64(index_44100, (int64_t) 10)) && (sle64((int64_t) 0, index_44101) && slt64(index_44101, (int64_t) 10))) {
                                    double x_44050;
                                    double y_44051;
                                    
                                    x_44050 = ((double *) mem_47616)[index_44100 * (int64_t) 10 + index_44101];
                                    y_44051 = binop_x_adj_44086;
                                    
                                    double binlam_res_44052 = x_44050 + y_44051;
                                    
                                    ((double *) mem_47616)[index_44100 * (int64_t) 10 + index_44101] = binlam_res_44052;
                                }
                            }
                        }
                    }
                }
            }
            
            int64_t binop_x_46200 = (int64_t) 100 * i_45612;
            
            for (int64_t i_45608 = 0; i_45608 < (int64_t) 10; i_45608++) {
                int64_t binop_y_46201 = (int64_t) 10 * i_45608;
                int64_t binop_x_46202 = binop_x_46200 + binop_y_46201;
                
                for (int64_t i_45604 = 0; i_45604 < (int64_t) 10; i_45604++) {
                    int64_t binop_x_46203 = i_45604 + binop_x_46202;
                    int64_t new_index_46204 = squot64(binop_x_46203, (int64_t) 100);
                    int64_t binop_y_46214 = (int64_t) 100 * new_index_46204;
                    int64_t new_index_46215 = binop_x_46203 - binop_y_46214;
                    double x_44202 = ((double *) mem_47247)[new_index_46204 * (int64_t) 100 + new_index_46215];
                    double map_adj_p_44201 = ((double *) mem_47616)[i_45608 * (int64_t) 10 + i_45604];
                    bool convop_x_44208 = 0.0 < x_44202;
                    int32_t convop_x_44209 = btoi_bool_i32(convop_x_44208);
                    double binop_y_44210 = sitofp_i32_f64(convop_x_44209);
                    double binop_y_adj_44211 = map_adj_p_44201 * binop_y_44210;
                    
                    ((double *) mem_47603)[i_45612 * (int64_t) 100 + i_45608 * (int64_t) 10 + i_45604] = binop_y_adj_44211;
                }
            }
        }
        for (int64_t nest_i_48454 = 0; nest_i_48454 < (int64_t) 100; nest_i_48454++) {
            for (int64_t nest_i_48455 = 0; nest_i_48455 < (int64_t) 150; nest_i_48455++) {
                ((double *) mem_47689)[nest_i_48454 * (int64_t) 150 + nest_i_48455] = 0.0;
            }
        }
        
        bool acc_cert_p_44239;
        
        for (int64_t i_45627 = 0; i_45627 < (int64_t) 16; i_45627++) {
            for (int64_t nest_i_48459 = 0; nest_i_48459 < (int64_t) 150; nest_i_48459++) {
                ((double *) mem_47708)[nest_i_48459] = 0.0;
            }
            
            int64_t binop_x_46172 = (int64_t) 100 * i_45627;
            double x_contrib_sum_45321;
            double redout_45614 = 0.0;
            
            for (int64_t i_45615 = 0; i_45615 < (int64_t) 100; i_45615++) {
                int64_t binop_x_46173 = i_45615 + binop_x_46172;
                int64_t new_index_46174 = squot64(binop_x_46173, (int64_t) 100);
                int64_t binop_y_46180 = (int64_t) 100 * new_index_46174;
                int64_t binop_x_46181 = binop_x_46173 - binop_y_46180;
                int64_t new_index_46182 = squot64(binop_x_46181, (int64_t) 10);
                int64_t binop_y_46198 = (int64_t) 10 * new_index_46182;
                int64_t new_index_46199 = binop_x_46181 - binop_y_46198;
                double x_44287 = ((double *) mem_47603)[new_index_46174 * (int64_t) 100 + new_index_46182 * (int64_t) 10 + new_index_46199];
                double binlam_res_44286 = x_44287 + redout_45614;
                double redout_tmp_48460 = binlam_res_44286;
                
                redout_45614 = redout_tmp_48460;
            }
            x_contrib_sum_45321 = redout_45614;
            
            int64_t binop_x_46078 = (int64_t) 150 * i_45627;
            bool acc_cert_p_44259;
            
            for (int64_t i_45621 = 0; i_45621 < (int64_t) 100; i_45621++) {
                int64_t binop_x_46051 = i_45621 + binop_x_46172;
                int64_t new_index_46052 = squot64(binop_x_46051, (int64_t) 100);
                int64_t binop_y_46058 = (int64_t) 100 * new_index_46052;
                int64_t binop_x_46059 = binop_x_46051 - binop_y_46058;
                int64_t new_index_46060 = squot64(binop_x_46059, (int64_t) 10);
                int64_t binop_y_46076 = (int64_t) 10 * new_index_46060;
                int64_t new_index_46077 = binop_x_46059 - binop_y_46076;
                double map_adj_p_45064 = ((double *) mem_47603)[new_index_46052 * (int64_t) 100 + new_index_46060 * (int64_t) 10 + new_index_46077];
                int64_t binop_x_46144 = (int64_t) 150 * i_45621;
                
                for (int64_t i_45618 = 0; i_45618 < (int64_t) 150; i_45618++) {
                    int64_t binop_x_46079 = i_45618 + binop_x_46078;
                    int64_t new_index_46080 = squot64(binop_x_46079, (int64_t) 150);
                    int64_t binop_y_46086 = (int64_t) 150 * new_index_46080;
                    int64_t binop_x_46087 = binop_x_46079 - binop_y_46086;
                    int64_t new_index_46088 = squot64(binop_x_46087, (int64_t) 25);
                    int64_t binop_y_46104 = (int64_t) 25 * new_index_46088;
                    int64_t binop_x_46105 = binop_x_46087 - binop_y_46104;
                    int64_t new_index_46106 = squot64(binop_x_46105, (int64_t) 5);
                    int64_t binop_y_46142 = (int64_t) 5 * new_index_46106;
                    int64_t new_index_46143 = binop_x_46105 - binop_y_46142;
                    double x_45102 = ((double *) mem_param_46860.mem)[new_index_46080 * (int64_t) 150 + new_index_46088 * (int64_t) 25 + new_index_46106 * (int64_t) 5 + new_index_46143];
                    int64_t binop_x_46145 = i_45618 + binop_x_46144;
                    int64_t new_index_46146 = squot64(binop_x_46145, (int64_t) 1500);
                    int64_t binop_y_46152 = (int64_t) 1500 * new_index_46146;
                    int64_t binop_x_46153 = binop_x_46145 - binop_y_46152;
                    int64_t new_index_46154 = squot64(binop_x_46153, (int64_t) 150);
                    int64_t binop_y_46170 = (int64_t) 150 * new_index_46154;
                    int64_t new_index_46171 = binop_x_46153 - binop_y_46170;
                    double x_45103 = ((double *) mem_47195)[new_index_46146 * (int64_t) 1500 + new_index_46154 * (int64_t) 150 + new_index_46171];
                    double binop_x_adj_45106 = map_adj_p_45064 * x_45103;
                    double binop_y_adj_45107 = map_adj_p_45064 * x_45102;
                    
                    // UpdateAcc
                    {
                        int64_t idx_44237 = i_45621;
                        int64_t idx_44238 = i_45618;
                        
                        if ((sle64((int64_t) 0, i_45621) && slt64(i_45621, (int64_t) 100)) && (sle64((int64_t) 0, i_45618) && slt64(i_45618, (int64_t) 150))) {
                            double x_44234;
                            double y_44235;
                            
                            x_44234 = ((double *) mem_47689)[i_45621 * (int64_t) 150 + i_45618];
                            y_44235 = binop_y_adj_45107;
                            
                            double binlam_res_44236 = x_44234 + y_44235;
                            
                            ((double *) mem_47689)[i_45621 * (int64_t) 150 + i_45618] = binlam_res_44236;
                        }
                    }
                    // UpdateAcc
                    {
                        int64_t idx_44258 = i_45618;
                        
                        if (sle64((int64_t) 0, i_45618) && slt64(i_45618, (int64_t) 150)) {
                            double x_44255;
                            double y_44256;
                            
                            x_44255 = ((double *) mem_47708)[i_45618];
                            y_44256 = binop_x_adj_45106;
                            
                            double binlam_res_44257 = x_44255 + y_44256;
                            
                            ((double *) mem_47708)[i_45618] = binlam_res_44257;
                        }
                    }
                }
            }
            if ((int64_t) 1200 > 0)
                memmove(mem_47691 + i_45627 * (int64_t) 150 * (int64_t) 8, mem_47708 + (int64_t) 0, (int64_t) 1200);
            ((double *) mem_47693)[i_45627] = x_contrib_sum_45321;
        }
        if ((int64_t) 19200 > 0)
            memmove(mem_47723 + (int64_t) 0, mem_47691 + (int64_t) 0, (int64_t) 19200);
        if ((int64_t) 128 > 0)
            memmove(mem_47725 + (int64_t) 0, mem_47693 + (int64_t) 0, (int64_t) 128);
        if (memblock_alloc(ctx, &mem_47727, (int64_t) 19200, "mem_47727")) {
            err = 1;
            goto cleanup;
        }
        for (int64_t i_45644 = 0; i_45644 < (int64_t) 16; i_45644++) {
            int64_t binop_x_46028 = (int64_t) 150 * i_45644;
            
            for (int64_t i_45640 = 0; i_45640 < (int64_t) 6; i_45640++) {
                int64_t binop_y_46029 = (int64_t) 25 * i_45640;
                int64_t binop_x_46030 = binop_x_46028 + binop_y_46029;
                
                for (int64_t i_45636 = 0; i_45636 < (int64_t) 5; i_45636++) {
                    int64_t binop_y_46031 = (int64_t) 5 * i_45636;
                    int64_t binop_x_46032 = binop_x_46030 + binop_y_46031;
                    
                    for (int64_t i_45632 = 0; i_45632 < (int64_t) 5; i_45632++) {
                        double x_40804 = ((double *) mem_param_46860.mem)[i_45644 * (int64_t) 150 + i_45640 * (int64_t) 25 + i_45636 * (int64_t) 5 + i_45632];
                        int64_t binop_x_46033 = i_45632 + binop_x_46032;
                        int64_t new_index_46034 = squot64(binop_x_46033, (int64_t) 150);
                        int64_t binop_y_46048 = (int64_t) 150 * new_index_46034;
                        int64_t new_index_46049 = binop_x_46033 - binop_y_46048;
                        double x_40805 = ((double *) mem_47723)[new_index_46034 * (int64_t) 150 + new_index_46049];
                        double arg_40806 = 0.1 * x_40805;
                        double defunc_0_f_res_40807 = x_40804 - arg_40806;
                        
                        ((double *) mem_47727.mem)[i_45644 * (int64_t) 150 + i_45640 * (int64_t) 25 + i_45636 * (int64_t) 5 + i_45632] = defunc_0_f_res_40807;
                    }
                }
            }
        }
        for (int64_t nest_i_48469 = 0; nest_i_48469 < (int64_t) 6; nest_i_48469++) {
            for (int64_t nest_i_48470 = 0; nest_i_48470 < (int64_t) 14; nest_i_48470++) {
                for (int64_t nest_i_48471 = 0; nest_i_48471 < (int64_t) 14; nest_i_48471++) {
                    ((double *) mem_47871)[nest_i_48469 * (int64_t) 196 + nest_i_48470 * (int64_t) 14 + nest_i_48471] = 0.0;
                }
            }
        }
        
        bool acc_cert_p_44355;
        
        for (int64_t i_45655 = 0; i_45655 < (int64_t) 10; i_45655++) {
            int64_t binop_x_46000 = (int64_t) 1500 * i_45655;
            
            for (int64_t i_45653 = 0; i_45653 < (int64_t) 10; i_45653++) {
                int64_t binop_y_46001 = (int64_t) 150 * i_45653;
                int64_t binop_x_46002 = binop_x_46000 + binop_y_46001;
                
                for (int64_t i_45651 = 0; i_45651 < (int64_t) 6; i_45651++) {
                    int64_t binop_y_46003 = (int64_t) 25 * i_45651;
                    int64_t binop_x_46004 = binop_x_46002 + binop_y_46003;
                    
                    for (int64_t i_45649 = 0; i_45649 < (int64_t) 5; i_45649++) {
                        int64_t index_44392 = i_45649 + i_45655;
                        int64_t binop_y_46005 = (int64_t) 5 * i_45649;
                        int64_t binop_x_46006 = binop_x_46004 + binop_y_46005;
                        
                        for (int64_t i_45647 = 0; i_45647 < (int64_t) 5; i_45647++) {
                            int64_t binop_x_46007 = i_45647 + binop_x_46006;
                            int64_t new_index_46008 = squot64(binop_x_46007, (int64_t) 150);
                            int64_t binop_y_46026 = (int64_t) 150 * new_index_46008;
                            int64_t new_index_46027 = binop_x_46007 - binop_y_46026;
                            double adj_reshape_p_p_p_44390 = ((double *) mem_47689)[new_index_46008 * (int64_t) 150 + new_index_46027];
                            int64_t index_44393 = i_45647 + i_45653;
                            
                            // UpdateAcc
                            {
                                int64_t idx_44350 = i_45651;
                                int64_t idx_44351 = index_44392;
                                int64_t idx_44352 = index_44393;
                                
                                if (((sle64((int64_t) 0, i_45651) && slt64(i_45651, (int64_t) 6)) && (sle64((int64_t) 0, index_44392) && slt64(index_44392, (int64_t) 14))) && (sle64((int64_t) 0, index_44393) && slt64(index_44393, (int64_t) 14))) {
                                    double x_44347;
                                    double y_44348;
                                    
                                    x_44347 = ((double *) mem_47871)[i_45651 * (int64_t) 196 + index_44392 * (int64_t) 14 + index_44393];
                                    y_44348 = adj_reshape_p_p_p_44390;
                                    
                                    double binlam_res_44349 = x_44347 + y_44348;
                                    
                                    ((double *) mem_47871)[i_45651 * (int64_t) 196 + index_44392 * (int64_t) 14 + index_44393] = binlam_res_44349;
                                }
                            }
                        }
                    }
                }
            }
        }
        for (int64_t i_45674 = 0; i_45674 < (int64_t) 6; i_45674++) {
            for (int64_t nest_i_48478 = 0; nest_i_48478 < (int64_t) 28; nest_i_48478++) {
                for (int64_t nest_i_48479 = 0; nest_i_48479 < (int64_t) 28; nest_i_48479++) {
                    ((double *) mem_47886)[nest_i_48478 * (int64_t) 28 + nest_i_48479] = 0.0;
                }
            }
            
            bool acc_cert_p_44580;
            
            for (int64_t i_45663 = 0; i_45663 < (int64_t) 14; i_45663++) {
                int64_t i_44539 = mul64((int64_t) 2, i_45663);
                
                for (int64_t i_45661 = 0; i_45661 < (int64_t) 14; i_45661++) {
                    double map_adj_p_44584 = ((double *) mem_47871)[i_45674 * (int64_t) 196 + i_45663 * (int64_t) 14 + i_45661];
                    int64_t i_44586 = mul64((int64_t) 2, i_45661);
                    double binop_x_adj_44611 = 0.25 * map_adj_p_44584;
                    
                    for (int64_t i_45659 = 0; i_45659 < (int64_t) 2; i_45659++) {
                        int64_t index_44625 = i_44539 + i_45659;
                        
                        for (int64_t i_45657 = 0; i_45657 < (int64_t) 2; i_45657++) {
                            int64_t index_44626 = i_44586 + i_45657;
                            
                            // UpdateAcc
                            {
                                int64_t idx_44578 = index_44625;
                                int64_t idx_44579 = index_44626;
                                
                                if ((sle64((int64_t) 0, index_44625) && slt64(index_44625, (int64_t) 28)) && (sle64((int64_t) 0, index_44626) && slt64(index_44626, (int64_t) 28))) {
                                    double x_44575;
                                    double y_44576;
                                    
                                    x_44575 = ((double *) mem_47886)[index_44625 * (int64_t) 28 + index_44626];
                                    y_44576 = binop_x_adj_44611;
                                    
                                    double binlam_res_44577 = x_44575 + y_44576;
                                    
                                    ((double *) mem_47886)[index_44625 * (int64_t) 28 + index_44626] = binlam_res_44577;
                                }
                            }
                        }
                    }
                }
            }
            
            int64_t binop_x_45984 = (int64_t) 784 * i_45674;
            
            for (int64_t i_45670 = 0; i_45670 < (int64_t) 28; i_45670++) {
                int64_t binop_y_45985 = (int64_t) 28 * i_45670;
                int64_t binop_x_45986 = binop_x_45984 + binop_y_45985;
                
                for (int64_t i_45666 = 0; i_45666 < (int64_t) 28; i_45666++) {
                    int64_t binop_x_45987 = i_45666 + binop_x_45986;
                    int64_t new_index_45988 = squot64(binop_x_45987, flat_dim_41597);
                    int64_t binop_y_45998 = flat_dim_41597 * new_index_45988;
                    int64_t new_index_45999 = binop_x_45987 - binop_y_45998;
                    double x_44727 = ((double *) mem_47028)[new_index_45988 * flat_dim_41597 + new_index_45999];
                    double map_adj_p_44726 = ((double *) mem_47886)[i_45670 * (int64_t) 28 + i_45666];
                    bool convop_x_44733 = 0.0 < x_44727;
                    int32_t convop_x_44734 = btoi_bool_i32(convop_x_44733);
                    double binop_y_44735 = sitofp_i32_f64(convop_x_44734);
                    double binop_y_adj_44736 = map_adj_p_44726 * binop_y_44735;
                    
                    ((double *) mem_47873)[i_45674 * (int64_t) 784 + i_45670 * (int64_t) 28 + i_45666] = binop_y_adj_44736;
                }
            }
        }
        if (memblock_alloc(ctx, &mem_47959, (int64_t) 48, "mem_47959")) {
            err = 1;
            goto cleanup;
        }
        for (int64_t i_45686 = 0; i_45686 < (int64_t) 6; i_45686++) {
            double x_44900 = ((double *) mem_param_46843.mem)[i_45686];
            
            for (int64_t nest_i_48488 = 0; nest_i_48488 < (int64_t) 25; nest_i_48488++) {
                ((double *) mem_47976)[nest_i_48488] = 0.0;
            }
            
            int64_t binop_x_45956 = flat_dim_41597 * i_45686;
            double x_contrib_sum_45341;
            double redout_45676 = 0.0;
            
            for (int64_t i_45677 = 0; i_45677 < flat_dim_41597; i_45677++) {
                int64_t binop_x_45957 = i_45677 + binop_x_45956;
                int64_t new_index_45958 = squot64(binop_x_45957, (int64_t) 784);
                int64_t binop_y_45964 = (int64_t) 784 * new_index_45958;
                int64_t binop_x_45965 = binop_x_45957 - binop_y_45964;
                int64_t new_index_45966 = squot64(binop_x_45965, (int64_t) 28);
                int64_t binop_y_45982 = (int64_t) 28 * new_index_45966;
                int64_t new_index_45983 = binop_x_45965 - binop_y_45982;
                double x_44907 = ((double *) mem_47873)[new_index_45958 * (int64_t) 784 + new_index_45966 * (int64_t) 28 + new_index_45983];
                double binlam_res_44906 = x_44907 + redout_45676;
                double redout_tmp_48489 = binlam_res_44906;
                
                redout_45676 = redout_tmp_48489;
            }
            x_contrib_sum_45341 = redout_45676;
            
            bool acc_cert_p_44913;
            
            for (int64_t i_45681 = 0; i_45681 < flat_dim_41597; i_45681++) {
                int64_t binop_x_45894 = i_45681 + binop_x_45956;
                int64_t new_index_45895 = squot64(binop_x_45894, (int64_t) 784);
                int64_t binop_y_45901 = (int64_t) 784 * new_index_45895;
                int64_t binop_x_45902 = binop_x_45894 - binop_y_45901;
                int64_t new_index_45903 = squot64(binop_x_45902, (int64_t) 28);
                int64_t binop_y_45919 = (int64_t) 28 * new_index_45903;
                int64_t new_index_45920 = binop_x_45902 - binop_y_45919;
                double map_adj_p_44917 = ((double *) mem_47873)[new_index_45895 * (int64_t) 784 + new_index_45903 * (int64_t) 28 + new_index_45920];
                int64_t binop_x_45921 = (int64_t) 25 * i_45681;
                
                for (int64_t i_45679 = 0; i_45679 < (int64_t) 25; i_45679++) {
                    int64_t binop_x_45922 = i_45679 + binop_x_45921;
                    int64_t new_index_45924 = squot64(binop_x_45922, binop_y_46414);
                    int64_t binop_y_45932 = new_index_45924 * binop_y_46414;
                    int64_t binop_x_45933 = binop_x_45922 - binop_y_45932;
                    int64_t new_index_45934 = squot64(binop_x_45933, (int64_t) 25);
                    int64_t binop_y_45954 = (int64_t) 25 * new_index_45934;
                    int64_t new_index_45955 = binop_x_45933 - binop_y_45954;
                    double x_45148 = ((double *) mem_46967)[new_index_45924 * binop_y_46414 + new_index_45934 * (int64_t) 25 + new_index_45955];
                    double binop_x_adj_45151 = map_adj_p_44917 * x_45148;
                    
                    // UpdateAcc
                    {
                        int64_t idx_44909 = i_45679;
                        
                        if (sle64((int64_t) 0, i_45679) && slt64(i_45679, (int64_t) 25)) {
                            double x_44910;
                            double y_44911;
                            
                            x_44910 = ((double *) mem_47976)[i_45679];
                            y_44911 = binop_x_adj_45151;
                            
                            double binlam_res_44912 = x_44910 + y_44911;
                            
                            ((double *) mem_47976)[i_45679] = binlam_res_44912;
                        }
                    }
                }
            }
            
            double arg_44929 = 0.1 * x_contrib_sum_45341;
            double defunc_0_f_res_44930 = x_44900 - arg_44929;
            
            ((double *) mem_47959.mem)[i_45686] = defunc_0_f_res_44930;
            if ((int64_t) 200 > 0)
                memmove(mem_47961 + i_45686 * (int64_t) 25 * (int64_t) 8, mem_47976 + (int64_t) 0, (int64_t) 200);
        }
        if (memblock_alloc(ctx, &mem_47991, (int64_t) 1200, "mem_47991")) {
            err = 1;
            goto cleanup;
        }
        for (int64_t i_45699 = 0; i_45699 < (int64_t) 6; i_45699++) {
            int64_t binop_x_45877 = (int64_t) 25 * i_45699;
            
            for (int64_t i_45695 = 0; i_45695 < (int64_t) 5; i_45695++) {
                int64_t binop_y_45878 = (int64_t) 5 * i_45695;
                int64_t binop_x_45879 = binop_x_45877 + binop_y_45878;
                
                for (int64_t i_45691 = 0; i_45691 < (int64_t) 5; i_45691++) {
                    double x_40763 = ((double *) mem_param_46838.mem)[i_45699 * (int64_t) 25 + i_45695 * (int64_t) 5 + i_45691];
                    int64_t binop_x_45880 = i_45691 + binop_x_45879;
                    int64_t new_index_45881 = squot64(binop_x_45880, (int64_t) 25);
                    int64_t binop_y_45891 = (int64_t) 25 * new_index_45881;
                    int64_t new_index_45892 = binop_x_45880 - binop_y_45891;
                    double x_40764 = ((double *) mem_47961)[new_index_45881 * (int64_t) 25 + new_index_45892];
                    double arg_40765 = 0.1 * x_40764;
                    double defunc_0_f_res_40766 = x_40763 - arg_40765;
                    
                    ((double *) mem_48007)[i_45695 * (int64_t) 5 + i_45691] = defunc_0_f_res_40766;
                }
            }
            for (int64_t nest_i_48495 = 0; nest_i_48495 < (int64_t) 1; nest_i_48495++) {
                if ((int64_t) 200 > 0)
                    memmove(mem_47991.mem + (i_45699 * (int64_t) 25 + nest_i_48495 * (int64_t) 25) * (int64_t) 8, mem_48007 + (int64_t) 0, (int64_t) 200);
            }
        }
        if (memblock_alloc(ctx, &mem_48063, (int64_t) 128, "mem_48063")) {
            err = 1;
            goto cleanup;
        }
        for (int64_t i_45703 = 0; i_45703 < (int64_t) 16; i_45703++) {
            double x_40812 = ((double *) mem_param_46865.mem)[i_45703];
            double x_40813 = ((double *) mem_47725)[i_45703];
            double arg_40814 = 0.1 * x_40813;
            double defunc_0_f_res_40815 = x_40812 - arg_40814;
            
            ((double *) mem_48063.mem)[i_45703] = defunc_0_f_res_40815;
        }
        if (memblock_alloc(ctx, &mem_48075, (int64_t) 384000, "mem_48075")) {
            err = 1;
            goto cleanup;
        }
        for (int64_t i_45711 = 0; i_45711 < (int64_t) 120; i_45711++) {
            for (int64_t i_45707 = 0; i_45707 < (int64_t) 400; i_45707++) {
                double x_40827 = ((double *) mem_param_46876.mem)[i_45711 * (int64_t) 400 + i_45707];
                double x_40828 = ((double *) mem_47599)[i_45711 * (int64_t) 400 + i_45707];
                double arg_40829 = 0.1 * x_40828;
                double defunc_0_f_res_40830 = x_40827 - arg_40829;
                
                ((double *) mem_48075.mem)[i_45711 * (int64_t) 400 + i_45707] = defunc_0_f_res_40830;
            }
        }
        if (memblock_alloc(ctx, &mem_48115, (int64_t) 960, "mem_48115")) {
            err = 1;
            goto cleanup;
        }
        for (int64_t i_45715 = 0; i_45715 < (int64_t) 120; i_45715++) {
            double x_40839 = ((double *) mem_param_46881.mem)[i_45715];
            double x_40840 = ((double *) mem_47601)[i_45715];
            double arg_40841 = 0.1 * x_40840;
            double defunc_0_f_res_40842 = x_40839 - arg_40841;
            
            ((double *) mem_48115.mem)[i_45715] = defunc_0_f_res_40842;
        }
        if (memblock_alloc(ctx, &mem_48127, (int64_t) 80640, "mem_48127")) {
            err = 1;
            goto cleanup;
        }
        for (int64_t i_45723 = 0; i_45723 < (int64_t) 84; i_45723++) {
            for (int64_t i_45719 = 0; i_45719 < (int64_t) 120; i_45719++) {
                double x_40854 = ((double *) mem_param_46892.mem)[i_45723 * (int64_t) 120 + i_45719];
                double x_40855 = ((double *) mem_47551)[i_45723 * (int64_t) 120 + i_45719];
                double arg_40856 = 0.1 * x_40855;
                double defunc_0_f_res_40857 = x_40854 - arg_40856;
                
                ((double *) mem_48127.mem)[i_45723 * (int64_t) 120 + i_45719] = defunc_0_f_res_40857;
            }
        }
        if (memblock_alloc(ctx, &mem_48167, (int64_t) 672, "mem_48167")) {
            err = 1;
            goto cleanup;
        }
        for (int64_t i_45727 = 0; i_45727 < (int64_t) 84; i_45727++) {
            double x_40866 = ((double *) mem_param_46897.mem)[i_45727];
            double x_40867 = ((double *) mem_47553)[i_45727];
            double arg_40868 = 0.1 * x_40867;
            double defunc_0_f_res_40869 = x_40866 - arg_40868;
            
            ((double *) mem_48167.mem)[i_45727] = defunc_0_f_res_40869;
        }
        if (memblock_alloc(ctx, &mem_48179, (int64_t) 6720, "mem_48179")) {
            err = 1;
            goto cleanup;
        }
        for (int64_t i_45735 = 0; i_45735 < (int64_t) 10; i_45735++) {
            for (int64_t i_45731 = 0; i_45731 < (int64_t) 84; i_45731++) {
                double x_40881 = ((double *) mem_param_46908.mem)[i_45735 * (int64_t) 84 + i_45731];
                double x_40882 = ((double *) mem_47503)[i_45735 * (int64_t) 84 + i_45731];
                double arg_40883 = 0.1 * x_40882;
                double defunc_0_f_res_40884 = x_40881 - arg_40883;
                
                ((double *) mem_48179.mem)[i_45735 * (int64_t) 84 + i_45731] = defunc_0_f_res_40884;
            }
        }
        if (memblock_alloc(ctx, &mem_48219, (int64_t) 80, "mem_48219")) {
            err = 1;
            goto cleanup;
        }
        for (int64_t i_45739 = 0; i_45739 < (int64_t) 10; i_45739++) {
            double x_40893 = ((double *) mem_param_46913.mem)[i_45739];
            double x_40894 = ((double *) mem_47505)[i_45739];
            double arg_40895 = 0.1 * x_40894;
            double defunc_0_f_res_40896 = x_40893 - arg_40895;
            
            ((double *) mem_48219.mem)[i_45739] = defunc_0_f_res_40896;
        }
        if (memblock_set(ctx, &mem_param_tmp_48366, &mem_47991, "mem_47991") != 0)
            return 1;
        if (memblock_set(ctx, &mem_param_tmp_48367, &mem_47959, "mem_47959") != 0)
            return 1;
        if (memblock_set(ctx, &mem_param_tmp_48368, &mem_47727, "mem_47727") != 0)
            return 1;
        if (memblock_set(ctx, &mem_param_tmp_48369, &mem_48063, "mem_48063") != 0)
            return 1;
        if (memblock_set(ctx, &mem_param_tmp_48370, &mem_48075, "mem_48075") != 0)
            return 1;
        if (memblock_set(ctx, &mem_param_tmp_48371, &mem_48115, "mem_48115") != 0)
            return 1;
        if (memblock_set(ctx, &mem_param_tmp_48372, &mem_48127, "mem_48127") != 0)
            return 1;
        if (memblock_set(ctx, &mem_param_tmp_48373, &mem_48167, "mem_48167") != 0)
            return 1;
        if (memblock_set(ctx, &mem_param_tmp_48374, &mem_48179, "mem_48179") != 0)
            return 1;
        if (memblock_set(ctx, &mem_param_tmp_48375, &mem_48219, "mem_48219") != 0)
            return 1;
        if (memblock_set(ctx, &mem_param_46838, &mem_param_tmp_48366, "mem_param_tmp_48366") != 0)
            return 1;
        if (memblock_set(ctx, &mem_param_46843, &mem_param_tmp_48367, "mem_param_tmp_48367") != 0)
            return 1;
        if (memblock_set(ctx, &mem_param_46860, &mem_param_tmp_48368, "mem_param_tmp_48368") != 0)
            return 1;
        if (memblock_set(ctx, &mem_param_46865, &mem_param_tmp_48369, "mem_param_tmp_48369") != 0)
            return 1;
        if (memblock_set(ctx, &mem_param_46876, &mem_param_tmp_48370, "mem_param_tmp_48370") != 0)
            return 1;
        if (memblock_set(ctx, &mem_param_46881, &mem_param_tmp_48371, "mem_param_tmp_48371") != 0)
            return 1;
        if (memblock_set(ctx, &mem_param_46892, &mem_param_tmp_48372, "mem_param_tmp_48372") != 0)
            return 1;
        if (memblock_set(ctx, &mem_param_46897, &mem_param_tmp_48373, "mem_param_tmp_48373") != 0)
            return 1;
        if (memblock_set(ctx, &mem_param_46908, &mem_param_tmp_48374, "mem_param_tmp_48374") != 0)
            return 1;
        if (memblock_set(ctx, &mem_param_46913, &mem_param_tmp_48375, "mem_param_tmp_48375") != 0)
            return 1;
    }
    if (memblock_set(ctx, &ext_mem_48306, &mem_param_46838, "mem_param_46838") != 0)
        return 1;
    if (memblock_set(ctx, &ext_mem_48305, &mem_param_46843, "mem_param_46843") != 0)
        return 1;
    if (memblock_set(ctx, &ext_mem_48304, &mem_param_46860, "mem_param_46860") != 0)
        return 1;
    if (memblock_set(ctx, &ext_mem_48303, &mem_param_46865, "mem_param_46865") != 0)
        return 1;
    if (memblock_set(ctx, &ext_mem_48302, &mem_param_46876, "mem_param_46876") != 0)
        return 1;
    if (memblock_set(ctx, &ext_mem_48301, &mem_param_46881, "mem_param_46881") != 0)
        return 1;
    if (memblock_set(ctx, &ext_mem_48300, &mem_param_46892, "mem_param_46892") != 0)
        return 1;
    if (memblock_set(ctx, &ext_mem_48299, &mem_param_46897, "mem_param_46897") != 0)
        return 1;
    if (memblock_set(ctx, &ext_mem_48298, &mem_param_46908, "mem_param_46908") != 0)
        return 1;
    if (memblock_set(ctx, &ext_mem_48297, &mem_param_46913, "mem_param_46913") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_46824, "mem_46824") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_46845, "mem_46845") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_46867, "mem_46867") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_46883, "mem_46883") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_46899, "mem_46899") != 0)
        return 1;
    if (memblock_alloc(ctx, &mem_48308, (int64_t) 200, "mem_48308")) {
        err = 1;
        goto cleanup;
    }
    if ((int64_t) 200 > 0)
        memmove(mem_48308.mem + (int64_t) 0, ext_mem_48306.mem + (int64_t) 0, (int64_t) 200);
    if (memblock_unref(ctx, &ext_mem_48306, "ext_mem_48306") != 0)
        return 1;
    if (memblock_set(ctx, &mem_out_48365, &mem_48308, "mem_48308") != 0)
        return 1;
    if (memblock_set(ctx, &*mem_out_p_48591, &mem_out_48365, "mem_out_48365") != 0)
        return 1;
    
  cleanup:
    {
        free(mem_46917);
        free(mem_46962);
        free(mem_46967);
        free(mem_47028);
        free(mem_47071);
        free(mem_47084);
        free(mem_47195);
        free(mem_47247);
        free(mem_47287);
        free(mem_47300);
        free(mem_47411);
        free(mem_47423);
        free(mem_47435);
        free(mem_47447);
        free(mem_47459);
        free(mem_47461);
        free(mem_47463);
        free(mem_47478);
        free(mem_47503);
        free(mem_47505);
        free(mem_47507);
        free(mem_47509);
        free(mem_47511);
        free(mem_47526);
        free(mem_47551);
        free(mem_47553);
        free(mem_47555);
        free(mem_47557);
        free(mem_47559);
        free(mem_47574);
        free(mem_47599);
        free(mem_47601);
        free(mem_47603);
        free(mem_47616);
        free(mem_47689);
        free(mem_47691);
        free(mem_47693);
        free(mem_47708);
        free(mem_47723);
        free(mem_47725);
        free(mem_47871);
        free(mem_47873);
        free(mem_47886);
        free(mem_47961);
        free(mem_47976);
        free(mem_48007);
        if (memblock_unref(ctx, &mem_48308, "mem_48308") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_param_tmp_48375, "mem_param_tmp_48375") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_param_tmp_48374, "mem_param_tmp_48374") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_param_tmp_48373, "mem_param_tmp_48373") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_param_tmp_48372, "mem_param_tmp_48372") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_param_tmp_48371, "mem_param_tmp_48371") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_param_tmp_48370, "mem_param_tmp_48370") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_param_tmp_48369, "mem_param_tmp_48369") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_param_tmp_48368, "mem_param_tmp_48368") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_param_tmp_48367, "mem_param_tmp_48367") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_param_tmp_48366, "mem_param_tmp_48366") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_48219, "mem_48219") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_48179, "mem_48179") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_48167, "mem_48167") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_48127, "mem_48127") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_48115, "mem_48115") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_48075, "mem_48075") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_48063, "mem_48063") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_47991, "mem_47991") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_47959, "mem_47959") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_47727, "mem_47727") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_param_46913, "mem_param_46913") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_param_46908, "mem_param_46908") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_param_46897, "mem_param_46897") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_param_46892, "mem_param_46892") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_param_46881, "mem_param_46881") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_param_46876, "mem_param_46876") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_param_46865, "mem_param_46865") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_param_46860, "mem_param_46860") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_param_46843, "mem_param_46843") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_param_46838, "mem_param_46838") != 0)
            return 1;
        if (memblock_unref(ctx, &ext_mem_48297, "ext_mem_48297") != 0)
            return 1;
        if (memblock_unref(ctx, &ext_mem_48298, "ext_mem_48298") != 0)
            return 1;
        if (memblock_unref(ctx, &ext_mem_48299, "ext_mem_48299") != 0)
            return 1;
        if (memblock_unref(ctx, &ext_mem_48300, "ext_mem_48300") != 0)
            return 1;
        if (memblock_unref(ctx, &ext_mem_48301, "ext_mem_48301") != 0)
            return 1;
        if (memblock_unref(ctx, &ext_mem_48302, "ext_mem_48302") != 0)
            return 1;
        if (memblock_unref(ctx, &ext_mem_48303, "ext_mem_48303") != 0)
            return 1;
        if (memblock_unref(ctx, &ext_mem_48304, "ext_mem_48304") != 0)
            return 1;
        if (memblock_unref(ctx, &ext_mem_48305, "ext_mem_48305") != 0)
            return 1;
        if (memblock_unref(ctx, &ext_mem_48306, "ext_mem_48306") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_46899, "mem_46899") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_46883, "mem_46883") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_46867, "mem_46867") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_46845, "mem_46845") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_46824, "mem_46824") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_out_48365, "mem_out_48365") != 0)
            return 1;
    }
    return err;
}

int futhark_entry_bench_cnn(struct futhark_context *ctx, struct futhark_f64_1d **out0, const struct futhark_f64_3d *in0, const struct futhark_f64_2d *in1, const int64_t in2)
{
    int64_t l_37763 = (int64_t) 0;
    int64_t m_37764 = (int64_t) 0;
    int64_t n_37765 = (int64_t) 0;
    int64_t epochs_37768 = (int64_t) 0;
    int64_t prim_out_48366 = (int64_t) 0;
    int ret = 0;
    
    lock_lock(&ctx->lock);
    
    struct memblock mem_out_48365;
    
    mem_out_48365.references = NULL;
    
    struct memblock y_train_mem_46822;
    
    y_train_mem_46822.references = NULL;
    
    struct memblock x_train_mem_46821;
    
    x_train_mem_46821.references = NULL;
    x_train_mem_46821 = in0->mem;
    l_37763 = in0->shape[0];
    m_37764 = in0->shape[1];
    n_37765 = in0->shape[2];
    y_train_mem_46822 = in1->mem;
    l_37763 = in1->shape[0];
    epochs_37768 = in2;
    if (!((l_37763 == in0->shape[0] && (m_37764 == in0->shape[1] && n_37765 == in0->shape[2])) && (l_37763 == in1->shape[0] && (int64_t) 10 == in1->shape[1]))) {
        ret = 1;
        set_error(ctx, msgprintf("Error: entry point arguments have invalid sizes.\n"));
    }
    if (ret == 0) {
        ret = futrts_entry_bench_cnn(ctx, &mem_out_48365, &prim_out_48366, x_train_mem_46821, y_train_mem_46822, l_37763, m_37764, n_37765, epochs_37768);
        if (ret == 0) {
            struct memblock mem_46702 = ctx->constants->mem_46702;
            struct memblock mem_46714 = ctx->constants->mem_46714;
            struct memblock mem_46726 = ctx->constants->mem_46726;
            struct memblock mem_46738 = ctx->constants->mem_46738;
            struct memblock mem_46750 = ctx->constants->mem_46750;
            struct memblock mem_46762 = ctx->constants->mem_46762;
            struct memblock mem_46774 = ctx->constants->mem_46774;
            struct memblock mem_46786 = ctx->constants->mem_46786;
            struct memblock mem_46798 = ctx->constants->mem_46798;
            struct memblock mem_46810 = ctx->constants->mem_46810;
            
            assert((*out0 = (struct futhark_f64_1d *) malloc(sizeof(struct futhark_f64_1d))) != NULL);
            (*out0)->mem = mem_out_48365;
            (*out0)->shape[0] = prim_out_48366;
        }
    }
    lock_unlock(&ctx->lock);
    return ret;
}
int futhark_entry_bench_cnn_futhark_ad(struct futhark_context *ctx, struct futhark_f64_4d **out0, struct futhark_f64_1d **out1, struct futhark_f64_4d **out2, struct futhark_f64_1d **out3, struct futhark_f64_2d **out4, struct futhark_f64_1d **out5, struct futhark_f64_2d **out6, struct futhark_f64_1d **out7, struct futhark_f64_2d **out8, struct futhark_f64_1d **out9, const struct futhark_f64_3d *in0, const struct futhark_f64_2d *in1, const int64_t in2)
{
    int64_t l_38230 = (int64_t) 0;
    int64_t m_38231 = (int64_t) 0;
    int64_t n_38232 = (int64_t) 0;
    int64_t epochs_38235 = (int64_t) 0;
    int ret = 0;
    
    lock_lock(&ctx->lock);
    
    struct memblock mem_out_48374;
    
    mem_out_48374.references = NULL;
    
    struct memblock mem_out_48373;
    
    mem_out_48373.references = NULL;
    
    struct memblock mem_out_48372;
    
    mem_out_48372.references = NULL;
    
    struct memblock mem_out_48371;
    
    mem_out_48371.references = NULL;
    
    struct memblock mem_out_48370;
    
    mem_out_48370.references = NULL;
    
    struct memblock mem_out_48369;
    
    mem_out_48369.references = NULL;
    
    struct memblock mem_out_48368;
    
    mem_out_48368.references = NULL;
    
    struct memblock mem_out_48367;
    
    mem_out_48367.references = NULL;
    
    struct memblock mem_out_48366;
    
    mem_out_48366.references = NULL;
    
    struct memblock mem_out_48365;
    
    mem_out_48365.references = NULL;
    
    struct memblock y_train_mem_46822;
    
    y_train_mem_46822.references = NULL;
    
    struct memblock x_train_mem_46821;
    
    x_train_mem_46821.references = NULL;
    x_train_mem_46821 = in0->mem;
    l_38230 = in0->shape[0];
    m_38231 = in0->shape[1];
    n_38232 = in0->shape[2];
    y_train_mem_46822 = in1->mem;
    l_38230 = in1->shape[0];
    epochs_38235 = in2;
    if (!((l_38230 == in0->shape[0] && (m_38231 == in0->shape[1] && n_38232 == in0->shape[2])) && (l_38230 == in1->shape[0] && (int64_t) 10 == in1->shape[1]))) {
        ret = 1;
        set_error(ctx, msgprintf("Error: entry point arguments have invalid sizes.\n"));
    }
    if (ret == 0) {
        ret = futrts_entry_bench_cnn_futhark_ad(ctx, &mem_out_48365, &mem_out_48366, &mem_out_48367, &mem_out_48368, &mem_out_48369, &mem_out_48370, &mem_out_48371, &mem_out_48372, &mem_out_48373, &mem_out_48374, x_train_mem_46821, y_train_mem_46822, l_38230, m_38231, n_38232, epochs_38235);
        if (ret == 0) {
            struct memblock mem_46702 = ctx->constants->mem_46702;
            struct memblock mem_46714 = ctx->constants->mem_46714;
            struct memblock mem_46726 = ctx->constants->mem_46726;
            struct memblock mem_46738 = ctx->constants->mem_46738;
            struct memblock mem_46750 = ctx->constants->mem_46750;
            struct memblock mem_46762 = ctx->constants->mem_46762;
            struct memblock mem_46774 = ctx->constants->mem_46774;
            struct memblock mem_46786 = ctx->constants->mem_46786;
            struct memblock mem_46798 = ctx->constants->mem_46798;
            struct memblock mem_46810 = ctx->constants->mem_46810;
            
            assert((*out0 = (struct futhark_f64_4d *) malloc(sizeof(struct futhark_f64_4d))) != NULL);
            (*out0)->mem = mem_out_48365;
            (*out0)->shape[0] = (int64_t) 6;
            (*out0)->shape[1] = (int64_t) 1;
            (*out0)->shape[2] = (int64_t) 5;
            (*out0)->shape[3] = (int64_t) 5;
            assert((*out1 = (struct futhark_f64_1d *) malloc(sizeof(struct futhark_f64_1d))) != NULL);
            (*out1)->mem = mem_out_48366;
            (*out1)->shape[0] = (int64_t) 6;
            assert((*out2 = (struct futhark_f64_4d *) malloc(sizeof(struct futhark_f64_4d))) != NULL);
            (*out2)->mem = mem_out_48367;
            (*out2)->shape[0] = (int64_t) 16;
            (*out2)->shape[1] = (int64_t) 6;
            (*out2)->shape[2] = (int64_t) 5;
            (*out2)->shape[3] = (int64_t) 5;
            assert((*out3 = (struct futhark_f64_1d *) malloc(sizeof(struct futhark_f64_1d))) != NULL);
            (*out3)->mem = mem_out_48368;
            (*out3)->shape[0] = (int64_t) 16;
            assert((*out4 = (struct futhark_f64_2d *) malloc(sizeof(struct futhark_f64_2d))) != NULL);
            (*out4)->mem = mem_out_48369;
            (*out4)->shape[0] = (int64_t) 120;
            (*out4)->shape[1] = (int64_t) 400;
            assert((*out5 = (struct futhark_f64_1d *) malloc(sizeof(struct futhark_f64_1d))) != NULL);
            (*out5)->mem = mem_out_48370;
            (*out5)->shape[0] = (int64_t) 120;
            assert((*out6 = (struct futhark_f64_2d *) malloc(sizeof(struct futhark_f64_2d))) != NULL);
            (*out6)->mem = mem_out_48371;
            (*out6)->shape[0] = (int64_t) 84;
            (*out6)->shape[1] = (int64_t) 120;
            assert((*out7 = (struct futhark_f64_1d *) malloc(sizeof(struct futhark_f64_1d))) != NULL);
            (*out7)->mem = mem_out_48372;
            (*out7)->shape[0] = (int64_t) 84;
            assert((*out8 = (struct futhark_f64_2d *) malloc(sizeof(struct futhark_f64_2d))) != NULL);
            (*out8)->mem = mem_out_48373;
            (*out8)->shape[0] = (int64_t) 10;
            (*out8)->shape[1] = (int64_t) 84;
            assert((*out9 = (struct futhark_f64_1d *) malloc(sizeof(struct futhark_f64_1d))) != NULL);
            (*out9)->mem = mem_out_48374;
            (*out9)->shape[0] = (int64_t) 10;
        }
    }
    lock_unlock(&ctx->lock);
    return ret;
}
int futhark_entry_test_cnn_futhark_ad(struct futhark_context *ctx, struct futhark_f64_3d **out0, const struct futhark_f64_3d *in0, const struct futhark_f64_2d *in1)
{
    int64_t l_31478 = (int64_t) 0;
    int64_t m_31479 = (int64_t) 0;
    int64_t n_31480 = (int64_t) 0;
    int ret = 0;
    
    lock_lock(&ctx->lock);
    
    struct memblock mem_out_48365;
    
    mem_out_48365.references = NULL;
    
    struct memblock y_train_mem_46822;
    
    y_train_mem_46822.references = NULL;
    
    struct memblock x_train_mem_46821;
    
    x_train_mem_46821.references = NULL;
    x_train_mem_46821 = in0->mem;
    l_31478 = in0->shape[0];
    m_31479 = in0->shape[1];
    n_31480 = in0->shape[2];
    y_train_mem_46822 = in1->mem;
    l_31478 = in1->shape[0];
    if (!((l_31478 == in0->shape[0] && (m_31479 == in0->shape[1] && n_31480 == in0->shape[2])) && (l_31478 == in1->shape[0] && (int64_t) 10 == in1->shape[1]))) {
        ret = 1;
        set_error(ctx, msgprintf("Error: entry point arguments have invalid sizes.\n"));
    }
    if (ret == 0) {
        ret = futrts_entry_test_cnn_futhark_ad(ctx, &mem_out_48365, x_train_mem_46821, y_train_mem_46822, l_31478, m_31479, n_31480);
        if (ret == 0) {
            struct memblock mem_46702 = ctx->constants->mem_46702;
            struct memblock mem_46714 = ctx->constants->mem_46714;
            struct memblock mem_46726 = ctx->constants->mem_46726;
            struct memblock mem_46738 = ctx->constants->mem_46738;
            struct memblock mem_46750 = ctx->constants->mem_46750;
            struct memblock mem_46762 = ctx->constants->mem_46762;
            struct memblock mem_46774 = ctx->constants->mem_46774;
            struct memblock mem_46786 = ctx->constants->mem_46786;
            struct memblock mem_46798 = ctx->constants->mem_46798;
            struct memblock mem_46810 = ctx->constants->mem_46810;
            
            assert((*out0 = (struct futhark_f64_3d *) malloc(sizeof(struct futhark_f64_3d))) != NULL);
            (*out0)->mem = mem_out_48365;
            (*out0)->shape[0] = (int64_t) 1;
            (*out0)->shape[1] = (int64_t) 5;
            (*out0)->shape[2] = (int64_t) 5;
        }
    }
    lock_unlock(&ctx->lock);
    return ret;
}
  
