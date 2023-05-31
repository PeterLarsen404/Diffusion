
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

// Opaque values



// Entry points
int futhark_entry_main(struct futhark_context *ctx, struct futhark_f64_1d **out0, struct futhark_f64_1d **out1, const struct futhark_f64_3d *in0, const struct futhark_f64_2d *in1);

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
#include <unistd.h>
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

static int binary_output = 0;
static int print_result = 1;
static int print_report = 0;
static FILE *runtime_file;
static int perform_warmup = 0;
static int num_runs = 1;
static const char *entry_point = "main";
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

int parse_options(struct futhark_context_config *cfg, int argc, char *const argv[])
{
    int ch;
    static struct option long_options[] = {{"write-runtime-to", required_argument, NULL, 1}, {"runs", required_argument, NULL, 2}, {"debugging", no_argument, NULL, 3}, {"log", no_argument, NULL, 4}, {"entry-point", required_argument, NULL, 5}, {"binary-output", no_argument, NULL, 6}, {"no-print-result", no_argument, NULL, 7}, {"help", no_argument, NULL, 8}, {"print-params", no_argument, NULL, 9}, {"param", required_argument, NULL, 10}, {"tuning", required_argument, NULL, 11}, {"cache-file", required_argument, NULL, 12}, {0, 0, 0, 0}};
    static char *option_descriptions = "  -t/--write-runtime-to FILE Print the time taken to execute the program to the indicated file, an integral number of microseconds.\n  -r/--runs INT              Perform NUM runs of the program.\n  -D/--debugging             Perform possibly expensive internal correctness checks and verbose logging.\n  -L/--log                   Print various low-overhead logging information to stderr while running.\n  -e/--entry-point NAME      The entry point to run. Defaults to main.\n  -b/--binary-output         Print the program result in the binary output format.\n  -n/--no-print-result       Do not print the program result.\n  -h/--help                  Print help information and exit.\n  --print-params             Print all tuning parameters that can be set with --param or --tuning.\n  --param ASSIGNMENT         Set a tuning parameter to the given value.\n  --tuning FILE              Read size=value assignments from the given file.\n  --cache-file FILE          Store program cache here.\n";
    
    while ((ch = getopt_long(argc, argv, ":t:r:DLe:bnh", long_options, NULL)) != -1) {
        if (ch == 1 || ch == 't') {
            runtime_file = fopen(optarg, "w");
            if (runtime_file == NULL)
                futhark_panic(1, "Cannot open %s: %s\n", optarg, strerror(errno));
        }
        if (ch == 2 || ch == 'r') {
            num_runs = atoi(optarg);
            perform_warmup = 1;
            if (num_runs <= 0)
                futhark_panic(1, "Need a positive number of runs, not %s\n", optarg);
        }
        if (ch == 3 || ch == 'D') {
            futhark_context_config_set_debugging(cfg, 1);
            print_report = 1;
        }
        if (ch == 4 || ch == 'L') {
            futhark_context_config_set_logging(cfg, 1);
            print_report = 1;
        }
        if (ch == 5 || ch == 'e') {
            if (entry_point != NULL)
                entry_point = optarg;
        }
        if (ch == 6 || ch == 'b')
            binary_output = 1;
        if (ch == 7 || ch == 'n')
            print_result = 0;
        if (ch == 8 || ch == 'h') {
            printf("Usage: %s [OPTION]...\nOptions:\n\n%s\nFor more information, consult the Futhark User's Guide or the man pages.\n", fut_progname, option_descriptions);
            exit(0);
        }
        if (ch == 9) {
            int n = futhark_get_tuning_param_count();
            
            for (int i = 0; i < n; i++)
                printf("%s (%s)\n", futhark_get_tuning_param_name(i), futhark_get_tuning_param_class(i));
            exit(0);
        }
        if (ch == 10) {
            char *name = optarg;
            char *equals = strstr(optarg, "=");
            char *value_str = equals != NULL ? equals + 1 : optarg;
            int value = atoi(value_str);
            
            if (equals != NULL) {
                *equals = 0;
                if (futhark_context_config_set_tuning_param(cfg, name, (size_t) value) != 0)
                    futhark_panic(1, "Unknown size: %s\n", name);
            } else
                futhark_panic(1, "Invalid argument for size option: %s\n", optarg);
        }
        if (ch == 11) {
            char *ret = load_tuning_file(optarg, cfg, (int (*)(void *, const char *, size_t)) futhark_context_config_set_tuning_param);
            
            if (ret != NULL)
                futhark_panic(1, "When loading tuning from '%s': %s\n", optarg, ret);
        }
        if (ch == 12)
            futhark_context_config_set_cache_file(cfg, optarg);
        if (ch == ':')
            futhark_panic(-1, "Missing argument for option %s\n", argv[optind - 1]);
        if (ch == '?') {
            fprintf(stderr, "Usage: %s [OPTIONS]...\nOptions:\n\n%s\n", fut_progname, "  -t/--write-runtime-to FILE Print the time taken to execute the program to the indicated file, an integral number of microseconds.\n  -r/--runs INT              Perform NUM runs of the program.\n  -D/--debugging             Perform possibly expensive internal correctness checks and verbose logging.\n  -L/--log                   Print various low-overhead logging information to stderr while running.\n  -e/--entry-point NAME      The entry point to run. Defaults to main.\n  -b/--binary-output         Print the program result in the binary output format.\n  -n/--no-print-result       Do not print the program result.\n  -h/--help                  Print help information and exit.\n  --print-params             Print all tuning parameters that can be set with --param or --tuning.\n  --param ASSIGNMENT         Set a tuning parameter to the given value.\n  --tuning FILE              Read size=value assignments from the given file.\n  --cache-file FILE          Store program cache here.\n");
            futhark_panic(1, "Unknown option: %s\n", argv[optind - 1]);
        }
    }
    return optind;
}
static int futrts_cli_entry_main(struct futhark_context *ctx)
{
    int64_t t_start, t_end;
    int time_runs = 0, profile_run = 0;
    int retval = 0;
    
    // We do not want to profile all the initialisation.
    futhark_context_pause_profiling(ctx);
    // Declare and read input.
    set_binary_mode(stdin);
    
    struct futhark_f64_3d * read_value_0;
    int64_t read_shape_0[3];
    double *read_arr_0 = NULL;
    
    errno = 0;
    if (read_array(stdin, &f64_info, (void **) &read_arr_0, read_shape_0, 3) != 0)
        futhark_panic(1, "Cannot read input #%d of type %s (errno: %s).\n", 0, "[][][]f64", strerror(errno));
    
    struct futhark_f64_2d * read_value_1;
    int64_t read_shape_1[2];
    double *read_arr_1 = NULL;
    
    errno = 0;
    if (read_array(stdin, &f64_info, (void **) &read_arr_1, read_shape_1, 2) != 0)
        futhark_panic(1, "Cannot read input #%d of type %s (errno: %s).\n", 1, "[][]f64", strerror(errno));
    if (end_of_input(stdin) != 0)
        futhark_panic(1, "Expected EOF on stdin after reading input for \"%s\".\n", "main");
    
    struct futhark_f64_1d * result_0;
    struct futhark_f64_1d * result_1;
    
    if (perform_warmup) {
        int r;
        
        assert((read_value_0 = futhark_new_f64_3d(ctx, read_arr_0, read_shape_0[0], read_shape_0[1], read_shape_0[2])) != NULL);
        assert((read_value_1 = futhark_new_f64_2d(ctx, read_arr_1, read_shape_1[0], read_shape_1[1])) != NULL);
        if (futhark_context_sync(ctx) != 0)
            futhark_panic(1, "%s", futhark_context_get_error(ctx));
        ;
        // Only profile last run.
        if (profile_run)
            futhark_context_unpause_profiling(ctx);
        t_start = get_wall_time();
        r = futhark_entry_main(ctx, &result_0, &result_1, read_value_0, read_value_1);
        if (r != 0)
            futhark_panic(1, "%s", futhark_context_get_error(ctx));
        if (futhark_context_sync(ctx) != 0)
            futhark_panic(1, "%s", futhark_context_get_error(ctx));
        ;
        if (profile_run)
            futhark_context_pause_profiling(ctx);
        t_end = get_wall_time();
        
        long elapsed_usec = t_end - t_start;
        
        if (time_runs && runtime_file != NULL) {
            fprintf(runtime_file, "%lld\n", (long long) elapsed_usec);
            fflush(runtime_file);
        }
        assert(futhark_free_f64_3d(ctx, read_value_0) == 0);
        assert(futhark_free_f64_2d(ctx, read_value_1) == 0);
        assert(futhark_free_f64_1d(ctx, result_0) == 0);
        assert(futhark_free_f64_1d(ctx, result_1) == 0);
    }
    time_runs = 1;
    // Proper run.
    for (int run = 0; run < num_runs; run++) {
        // Only profile last run.
        profile_run = run == num_runs - 1;
        
        int r;
        
        assert((read_value_0 = futhark_new_f64_3d(ctx, read_arr_0, read_shape_0[0], read_shape_0[1], read_shape_0[2])) != NULL);
        assert((read_value_1 = futhark_new_f64_2d(ctx, read_arr_1, read_shape_1[0], read_shape_1[1])) != NULL);
        if (futhark_context_sync(ctx) != 0)
            futhark_panic(1, "%s", futhark_context_get_error(ctx));
        ;
        // Only profile last run.
        if (profile_run)
            futhark_context_unpause_profiling(ctx);
        t_start = get_wall_time();
        r = futhark_entry_main(ctx, &result_0, &result_1, read_value_0, read_value_1);
        if (r != 0)
            futhark_panic(1, "%s", futhark_context_get_error(ctx));
        if (futhark_context_sync(ctx) != 0)
            futhark_panic(1, "%s", futhark_context_get_error(ctx));
        ;
        if (profile_run)
            futhark_context_pause_profiling(ctx);
        t_end = get_wall_time();
        
        long elapsed_usec = t_end - t_start;
        
        if (time_runs && runtime_file != NULL) {
            fprintf(runtime_file, "%lld\n", (long long) elapsed_usec);
            fflush(runtime_file);
        }
        assert(futhark_free_f64_3d(ctx, read_value_0) == 0);
        assert(futhark_free_f64_2d(ctx, read_value_1) == 0);
        if (run < num_runs - 1) {
            assert(futhark_free_f64_1d(ctx, result_0) == 0);
            assert(futhark_free_f64_1d(ctx, result_1) == 0);
        }
    }
    free(read_arr_0);
    free(read_arr_1);
    if (print_result) {
        // Print the final result.
        if (binary_output)
            set_binary_mode(stdout);
        {
            double *arr = calloc(futhark_shape_f64_1d(ctx, result_0)[0], f64_info.size);
            
            assert(arr != NULL);
            assert(futhark_values_f64_1d(ctx, result_0, arr) == 0);
            assert(futhark_context_sync(ctx) == 0);
            write_array(stdout, binary_output, &f64_info, arr, futhark_shape_f64_1d(ctx, result_0), 1);
            free(arr);
        }
        printf("\n");
        {
            double *arr = calloc(futhark_shape_f64_1d(ctx, result_1)[0], f64_info.size);
            
            assert(arr != NULL);
            assert(futhark_values_f64_1d(ctx, result_1, arr) == 0);
            assert(futhark_context_sync(ctx) == 0);
            write_array(stdout, binary_output, &f64_info, arr, futhark_shape_f64_1d(ctx, result_1), 1);
            free(arr);
        }
        printf("\n");
    }
    
  print_end:
    { }
    assert(futhark_free_f64_1d(ctx, result_0) == 0);
    assert(futhark_free_f64_1d(ctx, result_1) == 0);
    return retval;
}
typedef int entry_point_fun(struct futhark_context *);
struct entry_point_entry {
    const char *name;
    entry_point_fun *fun;
};
int main(int argc, char **argv)
{
    int retval = 0;
    
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
    
    char *error = futhark_context_get_error(ctx);
    
    if (error != NULL)
        futhark_panic(1, "%s", error);
    
    struct entry_point_entry entry_points[] = {{.name ="main", .fun =futrts_cli_entry_main}};
    
    if (entry_point != NULL) {
        int num_entry_points = sizeof(entry_points) / sizeof(entry_points[0]);
        entry_point_fun *entry_point_fun = NULL;
        
        for (int i = 0; i < num_entry_points; i++) {
            if (strcmp(entry_points[i].name, entry_point) == 0) {
                entry_point_fun = entry_points[i].fun;
                break;
            }
        }
        if (entry_point_fun == NULL) {
            fprintf(stderr, "No entry point '%s'.  Select another with --entry-point.  Options are:\n", entry_point);
            for (int i = 0; i < num_entry_points; i++)
                fprintf(stderr, "%s\n", entry_points[i].name);
            return 1;
        }
        if (isatty(fileno(stdin))) {
            fprintf(stderr, "Reading input from TTY.\n");
            fprintf(stderr, "Send EOF (CTRL-d) after typing all input values.\n");
        }
        retval = entry_point_fun(ctx);
        if (runtime_file != NULL)
            fclose(runtime_file);
        if (print_report) {
            char *report = futhark_context_report(ctx);
            
            fputs(report, stderr);
            free(report);
        }
    }
    futhark_context_free(ctx);
    futhark_context_config_free(cfg);
    return retval;
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

static int futrts_entry_main(struct futhark_context *ctx, struct memblock *mem_out_p_37577, struct memblock *mem_out_p_37578, struct memblock x_train_mem_35080, struct memblock y_train_mem_35081, int64_t dz2080U_26089, int64_t dz2081U_26090, int64_t dz2082U_26091, int64_t dz2083U_26092);

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

static int futrts_entry_main(struct futhark_context *ctx, struct memblock *mem_out_p_37577, struct memblock *mem_out_p_37578, struct memblock x_train_mem_35080, struct memblock y_train_mem_35081, int64_t dz2080U_26089, int64_t dz2081U_26090, int64_t dz2082U_26091, int64_t dz2083U_26092)
{
    (void) ctx;
    
    int err = 0;
    int64_t mem_35083_cached_sizze_37579 = 0;
    unsigned char *mem_35083 = NULL;
    int64_t mem_35095_cached_sizze_37580 = 0;
    unsigned char *mem_35095 = NULL;
    int64_t mem_35097_cached_sizze_37581 = 0;
    unsigned char *mem_35097 = NULL;
    int64_t mem_35099_cached_sizze_37582 = 0;
    unsigned char *mem_35099 = NULL;
    int64_t mem_35101_cached_sizze_37583 = 0;
    unsigned char *mem_35101 = NULL;
    int64_t mem_35103_cached_sizze_37584 = 0;
    unsigned char *mem_35103 = NULL;
    int64_t mem_35155_cached_sizze_37585 = 0;
    unsigned char *mem_35155 = NULL;
    int64_t mem_35179_cached_sizze_37586 = 0;
    unsigned char *mem_35179 = NULL;
    int64_t mem_35203_cached_sizze_37587 = 0;
    unsigned char *mem_35203 = NULL;
    int64_t mem_35227_cached_sizze_37588 = 0;
    unsigned char *mem_35227 = NULL;
    int64_t mem_35251_cached_sizze_37589 = 0;
    unsigned char *mem_35251 = NULL;
    int64_t mem_35369_cached_sizze_37590 = 0;
    unsigned char *mem_35369 = NULL;
    int64_t mem_35414_cached_sizze_37591 = 0;
    unsigned char *mem_35414 = NULL;
    int64_t mem_35419_cached_sizze_37592 = 0;
    unsigned char *mem_35419 = NULL;
    int64_t mem_35480_cached_sizze_37593 = 0;
    unsigned char *mem_35480 = NULL;
    int64_t mem_35523_cached_sizze_37594 = 0;
    unsigned char *mem_35523 = NULL;
    int64_t mem_35536_cached_sizze_37595 = 0;
    unsigned char *mem_35536 = NULL;
    int64_t mem_35647_cached_sizze_37596 = 0;
    unsigned char *mem_35647 = NULL;
    int64_t mem_35699_cached_sizze_37597 = 0;
    unsigned char *mem_35699 = NULL;
    int64_t mem_35739_cached_sizze_37598 = 0;
    unsigned char *mem_35739 = NULL;
    int64_t mem_35752_cached_sizze_37599 = 0;
    unsigned char *mem_35752 = NULL;
    int64_t mem_35863_cached_sizze_37600 = 0;
    unsigned char *mem_35863 = NULL;
    int64_t mem_35875_cached_sizze_37601 = 0;
    unsigned char *mem_35875 = NULL;
    int64_t mem_35887_cached_sizze_37602 = 0;
    unsigned char *mem_35887 = NULL;
    int64_t mem_35899_cached_sizze_37603 = 0;
    unsigned char *mem_35899 = NULL;
    int64_t mem_35911_cached_sizze_37604 = 0;
    unsigned char *mem_35911 = NULL;
    int64_t mem_35913_cached_sizze_37605 = 0;
    unsigned char *mem_35913 = NULL;
    int64_t mem_35915_cached_sizze_37606 = 0;
    unsigned char *mem_35915 = NULL;
    int64_t mem_35930_cached_sizze_37607 = 0;
    unsigned char *mem_35930 = NULL;
    int64_t mem_35955_cached_sizze_37608 = 0;
    unsigned char *mem_35955 = NULL;
    int64_t mem_35957_cached_sizze_37609 = 0;
    unsigned char *mem_35957 = NULL;
    int64_t mem_35959_cached_sizze_37610 = 0;
    unsigned char *mem_35959 = NULL;
    int64_t mem_35961_cached_sizze_37611 = 0;
    unsigned char *mem_35961 = NULL;
    int64_t mem_35963_cached_sizze_37612 = 0;
    unsigned char *mem_35963 = NULL;
    int64_t mem_35978_cached_sizze_37613 = 0;
    unsigned char *mem_35978 = NULL;
    int64_t mem_36003_cached_sizze_37614 = 0;
    unsigned char *mem_36003 = NULL;
    int64_t mem_36005_cached_sizze_37615 = 0;
    unsigned char *mem_36005 = NULL;
    int64_t mem_36007_cached_sizze_37616 = 0;
    unsigned char *mem_36007 = NULL;
    int64_t mem_36009_cached_sizze_37617 = 0;
    unsigned char *mem_36009 = NULL;
    int64_t mem_36011_cached_sizze_37618 = 0;
    unsigned char *mem_36011 = NULL;
    int64_t mem_36026_cached_sizze_37619 = 0;
    unsigned char *mem_36026 = NULL;
    int64_t mem_36051_cached_sizze_37620 = 0;
    unsigned char *mem_36051 = NULL;
    int64_t mem_36053_cached_sizze_37621 = 0;
    unsigned char *mem_36053 = NULL;
    int64_t mem_36055_cached_sizze_37622 = 0;
    unsigned char *mem_36055 = NULL;
    int64_t mem_36068_cached_sizze_37623 = 0;
    unsigned char *mem_36068 = NULL;
    int64_t mem_36141_cached_sizze_37624 = 0;
    unsigned char *mem_36141 = NULL;
    int64_t mem_36143_cached_sizze_37625 = 0;
    unsigned char *mem_36143 = NULL;
    int64_t mem_36145_cached_sizze_37626 = 0;
    unsigned char *mem_36145 = NULL;
    int64_t mem_36160_cached_sizze_37627 = 0;
    unsigned char *mem_36160 = NULL;
    int64_t mem_36175_cached_sizze_37628 = 0;
    unsigned char *mem_36175 = NULL;
    int64_t mem_36177_cached_sizze_37629 = 0;
    unsigned char *mem_36177 = NULL;
    int64_t mem_36323_cached_sizze_37630 = 0;
    unsigned char *mem_36323 = NULL;
    int64_t mem_36325_cached_sizze_37631 = 0;
    unsigned char *mem_36325 = NULL;
    int64_t mem_36338_cached_sizze_37632 = 0;
    unsigned char *mem_36338 = NULL;
    int64_t mem_36413_cached_sizze_37633 = 0;
    unsigned char *mem_36413 = NULL;
    int64_t mem_36428_cached_sizze_37634 = 0;
    unsigned char *mem_36428 = NULL;
    int64_t mem_36459_cached_sizze_37635 = 0;
    unsigned char *mem_36459 = NULL;
    int64_t mem_36762_cached_sizze_37636 = 0;
    unsigned char *mem_36762 = NULL;
    int64_t mem_36807_cached_sizze_37637 = 0;
    unsigned char *mem_36807 = NULL;
    int64_t mem_36812_cached_sizze_37638 = 0;
    unsigned char *mem_36812 = NULL;
    int64_t mem_36873_cached_sizze_37639 = 0;
    unsigned char *mem_36873 = NULL;
    int64_t mem_36916_cached_sizze_37640 = 0;
    unsigned char *mem_36916 = NULL;
    int64_t mem_36929_cached_sizze_37641 = 0;
    unsigned char *mem_36929 = NULL;
    int64_t mem_37040_cached_sizze_37642 = 0;
    unsigned char *mem_37040 = NULL;
    int64_t mem_37092_cached_sizze_37643 = 0;
    unsigned char *mem_37092 = NULL;
    int64_t mem_37132_cached_sizze_37644 = 0;
    unsigned char *mem_37132 = NULL;
    int64_t mem_37145_cached_sizze_37645 = 0;
    unsigned char *mem_37145 = NULL;
    int64_t mem_37256_cached_sizze_37646 = 0;
    unsigned char *mem_37256 = NULL;
    int64_t mem_37268_cached_sizze_37647 = 0;
    unsigned char *mem_37268 = NULL;
    int64_t mem_37280_cached_sizze_37648 = 0;
    unsigned char *mem_37280 = NULL;
    struct memblock mem_37307;
    
    mem_37307.references = NULL;
    
    struct memblock mem_37292;
    
    mem_37292.references = NULL;
    
    struct memblock mem_param_tmp_37409;
    
    mem_param_tmp_37409.references = NULL;
    
    struct memblock mem_param_tmp_37408;
    
    mem_param_tmp_37408.references = NULL;
    
    struct memblock mem_param_tmp_37407;
    
    mem_param_tmp_37407.references = NULL;
    
    struct memblock mem_param_tmp_37406;
    
    mem_param_tmp_37406.references = NULL;
    
    struct memblock mem_param_tmp_37405;
    
    mem_param_tmp_37405.references = NULL;
    
    struct memblock mem_param_tmp_37404;
    
    mem_param_tmp_37404.references = NULL;
    
    struct memblock mem_param_tmp_37403;
    
    mem_param_tmp_37403.references = NULL;
    
    struct memblock mem_param_tmp_37402;
    
    mem_param_tmp_37402.references = NULL;
    
    struct memblock mem_param_tmp_37401;
    
    mem_param_tmp_37401.references = NULL;
    
    struct memblock mem_param_tmp_37400;
    
    mem_param_tmp_37400.references = NULL;
    
    struct memblock mem_36671;
    
    mem_36671.references = NULL;
    
    struct memblock mem_36631;
    
    mem_36631.references = NULL;
    
    struct memblock mem_36619;
    
    mem_36619.references = NULL;
    
    struct memblock mem_36579;
    
    mem_36579.references = NULL;
    
    struct memblock mem_36567;
    
    mem_36567.references = NULL;
    
    struct memblock mem_36527;
    
    mem_36527.references = NULL;
    
    struct memblock mem_36515;
    
    mem_36515.references = NULL;
    
    struct memblock mem_36443;
    
    mem_36443.references = NULL;
    
    struct memblock mem_36411;
    
    mem_36411.references = NULL;
    
    struct memblock mem_36179;
    
    mem_36179.references = NULL;
    
    struct memblock mem_param_35365;
    
    mem_param_35365.references = NULL;
    
    struct memblock mem_param_35360;
    
    mem_param_35360.references = NULL;
    
    struct memblock mem_param_35349;
    
    mem_param_35349.references = NULL;
    
    struct memblock mem_param_35344;
    
    mem_param_35344.references = NULL;
    
    struct memblock mem_param_35333;
    
    mem_param_35333.references = NULL;
    
    struct memblock mem_param_35328;
    
    mem_param_35328.references = NULL;
    
    struct memblock mem_param_35317;
    
    mem_param_35317.references = NULL;
    
    struct memblock mem_param_35312;
    
    mem_param_35312.references = NULL;
    
    struct memblock mem_param_35295;
    
    mem_param_35295.references = NULL;
    
    struct memblock mem_param_35290;
    
    mem_param_35290.references = NULL;
    
    struct memblock ext_mem_36749;
    
    ext_mem_36749.references = NULL;
    
    struct memblock ext_mem_36750;
    
    ext_mem_36750.references = NULL;
    
    struct memblock ext_mem_36751;
    
    ext_mem_36751.references = NULL;
    
    struct memblock ext_mem_36752;
    
    ext_mem_36752.references = NULL;
    
    struct memblock ext_mem_36753;
    
    ext_mem_36753.references = NULL;
    
    struct memblock ext_mem_36754;
    
    ext_mem_36754.references = NULL;
    
    struct memblock ext_mem_36755;
    
    ext_mem_36755.references = NULL;
    
    struct memblock ext_mem_36756;
    
    ext_mem_36756.references = NULL;
    
    struct memblock ext_mem_36757;
    
    ext_mem_36757.references = NULL;
    
    struct memblock ext_mem_36758;
    
    ext_mem_36758.references = NULL;
    
    struct memblock mem_35351;
    
    mem_35351.references = NULL;
    
    struct memblock mem_35335;
    
    mem_35335.references = NULL;
    
    struct memblock mem_35319;
    
    mem_35319.references = NULL;
    
    struct memblock mem_35297;
    
    mem_35297.references = NULL;
    
    struct memblock mem_35275;
    
    mem_35275.references = NULL;
    
    struct memblock mem_35263;
    
    mem_35263.references = NULL;
    
    struct memblock mem_35239;
    
    mem_35239.references = NULL;
    
    struct memblock mem_35215;
    
    mem_35215.references = NULL;
    
    struct memblock mem_35191;
    
    mem_35191.references = NULL;
    
    struct memblock mem_35167;
    
    mem_35167.references = NULL;
    
    struct memblock mem_out_37365;
    
    mem_out_37365.references = NULL;
    
    struct memblock mem_out_37364;
    
    mem_out_37364.references = NULL;
    
    int64_t arg_28836 = add64((int64_t) 4, dz2081U_26090);
    int64_t arg_28837 = sub64(arg_28836, (int64_t) 5);
    int64_t new_n_28838 = add64((int64_t) 1, arg_28837);
    int64_t arg_28840 = add64((int64_t) 4, dz2082U_26091);
    int64_t arg_28841 = sub64(arg_28840, (int64_t) 5);
    int64_t new_m_28842 = add64((int64_t) 1, arg_28841);
    bool bounds_invalid_upwards_28854 = slt64(arg_28836, (int64_t) 0);
    bool valid_28855 = !bounds_invalid_upwards_28854;
    bool range_valid_c_28856;
    
    if (!valid_28855) {
        set_error(ctx, msgprintf("Error: %s%lld%s%lld%s%lld%s\n\nBacktrace:\n%s", "Range ", (long long) (int64_t) 0, "..", (long long) (int64_t) 1, "..<", (long long) arg_28836, " is invalid.", "-> #0  /prelude/array.fut:95:3-10\n   #1  ../layers/conv2d.fut:7:120-123\n   #2  ../layers/conv2d.fut:22:7-30\n"));
        err = FUTHARK_PROGRAM_ERROR;
        goto cleanup;
    }
    
    bool bounds_invalid_upwards_28896 = slt64(new_n_28838, (int64_t) 0);
    bool valid_28897 = !bounds_invalid_upwards_28896;
    bool range_valid_c_28898;
    
    if (!valid_28897) {
        set_error(ctx, msgprintf("Error: %s%lld%s%lld%s%lld%s\n\nBacktrace:\n%s", "Range ", (long long) (int64_t) 0, "..", (long long) (int64_t) 1, "..<", (long long) new_n_28838, " is invalid.", "-> #0  /prelude/array.fut:95:3-10\n   #1  /prelude/array.fut:208:28-33\n   #2  ../layers/conv2d.fut:13:50-162\n   #3  ../layers/conv2d.fut:26:17-54\n"));
        err = FUTHARK_PROGRAM_ERROR;
        goto cleanup;
    }
    
    int64_t flat_dim_28947 = new_n_28838 * new_m_28842;
    int64_t binop_x_35366 = arg_28836 * arg_28840;
    int64_t binop_y_35367 = (int64_t) 8 * binop_x_35366;
    int64_t bytes_35368 = smax64((int64_t) 0, binop_y_35367);
    int64_t binop_y_35417 = (int64_t) 200 * flat_dim_28947;
    int64_t bytes_35418 = smax64((int64_t) 0, binop_y_35417);
    int64_t binop_y_35478 = (int64_t) 48 * flat_dim_28947;
    int64_t bytes_35479 = smax64((int64_t) 0, binop_y_35478);
    int64_t binop_y_36760 = (int64_t) 8 * binop_x_35366;
    int64_t bytes_36761 = smax64((int64_t) 0, binop_y_36760);
    int64_t bytes_36811 = smax64((int64_t) 0, binop_y_35417);
    bool i_p_m_t_s_leq_w_28003 = slt64((int64_t) 199, dz2080U_26089);
    bool index_certs_28004;
    
    if (!i_p_m_t_s_leq_w_28003) {
        set_error(ctx, msgprintf("Error: %s%lld%s%lld%s\n\nBacktrace:\n%s", "Index [:", (long long) (int64_t) 200, "] out of bounds for array of shape [", (long long) dz2080U_26089, "].", "-> #0  cnn_playground.fut:7:22-34\n   #1  cnn_playground.fut:6:1-21:24\n"));
        err = FUTHARK_PROGRAM_ERROR;
        goto cleanup;
    }
    
    bool i_p_m_t_s_leq_w_28006 = slt64((int64_t) 199, dz2083U_26092);
    bool index_certs_28007;
    
    if (!i_p_m_t_s_leq_w_28006) {
        set_error(ctx, msgprintf("Error: %s%lld%s%lld%s\n\nBacktrace:\n%s", "Index [:", (long long) (int64_t) 200, "] out of bounds for array of shape [", (long long) dz2083U_26092, "].", "-> #0  cnn_playground.fut:8:22-34\n   #1  cnn_playground.fut:6:1-21:24\n"));
        err = FUTHARK_PROGRAM_ERROR;
        goto cleanup;
    }
    if (mem_35083_cached_sizze_37579 < (int64_t) 20) {
        err = lexical_realloc(ctx, &mem_35083, &mem_35083_cached_sizze_37579, (int64_t) 20);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    for (int64_t i_33366 = 0; i_33366 < (int64_t) 5; i_33366++) {
        int32_t i64_res_30692 = sext_i64_i32(i_33366);
        int32_t arg_30693 = lshr32(i64_res_30692, 16);
        int32_t arg_30694 = i64_res_30692 ^ arg_30693;
        int32_t x_30695 = mul32(73244475, arg_30694);
        int32_t arg_30696 = lshr32(x_30695, 16);
        int32_t arg_30697 = x_30695 ^ arg_30696;
        int32_t x_30698 = mul32(73244475, arg_30697);
        int32_t arg_30699 = lshr32(x_30698, 16);
        int32_t x_30700 = x_30698 ^ arg_30699;
        int32_t unsign_arg_30701 = 1822209471 ^ x_30700;
        int32_t unsign_arg_30703 = mul32(48271, unsign_arg_30701);
        int32_t unsign_arg_30704 = umod32(unsign_arg_30703, 2147483647);
        bool zgze_res_30705 = ule32(2147000000, unsign_arg_30704);
        bool defunc_0_f_res_f_res_30706;
        int32_t defunc_0_f_res_f_res_30707;
        int32_t defunc_0_f_res_f_res_30708;
        bool loop_while_30709;
        int32_t rng_30710;
        int32_t x_30711;
        
        loop_while_30709 = zgze_res_30705;
        rng_30710 = unsign_arg_30704;
        x_30711 = unsign_arg_30704;
        while (loop_while_30709) {
            int32_t unsign_arg_30712 = mul32(48271, rng_30710);
            int32_t unsign_arg_30713 = umod32(unsign_arg_30712, 2147483647);
            bool zgze_res_30714 = ule32(2147000000, unsign_arg_30713);
            bool loop_while_tmp_37367 = zgze_res_30714;
            int32_t rng_tmp_37368 = unsign_arg_30713;
            int32_t x_tmp_37369 = unsign_arg_30713;
            
            loop_while_30709 = loop_while_tmp_37367;
            rng_30710 = rng_tmp_37368;
            x_30711 = x_tmp_37369;
        }
        defunc_0_f_res_f_res_30706 = loop_while_30709;
        defunc_0_f_res_f_res_30707 = rng_30710;
        defunc_0_f_res_f_res_30708 = x_30711;
        
        int32_t unsign_arg_30715 = umod32(defunc_0_f_res_f_res_30708, 1000000);
        int64_t to_i64_res_30716 = zext_i32_i64(unsign_arg_30715);
        int32_t defunc_0_f_res_30718 = sext_i64_i32(to_i64_res_30716);
        
        ((int32_t *) mem_35083)[i_33366] = defunc_0_f_res_30718;
    }
    
    int32_t mk_conv_wandb_arg_28010 = ((int32_t *) mem_35083)[(int64_t) 0];
    int32_t unsign_arg_29521 = 5460 ^ mk_conv_wandb_arg_28010;
    int32_t unsign_arg_29522 = mul32(48271, unsign_arg_29521);
    int32_t unsign_arg_29523 = umod32(unsign_arg_29522, 2147483647);
    int32_t unsign_arg_29524 = mul32(48271, unsign_arg_29523);
    int32_t unsign_arg_29525 = umod32(unsign_arg_29524, 2147483647);
    int32_t mk_dense_wandb_arg_28022 = ((int32_t *) mem_35083)[(int64_t) 4];
    int32_t unsign_arg_29967 = 5460 ^ mk_dense_wandb_arg_28022;
    int32_t unsign_arg_29968 = mul32(48271, unsign_arg_29967);
    int32_t unsign_arg_29969 = umod32(unsign_arg_29968, 2147483647);
    int32_t unsign_arg_29970 = mul32(48271, unsign_arg_29969);
    int32_t unsign_arg_29971 = umod32(unsign_arg_29970, 2147483647);
    int32_t mk_dense_wandb_arg_28019 = ((int32_t *) mem_35083)[(int64_t) 3];
    int32_t unsign_arg_29858 = 5460 ^ mk_dense_wandb_arg_28019;
    int32_t unsign_arg_29859 = mul32(48271, unsign_arg_29858);
    int32_t unsign_arg_29860 = umod32(unsign_arg_29859, 2147483647);
    int32_t unsign_arg_29861 = mul32(48271, unsign_arg_29860);
    int32_t unsign_arg_29862 = umod32(unsign_arg_29861, 2147483647);
    int32_t mk_dense_wandb_arg_28016 = ((int32_t *) mem_35083)[(int64_t) 2];
    int32_t unsign_arg_29749 = 5460 ^ mk_dense_wandb_arg_28016;
    int32_t unsign_arg_29750 = mul32(48271, unsign_arg_29749);
    int32_t unsign_arg_29751 = umod32(unsign_arg_29750, 2147483647);
    int32_t unsign_arg_29752 = mul32(48271, unsign_arg_29751);
    int32_t unsign_arg_29753 = umod32(unsign_arg_29752, 2147483647);
    int32_t mk_conv_wandb_arg_28013 = ((int32_t *) mem_35083)[(int64_t) 1];
    int32_t unsign_arg_29636 = 5460 ^ mk_conv_wandb_arg_28013;
    int32_t unsign_arg_29637 = mul32(48271, unsign_arg_29636);
    int32_t unsign_arg_29638 = umod32(unsign_arg_29637, 2147483647);
    int32_t unsign_arg_29639 = mul32(48271, unsign_arg_29638);
    int32_t unsign_arg_29640 = umod32(unsign_arg_29639, 2147483647);
    
    if (mem_35095_cached_sizze_37580 < (int64_t) 8) {
        err = lexical_realloc(ctx, &mem_35095, &mem_35095_cached_sizze_37580, (int64_t) 8);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_35097_cached_sizze_37581 < (int64_t) 8) {
        err = lexical_realloc(ctx, &mem_35097, &mem_35097_cached_sizze_37581, (int64_t) 8);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_35099_cached_sizze_37582 < (int64_t) 8) {
        err = lexical_realloc(ctx, &mem_35099, &mem_35099_cached_sizze_37582, (int64_t) 8);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_35101_cached_sizze_37583 < (int64_t) 8) {
        err = lexical_realloc(ctx, &mem_35101, &mem_35101_cached_sizze_37583, (int64_t) 8);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_35103_cached_sizze_37584 < (int64_t) 8) {
        err = lexical_realloc(ctx, &mem_35103, &mem_35103_cached_sizze_37584, (int64_t) 8);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    for (int64_t i_33378 = 0; i_33378 < (int64_t) 2; i_33378++) {
        int32_t i64_res_30996 = sext_i64_i32(i_33378);
        int32_t arg_30997 = lshr32(i64_res_30996, 16);
        int32_t arg_30998 = i64_res_30996 ^ arg_30997;
        int32_t x_30999 = mul32(73244475, arg_30998);
        int32_t arg_31000 = lshr32(x_30999, 16);
        int32_t arg_31001 = x_30999 ^ arg_31000;
        int32_t x_31002 = mul32(73244475, arg_31001);
        int32_t arg_31003 = lshr32(x_31002, 16);
        int32_t x_31004 = x_31002 ^ arg_31003;
        int32_t unsign_arg_31005 = unsign_arg_29525 ^ x_31004;
        int32_t unsign_arg_31007 = mul32(48271, unsign_arg_31005);
        int32_t unsign_arg_31008 = umod32(unsign_arg_31007, 2147483647);
        bool zgze_res_31009 = ule32(2147000000, unsign_arg_31008);
        bool defunc_0_f_res_f_res_31010;
        int32_t defunc_0_f_res_f_res_31011;
        int32_t defunc_0_f_res_f_res_31012;
        bool loop_while_31013;
        int32_t rng_31014;
        int32_t x_31015;
        
        loop_while_31013 = zgze_res_31009;
        rng_31014 = unsign_arg_31008;
        x_31015 = unsign_arg_31008;
        while (loop_while_31013) {
            int32_t unsign_arg_31016 = mul32(48271, rng_31014);
            int32_t unsign_arg_31017 = umod32(unsign_arg_31016, 2147483647);
            bool zgze_res_31018 = ule32(2147000000, unsign_arg_31017);
            bool loop_while_tmp_37375 = zgze_res_31018;
            int32_t rng_tmp_37376 = unsign_arg_31017;
            int32_t x_tmp_37377 = unsign_arg_31017;
            
            loop_while_31013 = loop_while_tmp_37375;
            rng_31014 = rng_tmp_37376;
            x_31015 = x_tmp_37377;
        }
        defunc_0_f_res_f_res_31010 = loop_while_31013;
        defunc_0_f_res_f_res_31011 = rng_31014;
        defunc_0_f_res_f_res_31012 = x_31015;
        
        int32_t unsign_arg_31019 = umod32(defunc_0_f_res_f_res_31012, 1000000);
        int64_t to_i64_res_31020 = zext_i32_i64(unsign_arg_31019);
        int32_t defunc_0_f_res_31022 = sext_i64_i32(to_i64_res_31020);
        int32_t unsign_arg_31033 = unsign_arg_29640 ^ x_31004;
        int32_t unsign_arg_31035 = mul32(48271, unsign_arg_31033);
        int32_t unsign_arg_31036 = umod32(unsign_arg_31035, 2147483647);
        bool zgze_res_31037 = ule32(2147000000, unsign_arg_31036);
        bool defunc_0_f_res_f_res_31038;
        int32_t defunc_0_f_res_f_res_31039;
        int32_t defunc_0_f_res_f_res_31040;
        bool loop_while_31041;
        int32_t rng_31042;
        int32_t x_31043;
        
        loop_while_31041 = zgze_res_31037;
        rng_31042 = unsign_arg_31036;
        x_31043 = unsign_arg_31036;
        while (loop_while_31041) {
            int32_t unsign_arg_31044 = mul32(48271, rng_31042);
            int32_t unsign_arg_31045 = umod32(unsign_arg_31044, 2147483647);
            bool zgze_res_31046 = ule32(2147000000, unsign_arg_31045);
            bool loop_while_tmp_37378 = zgze_res_31046;
            int32_t rng_tmp_37379 = unsign_arg_31045;
            int32_t x_tmp_37380 = unsign_arg_31045;
            
            loop_while_31041 = loop_while_tmp_37378;
            rng_31042 = rng_tmp_37379;
            x_31043 = x_tmp_37380;
        }
        defunc_0_f_res_f_res_31038 = loop_while_31041;
        defunc_0_f_res_f_res_31039 = rng_31042;
        defunc_0_f_res_f_res_31040 = x_31043;
        
        int32_t unsign_arg_31047 = umod32(defunc_0_f_res_f_res_31040, 1000000);
        int64_t to_i64_res_31048 = zext_i32_i64(unsign_arg_31047);
        int32_t defunc_0_f_res_31050 = sext_i64_i32(to_i64_res_31048);
        int32_t unsign_arg_31062 = unsign_arg_29753 ^ x_31004;
        int32_t unsign_arg_31064 = mul32(48271, unsign_arg_31062);
        int32_t unsign_arg_31065 = umod32(unsign_arg_31064, 2147483647);
        bool zgze_res_31066 = ule32(2147000000, unsign_arg_31065);
        bool defunc_0_f_res_f_res_31067;
        int32_t defunc_0_f_res_f_res_31068;
        int32_t defunc_0_f_res_f_res_31069;
        bool loop_while_31070;
        int32_t rng_31071;
        int32_t x_31072;
        
        loop_while_31070 = zgze_res_31066;
        rng_31071 = unsign_arg_31065;
        x_31072 = unsign_arg_31065;
        while (loop_while_31070) {
            int32_t unsign_arg_31073 = mul32(48271, rng_31071);
            int32_t unsign_arg_31074 = umod32(unsign_arg_31073, 2147483647);
            bool zgze_res_31075 = ule32(2147000000, unsign_arg_31074);
            bool loop_while_tmp_37381 = zgze_res_31075;
            int32_t rng_tmp_37382 = unsign_arg_31074;
            int32_t x_tmp_37383 = unsign_arg_31074;
            
            loop_while_31070 = loop_while_tmp_37381;
            rng_31071 = rng_tmp_37382;
            x_31072 = x_tmp_37383;
        }
        defunc_0_f_res_f_res_31067 = loop_while_31070;
        defunc_0_f_res_f_res_31068 = rng_31071;
        defunc_0_f_res_f_res_31069 = x_31072;
        
        int32_t unsign_arg_31076 = umod32(defunc_0_f_res_f_res_31069, 1000000);
        int64_t to_i64_res_31077 = zext_i32_i64(unsign_arg_31076);
        int32_t defunc_0_f_res_31079 = sext_i64_i32(to_i64_res_31077);
        int32_t unsign_arg_31092 = unsign_arg_29862 ^ x_31004;
        int32_t unsign_arg_31094 = mul32(48271, unsign_arg_31092);
        int32_t unsign_arg_31095 = umod32(unsign_arg_31094, 2147483647);
        bool zgze_res_31096 = ule32(2147000000, unsign_arg_31095);
        bool defunc_0_f_res_f_res_31097;
        int32_t defunc_0_f_res_f_res_31098;
        int32_t defunc_0_f_res_f_res_31099;
        bool loop_while_31100;
        int32_t rng_31101;
        int32_t x_31102;
        
        loop_while_31100 = zgze_res_31096;
        rng_31101 = unsign_arg_31095;
        x_31102 = unsign_arg_31095;
        while (loop_while_31100) {
            int32_t unsign_arg_31103 = mul32(48271, rng_31101);
            int32_t unsign_arg_31104 = umod32(unsign_arg_31103, 2147483647);
            bool zgze_res_31105 = ule32(2147000000, unsign_arg_31104);
            bool loop_while_tmp_37384 = zgze_res_31105;
            int32_t rng_tmp_37385 = unsign_arg_31104;
            int32_t x_tmp_37386 = unsign_arg_31104;
            
            loop_while_31100 = loop_while_tmp_37384;
            rng_31101 = rng_tmp_37385;
            x_31102 = x_tmp_37386;
        }
        defunc_0_f_res_f_res_31097 = loop_while_31100;
        defunc_0_f_res_f_res_31098 = rng_31101;
        defunc_0_f_res_f_res_31099 = x_31102;
        
        int32_t unsign_arg_31106 = umod32(defunc_0_f_res_f_res_31099, 1000000);
        int64_t to_i64_res_31107 = zext_i32_i64(unsign_arg_31106);
        int32_t defunc_0_f_res_31109 = sext_i64_i32(to_i64_res_31107);
        int32_t unsign_arg_31123 = unsign_arg_29971 ^ x_31004;
        int32_t unsign_arg_31125 = mul32(48271, unsign_arg_31123);
        int32_t unsign_arg_31126 = umod32(unsign_arg_31125, 2147483647);
        bool zgze_res_31127 = ule32(2147000000, unsign_arg_31126);
        bool defunc_0_f_res_f_res_31128;
        int32_t defunc_0_f_res_f_res_31129;
        int32_t defunc_0_f_res_f_res_31130;
        bool loop_while_31131;
        int32_t rng_31132;
        int32_t x_31133;
        
        loop_while_31131 = zgze_res_31127;
        rng_31132 = unsign_arg_31126;
        x_31133 = unsign_arg_31126;
        while (loop_while_31131) {
            int32_t unsign_arg_31134 = mul32(48271, rng_31132);
            int32_t unsign_arg_31135 = umod32(unsign_arg_31134, 2147483647);
            bool zgze_res_31136 = ule32(2147000000, unsign_arg_31135);
            bool loop_while_tmp_37387 = zgze_res_31136;
            int32_t rng_tmp_37388 = unsign_arg_31135;
            int32_t x_tmp_37389 = unsign_arg_31135;
            
            loop_while_31131 = loop_while_tmp_37387;
            rng_31132 = rng_tmp_37388;
            x_31133 = x_tmp_37389;
        }
        defunc_0_f_res_f_res_31128 = loop_while_31131;
        defunc_0_f_res_f_res_31129 = rng_31132;
        defunc_0_f_res_f_res_31130 = x_31133;
        
        int32_t unsign_arg_31137 = umod32(defunc_0_f_res_f_res_31130, 1000000);
        int64_t to_i64_res_31138 = zext_i32_i64(unsign_arg_31137);
        int32_t defunc_0_f_res_31140 = sext_i64_i32(to_i64_res_31138);
        
        ((int32_t *) mem_35095)[i_33378] = defunc_0_f_res_31140;
        ((int32_t *) mem_35097)[i_33378] = defunc_0_f_res_31109;
        ((int32_t *) mem_35099)[i_33378] = defunc_0_f_res_31079;
        ((int32_t *) mem_35101)[i_33378] = defunc_0_f_res_31050;
        ((int32_t *) mem_35103)[i_33378] = defunc_0_f_res_31022;
    }
    
    int32_t mk_conv_weights_arg_29561 = ((int32_t *) mem_35103)[(int64_t) 0];
    int32_t unsign_arg_29566 = 5460 ^ mk_conv_weights_arg_29561;
    int32_t unsign_arg_29567 = mul32(48271, unsign_arg_29566);
    int32_t unsign_arg_29568 = umod32(unsign_arg_29567, 2147483647);
    int32_t unsign_arg_29572 = mul32(48271, unsign_arg_29568);
    int32_t unsign_arg_29573 = umod32(unsign_arg_29572, 2147483647);
    
    if (mem_35155_cached_sizze_37585 < (int64_t) 1200) {
        err = lexical_realloc(ctx, &mem_35155, &mem_35155_cached_sizze_37585, (int64_t) 1200);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    for (int64_t i_33386 = 0; i_33386 < (int64_t) 150; i_33386++) {
        int32_t i64_res_30608 = sext_i64_i32(i_33386);
        int32_t arg_30609 = lshr32(i64_res_30608, 16);
        int32_t arg_30610 = i64_res_30608 ^ arg_30609;
        int32_t x_30611 = mul32(73244475, arg_30610);
        int32_t arg_30612 = lshr32(x_30611, 16);
        int32_t arg_30613 = x_30611 ^ arg_30612;
        int32_t x_30614 = mul32(73244475, arg_30613);
        int32_t arg_30615 = lshr32(x_30614, 16);
        int32_t x_30616 = x_30614 ^ arg_30615;
        int32_t unsign_arg_30617 = unsign_arg_29573 ^ x_30616;
        int32_t unsign_arg_30619 = mul32(48271, unsign_arg_30617);
        int32_t unsign_arg_30620 = umod32(unsign_arg_30619, 2147483647);
        double u64_res_30621 = uitofp_i32_f64(unsign_arg_30620);
        double zs_res_30622 = u64_res_30621 / 2.147483647e9;
        double zt_res_30623 = 0.4 * zs_res_30622;
        double zp_res_30624 = -0.2 + zt_res_30623;
        
        ((double *) mem_35155)[i_33386] = zp_res_30624;
    }
    
    int32_t mk_conv_biases_arg_29604 = ((int32_t *) mem_35103)[(int64_t) 1];
    int32_t unsign_arg_29605 = 5460 ^ mk_conv_biases_arg_29604;
    int32_t unsign_arg_29606 = mul32(48271, unsign_arg_29605);
    int32_t unsign_arg_29607 = umod32(unsign_arg_29606, 2147483647);
    int32_t unsign_arg_29608 = mul32(48271, unsign_arg_29607);
    int32_t unsign_arg_29609 = umod32(unsign_arg_29608, 2147483647);
    
    if (memblock_alloc(ctx, &mem_35167, (int64_t) 48, "mem_35167")) {
        err = 1;
        goto cleanup;
    }
    for (int64_t i_33390 = 0; i_33390 < (int64_t) 6; i_33390++) {
        int32_t i64_res_30589 = sext_i64_i32(i_33390);
        int32_t arg_30590 = lshr32(i64_res_30589, 16);
        int32_t arg_30591 = i64_res_30589 ^ arg_30590;
        int32_t x_30592 = mul32(73244475, arg_30591);
        int32_t arg_30593 = lshr32(x_30592, 16);
        int32_t arg_30594 = x_30592 ^ arg_30593;
        int32_t x_30595 = mul32(73244475, arg_30594);
        int32_t arg_30596 = lshr32(x_30595, 16);
        int32_t x_30597 = x_30595 ^ arg_30596;
        int32_t unsign_arg_30598 = unsign_arg_29609 ^ x_30597;
        int32_t unsign_arg_30600 = mul32(48271, unsign_arg_30598);
        int32_t unsign_arg_30601 = umod32(unsign_arg_30600, 2147483647);
        double u64_res_30602 = uitofp_i32_f64(unsign_arg_30601);
        double zs_res_30603 = u64_res_30602 / 2.147483647e9;
        double zt_res_30604 = 0.4 * zs_res_30603;
        double zp_res_30605 = -0.2 + zt_res_30604;
        
        ((double *) mem_35167.mem)[i_33390] = zp_res_30605;
    }
    
    int32_t mk_conv_weights_arg_29676 = ((int32_t *) mem_35101)[(int64_t) 0];
    int32_t unsign_arg_29681 = 5460 ^ mk_conv_weights_arg_29676;
    int32_t unsign_arg_29682 = mul32(48271, unsign_arg_29681);
    int32_t unsign_arg_29683 = umod32(unsign_arg_29682, 2147483647);
    int32_t unsign_arg_29687 = mul32(48271, unsign_arg_29683);
    int32_t unsign_arg_29688 = umod32(unsign_arg_29687, 2147483647);
    
    if (mem_35179_cached_sizze_37586 < (int64_t) 19200) {
        err = lexical_realloc(ctx, &mem_35179, &mem_35179_cached_sizze_37586, (int64_t) 19200);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    for (int64_t i_33394 = 0; i_33394 < (int64_t) 2400; i_33394++) {
        int32_t i64_res_30523 = sext_i64_i32(i_33394);
        int32_t arg_30524 = lshr32(i64_res_30523, 16);
        int32_t arg_30525 = i64_res_30523 ^ arg_30524;
        int32_t x_30526 = mul32(73244475, arg_30525);
        int32_t arg_30527 = lshr32(x_30526, 16);
        int32_t arg_30528 = x_30526 ^ arg_30527;
        int32_t x_30529 = mul32(73244475, arg_30528);
        int32_t arg_30530 = lshr32(x_30529, 16);
        int32_t x_30531 = x_30529 ^ arg_30530;
        int32_t unsign_arg_30532 = unsign_arg_29688 ^ x_30531;
        int32_t unsign_arg_30534 = mul32(48271, unsign_arg_30532);
        int32_t unsign_arg_30535 = umod32(unsign_arg_30534, 2147483647);
        double u64_res_30536 = uitofp_i32_f64(unsign_arg_30535);
        double zs_res_30537 = u64_res_30536 / 2.147483647e9;
        double zt_res_30538 = 0.16329931618554522 * zs_res_30537;
        double zp_res_30539 = -8.164965809277261e-2 + zt_res_30538;
        
        ((double *) mem_35179)[i_33394] = zp_res_30539;
    }
    
    int32_t mk_conv_biases_arg_29719 = ((int32_t *) mem_35101)[(int64_t) 1];
    int32_t unsign_arg_29720 = 5460 ^ mk_conv_biases_arg_29719;
    int32_t unsign_arg_29721 = mul32(48271, unsign_arg_29720);
    int32_t unsign_arg_29722 = umod32(unsign_arg_29721, 2147483647);
    int32_t unsign_arg_29723 = mul32(48271, unsign_arg_29722);
    int32_t unsign_arg_29724 = umod32(unsign_arg_29723, 2147483647);
    
    if (memblock_alloc(ctx, &mem_35191, (int64_t) 128, "mem_35191")) {
        err = 1;
        goto cleanup;
    }
    for (int64_t i_33398 = 0; i_33398 < (int64_t) 16; i_33398++) {
        int32_t i64_res_30504 = sext_i64_i32(i_33398);
        int32_t arg_30505 = lshr32(i64_res_30504, 16);
        int32_t arg_30506 = i64_res_30504 ^ arg_30505;
        int32_t x_30507 = mul32(73244475, arg_30506);
        int32_t arg_30508 = lshr32(x_30507, 16);
        int32_t arg_30509 = x_30507 ^ arg_30508;
        int32_t x_30510 = mul32(73244475, arg_30509);
        int32_t arg_30511 = lshr32(x_30510, 16);
        int32_t x_30512 = x_30510 ^ arg_30511;
        int32_t unsign_arg_30513 = unsign_arg_29724 ^ x_30512;
        int32_t unsign_arg_30515 = mul32(48271, unsign_arg_30513);
        int32_t unsign_arg_30516 = umod32(unsign_arg_30515, 2147483647);
        double u64_res_30517 = uitofp_i32_f64(unsign_arg_30516);
        double zs_res_30518 = u64_res_30517 / 2.147483647e9;
        double zt_res_30519 = 0.16329931618554522 * zs_res_30518;
        double zp_res_30520 = -8.164965809277261e-2 + zt_res_30519;
        
        ((double *) mem_35191.mem)[i_33398] = zp_res_30520;
    }
    
    int32_t mk_dense_weights_arg_29789 = ((int32_t *) mem_35099)[(int64_t) 0];
    int32_t unsign_arg_29792 = 5460 ^ mk_dense_weights_arg_29789;
    int32_t unsign_arg_29793 = mul32(48271, unsign_arg_29792);
    int32_t unsign_arg_29794 = umod32(unsign_arg_29793, 2147483647);
    int32_t unsign_arg_29796 = mul32(48271, unsign_arg_29794);
    int32_t unsign_arg_29797 = umod32(unsign_arg_29796, 2147483647);
    
    if (mem_35203_cached_sizze_37587 < (int64_t) 384000) {
        err = lexical_realloc(ctx, &mem_35203, &mem_35203_cached_sizze_37587, (int64_t) 384000);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    for (int64_t i_33402 = 0; i_33402 < (int64_t) 48000; i_33402++) {
        int32_t i64_res_30438 = sext_i64_i32(i_33402);
        int32_t arg_30439 = lshr32(i64_res_30438, 16);
        int32_t arg_30440 = i64_res_30438 ^ arg_30439;
        int32_t x_30441 = mul32(73244475, arg_30440);
        int32_t arg_30442 = lshr32(x_30441, 16);
        int32_t arg_30443 = x_30441 ^ arg_30442;
        int32_t x_30444 = mul32(73244475, arg_30443);
        int32_t arg_30445 = lshr32(x_30444, 16);
        int32_t x_30446 = x_30444 ^ arg_30445;
        int32_t unsign_arg_30447 = unsign_arg_29797 ^ x_30446;
        int32_t unsign_arg_30449 = mul32(48271, unsign_arg_30447);
        int32_t unsign_arg_30450 = umod32(unsign_arg_30449, 2147483647);
        double u64_res_30451 = uitofp_i32_f64(unsign_arg_30450);
        double zs_res_30452 = u64_res_30451 / 2.147483647e9;
        double zt_res_30453 = 0.1 * zs_res_30452;
        double zp_res_30454 = -5.0e-2 + zt_res_30453;
        
        ((double *) mem_35203)[i_33402] = zp_res_30454;
    }
    
    int32_t mk_dense_biases_arg_29828 = ((int32_t *) mem_35099)[(int64_t) 1];
    int32_t unsign_arg_29829 = 5460 ^ mk_dense_biases_arg_29828;
    int32_t unsign_arg_29830 = mul32(48271, unsign_arg_29829);
    int32_t unsign_arg_29831 = umod32(unsign_arg_29830, 2147483647);
    int32_t unsign_arg_29832 = mul32(48271, unsign_arg_29831);
    int32_t unsign_arg_29833 = umod32(unsign_arg_29832, 2147483647);
    
    if (memblock_alloc(ctx, &mem_35215, (int64_t) 960, "mem_35215")) {
        err = 1;
        goto cleanup;
    }
    for (int64_t i_33406 = 0; i_33406 < (int64_t) 120; i_33406++) {
        int32_t i64_res_30419 = sext_i64_i32(i_33406);
        int32_t arg_30420 = lshr32(i64_res_30419, 16);
        int32_t arg_30421 = i64_res_30419 ^ arg_30420;
        int32_t x_30422 = mul32(73244475, arg_30421);
        int32_t arg_30423 = lshr32(x_30422, 16);
        int32_t arg_30424 = x_30422 ^ arg_30423;
        int32_t x_30425 = mul32(73244475, arg_30424);
        int32_t arg_30426 = lshr32(x_30425, 16);
        int32_t x_30427 = x_30425 ^ arg_30426;
        int32_t unsign_arg_30428 = unsign_arg_29833 ^ x_30427;
        int32_t unsign_arg_30430 = mul32(48271, unsign_arg_30428);
        int32_t unsign_arg_30431 = umod32(unsign_arg_30430, 2147483647);
        double u64_res_30432 = uitofp_i32_f64(unsign_arg_30431);
        double zs_res_30433 = u64_res_30432 / 2.147483647e9;
        double zt_res_30434 = 0.1 * zs_res_30433;
        double zp_res_30435 = -5.0e-2 + zt_res_30434;
        
        ((double *) mem_35215.mem)[i_33406] = zp_res_30435;
    }
    
    int32_t mk_dense_weights_arg_29898 = ((int32_t *) mem_35097)[(int64_t) 0];
    int32_t unsign_arg_29901 = 5460 ^ mk_dense_weights_arg_29898;
    int32_t unsign_arg_29902 = mul32(48271, unsign_arg_29901);
    int32_t unsign_arg_29903 = umod32(unsign_arg_29902, 2147483647);
    int32_t unsign_arg_29905 = mul32(48271, unsign_arg_29903);
    int32_t unsign_arg_29906 = umod32(unsign_arg_29905, 2147483647);
    
    if (mem_35227_cached_sizze_37588 < (int64_t) 80640) {
        err = lexical_realloc(ctx, &mem_35227, &mem_35227_cached_sizze_37588, (int64_t) 80640);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    for (int64_t i_33410 = 0; i_33410 < (int64_t) 10080; i_33410++) {
        int32_t i64_res_30353 = sext_i64_i32(i_33410);
        int32_t arg_30354 = lshr32(i64_res_30353, 16);
        int32_t arg_30355 = i64_res_30353 ^ arg_30354;
        int32_t x_30356 = mul32(73244475, arg_30355);
        int32_t arg_30357 = lshr32(x_30356, 16);
        int32_t arg_30358 = x_30356 ^ arg_30357;
        int32_t x_30359 = mul32(73244475, arg_30358);
        int32_t arg_30360 = lshr32(x_30359, 16);
        int32_t x_30361 = x_30359 ^ arg_30360;
        int32_t unsign_arg_30362 = unsign_arg_29906 ^ x_30361;
        int32_t unsign_arg_30364 = mul32(48271, unsign_arg_30362);
        int32_t unsign_arg_30365 = umod32(unsign_arg_30364, 2147483647);
        double u64_res_30366 = uitofp_i32_f64(unsign_arg_30365);
        double zs_res_30367 = u64_res_30366 / 2.147483647e9;
        double zt_res_30368 = 0.18257418583505536 * zs_res_30367;
        double zp_res_30369 = -9.128709291752768e-2 + zt_res_30368;
        
        ((double *) mem_35227)[i_33410] = zp_res_30369;
    }
    
    int32_t mk_dense_biases_arg_29937 = ((int32_t *) mem_35097)[(int64_t) 1];
    int32_t unsign_arg_29938 = 5460 ^ mk_dense_biases_arg_29937;
    int32_t unsign_arg_29939 = mul32(48271, unsign_arg_29938);
    int32_t unsign_arg_29940 = umod32(unsign_arg_29939, 2147483647);
    int32_t unsign_arg_29941 = mul32(48271, unsign_arg_29940);
    int32_t unsign_arg_29942 = umod32(unsign_arg_29941, 2147483647);
    
    if (memblock_alloc(ctx, &mem_35239, (int64_t) 672, "mem_35239")) {
        err = 1;
        goto cleanup;
    }
    for (int64_t i_33414 = 0; i_33414 < (int64_t) 84; i_33414++) {
        int32_t i64_res_30334 = sext_i64_i32(i_33414);
        int32_t arg_30335 = lshr32(i64_res_30334, 16);
        int32_t arg_30336 = i64_res_30334 ^ arg_30335;
        int32_t x_30337 = mul32(73244475, arg_30336);
        int32_t arg_30338 = lshr32(x_30337, 16);
        int32_t arg_30339 = x_30337 ^ arg_30338;
        int32_t x_30340 = mul32(73244475, arg_30339);
        int32_t arg_30341 = lshr32(x_30340, 16);
        int32_t x_30342 = x_30340 ^ arg_30341;
        int32_t unsign_arg_30343 = unsign_arg_29942 ^ x_30342;
        int32_t unsign_arg_30345 = mul32(48271, unsign_arg_30343);
        int32_t unsign_arg_30346 = umod32(unsign_arg_30345, 2147483647);
        double u64_res_30347 = uitofp_i32_f64(unsign_arg_30346);
        double zs_res_30348 = u64_res_30347 / 2.147483647e9;
        double zt_res_30349 = 0.18257418583505536 * zs_res_30348;
        double zp_res_30350 = -9.128709291752768e-2 + zt_res_30349;
        
        ((double *) mem_35239.mem)[i_33414] = zp_res_30350;
    }
    
    int32_t mk_dense_weights_arg_30007 = ((int32_t *) mem_35095)[(int64_t) 0];
    int32_t unsign_arg_30010 = 5460 ^ mk_dense_weights_arg_30007;
    int32_t unsign_arg_30011 = mul32(48271, unsign_arg_30010);
    int32_t unsign_arg_30012 = umod32(unsign_arg_30011, 2147483647);
    int32_t unsign_arg_30014 = mul32(48271, unsign_arg_30012);
    int32_t unsign_arg_30015 = umod32(unsign_arg_30014, 2147483647);
    
    if (mem_35251_cached_sizze_37589 < (int64_t) 6720) {
        err = lexical_realloc(ctx, &mem_35251, &mem_35251_cached_sizze_37589, (int64_t) 6720);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    for (int64_t i_33418 = 0; i_33418 < (int64_t) 840; i_33418++) {
        int32_t i64_res_30268 = sext_i64_i32(i_33418);
        int32_t arg_30269 = lshr32(i64_res_30268, 16);
        int32_t arg_30270 = i64_res_30268 ^ arg_30269;
        int32_t x_30271 = mul32(73244475, arg_30270);
        int32_t arg_30272 = lshr32(x_30271, 16);
        int32_t arg_30273 = x_30271 ^ arg_30272;
        int32_t x_30274 = mul32(73244475, arg_30273);
        int32_t arg_30275 = lshr32(x_30274, 16);
        int32_t x_30276 = x_30274 ^ arg_30275;
        int32_t unsign_arg_30277 = unsign_arg_30015 ^ x_30276;
        int32_t unsign_arg_30279 = mul32(48271, unsign_arg_30277);
        int32_t unsign_arg_30280 = umod32(unsign_arg_30279, 2147483647);
        double u64_res_30281 = uitofp_i32_f64(unsign_arg_30280);
        double zs_res_30282 = u64_res_30281 / 2.147483647e9;
        double zt_res_30283 = 0.21821789023599236 * zs_res_30282;
        double zp_res_30284 = -0.10910894511799618 + zt_res_30283;
        
        ((double *) mem_35251)[i_33418] = zp_res_30284;
    }
    
    int32_t mk_dense_biases_arg_30046 = ((int32_t *) mem_35095)[(int64_t) 1];
    int32_t unsign_arg_30047 = 5460 ^ mk_dense_biases_arg_30046;
    int32_t unsign_arg_30048 = mul32(48271, unsign_arg_30047);
    int32_t unsign_arg_30049 = umod32(unsign_arg_30048, 2147483647);
    int32_t unsign_arg_30050 = mul32(48271, unsign_arg_30049);
    int32_t unsign_arg_30051 = umod32(unsign_arg_30050, 2147483647);
    
    if (memblock_alloc(ctx, &mem_35263, (int64_t) 80, "mem_35263")) {
        err = 1;
        goto cleanup;
    }
    for (int64_t i_33422 = 0; i_33422 < (int64_t) 10; i_33422++) {
        int32_t i64_res_30249 = sext_i64_i32(i_33422);
        int32_t arg_30250 = lshr32(i64_res_30249, 16);
        int32_t arg_30251 = i64_res_30249 ^ arg_30250;
        int32_t x_30252 = mul32(73244475, arg_30251);
        int32_t arg_30253 = lshr32(x_30252, 16);
        int32_t arg_30254 = x_30252 ^ arg_30253;
        int32_t x_30255 = mul32(73244475, arg_30254);
        int32_t arg_30256 = lshr32(x_30255, 16);
        int32_t x_30257 = x_30255 ^ arg_30256;
        int32_t unsign_arg_30258 = unsign_arg_30051 ^ x_30257;
        int32_t unsign_arg_30260 = mul32(48271, unsign_arg_30258);
        int32_t unsign_arg_30261 = umod32(unsign_arg_30260, 2147483647);
        double u64_res_30262 = uitofp_i32_f64(unsign_arg_30261);
        double zs_res_30263 = u64_res_30262 / 2.147483647e9;
        double zt_res_30264 = 0.21821789023599236 * zs_res_30263;
        double zp_res_30265 = -0.10910894511799618 + zt_res_30264;
        
        ((double *) mem_35263.mem)[i_33422] = zp_res_30265;
    }
    
    bool bounds_invalid_upwards_28858 = slt64(arg_28840, (int64_t) 0);
    bool valid_28859 = !bounds_invalid_upwards_28858;
    bool range_valid_c_28860;
    
    if (!valid_28859) {
        set_error(ctx, msgprintf("Error: %s%lld%s%lld%s%lld%s\n\nBacktrace:\n%s", "Range ", (long long) (int64_t) 0, "..", (long long) (int64_t) 1, "..<", (long long) arg_28840, " is invalid.", "-> #0  /prelude/array.fut:95:3-10\n   #1  ../layers/conv2d.fut:7:120-123\n   #2  ../layers/conv2d.fut:22:7-30\n"));
        err = FUTHARK_PROGRAM_ERROR;
        goto cleanup;
    }
    
    int64_t arg_28862 = add64((int64_t) 2, dz2081U_26090);
    int64_t arg_28863 = add64((int64_t) 2, dz2082U_26091);
    bool bounds_invalid_upwards_28900 = slt64(new_m_28842, (int64_t) 0);
    bool valid_28901 = !bounds_invalid_upwards_28900;
    bool range_valid_c_28902;
    
    if (!valid_28901) {
        set_error(ctx, msgprintf("Error: %s%lld%s%lld%s%lld%s\n\nBacktrace:\n%s", "Range ", (long long) (int64_t) 0, "..", (long long) (int64_t) 1, "..<", (long long) new_m_28842, " is invalid.", "-> #0  /prelude/array.fut:95:3-10\n   #1  /prelude/array.fut:208:27-34\n   #2  ../layers/conv2d.fut:13:50-162\n   #3  ../layers/conv2d.fut:26:17-54\n"));
        err = FUTHARK_PROGRAM_ERROR;
        goto cleanup;
    }
    
    bool dim_match_28107 = (int64_t) 28 == new_n_28838;
    bool dim_match_28108 = (int64_t) 28 == new_m_28842;
    bool match_28110 = dim_match_28107 && dim_match_28108;
    bool empty_or_match_cert_28111;
    
    if (!match_28110) {
        set_error(ctx, msgprintf("Error: %s%lld%s%lld%s%lld%s%lld%s%lld%s%lld%s\n\nBacktrace:\n%s", "Value of (core language) shape (", (long long) (int64_t) 6, ", ", (long long) new_n_28838, ", ", (long long) new_m_28842, ") cannot match shape of type `[", (long long) (int64_t) 6, "][", (long long) (int64_t) 28, "][", (long long) (int64_t) 28, "]f64`.", "-> #0  ../lenet/lenet.fut:10:37-82\n   #1  cnn.fut:18:41-71\n   #2  /prelude/ad.fut:23:13-14\n   #3  cnn.fut:19:37-40\n   #4  cnn_playground.fut:6:1-21:24\n"));
        err = FUTHARK_PROGRAM_ERROR;
        goto cleanup;
    }
    
    int64_t binop_y_34785 = (int64_t) 25 * new_m_28842;
    
    if (memblock_alloc(ctx, &mem_35275, (int64_t) 1200, "mem_35275")) {
        err = 1;
        goto cleanup;
    }
    if ((int64_t) 1200 > 0)
        memmove(mem_35275.mem + (int64_t) 0, mem_35155 + (int64_t) 0, (int64_t) 1200);
    if (memblock_alloc(ctx, &mem_35297, (int64_t) 19200, "mem_35297")) {
        err = 1;
        goto cleanup;
    }
    if ((int64_t) 19200 > 0)
        memmove(mem_35297.mem + (int64_t) 0, mem_35179 + (int64_t) 0, (int64_t) 19200);
    if (memblock_alloc(ctx, &mem_35319, (int64_t) 384000, "mem_35319")) {
        err = 1;
        goto cleanup;
    }
    if ((int64_t) 384000 > 0)
        memmove(mem_35319.mem + (int64_t) 0, mem_35203 + (int64_t) 0, (int64_t) 384000);
    if (memblock_alloc(ctx, &mem_35335, (int64_t) 80640, "mem_35335")) {
        err = 1;
        goto cleanup;
    }
    if ((int64_t) 80640 > 0)
        memmove(mem_35335.mem + (int64_t) 0, mem_35227 + (int64_t) 0, (int64_t) 80640);
    if (memblock_alloc(ctx, &mem_35351, (int64_t) 6720, "mem_35351")) {
        err = 1;
        goto cleanup;
    }
    if ((int64_t) 6720 > 0)
        memmove(mem_35351.mem + (int64_t) 0, mem_35251 + (int64_t) 0, (int64_t) 6720);
    if (mem_35369_cached_sizze_37590 < bytes_35368) {
        err = lexical_realloc(ctx, &mem_35369, &mem_35369_cached_sizze_37590, bytes_35368);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_35414_cached_sizze_37591 < bytes_35368) {
        err = lexical_realloc(ctx, &mem_35414, &mem_35414_cached_sizze_37591, bytes_35368);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_35419_cached_sizze_37592 < bytes_35418) {
        err = lexical_realloc(ctx, &mem_35419, &mem_35419_cached_sizze_37592, bytes_35418);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_35480_cached_sizze_37593 < bytes_35479) {
        err = lexical_realloc(ctx, &mem_35480, &mem_35480_cached_sizze_37593, bytes_35479);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_35523_cached_sizze_37594 < (int64_t) 9408) {
        err = lexical_realloc(ctx, &mem_35523, &mem_35523_cached_sizze_37594, (int64_t) 9408);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_35536_cached_sizze_37595 < (int64_t) 6272) {
        err = lexical_realloc(ctx, &mem_35536, &mem_35536_cached_sizze_37595, (int64_t) 6272);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_35647_cached_sizze_37596 < (int64_t) 120000) {
        err = lexical_realloc(ctx, &mem_35647, &mem_35647_cached_sizze_37596, (int64_t) 120000);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_35699_cached_sizze_37597 < (int64_t) 12800) {
        err = lexical_realloc(ctx, &mem_35699, &mem_35699_cached_sizze_37597, (int64_t) 12800);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_35739_cached_sizze_37598 < (int64_t) 3200) {
        err = lexical_realloc(ctx, &mem_35739, &mem_35739_cached_sizze_37598, (int64_t) 3200);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_35752_cached_sizze_37599 < (int64_t) 800) {
        err = lexical_realloc(ctx, &mem_35752, &mem_35752_cached_sizze_37599, (int64_t) 800);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_35863_cached_sizze_37600 < (int64_t) 960) {
        err = lexical_realloc(ctx, &mem_35863, &mem_35863_cached_sizze_37600, (int64_t) 960);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_35875_cached_sizze_37601 < (int64_t) 672) {
        err = lexical_realloc(ctx, &mem_35875, &mem_35875_cached_sizze_37601, (int64_t) 672);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_35887_cached_sizze_37602 < (int64_t) 80) {
        err = lexical_realloc(ctx, &mem_35887, &mem_35887_cached_sizze_37602, (int64_t) 80);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_35899_cached_sizze_37603 < (int64_t) 80) {
        err = lexical_realloc(ctx, &mem_35899, &mem_35899_cached_sizze_37603, (int64_t) 80);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_35911_cached_sizze_37604 < (int64_t) 672) {
        err = lexical_realloc(ctx, &mem_35911, &mem_35911_cached_sizze_37604, (int64_t) 672);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_35913_cached_sizze_37605 < (int64_t) 80) {
        err = lexical_realloc(ctx, &mem_35913, &mem_35913_cached_sizze_37605, (int64_t) 80);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_35915_cached_sizze_37606 < (int64_t) 6720) {
        err = lexical_realloc(ctx, &mem_35915, &mem_35915_cached_sizze_37606, (int64_t) 6720);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_35930_cached_sizze_37607 < (int64_t) 672) {
        err = lexical_realloc(ctx, &mem_35930, &mem_35930_cached_sizze_37607, (int64_t) 672);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_35955_cached_sizze_37608 < (int64_t) 80) {
        err = lexical_realloc(ctx, &mem_35955, &mem_35955_cached_sizze_37608, (int64_t) 80);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_35957_cached_sizze_37609 < (int64_t) 6720) {
        err = lexical_realloc(ctx, &mem_35957, &mem_35957_cached_sizze_37609, (int64_t) 6720);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_35959_cached_sizze_37610 < (int64_t) 960) {
        err = lexical_realloc(ctx, &mem_35959, &mem_35959_cached_sizze_37610, (int64_t) 960);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_35961_cached_sizze_37611 < (int64_t) 672) {
        err = lexical_realloc(ctx, &mem_35961, &mem_35961_cached_sizze_37611, (int64_t) 672);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_35963_cached_sizze_37612 < (int64_t) 80640) {
        err = lexical_realloc(ctx, &mem_35963, &mem_35963_cached_sizze_37612, (int64_t) 80640);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_35978_cached_sizze_37613 < (int64_t) 960) {
        err = lexical_realloc(ctx, &mem_35978, &mem_35978_cached_sizze_37613, (int64_t) 960);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_36003_cached_sizze_37614 < (int64_t) 672) {
        err = lexical_realloc(ctx, &mem_36003, &mem_36003_cached_sizze_37614, (int64_t) 672);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_36005_cached_sizze_37615 < (int64_t) 80640) {
        err = lexical_realloc(ctx, &mem_36005, &mem_36005_cached_sizze_37615, (int64_t) 80640);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_36007_cached_sizze_37616 < (int64_t) 3200) {
        err = lexical_realloc(ctx, &mem_36007, &mem_36007_cached_sizze_37616, (int64_t) 3200);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_36009_cached_sizze_37617 < (int64_t) 960) {
        err = lexical_realloc(ctx, &mem_36009, &mem_36009_cached_sizze_37617, (int64_t) 960);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_36011_cached_sizze_37618 < (int64_t) 384000) {
        err = lexical_realloc(ctx, &mem_36011, &mem_36011_cached_sizze_37618, (int64_t) 384000);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_36026_cached_sizze_37619 < (int64_t) 3200) {
        err = lexical_realloc(ctx, &mem_36026, &mem_36026_cached_sizze_37619, (int64_t) 3200);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_36051_cached_sizze_37620 < (int64_t) 960) {
        err = lexical_realloc(ctx, &mem_36051, &mem_36051_cached_sizze_37620, (int64_t) 960);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_36053_cached_sizze_37621 < (int64_t) 384000) {
        err = lexical_realloc(ctx, &mem_36053, &mem_36053_cached_sizze_37621, (int64_t) 384000);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_36055_cached_sizze_37622 < (int64_t) 12800) {
        err = lexical_realloc(ctx, &mem_36055, &mem_36055_cached_sizze_37622, (int64_t) 12800);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_36068_cached_sizze_37623 < (int64_t) 800) {
        err = lexical_realloc(ctx, &mem_36068, &mem_36068_cached_sizze_37623, (int64_t) 800);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_36141_cached_sizze_37624 < (int64_t) 120000) {
        err = lexical_realloc(ctx, &mem_36141, &mem_36141_cached_sizze_37624, (int64_t) 120000);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_36143_cached_sizze_37625 < (int64_t) 19200) {
        err = lexical_realloc(ctx, &mem_36143, &mem_36143_cached_sizze_37625, (int64_t) 19200);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_36145_cached_sizze_37626 < (int64_t) 128) {
        err = lexical_realloc(ctx, &mem_36145, &mem_36145_cached_sizze_37626, (int64_t) 128);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_36160_cached_sizze_37627 < (int64_t) 1200) {
        err = lexical_realloc(ctx, &mem_36160, &mem_36160_cached_sizze_37627, (int64_t) 1200);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_36175_cached_sizze_37628 < (int64_t) 19200) {
        err = lexical_realloc(ctx, &mem_36175, &mem_36175_cached_sizze_37628, (int64_t) 19200);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_36177_cached_sizze_37629 < (int64_t) 128) {
        err = lexical_realloc(ctx, &mem_36177, &mem_36177_cached_sizze_37629, (int64_t) 128);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_36323_cached_sizze_37630 < (int64_t) 9408) {
        err = lexical_realloc(ctx, &mem_36323, &mem_36323_cached_sizze_37630, (int64_t) 9408);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_36325_cached_sizze_37631 < (int64_t) 37632) {
        err = lexical_realloc(ctx, &mem_36325, &mem_36325_cached_sizze_37631, (int64_t) 37632);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_36338_cached_sizze_37632 < (int64_t) 6272) {
        err = lexical_realloc(ctx, &mem_36338, &mem_36338_cached_sizze_37632, (int64_t) 6272);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_36413_cached_sizze_37633 < (int64_t) 1200) {
        err = lexical_realloc(ctx, &mem_36413, &mem_36413_cached_sizze_37633, (int64_t) 1200);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_36428_cached_sizze_37634 < (int64_t) 200) {
        err = lexical_realloc(ctx, &mem_36428, &mem_36428_cached_sizze_37634, (int64_t) 200);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_36459_cached_sizze_37635 < (int64_t) 200) {
        err = lexical_realloc(ctx, &mem_36459, &mem_36459_cached_sizze_37635, (int64_t) 200);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (memblock_set(ctx, &mem_param_35290, &mem_35275, "mem_35275") != 0)
        return 1;
    if (memblock_set(ctx, &mem_param_35295, &mem_35167, "mem_35167") != 0)
        return 1;
    if (memblock_set(ctx, &mem_param_35312, &mem_35297, "mem_35297") != 0)
        return 1;
    if (memblock_set(ctx, &mem_param_35317, &mem_35191, "mem_35191") != 0)
        return 1;
    if (memblock_set(ctx, &mem_param_35328, &mem_35319, "mem_35319") != 0)
        return 1;
    if (memblock_set(ctx, &mem_param_35333, &mem_35215, "mem_35215") != 0)
        return 1;
    if (memblock_set(ctx, &mem_param_35344, &mem_35335, "mem_35335") != 0)
        return 1;
    if (memblock_set(ctx, &mem_param_35349, &mem_35239, "mem_35239") != 0)
        return 1;
    if (memblock_set(ctx, &mem_param_35360, &mem_35351, "mem_35351") != 0)
        return 1;
    if (memblock_set(ctx, &mem_param_35365, &mem_35263, "mem_35263") != 0)
        return 1;
    for (int64_t e_28035 = 0; e_28035 < (int64_t) 10; e_28035++) {
        for (int64_t i_33430 = 0; i_33430 < arg_28836; i_33430++) {
            bool cond_28868 = slt64(i_33430, (int64_t) 2);
            bool cond_f_res_28869 = sle64(arg_28862, i_33430);
            bool x_28870 = !cond_28868;
            bool y_28871 = cond_f_res_28869 && x_28870;
            bool cond_28872 = cond_28868 || y_28871;
            bool x_28873 = !cond_28872;
            
            for (int64_t i_33426 = 0; i_33426 < arg_28840; i_33426++) {
                bool cond_f_res_28876 = slt64(i_33426, (int64_t) 2);
                bool y_28877 = x_28873 && cond_f_res_28876;
                bool cond_28878 = cond_28872 || y_28877;
                bool cond_f_res_28879 = sle64(arg_28863, i_33426);
                bool x_28880 = !cond_28878;
                bool y_28881 = cond_f_res_28879 && x_28880;
                bool cond_28882 = cond_28878 || y_28881;
                double defunc_0_f_res_28883;
                
                if (cond_28882 == 1) {
                    defunc_0_f_res_28883 = 0.0;
                } else {
                    int64_t i_28884 = sub64(i_33430, (int64_t) 2);
                    int64_t i_28888 = sub64(i_33426, (int64_t) 2);
                    double defunc_0_f_res_f_res_28894 = ((double *) x_train_mem_35080.mem)[e_28035 * (dz2082U_26091 * dz2081U_26090) + i_28884 * dz2082U_26091 + i_28888];
                    
                    defunc_0_f_res_28883 = defunc_0_f_res_f_res_28894;
                }
                ((double *) mem_35369)[i_33430 * arg_28840 + i_33426] = defunc_0_f_res_28883;
            }
        }
        for (int64_t nest_i_37422 = 0; nest_i_37422 < (int64_t) 1; nest_i_37422++) {
            if (arg_28836 * arg_28840 * (int64_t) 8 > 0)
                memmove(mem_35414 + nest_i_37422 * (arg_28840 * arg_28836) * (int64_t) 8, mem_35369 + (int64_t) 0, arg_28836 * arg_28840 * (int64_t) 8);
        }
        for (int64_t i_33438 = 0; i_33438 < new_n_28838; i_33438++) {
            int64_t j_28908 = add64((int64_t) 5, i_33438);
            int64_t i_p_m_t_s_28909 = add64((int64_t) 4, i_33438);
            bool zzero_leq_i_p_m_t_s_28910 = sle64((int64_t) 0, i_p_m_t_s_28909);
            bool i_p_m_t_s_leq_w_28911 = slt64(i_p_m_t_s_28909, arg_28836);
            bool i_lte_j_28913 = sle64(i_33438, j_28908);
            bool y_28915 = zzero_leq_i_p_m_t_s_28910 && i_p_m_t_s_leq_w_28911;
            bool y_28916 = i_lte_j_28913 && y_28915;
            
            for (int64_t i_33434 = 0; i_33434 < new_m_28842; i_33434++) {
                int64_t j_28921 = add64((int64_t) 5, i_33434);
                int64_t i_p_m_t_s_28922 = add64((int64_t) 4, i_33434);
                bool zzero_leq_i_p_m_t_s_28923 = sle64((int64_t) 0, i_p_m_t_s_28922);
                bool i_p_m_t_s_leq_w_28924 = slt64(i_p_m_t_s_28922, arg_28840);
                bool i_lte_j_28926 = sle64(i_33434, j_28921);
                bool y_28928 = zzero_leq_i_p_m_t_s_28923 && i_p_m_t_s_leq_w_28924;
                bool y_28929 = i_lte_j_28926 && y_28928;
                bool index_ok_28932 = y_28916 && y_28929;
                bool index_certs_28933;
                
                if (!index_ok_28932) {
                    set_error(ctx, msgprintf("Error: %s%lld%s%lld%s%lld%s%lld%s%lld%s%lld%s\n\nBacktrace:\n%s", "Index [", (long long) i_33438, ":", (long long) j_28908, ", ", (long long) i_33434, ":", (long long) j_28921, "] out of bounds for array of shape [", (long long) arg_28836, "][", (long long) arg_28840, "].", "-> #0  ../layers/conv2d.fut:13:90-124\n   #1  ../layers/conv2d.fut:13:144-146\n   #2  /prelude/soacs.fut:59:9-10\n   #3  /prelude/array.fut:200:10-17\n   #4  /prelude/functional.fut:39:61-65\n   #5  /prelude/soacs.fut:59:9-10\n   #6  /prelude/array.fut:208:27-34\n   #7  ../layers/conv2d.fut:13:50-162\n   #8  ../layers/conv2d.fut:26:17-54\n"));
                    err = FUTHARK_PROGRAM_ERROR;
                    goto cleanup;
                }
                for (int64_t i_37425 = 0; i_37425 < (int64_t) 25; i_37425++) {
                    double tmp_37426 = ((double *) mem_35414)[arg_28840 * i_33438 + i_33434 + (squot64(i_37425, (int64_t) 25) * (arg_28840 * arg_28836) + squot64(i_37425 - squot64(i_37425, (int64_t) 25) * (int64_t) 25, (int64_t) 5) * arg_28840 + (i_37425 - squot64(i_37425, (int64_t) 25) * (int64_t) 25 - squot64(i_37425 - squot64(i_37425, (int64_t) 25) * (int64_t) 25, (int64_t) 5) * (int64_t) 5))];
                    
                    ((double *) mem_35419)[i_33438 * binop_y_34785 + i_33434 * (int64_t) 25 + i_37425] = tmp_37426;
                }
            }
        }
        for (int64_t i_33448 = 0; i_33448 < (int64_t) 6; i_33448++) {
            double x_31315 = ((double *) mem_param_35295.mem)[i_33448];
            int64_t binop_x_34717 = (int64_t) 25 * i_33448;
            
            for (int64_t i_33444 = 0; i_33444 < flat_dim_28947; i_33444++) {
                int64_t binop_x_34783 = (int64_t) 25 * i_33444;
                double defunc_0_reduce_res_33206;
                double redout_33440 = 0.0;
                
                for (int64_t i_33441 = 0; i_33441 < (int64_t) 25; i_33441++) {
                    int64_t binop_x_34718 = i_33441 + binop_x_34717;
                    int64_t new_index_34719 = squot64(binop_x_34718, (int64_t) 25);
                    int64_t binop_y_34725 = (int64_t) 25 * new_index_34719;
                    int64_t binop_x_34726 = binop_x_34718 - binop_y_34725;
                    int64_t new_index_34727 = squot64(binop_x_34726, (int64_t) 25);
                    int64_t binop_y_34743 = (int64_t) 25 * new_index_34727;
                    int64_t binop_x_34744 = binop_x_34726 - binop_y_34743;
                    int64_t new_index_34745 = squot64(binop_x_34744, (int64_t) 5);
                    int64_t binop_y_34781 = (int64_t) 5 * new_index_34745;
                    int64_t new_index_34782 = binop_x_34744 - binop_y_34781;
                    double x_31345 = ((double *) mem_param_35290.mem)[new_index_34719 * (int64_t) 25 + new_index_34727 * (int64_t) 25 + new_index_34745 * (int64_t) 5 + new_index_34782];
                    int64_t binop_x_34784 = i_33441 + binop_x_34783;
                    int64_t new_index_34786 = squot64(binop_x_34784, binop_y_34785);
                    int64_t binop_y_34794 = binop_y_34785 * new_index_34786;
                    int64_t binop_x_34795 = binop_x_34784 - binop_y_34794;
                    int64_t new_index_34796 = squot64(binop_x_34795, (int64_t) 25);
                    int64_t binop_y_34816 = (int64_t) 25 * new_index_34796;
                    int64_t new_index_34817 = binop_x_34795 - binop_y_34816;
                    double x_31346 = ((double *) mem_35419)[new_index_34786 * binop_y_34785 + new_index_34796 * (int64_t) 25 + new_index_34817];
                    double defunc_0_f_res_31347 = x_31345 * x_31346;
                    double defunc_0_op_res_31340 = defunc_0_f_res_31347 + redout_33440;
                    double redout_tmp_37429 = defunc_0_op_res_31340;
                    
                    redout_33440 = redout_tmp_37429;
                }
                defunc_0_reduce_res_33206 = redout_33440;
                
                double defunc_0_f_res_31343 = x_31315 + defunc_0_reduce_res_33206;
                
                ((double *) mem_35480)[i_33448 * flat_dim_28947 + i_33444] = defunc_0_f_res_31343;
            }
        }
        for (int64_t i_33470 = 0; i_33470 < (int64_t) 6; i_33470++) {
            int64_t binop_x_34701 = (int64_t) 784 * i_33470;
            
            for (int64_t i_33456 = 0; i_33456 < (int64_t) 28; i_33456++) {
                int64_t binop_y_34702 = (int64_t) 28 * i_33456;
                int64_t binop_x_34703 = binop_x_34701 + binop_y_34702;
                
                for (int64_t i_33452 = 0; i_33452 < (int64_t) 28; i_33452++) {
                    int64_t binop_x_34704 = i_33452 + binop_x_34703;
                    int64_t new_index_34705 = squot64(binop_x_34704, flat_dim_28947);
                    int64_t binop_y_34715 = flat_dim_28947 * new_index_34705;
                    int64_t new_index_34716 = binop_x_34704 - binop_y_34715;
                    double x_31274 = ((double *) mem_35480)[new_index_34705 * flat_dim_28947 + new_index_34716];
                    double max_res_31275 = fmax64(0.0, x_31274);
                    
                    ((double *) mem_35536)[i_33456 * (int64_t) 28 + i_33452] = max_res_31275;
                }
            }
            for (int64_t i_33466 = 0; i_33466 < (int64_t) 14; i_33466++) {
                int64_t i_31279 = mul64((int64_t) 2, i_33466);
                int64_t j_31280 = add64((int64_t) 2, i_31279);
                int64_t i_p_m_t_s_31281 = add64((int64_t) 1, i_31279);
                bool zzero_leq_i_p_m_t_s_31282 = sle64((int64_t) 0, i_p_m_t_s_31281);
                bool i_p_m_t_s_leq_w_31283 = slt64(i_p_m_t_s_31281, (int64_t) 28);
                bool zzero_lte_i_31284 = sle64((int64_t) 0, i_31279);
                bool i_lte_j_31285 = sle64(i_31279, j_31280);
                bool y_31286 = i_p_m_t_s_leq_w_31283 && zzero_lte_i_31284;
                bool y_31287 = zzero_leq_i_p_m_t_s_31282 && y_31286;
                bool y_31288 = i_lte_j_31285 && y_31287;
                bool forwards_ok_31289 = zzero_lte_i_31284 && y_31288;
                
                for (int64_t i_33462 = 0; i_33462 < (int64_t) 14; i_33462++) {
                    int64_t i_31292 = mul64((int64_t) 2, i_33462);
                    int64_t j_31293 = add64((int64_t) 2, i_31292);
                    int64_t i_p_m_t_s_31294 = add64((int64_t) 1, i_31292);
                    bool zzero_leq_i_p_m_t_s_31295 = sle64((int64_t) 0, i_p_m_t_s_31294);
                    bool i_p_m_t_s_leq_w_31296 = slt64(i_p_m_t_s_31294, (int64_t) 28);
                    bool zzero_lte_i_31297 = sle64((int64_t) 0, i_31292);
                    bool i_lte_j_31298 = sle64(i_31292, j_31293);
                    bool y_31299 = i_p_m_t_s_leq_w_31296 && zzero_lte_i_31297;
                    bool y_31300 = zzero_leq_i_p_m_t_s_31295 && y_31299;
                    bool y_31301 = i_lte_j_31298 && y_31300;
                    bool forwards_ok_31302 = zzero_lte_i_31297 && y_31301;
                    bool index_ok_31303 = forwards_ok_31289 && forwards_ok_31302;
                    bool index_certs_31304;
                    
                    if (!index_ok_31303) {
                        set_error(ctx, msgprintf("Error: %s%lld%s%lld%s%lld%s%lld%s%lld%s%lld%s\n\nBacktrace:\n%s", "Index [", (long long) i_31279, ":", (long long) j_31280, ", ", (long long) i_31292, ":", (long long) j_31293, "] out of bounds for array of shape [", (long long) (int64_t) 28, "][", (long long) (int64_t) 28, "].", "-> #0  ../layers/avgpool.fut:7:18-80\n   #1  /prelude/soacs.fut:59:9-10\n   #2  /prelude/array.fut:200:10-17\n   #3  /prelude/functional.fut:39:61-65\n   #4  /prelude/soacs.fut:59:9-10\n   #5  /prelude/array.fut:208:27-34\n   #6  ../layers/avgpool.fut:6:29-8:49\n   #7  ../layers/avgpool.fut:8:73-76\n"));
                        err = FUTHARK_PROGRAM_ERROR;
                        goto cleanup;
                    }
                    
                    double defunc_0_reduce_res_33209;
                    double redout_33458 = 0.0;
                    
                    for (int64_t i_33459 = 0; i_33459 < (int64_t) 4; i_33459++) {
                        int64_t new_index_33979 = squot64(i_33459, (int64_t) 2);
                        int64_t binop_y_33981 = (int64_t) 2 * new_index_33979;
                        int64_t new_index_33982 = i_33459 - binop_y_33981;
                        int64_t slice_33983 = i_31279 + new_index_33979;
                        int64_t slice_33984 = i_31292 + new_index_33982;
                        double x_31311 = ((double *) mem_35536)[slice_33983 * (int64_t) 28 + slice_33984];
                        double defunc_0_op_res_31310 = x_31311 + redout_33458;
                        double redout_tmp_37435 = defunc_0_op_res_31310;
                        
                        redout_33458 = redout_tmp_37435;
                    }
                    defunc_0_reduce_res_33209 = redout_33458;
                    
                    double defunc_0_f_res_31312 = defunc_0_reduce_res_33209 / 4.0;
                    
                    ((double *) mem_35523)[i_33470 * (int64_t) 196 + i_33466 * (int64_t) 14 + i_33462] = defunc_0_f_res_31312;
                }
            }
        }
        for (int64_t i_33478 = 0; i_33478 < (int64_t) 10; i_33478++) {
            int64_t j_29067 = add64((int64_t) 5, i_33478);
            int64_t i_p_m_t_s_29068 = add64((int64_t) 4, i_33478);
            bool zzero_leq_i_p_m_t_s_29069 = sle64((int64_t) 0, i_p_m_t_s_29068);
            bool i_p_m_t_s_leq_w_29070 = slt64(i_p_m_t_s_29068, (int64_t) 14);
            bool i_lte_j_29072 = sle64(i_33478, j_29067);
            bool y_29074 = zzero_leq_i_p_m_t_s_29069 && i_p_m_t_s_leq_w_29070;
            bool y_29075 = i_lte_j_29072 && y_29074;
            
            for (int64_t i_33474 = 0; i_33474 < (int64_t) 10; i_33474++) {
                int64_t j_29080 = add64((int64_t) 5, i_33474);
                int64_t i_p_m_t_s_29081 = add64((int64_t) 4, i_33474);
                bool zzero_leq_i_p_m_t_s_29082 = sle64((int64_t) 0, i_p_m_t_s_29081);
                bool i_p_m_t_s_leq_w_29083 = slt64(i_p_m_t_s_29081, (int64_t) 14);
                bool i_lte_j_29085 = sle64(i_33474, j_29080);
                bool y_29087 = zzero_leq_i_p_m_t_s_29082 && i_p_m_t_s_leq_w_29083;
                bool y_29088 = i_lte_j_29085 && y_29087;
                bool index_ok_29091 = y_29075 && y_29088;
                bool index_certs_29092;
                
                if (!index_ok_29091) {
                    set_error(ctx, msgprintf("Error: %s%lld%s%lld%s%lld%s%lld%s%lld%s%lld%s\n\nBacktrace:\n%s", "Index [", (long long) i_33478, ":", (long long) j_29067, ", ", (long long) i_33474, ":", (long long) j_29080, "] out of bounds for array of shape [", (long long) (int64_t) 14, "][", (long long) (int64_t) 14, "].", "-> #0  ../layers/conv2d.fut:13:90-124\n   #1  ../layers/conv2d.fut:13:144-146\n   #2  /prelude/soacs.fut:59:9-10\n   #3  /prelude/array.fut:200:10-17\n   #4  /prelude/functional.fut:39:61-65\n   #5  /prelude/soacs.fut:59:9-10\n   #6  /prelude/array.fut:208:27-34\n   #7  ../layers/conv2d.fut:13:50-162\n   #8  ../layers/conv2d.fut:26:17-54\n"));
                    err = FUTHARK_PROGRAM_ERROR;
                    goto cleanup;
                }
                for (int64_t i_37438 = 0; i_37438 < (int64_t) 150; i_37438++) {
                    double tmp_37439 = ((double *) mem_35523)[(int64_t) 14 * i_33478 + i_33474 + (squot64(i_37438, (int64_t) 25) * (int64_t) 196 + squot64(i_37438 - squot64(i_37438, (int64_t) 25) * (int64_t) 25, (int64_t) 5) * (int64_t) 14 + (i_37438 - squot64(i_37438, (int64_t) 25) * (int64_t) 25 - squot64(i_37438 - squot64(i_37438, (int64_t) 25) * (int64_t) 25, (int64_t) 5) * (int64_t) 5))];
                    
                    ((double *) mem_35647)[i_33478 * (int64_t) 1500 + i_33474 * (int64_t) 150 + i_37438] = tmp_37439;
                }
            }
        }
        for (int64_t i_33488 = 0; i_33488 < (int64_t) 16; i_33488++) {
            double x_31253 = ((double *) mem_param_35317.mem)[i_33488];
            int64_t binop_x_34607 = (int64_t) 150 * i_33488;
            
            for (int64_t i_33484 = 0; i_33484 < (int64_t) 100; i_33484++) {
                int64_t binop_x_34673 = (int64_t) 150 * i_33484;
                double defunc_0_reduce_res_33215;
                double redout_33480 = 0.0;
                
                for (int64_t i_33481 = 0; i_33481 < (int64_t) 150; i_33481++) {
                    int64_t binop_x_34608 = i_33481 + binop_x_34607;
                    int64_t new_index_34609 = squot64(binop_x_34608, (int64_t) 150);
                    int64_t binop_y_34615 = (int64_t) 150 * new_index_34609;
                    int64_t binop_x_34616 = binop_x_34608 - binop_y_34615;
                    int64_t new_index_34617 = squot64(binop_x_34616, (int64_t) 25);
                    int64_t binop_y_34633 = (int64_t) 25 * new_index_34617;
                    int64_t binop_x_34634 = binop_x_34616 - binop_y_34633;
                    int64_t new_index_34635 = squot64(binop_x_34634, (int64_t) 5);
                    int64_t binop_y_34671 = (int64_t) 5 * new_index_34635;
                    int64_t new_index_34672 = binop_x_34634 - binop_y_34671;
                    double x_31373 = ((double *) mem_param_35312.mem)[new_index_34609 * (int64_t) 150 + new_index_34617 * (int64_t) 25 + new_index_34635 * (int64_t) 5 + new_index_34672];
                    int64_t binop_x_34674 = i_33481 + binop_x_34673;
                    int64_t new_index_34675 = squot64(binop_x_34674, (int64_t) 1500);
                    int64_t binop_y_34681 = (int64_t) 1500 * new_index_34675;
                    int64_t binop_x_34682 = binop_x_34674 - binop_y_34681;
                    int64_t new_index_34683 = squot64(binop_x_34682, (int64_t) 150);
                    int64_t binop_y_34699 = (int64_t) 150 * new_index_34683;
                    int64_t new_index_34700 = binop_x_34682 - binop_y_34699;
                    double x_31374 = ((double *) mem_35647)[new_index_34675 * (int64_t) 1500 + new_index_34683 * (int64_t) 150 + new_index_34700];
                    double defunc_0_f_res_31375 = x_31373 * x_31374;
                    double defunc_0_op_res_31368 = defunc_0_f_res_31375 + redout_33480;
                    double redout_tmp_37442 = defunc_0_op_res_31368;
                    
                    redout_33480 = redout_tmp_37442;
                }
                defunc_0_reduce_res_33215 = redout_33480;
                
                double defunc_0_f_res_31371 = x_31253 + defunc_0_reduce_res_33215;
                
                ((double *) mem_35699)[i_33488 * (int64_t) 100 + i_33484] = defunc_0_f_res_31371;
            }
        }
        for (int64_t i_33510 = 0; i_33510 < (int64_t) 16; i_33510++) {
            int64_t binop_x_34591 = (int64_t) 100 * i_33510;
            
            for (int64_t i_33496 = 0; i_33496 < (int64_t) 10; i_33496++) {
                int64_t binop_y_34592 = (int64_t) 10 * i_33496;
                int64_t binop_x_34593 = binop_x_34591 + binop_y_34592;
                
                for (int64_t i_33492 = 0; i_33492 < (int64_t) 10; i_33492++) {
                    int64_t binop_x_34594 = i_33492 + binop_x_34593;
                    int64_t new_index_34595 = squot64(binop_x_34594, (int64_t) 100);
                    int64_t binop_y_34605 = (int64_t) 100 * new_index_34595;
                    int64_t new_index_34606 = binop_x_34594 - binop_y_34605;
                    double x_31212 = ((double *) mem_35699)[new_index_34595 * (int64_t) 100 + new_index_34606];
                    double max_res_31213 = fmax64(0.0, x_31212);
                    
                    ((double *) mem_35752)[i_33496 * (int64_t) 10 + i_33492] = max_res_31213;
                }
            }
            for (int64_t i_33506 = 0; i_33506 < (int64_t) 5; i_33506++) {
                int64_t i_31217 = mul64((int64_t) 2, i_33506);
                int64_t j_31218 = add64((int64_t) 2, i_31217);
                int64_t i_p_m_t_s_31219 = add64((int64_t) 1, i_31217);
                bool zzero_leq_i_p_m_t_s_31220 = sle64((int64_t) 0, i_p_m_t_s_31219);
                bool i_p_m_t_s_leq_w_31221 = slt64(i_p_m_t_s_31219, (int64_t) 10);
                bool zzero_lte_i_31222 = sle64((int64_t) 0, i_31217);
                bool i_lte_j_31223 = sle64(i_31217, j_31218);
                bool y_31224 = i_p_m_t_s_leq_w_31221 && zzero_lte_i_31222;
                bool y_31225 = zzero_leq_i_p_m_t_s_31220 && y_31224;
                bool y_31226 = i_lte_j_31223 && y_31225;
                bool forwards_ok_31227 = zzero_lte_i_31222 && y_31226;
                
                for (int64_t i_33502 = 0; i_33502 < (int64_t) 5; i_33502++) {
                    int64_t i_31230 = mul64((int64_t) 2, i_33502);
                    int64_t j_31231 = add64((int64_t) 2, i_31230);
                    int64_t i_p_m_t_s_31232 = add64((int64_t) 1, i_31230);
                    bool zzero_leq_i_p_m_t_s_31233 = sle64((int64_t) 0, i_p_m_t_s_31232);
                    bool i_p_m_t_s_leq_w_31234 = slt64(i_p_m_t_s_31232, (int64_t) 10);
                    bool zzero_lte_i_31235 = sle64((int64_t) 0, i_31230);
                    bool i_lte_j_31236 = sle64(i_31230, j_31231);
                    bool y_31237 = i_p_m_t_s_leq_w_31234 && zzero_lte_i_31235;
                    bool y_31238 = zzero_leq_i_p_m_t_s_31233 && y_31237;
                    bool y_31239 = i_lte_j_31236 && y_31238;
                    bool forwards_ok_31240 = zzero_lte_i_31235 && y_31239;
                    bool index_ok_31241 = forwards_ok_31227 && forwards_ok_31240;
                    bool index_certs_31242;
                    
                    if (!index_ok_31241) {
                        set_error(ctx, msgprintf("Error: %s%lld%s%lld%s%lld%s%lld%s%lld%s%lld%s\n\nBacktrace:\n%s", "Index [", (long long) i_31217, ":", (long long) j_31218, ", ", (long long) i_31230, ":", (long long) j_31231, "] out of bounds for array of shape [", (long long) (int64_t) 10, "][", (long long) (int64_t) 10, "].", "-> #0  ../layers/avgpool.fut:7:18-80\n   #1  /prelude/soacs.fut:59:9-10\n   #2  /prelude/array.fut:200:10-17\n   #3  /prelude/functional.fut:39:61-65\n   #4  /prelude/soacs.fut:59:9-10\n   #5  /prelude/array.fut:208:27-34\n   #6  ../layers/avgpool.fut:6:29-8:49\n   #7  ../layers/avgpool.fut:8:73-76\n"));
                        err = FUTHARK_PROGRAM_ERROR;
                        goto cleanup;
                    }
                    
                    double defunc_0_reduce_res_33218;
                    double redout_33498 = 0.0;
                    
                    for (int64_t i_33499 = 0; i_33499 < (int64_t) 4; i_33499++) {
                        int64_t new_index_33965 = squot64(i_33499, (int64_t) 2);
                        int64_t binop_y_33967 = (int64_t) 2 * new_index_33965;
                        int64_t new_index_33968 = i_33499 - binop_y_33967;
                        int64_t slice_33969 = i_31217 + new_index_33965;
                        int64_t slice_33970 = i_31230 + new_index_33968;
                        double x_31249 = ((double *) mem_35752)[slice_33969 * (int64_t) 10 + slice_33970];
                        double defunc_0_op_res_31248 = x_31249 + redout_33498;
                        double redout_tmp_37448 = defunc_0_op_res_31248;
                        
                        redout_33498 = redout_tmp_37448;
                    }
                    defunc_0_reduce_res_33218 = redout_33498;
                    
                    double defunc_0_f_res_31250 = defunc_0_reduce_res_33218 / 4.0;
                    
                    ((double *) mem_35739)[i_33510 * (int64_t) 25 + i_33506 * (int64_t) 5 + i_33502] = defunc_0_f_res_31250;
                }
            }
        }
        for (int64_t i_33516 = 0; i_33516 < (int64_t) 120; i_33516++) {
            double x_31193 = ((double *) mem_param_35333.mem)[i_33516];
            double defunc_0_reduce_res_33223;
            double redout_33512 = 0.0;
            
            for (int64_t i_33513 = 0; i_33513 < (int64_t) 400; i_33513++) {
                int64_t new_index_33951 = squot64(i_33513, (int64_t) 25);
                int64_t binop_y_33953 = (int64_t) 25 * new_index_33951;
                int64_t binop_x_33954 = i_33513 - binop_y_33953;
                int64_t new_index_33955 = squot64(binop_x_33954, (int64_t) 5);
                int64_t binop_y_33963 = (int64_t) 5 * new_index_33955;
                int64_t new_index_33964 = binop_x_33954 - binop_y_33963;
                double x_31387 = ((double *) mem_35739)[new_index_33951 * (int64_t) 25 + new_index_33955 * (int64_t) 5 + new_index_33964];
                double x_31388 = ((double *) mem_param_35328.mem)[i_33516 * (int64_t) 400 + i_33513];
                double defunc_0_f_res_31389 = x_31387 * x_31388;
                double defunc_0_op_res_31202 = defunc_0_f_res_31389 + redout_33512;
                double redout_tmp_37450 = defunc_0_op_res_31202;
                
                redout_33512 = redout_tmp_37450;
            }
            defunc_0_reduce_res_33223 = redout_33512;
            
            double defunc_0_f_res_31204 = x_31193 + defunc_0_reduce_res_33223;
            double max_res_31206 = fmax64(0.0, defunc_0_f_res_31204);
            
            ((double *) mem_35863)[i_33516] = max_res_31206;
        }
        for (int64_t i_33522 = 0; i_33522 < (int64_t) 84; i_33522++) {
            double x_31178 = ((double *) mem_param_35349.mem)[i_33522];
            double defunc_0_reduce_res_33224;
            double redout_33518 = 0.0;
            
            for (int64_t i_33519 = 0; i_33519 < (int64_t) 120; i_33519++) {
                double x_31393 = ((double *) mem_35863)[i_33519];
                double x_31394 = ((double *) mem_param_35344.mem)[i_33522 * (int64_t) 120 + i_33519];
                double defunc_0_f_res_31395 = x_31393 * x_31394;
                double defunc_0_op_res_31187 = defunc_0_f_res_31395 + redout_33518;
                double redout_tmp_37452 = defunc_0_op_res_31187;
                
                redout_33518 = redout_tmp_37452;
            }
            defunc_0_reduce_res_33224 = redout_33518;
            
            double defunc_0_f_res_31189 = x_31178 + defunc_0_reduce_res_33224;
            double max_res_31191 = fmax64(0.0, defunc_0_f_res_31189);
            
            ((double *) mem_35875)[i_33522] = max_res_31191;
        }
        
        double defunc_0_reduce_res_33290;
        double redout_33527 = 0.0;
        
        for (int64_t i_33529 = 0; i_33529 < (int64_t) 10; i_33529++) {
            double x_32858 = ((double *) mem_param_35365.mem)[i_33529];
            double defunc_0_reduce_res_33225;
            double redout_33524 = 0.0;
            
            for (int64_t i_33525 = 0; i_33525 < (int64_t) 84; i_33525++) {
                double x_32864 = ((double *) mem_35875)[i_33525];
                double x_32865 = ((double *) mem_param_35360.mem)[i_33529 * (int64_t) 84 + i_33525];
                double defunc_0_f_res_32866 = x_32864 * x_32865;
                double defunc_0_op_res_32863 = defunc_0_f_res_32866 + redout_33524;
                double redout_tmp_37455 = defunc_0_op_res_32863;
                
                redout_33524 = redout_tmp_37455;
            }
            defunc_0_reduce_res_33225 = redout_33524;
            
            double defunc_0_f_res_32867 = x_32858 + defunc_0_reduce_res_33225;
            double defunc_0_f_res_32868 = futrts_exp64(defunc_0_f_res_32867);
            double defunc_0_op_res_28494 = defunc_0_f_res_32868 + redout_33527;
            
            ((double *) mem_35887)[i_33529] = defunc_0_f_res_32868;
            
            double redout_tmp_37453 = defunc_0_op_res_28494;
            
            redout_33527 = redout_tmp_37453;
        }
        defunc_0_reduce_res_33290 = redout_33527;
        
        double binop_y_31713 = 1.0 / defunc_0_reduce_res_33290;
        double binop_y_31715 = defunc_0_reduce_res_33290 * defunc_0_reduce_res_33290;
        double defunc_0_reduce_res_contrib_sum_33292;
        double redout_33532 = 0.0;
        
        for (int64_t i_33534 = 0; i_33534 < (int64_t) 10; i_33534++) {
            double x_32844 = ((double *) mem_35887)[i_33534];
            double x_32845 = ((double *) y_train_mem_35081.mem)[e_28035 * (int64_t) 10 + i_33534];
            double defunc_0_f_res_32846 = x_32844 / defunc_0_reduce_res_33290;
            double arg_32847 = x_32845 - defunc_0_f_res_32846;
            double binop_y_32848 = 2.0 * arg_32847;
            double binop_x_adj_32849 = 0.1 * binop_y_32848;
            double binop_y_adj_32850 = -1.0 * binop_x_adj_32849;
            double binop_x_adj_32851 = binop_y_31713 * binop_y_adj_32850;
            double binop_y_32852 = x_32844 / binop_y_31715;
            double binop_y_32853 = 0.0 - binop_y_32852;
            double binop_y_adj_32854 = binop_y_adj_32850 * binop_y_32853;
            double binlam_res_31724 = binop_y_adj_32854 + redout_33532;
            
            ((double *) mem_35899)[i_33534] = binop_x_adj_32851;
            
            double redout_tmp_37456 = binlam_res_31724;
            
            redout_33532 = redout_tmp_37456;
        }
        defunc_0_reduce_res_contrib_sum_33292 = redout_33532;
        for (int64_t nest_i_37458 = 0; nest_i_37458 < (int64_t) 84; nest_i_37458++) {
            ((double *) mem_35911)[nest_i_37458] = 0.0;
        }
        
        bool acc_cert_p_31747;
        
        for (int64_t i_33548 = 0; i_33548 < (int64_t) 10; i_33548++) {
            double x_31730 = ((double *) mem_param_35365.mem)[i_33548];
            double map_adj_p_31729 = ((double *) mem_35899)[i_33548];
            double defunc_0_f_res_adj_31750 = map_adj_p_31729 + defunc_0_reduce_res_contrib_sum_33292;
            double defunc_0_reduce_res_33226;
            double redout_33536 = 0.0;
            
            for (int64_t i_33537 = 0; i_33537 < (int64_t) 84; i_33537++) {
                double x_32904 = ((double *) mem_35875)[i_33537];
                double x_32905 = ((double *) mem_param_35360.mem)[i_33548 * (int64_t) 84 + i_33537];
                double defunc_0_f_res_32906 = x_32904 * x_32905;
                double defunc_0_op_res_31735 = defunc_0_f_res_32906 + redout_33536;
                double redout_tmp_37462 = defunc_0_op_res_31735;
                
                redout_33536 = redout_tmp_37462;
            }
            defunc_0_reduce_res_33226 = redout_33536;
            
            double defunc_0_f_res_31739 = x_31730 + defunc_0_reduce_res_33226;
            double binop_y_31753 = futrts_exp64(defunc_0_f_res_31739);
            double contrib_31754 = defunc_0_f_res_adj_31750 * binop_y_31753;
            
            for (int64_t i_33541 = 0; i_33541 < (int64_t) 84; i_33541++) {
                double x_32894 = ((double *) mem_35875)[i_33541];
                double x_32895 = ((double *) mem_param_35360.mem)[i_33548 * (int64_t) 84 + i_33541];
                double binop_x_adj_32898 = contrib_31754 * x_32895;
                double binop_y_adj_32899 = contrib_31754 * x_32894;
                
                // UpdateAcc
                {
                    int64_t idx_31746 = i_33541;
                    
                    if (sle64((int64_t) 0, i_33541) && slt64(i_33541, (int64_t) 84)) {
                        double x_31743;
                        double y_31744;
                        
                        x_31743 = ((double *) mem_35911)[i_33541];
                        y_31744 = binop_x_adj_32898;
                        
                        double binlam_res_31745 = x_31743 + y_31744;
                        
                        ((double *) mem_35911)[i_33541] = binlam_res_31745;
                    }
                }
                ((double *) mem_35930)[i_33541] = binop_y_adj_32899;
            }
            ((double *) mem_35913)[i_33548] = contrib_31754;
            if ((int64_t) 672 > 0)
                memmove(mem_35915 + i_33548 * (int64_t) 84 * (int64_t) 8, mem_35930 + (int64_t) 0, (int64_t) 672);
        }
        if ((int64_t) 80 > 0)
            memmove(mem_35955 + (int64_t) 0, mem_35913 + (int64_t) 0, (int64_t) 80);
        if ((int64_t) 6720 > 0)
            memmove(mem_35957 + (int64_t) 0, mem_35915 + (int64_t) 0, (int64_t) 6720);
        for (int64_t nest_i_37465 = 0; nest_i_37465 < (int64_t) 120; nest_i_37465++) {
            ((double *) mem_35959)[nest_i_37465] = 0.0;
        }
        
        bool acc_cert_p_31796;
        
        for (int64_t i_33563 = 0; i_33563 < (int64_t) 84; i_33563++) {
            double x_31779 = ((double *) mem_param_35349.mem)[i_33563];
            double map_adj_p_31778 = ((double *) mem_35911)[i_33563];
            double defunc_0_reduce_res_33232;
            double redout_33551 = 0.0;
            
            for (int64_t i_33552 = 0; i_33552 < (int64_t) 120; i_33552++) {
                double x_32929 = ((double *) mem_35863)[i_33552];
                double x_32930 = ((double *) mem_param_35344.mem)[i_33563 * (int64_t) 120 + i_33552];
                double defunc_0_f_res_32931 = x_32929 * x_32930;
                double defunc_0_op_res_31784 = defunc_0_f_res_32931 + redout_33551;
                double redout_tmp_37469 = defunc_0_op_res_31784;
                
                redout_33551 = redout_tmp_37469;
            }
            defunc_0_reduce_res_33232 = redout_33551;
            
            double defunc_0_f_res_31788 = x_31779 + defunc_0_reduce_res_33232;
            bool convop_x_31805 = 0.0 < defunc_0_f_res_31788;
            int32_t convop_x_31806 = btoi_bool_i32(convop_x_31805);
            double binop_y_31807 = sitofp_i32_f64(convop_x_31806);
            double binop_y_adj_31808 = map_adj_p_31778 * binop_y_31807;
            
            for (int64_t i_33556 = 0; i_33556 < (int64_t) 120; i_33556++) {
                double x_32919 = ((double *) mem_35863)[i_33556];
                double x_32920 = ((double *) mem_param_35344.mem)[i_33563 * (int64_t) 120 + i_33556];
                double binop_x_adj_32923 = binop_y_adj_31808 * x_32920;
                double binop_y_adj_32924 = binop_y_adj_31808 * x_32919;
                
                // UpdateAcc
                {
                    int64_t idx_31795 = i_33556;
                    
                    if (sle64((int64_t) 0, i_33556) && slt64(i_33556, (int64_t) 120)) {
                        double x_31792;
                        double y_31793;
                        
                        x_31792 = ((double *) mem_35959)[i_33556];
                        y_31793 = binop_x_adj_32923;
                        
                        double binlam_res_31794 = x_31792 + y_31793;
                        
                        ((double *) mem_35959)[i_33556] = binlam_res_31794;
                    }
                }
                ((double *) mem_35978)[i_33556] = binop_y_adj_32924;
            }
            ((double *) mem_35961)[i_33563] = binop_y_adj_31808;
            if ((int64_t) 960 > 0)
                memmove(mem_35963 + i_33563 * (int64_t) 120 * (int64_t) 8, mem_35978 + (int64_t) 0, (int64_t) 960);
        }
        if ((int64_t) 672 > 0)
            memmove(mem_36003 + (int64_t) 0, mem_35961 + (int64_t) 0, (int64_t) 672);
        if ((int64_t) 80640 > 0)
            memmove(mem_36005 + (int64_t) 0, mem_35963 + (int64_t) 0, (int64_t) 80640);
        for (int64_t nest_i_37472 = 0; nest_i_37472 < (int64_t) 400; nest_i_37472++) {
            ((double *) mem_36007)[nest_i_37472] = 0.0;
        }
        
        bool acc_cert_p_31850;
        
        for (int64_t i_33578 = 0; i_33578 < (int64_t) 120; i_33578++) {
            double x_31833 = ((double *) mem_param_35333.mem)[i_33578];
            double map_adj_p_31832 = ((double *) mem_35959)[i_33578];
            double defunc_0_reduce_res_33238;
            double redout_33566 = 0.0;
            
            for (int64_t i_33567 = 0; i_33567 < (int64_t) 400; i_33567++) {
                int64_t new_index_33933 = squot64(i_33567, (int64_t) 25);
                int64_t binop_y_33935 = (int64_t) 25 * new_index_33933;
                int64_t binop_x_33936 = i_33567 - binop_y_33935;
                int64_t new_index_33937 = squot64(binop_x_33936, (int64_t) 5);
                int64_t binop_y_33945 = (int64_t) 5 * new_index_33937;
                int64_t new_index_33946 = binop_x_33936 - binop_y_33945;
                double x_32954 = ((double *) mem_35739)[new_index_33933 * (int64_t) 25 + new_index_33937 * (int64_t) 5 + new_index_33946];
                double x_32955 = ((double *) mem_param_35328.mem)[i_33578 * (int64_t) 400 + i_33567];
                double defunc_0_f_res_32956 = x_32954 * x_32955;
                double defunc_0_op_res_31838 = defunc_0_f_res_32956 + redout_33566;
                double redout_tmp_37476 = defunc_0_op_res_31838;
                
                redout_33566 = redout_tmp_37476;
            }
            defunc_0_reduce_res_33238 = redout_33566;
            
            double defunc_0_f_res_31842 = x_31833 + defunc_0_reduce_res_33238;
            bool convop_x_31859 = 0.0 < defunc_0_f_res_31842;
            int32_t convop_x_31860 = btoi_bool_i32(convop_x_31859);
            double binop_y_31861 = sitofp_i32_f64(convop_x_31860);
            double binop_y_adj_31862 = map_adj_p_31832 * binop_y_31861;
            
            for (int64_t i_33571 = 0; i_33571 < (int64_t) 400; i_33571++) {
                int64_t new_index_33917 = squot64(i_33571, (int64_t) 25);
                int64_t binop_y_33919 = (int64_t) 25 * new_index_33917;
                int64_t binop_x_33920 = i_33571 - binop_y_33919;
                int64_t new_index_33921 = squot64(binop_x_33920, (int64_t) 5);
                int64_t binop_y_33929 = (int64_t) 5 * new_index_33921;
                int64_t new_index_33930 = binop_x_33920 - binop_y_33929;
                double x_32944 = ((double *) mem_35739)[new_index_33917 * (int64_t) 25 + new_index_33921 * (int64_t) 5 + new_index_33930];
                double x_32945 = ((double *) mem_param_35328.mem)[i_33578 * (int64_t) 400 + i_33571];
                double binop_x_adj_32948 = binop_y_adj_31862 * x_32945;
                double binop_y_adj_32949 = binop_y_adj_31862 * x_32944;
                
                // UpdateAcc
                {
                    int64_t idx_31849 = i_33571;
                    
                    if (sle64((int64_t) 0, i_33571) && slt64(i_33571, (int64_t) 400)) {
                        double x_31846;
                        double y_31847;
                        
                        x_31846 = ((double *) mem_36007)[i_33571];
                        y_31847 = binop_x_adj_32948;
                        
                        double binlam_res_31848 = x_31846 + y_31847;
                        
                        ((double *) mem_36007)[i_33571] = binlam_res_31848;
                    }
                }
                ((double *) mem_36026)[i_33571] = binop_y_adj_32949;
            }
            ((double *) mem_36009)[i_33578] = binop_y_adj_31862;
            if ((int64_t) 3200 > 0)
                memmove(mem_36011 + i_33578 * (int64_t) 400 * (int64_t) 8, mem_36026 + (int64_t) 0, (int64_t) 3200);
        }
        if ((int64_t) 960 > 0)
            memmove(mem_36051 + (int64_t) 0, mem_36009 + (int64_t) 0, (int64_t) 960);
        if ((int64_t) 384000 > 0)
            memmove(mem_36053 + (int64_t) 0, mem_36011 + (int64_t) 0, (int64_t) 384000);
        for (int64_t i_33599 = 0; i_33599 < (int64_t) 16; i_33599++) {
            for (int64_t nest_i_37480 = 0; nest_i_37480 < (int64_t) 10; nest_i_37480++) {
                for (int64_t nest_i_37481 = 0; nest_i_37481 < (int64_t) 10; nest_i_37481++) {
                    ((double *) mem_36068)[nest_i_37480 * (int64_t) 10 + nest_i_37481] = 0.0;
                }
            }
            
            int64_t binop_x_34587 = (int64_t) 25 * i_33599;
            bool acc_cert_p_31982;
            
            for (int64_t i_33588 = 0; i_33588 < (int64_t) 5; i_33588++) {
                int64_t i_31941 = mul64((int64_t) 2, i_33588);
                int64_t binop_y_34588 = (int64_t) 5 * i_33588;
                int64_t binop_x_34589 = binop_x_34587 + binop_y_34588;
                
                for (int64_t i_33586 = 0; i_33586 < (int64_t) 5; i_33586++) {
                    int64_t new_index_34590 = i_33586 + binop_x_34589;
                    double map_adj_p_31986 = ((double *) mem_36007)[new_index_34590];
                    int64_t i_31988 = mul64((int64_t) 2, i_33586);
                    double binop_x_adj_32013 = 0.25 * map_adj_p_31986;
                    
                    for (int64_t i_33584 = 0; i_33584 < (int64_t) 2; i_33584++) {
                        int64_t index_32027 = i_31941 + i_33584;
                        
                        for (int64_t i_33582 = 0; i_33582 < (int64_t) 2; i_33582++) {
                            int64_t index_32028 = i_31988 + i_33582;
                            
                            // UpdateAcc
                            {
                                int64_t idx_31980 = index_32027;
                                int64_t idx_31981 = index_32028;
                                
                                if ((sle64((int64_t) 0, index_32027) && slt64(index_32027, (int64_t) 10)) && (sle64((int64_t) 0, index_32028) && slt64(index_32028, (int64_t) 10))) {
                                    double x_31977;
                                    double y_31978;
                                    
                                    x_31977 = ((double *) mem_36068)[index_32027 * (int64_t) 10 + index_32028];
                                    y_31978 = binop_x_adj_32013;
                                    
                                    double binlam_res_31979 = x_31977 + y_31978;
                                    
                                    ((double *) mem_36068)[index_32027 * (int64_t) 10 + index_32028] = binlam_res_31979;
                                }
                            }
                        }
                    }
                }
            }
            
            int64_t binop_x_34571 = (int64_t) 100 * i_33599;
            
            for (int64_t i_33595 = 0; i_33595 < (int64_t) 10; i_33595++) {
                int64_t binop_y_34572 = (int64_t) 10 * i_33595;
                int64_t binop_x_34573 = binop_x_34571 + binop_y_34572;
                
                for (int64_t i_33591 = 0; i_33591 < (int64_t) 10; i_33591++) {
                    int64_t binop_x_34574 = i_33591 + binop_x_34573;
                    int64_t new_index_34575 = squot64(binop_x_34574, (int64_t) 100);
                    int64_t binop_y_34585 = (int64_t) 100 * new_index_34575;
                    int64_t new_index_34586 = binop_x_34574 - binop_y_34585;
                    double x_32129 = ((double *) mem_35699)[new_index_34575 * (int64_t) 100 + new_index_34586];
                    double map_adj_p_32128 = ((double *) mem_36068)[i_33595 * (int64_t) 10 + i_33591];
                    bool convop_x_32135 = 0.0 < x_32129;
                    int32_t convop_x_32136 = btoi_bool_i32(convop_x_32135);
                    double binop_y_32137 = sitofp_i32_f64(convop_x_32136);
                    double binop_y_adj_32138 = map_adj_p_32128 * binop_y_32137;
                    
                    ((double *) mem_36055)[i_33599 * (int64_t) 100 + i_33595 * (int64_t) 10 + i_33591] = binop_y_adj_32138;
                }
            }
        }
        for (int64_t nest_i_37488 = 0; nest_i_37488 < (int64_t) 100; nest_i_37488++) {
            for (int64_t nest_i_37489 = 0; nest_i_37489 < (int64_t) 150; nest_i_37489++) {
                ((double *) mem_36141)[nest_i_37488 * (int64_t) 150 + nest_i_37489] = 0.0;
            }
        }
        
        bool acc_cert_p_32166;
        
        for (int64_t i_33614 = 0; i_33614 < (int64_t) 16; i_33614++) {
            for (int64_t nest_i_37493 = 0; nest_i_37493 < (int64_t) 150; nest_i_37493++) {
                ((double *) mem_36160)[nest_i_37493] = 0.0;
            }
            
            int64_t binop_x_34543 = (int64_t) 100 * i_33614;
            double x_contrib_sum_33254;
            double redout_33601 = 0.0;
            
            for (int64_t i_33602 = 0; i_33602 < (int64_t) 100; i_33602++) {
                int64_t binop_x_34544 = i_33602 + binop_x_34543;
                int64_t new_index_34545 = squot64(binop_x_34544, (int64_t) 100);
                int64_t binop_y_34551 = (int64_t) 100 * new_index_34545;
                int64_t binop_x_34552 = binop_x_34544 - binop_y_34551;
                int64_t new_index_34553 = squot64(binop_x_34552, (int64_t) 10);
                int64_t binop_y_34569 = (int64_t) 10 * new_index_34553;
                int64_t new_index_34570 = binop_x_34552 - binop_y_34569;
                double x_32214 = ((double *) mem_36055)[new_index_34545 * (int64_t) 100 + new_index_34553 * (int64_t) 10 + new_index_34570];
                double binlam_res_32213 = x_32214 + redout_33601;
                double redout_tmp_37494 = binlam_res_32213;
                
                redout_33601 = redout_tmp_37494;
            }
            x_contrib_sum_33254 = redout_33601;
            
            int64_t binop_x_34449 = (int64_t) 150 * i_33614;
            bool acc_cert_p_32186;
            
            for (int64_t i_33608 = 0; i_33608 < (int64_t) 100; i_33608++) {
                int64_t binop_x_34422 = i_33608 + binop_x_34543;
                int64_t new_index_34423 = squot64(binop_x_34422, (int64_t) 100);
                int64_t binop_y_34429 = (int64_t) 100 * new_index_34423;
                int64_t binop_x_34430 = binop_x_34422 - binop_y_34429;
                int64_t new_index_34431 = squot64(binop_x_34430, (int64_t) 10);
                int64_t binop_y_34447 = (int64_t) 10 * new_index_34431;
                int64_t new_index_34448 = binop_x_34430 - binop_y_34447;
                double map_adj_p_32975 = ((double *) mem_36055)[new_index_34423 * (int64_t) 100 + new_index_34431 * (int64_t) 10 + new_index_34448];
                int64_t binop_x_34515 = (int64_t) 150 * i_33608;
                
                for (int64_t i_33605 = 0; i_33605 < (int64_t) 150; i_33605++) {
                    int64_t binop_x_34450 = i_33605 + binop_x_34449;
                    int64_t new_index_34451 = squot64(binop_x_34450, (int64_t) 150);
                    int64_t binop_y_34457 = (int64_t) 150 * new_index_34451;
                    int64_t binop_x_34458 = binop_x_34450 - binop_y_34457;
                    int64_t new_index_34459 = squot64(binop_x_34458, (int64_t) 25);
                    int64_t binop_y_34475 = (int64_t) 25 * new_index_34459;
                    int64_t binop_x_34476 = binop_x_34458 - binop_y_34475;
                    int64_t new_index_34477 = squot64(binop_x_34476, (int64_t) 5);
                    int64_t binop_y_34513 = (int64_t) 5 * new_index_34477;
                    int64_t new_index_34514 = binop_x_34476 - binop_y_34513;
                    double x_33013 = ((double *) mem_param_35312.mem)[new_index_34451 * (int64_t) 150 + new_index_34459 * (int64_t) 25 + new_index_34477 * (int64_t) 5 + new_index_34514];
                    int64_t binop_x_34516 = i_33605 + binop_x_34515;
                    int64_t new_index_34517 = squot64(binop_x_34516, (int64_t) 1500);
                    int64_t binop_y_34523 = (int64_t) 1500 * new_index_34517;
                    int64_t binop_x_34524 = binop_x_34516 - binop_y_34523;
                    int64_t new_index_34525 = squot64(binop_x_34524, (int64_t) 150);
                    int64_t binop_y_34541 = (int64_t) 150 * new_index_34525;
                    int64_t new_index_34542 = binop_x_34524 - binop_y_34541;
                    double x_33014 = ((double *) mem_35647)[new_index_34517 * (int64_t) 1500 + new_index_34525 * (int64_t) 150 + new_index_34542];
                    double binop_x_adj_33017 = map_adj_p_32975 * x_33014;
                    double binop_y_adj_33018 = map_adj_p_32975 * x_33013;
                    
                    // UpdateAcc
                    {
                        int64_t idx_32164 = i_33608;
                        int64_t idx_32165 = i_33605;
                        
                        if ((sle64((int64_t) 0, i_33608) && slt64(i_33608, (int64_t) 100)) && (sle64((int64_t) 0, i_33605) && slt64(i_33605, (int64_t) 150))) {
                            double x_32161;
                            double y_32162;
                            
                            x_32161 = ((double *) mem_36141)[i_33608 * (int64_t) 150 + i_33605];
                            y_32162 = binop_y_adj_33018;
                            
                            double binlam_res_32163 = x_32161 + y_32162;
                            
                            ((double *) mem_36141)[i_33608 * (int64_t) 150 + i_33605] = binlam_res_32163;
                        }
                    }
                    // UpdateAcc
                    {
                        int64_t idx_32185 = i_33605;
                        
                        if (sle64((int64_t) 0, i_33605) && slt64(i_33605, (int64_t) 150)) {
                            double x_32182;
                            double y_32183;
                            
                            x_32182 = ((double *) mem_36160)[i_33605];
                            y_32183 = binop_x_adj_33017;
                            
                            double binlam_res_32184 = x_32182 + y_32183;
                            
                            ((double *) mem_36160)[i_33605] = binlam_res_32184;
                        }
                    }
                }
            }
            if ((int64_t) 1200 > 0)
                memmove(mem_36143 + i_33614 * (int64_t) 150 * (int64_t) 8, mem_36160 + (int64_t) 0, (int64_t) 1200);
            ((double *) mem_36145)[i_33614] = x_contrib_sum_33254;
        }
        if ((int64_t) 19200 > 0)
            memmove(mem_36175 + (int64_t) 0, mem_36143 + (int64_t) 0, (int64_t) 19200);
        if ((int64_t) 128 > 0)
            memmove(mem_36177 + (int64_t) 0, mem_36145 + (int64_t) 0, (int64_t) 128);
        if (memblock_alloc(ctx, &mem_36179, (int64_t) 19200, "mem_36179")) {
            err = 1;
            goto cleanup;
        }
        for (int64_t i_33631 = 0; i_33631 < (int64_t) 16; i_33631++) {
            int64_t binop_x_34399 = (int64_t) 150 * i_33631;
            
            for (int64_t i_33627 = 0; i_33627 < (int64_t) 6; i_33627++) {
                int64_t binop_y_34400 = (int64_t) 25 * i_33627;
                int64_t binop_x_34401 = binop_x_34399 + binop_y_34400;
                
                for (int64_t i_33623 = 0; i_33623 < (int64_t) 5; i_33623++) {
                    int64_t binop_y_34402 = (int64_t) 5 * i_33623;
                    int64_t binop_x_34403 = binop_x_34401 + binop_y_34402;
                    
                    for (int64_t i_33619 = 0; i_33619 < (int64_t) 5; i_33619++) {
                        double x_28252 = ((double *) mem_param_35312.mem)[i_33631 * (int64_t) 150 + i_33627 * (int64_t) 25 + i_33623 * (int64_t) 5 + i_33619];
                        int64_t binop_x_34404 = i_33619 + binop_x_34403;
                        int64_t new_index_34405 = squot64(binop_x_34404, (int64_t) 150);
                        int64_t binop_y_34419 = (int64_t) 150 * new_index_34405;
                        int64_t new_index_34420 = binop_x_34404 - binop_y_34419;
                        double x_28253 = ((double *) mem_36175)[new_index_34405 * (int64_t) 150 + new_index_34420];
                        double arg_28254 = 0.1 * x_28253;
                        double defunc_0_f_res_28255 = x_28252 - arg_28254;
                        
                        ((double *) mem_36179.mem)[i_33631 * (int64_t) 150 + i_33627 * (int64_t) 25 + i_33623 * (int64_t) 5 + i_33619] = defunc_0_f_res_28255;
                    }
                }
            }
        }
        for (int64_t nest_i_37503 = 0; nest_i_37503 < (int64_t) 6; nest_i_37503++) {
            for (int64_t nest_i_37504 = 0; nest_i_37504 < (int64_t) 14; nest_i_37504++) {
                for (int64_t nest_i_37505 = 0; nest_i_37505 < (int64_t) 14; nest_i_37505++) {
                    ((double *) mem_36323)[nest_i_37503 * (int64_t) 196 + nest_i_37504 * (int64_t) 14 + nest_i_37505] = 0.0;
                }
            }
        }
        
        bool acc_cert_p_32282;
        
        for (int64_t i_33642 = 0; i_33642 < (int64_t) 10; i_33642++) {
            int64_t binop_x_34371 = (int64_t) 1500 * i_33642;
            
            for (int64_t i_33640 = 0; i_33640 < (int64_t) 10; i_33640++) {
                int64_t binop_y_34372 = (int64_t) 150 * i_33640;
                int64_t binop_x_34373 = binop_x_34371 + binop_y_34372;
                
                for (int64_t i_33638 = 0; i_33638 < (int64_t) 6; i_33638++) {
                    int64_t binop_y_34374 = (int64_t) 25 * i_33638;
                    int64_t binop_x_34375 = binop_x_34373 + binop_y_34374;
                    
                    for (int64_t i_33636 = 0; i_33636 < (int64_t) 5; i_33636++) {
                        int64_t index_32319 = i_33636 + i_33642;
                        int64_t binop_y_34376 = (int64_t) 5 * i_33636;
                        int64_t binop_x_34377 = binop_x_34375 + binop_y_34376;
                        
                        for (int64_t i_33634 = 0; i_33634 < (int64_t) 5; i_33634++) {
                            int64_t binop_x_34378 = i_33634 + binop_x_34377;
                            int64_t new_index_34379 = squot64(binop_x_34378, (int64_t) 150);
                            int64_t binop_y_34397 = (int64_t) 150 * new_index_34379;
                            int64_t new_index_34398 = binop_x_34378 - binop_y_34397;
                            double adj_reshape_p_p_p_32317 = ((double *) mem_36141)[new_index_34379 * (int64_t) 150 + new_index_34398];
                            int64_t index_32320 = i_33634 + i_33640;
                            
                            // UpdateAcc
                            {
                                int64_t idx_32277 = i_33638;
                                int64_t idx_32278 = index_32319;
                                int64_t idx_32279 = index_32320;
                                
                                if (((sle64((int64_t) 0, i_33638) && slt64(i_33638, (int64_t) 6)) && (sle64((int64_t) 0, index_32319) && slt64(index_32319, (int64_t) 14))) && (sle64((int64_t) 0, index_32320) && slt64(index_32320, (int64_t) 14))) {
                                    double x_32274;
                                    double y_32275;
                                    
                                    x_32274 = ((double *) mem_36323)[i_33638 * (int64_t) 196 + index_32319 * (int64_t) 14 + index_32320];
                                    y_32275 = adj_reshape_p_p_p_32317;
                                    
                                    double binlam_res_32276 = x_32274 + y_32275;
                                    
                                    ((double *) mem_36323)[i_33638 * (int64_t) 196 + index_32319 * (int64_t) 14 + index_32320] = binlam_res_32276;
                                }
                            }
                        }
                    }
                }
            }
        }
        for (int64_t i_33661 = 0; i_33661 < (int64_t) 6; i_33661++) {
            for (int64_t nest_i_37512 = 0; nest_i_37512 < (int64_t) 28; nest_i_37512++) {
                for (int64_t nest_i_37513 = 0; nest_i_37513 < (int64_t) 28; nest_i_37513++) {
                    ((double *) mem_36338)[nest_i_37512 * (int64_t) 28 + nest_i_37513] = 0.0;
                }
            }
            
            bool acc_cert_p_32507;
            
            for (int64_t i_33650 = 0; i_33650 < (int64_t) 14; i_33650++) {
                int64_t i_32466 = mul64((int64_t) 2, i_33650);
                
                for (int64_t i_33648 = 0; i_33648 < (int64_t) 14; i_33648++) {
                    double map_adj_p_32511 = ((double *) mem_36323)[i_33661 * (int64_t) 196 + i_33650 * (int64_t) 14 + i_33648];
                    int64_t i_32513 = mul64((int64_t) 2, i_33648);
                    double binop_x_adj_32538 = 0.25 * map_adj_p_32511;
                    
                    for (int64_t i_33646 = 0; i_33646 < (int64_t) 2; i_33646++) {
                        int64_t index_32552 = i_32466 + i_33646;
                        
                        for (int64_t i_33644 = 0; i_33644 < (int64_t) 2; i_33644++) {
                            int64_t index_32553 = i_32513 + i_33644;
                            
                            // UpdateAcc
                            {
                                int64_t idx_32505 = index_32552;
                                int64_t idx_32506 = index_32553;
                                
                                if ((sle64((int64_t) 0, index_32552) && slt64(index_32552, (int64_t) 28)) && (sle64((int64_t) 0, index_32553) && slt64(index_32553, (int64_t) 28))) {
                                    double x_32502;
                                    double y_32503;
                                    
                                    x_32502 = ((double *) mem_36338)[index_32552 * (int64_t) 28 + index_32553];
                                    y_32503 = binop_x_adj_32538;
                                    
                                    double binlam_res_32504 = x_32502 + y_32503;
                                    
                                    ((double *) mem_36338)[index_32552 * (int64_t) 28 + index_32553] = binlam_res_32504;
                                }
                            }
                        }
                    }
                }
            }
            
            int64_t binop_x_34355 = (int64_t) 784 * i_33661;
            
            for (int64_t i_33657 = 0; i_33657 < (int64_t) 28; i_33657++) {
                int64_t binop_y_34356 = (int64_t) 28 * i_33657;
                int64_t binop_x_34357 = binop_x_34355 + binop_y_34356;
                
                for (int64_t i_33653 = 0; i_33653 < (int64_t) 28; i_33653++) {
                    int64_t binop_x_34358 = i_33653 + binop_x_34357;
                    int64_t new_index_34359 = squot64(binop_x_34358, flat_dim_28947);
                    int64_t binop_y_34369 = flat_dim_28947 * new_index_34359;
                    int64_t new_index_34370 = binop_x_34358 - binop_y_34369;
                    double x_32654 = ((double *) mem_35480)[new_index_34359 * flat_dim_28947 + new_index_34370];
                    double map_adj_p_32653 = ((double *) mem_36338)[i_33657 * (int64_t) 28 + i_33653];
                    bool convop_x_32660 = 0.0 < x_32654;
                    int32_t convop_x_32661 = btoi_bool_i32(convop_x_32660);
                    double binop_y_32662 = sitofp_i32_f64(convop_x_32661);
                    double binop_y_adj_32663 = map_adj_p_32653 * binop_y_32662;
                    
                    ((double *) mem_36325)[i_33661 * (int64_t) 784 + i_33657 * (int64_t) 28 + i_33653] = binop_y_adj_32663;
                }
            }
        }
        if (memblock_alloc(ctx, &mem_36411, (int64_t) 48, "mem_36411")) {
            err = 1;
            goto cleanup;
        }
        for (int64_t i_33673 = 0; i_33673 < (int64_t) 6; i_33673++) {
            double x_32811 = ((double *) mem_param_35295.mem)[i_33673];
            
            for (int64_t nest_i_37522 = 0; nest_i_37522 < (int64_t) 25; nest_i_37522++) {
                ((double *) mem_36428)[nest_i_37522] = 0.0;
            }
            
            int64_t binop_x_34327 = flat_dim_28947 * i_33673;
            double x_contrib_sum_33274;
            double redout_33663 = 0.0;
            
            for (int64_t i_33664 = 0; i_33664 < flat_dim_28947; i_33664++) {
                int64_t binop_x_34328 = i_33664 + binop_x_34327;
                int64_t new_index_34329 = squot64(binop_x_34328, (int64_t) 784);
                int64_t binop_y_34335 = (int64_t) 784 * new_index_34329;
                int64_t binop_x_34336 = binop_x_34328 - binop_y_34335;
                int64_t new_index_34337 = squot64(binop_x_34336, (int64_t) 28);
                int64_t binop_y_34353 = (int64_t) 28 * new_index_34337;
                int64_t new_index_34354 = binop_x_34336 - binop_y_34353;
                double x_32818 = ((double *) mem_36325)[new_index_34329 * (int64_t) 784 + new_index_34337 * (int64_t) 28 + new_index_34354];
                double binlam_res_32817 = x_32818 + redout_33663;
                double redout_tmp_37523 = binlam_res_32817;
                
                redout_33663 = redout_tmp_37523;
            }
            x_contrib_sum_33274 = redout_33663;
            
            bool acc_cert_p_32824;
            
            for (int64_t i_33668 = 0; i_33668 < flat_dim_28947; i_33668++) {
                int64_t binop_x_34265 = i_33668 + binop_x_34327;
                int64_t new_index_34266 = squot64(binop_x_34265, (int64_t) 784);
                int64_t binop_y_34272 = (int64_t) 784 * new_index_34266;
                int64_t binop_x_34273 = binop_x_34265 - binop_y_34272;
                int64_t new_index_34274 = squot64(binop_x_34273, (int64_t) 28);
                int64_t binop_y_34290 = (int64_t) 28 * new_index_34274;
                int64_t new_index_34291 = binop_x_34273 - binop_y_34290;
                double map_adj_p_32828 = ((double *) mem_36325)[new_index_34266 * (int64_t) 784 + new_index_34274 * (int64_t) 28 + new_index_34291];
                int64_t binop_x_34292 = (int64_t) 25 * i_33668;
                
                for (int64_t i_33666 = 0; i_33666 < (int64_t) 25; i_33666++) {
                    int64_t binop_x_34293 = i_33666 + binop_x_34292;
                    int64_t new_index_34295 = squot64(binop_x_34293, binop_y_34785);
                    int64_t binop_y_34303 = new_index_34295 * binop_y_34785;
                    int64_t binop_x_34304 = binop_x_34293 - binop_y_34303;
                    int64_t new_index_34305 = squot64(binop_x_34304, (int64_t) 25);
                    int64_t binop_y_34325 = (int64_t) 25 * new_index_34305;
                    int64_t new_index_34326 = binop_x_34304 - binop_y_34325;
                    double x_33059 = ((double *) mem_35419)[new_index_34295 * binop_y_34785 + new_index_34305 * (int64_t) 25 + new_index_34326];
                    double binop_x_adj_33062 = map_adj_p_32828 * x_33059;
                    
                    // UpdateAcc
                    {
                        int64_t idx_32820 = i_33666;
                        
                        if (sle64((int64_t) 0, i_33666) && slt64(i_33666, (int64_t) 25)) {
                            double x_32821;
                            double y_32822;
                            
                            x_32821 = ((double *) mem_36428)[i_33666];
                            y_32822 = binop_x_adj_33062;
                            
                            double binlam_res_32823 = x_32821 + y_32822;
                            
                            ((double *) mem_36428)[i_33666] = binlam_res_32823;
                        }
                    }
                }
            }
            
            double arg_32840 = 0.1 * x_contrib_sum_33274;
            double defunc_0_f_res_32841 = x_32811 - arg_32840;
            
            ((double *) mem_36411.mem)[i_33673] = defunc_0_f_res_32841;
            if ((int64_t) 200 > 0)
                memmove(mem_36413 + i_33673 * (int64_t) 25 * (int64_t) 8, mem_36428 + (int64_t) 0, (int64_t) 200);
        }
        if (memblock_alloc(ctx, &mem_36443, (int64_t) 1200, "mem_36443")) {
            err = 1;
            goto cleanup;
        }
        for (int64_t i_33686 = 0; i_33686 < (int64_t) 6; i_33686++) {
            int64_t binop_x_34248 = (int64_t) 25 * i_33686;
            
            for (int64_t i_33682 = 0; i_33682 < (int64_t) 5; i_33682++) {
                int64_t binop_y_34249 = (int64_t) 5 * i_33682;
                int64_t binop_x_34250 = binop_x_34248 + binop_y_34249;
                
                for (int64_t i_33678 = 0; i_33678 < (int64_t) 5; i_33678++) {
                    double x_28211 = ((double *) mem_param_35290.mem)[i_33686 * (int64_t) 25 + i_33682 * (int64_t) 5 + i_33678];
                    int64_t binop_x_34251 = i_33678 + binop_x_34250;
                    int64_t new_index_34252 = squot64(binop_x_34251, (int64_t) 25);
                    int64_t binop_y_34262 = (int64_t) 25 * new_index_34252;
                    int64_t new_index_34263 = binop_x_34251 - binop_y_34262;
                    double x_28212 = ((double *) mem_36413)[new_index_34252 * (int64_t) 25 + new_index_34263];
                    double arg_28213 = 0.1 * x_28212;
                    double defunc_0_f_res_28214 = x_28211 - arg_28213;
                    
                    ((double *) mem_36459)[i_33682 * (int64_t) 5 + i_33678] = defunc_0_f_res_28214;
                }
            }
            for (int64_t nest_i_37529 = 0; nest_i_37529 < (int64_t) 1; nest_i_37529++) {
                if ((int64_t) 200 > 0)
                    memmove(mem_36443.mem + (i_33686 * (int64_t) 25 + nest_i_37529 * (int64_t) 25) * (int64_t) 8, mem_36459 + (int64_t) 0, (int64_t) 200);
            }
        }
        if (memblock_alloc(ctx, &mem_36515, (int64_t) 128, "mem_36515")) {
            err = 1;
            goto cleanup;
        }
        for (int64_t i_33690 = 0; i_33690 < (int64_t) 16; i_33690++) {
            double x_28260 = ((double *) mem_param_35317.mem)[i_33690];
            double x_28261 = ((double *) mem_36177)[i_33690];
            double arg_28262 = 0.1 * x_28261;
            double defunc_0_f_res_28263 = x_28260 - arg_28262;
            
            ((double *) mem_36515.mem)[i_33690] = defunc_0_f_res_28263;
        }
        if (memblock_alloc(ctx, &mem_36527, (int64_t) 384000, "mem_36527")) {
            err = 1;
            goto cleanup;
        }
        for (int64_t i_33698 = 0; i_33698 < (int64_t) 120; i_33698++) {
            for (int64_t i_33694 = 0; i_33694 < (int64_t) 400; i_33694++) {
                double x_28275 = ((double *) mem_param_35328.mem)[i_33698 * (int64_t) 400 + i_33694];
                double x_28276 = ((double *) mem_36053)[i_33698 * (int64_t) 400 + i_33694];
                double arg_28277 = 0.1 * x_28276;
                double defunc_0_f_res_28278 = x_28275 - arg_28277;
                
                ((double *) mem_36527.mem)[i_33698 * (int64_t) 400 + i_33694] = defunc_0_f_res_28278;
            }
        }
        if (memblock_alloc(ctx, &mem_36567, (int64_t) 960, "mem_36567")) {
            err = 1;
            goto cleanup;
        }
        for (int64_t i_33702 = 0; i_33702 < (int64_t) 120; i_33702++) {
            double x_28287 = ((double *) mem_param_35333.mem)[i_33702];
            double x_28288 = ((double *) mem_36051)[i_33702];
            double arg_28289 = 0.1 * x_28288;
            double defunc_0_f_res_28290 = x_28287 - arg_28289;
            
            ((double *) mem_36567.mem)[i_33702] = defunc_0_f_res_28290;
        }
        if (memblock_alloc(ctx, &mem_36579, (int64_t) 80640, "mem_36579")) {
            err = 1;
            goto cleanup;
        }
        for (int64_t i_33710 = 0; i_33710 < (int64_t) 84; i_33710++) {
            for (int64_t i_33706 = 0; i_33706 < (int64_t) 120; i_33706++) {
                double x_28302 = ((double *) mem_param_35344.mem)[i_33710 * (int64_t) 120 + i_33706];
                double x_28303 = ((double *) mem_36005)[i_33710 * (int64_t) 120 + i_33706];
                double arg_28304 = 0.1 * x_28303;
                double defunc_0_f_res_28305 = x_28302 - arg_28304;
                
                ((double *) mem_36579.mem)[i_33710 * (int64_t) 120 + i_33706] = defunc_0_f_res_28305;
            }
        }
        if (memblock_alloc(ctx, &mem_36619, (int64_t) 672, "mem_36619")) {
            err = 1;
            goto cleanup;
        }
        for (int64_t i_33714 = 0; i_33714 < (int64_t) 84; i_33714++) {
            double x_28314 = ((double *) mem_param_35349.mem)[i_33714];
            double x_28315 = ((double *) mem_36003)[i_33714];
            double arg_28316 = 0.1 * x_28315;
            double defunc_0_f_res_28317 = x_28314 - arg_28316;
            
            ((double *) mem_36619.mem)[i_33714] = defunc_0_f_res_28317;
        }
        if (memblock_alloc(ctx, &mem_36631, (int64_t) 6720, "mem_36631")) {
            err = 1;
            goto cleanup;
        }
        for (int64_t i_33722 = 0; i_33722 < (int64_t) 10; i_33722++) {
            for (int64_t i_33718 = 0; i_33718 < (int64_t) 84; i_33718++) {
                double x_28329 = ((double *) mem_param_35360.mem)[i_33722 * (int64_t) 84 + i_33718];
                double x_28330 = ((double *) mem_35957)[i_33722 * (int64_t) 84 + i_33718];
                double arg_28331 = 0.1 * x_28330;
                double defunc_0_f_res_28332 = x_28329 - arg_28331;
                
                ((double *) mem_36631.mem)[i_33722 * (int64_t) 84 + i_33718] = defunc_0_f_res_28332;
            }
        }
        if (memblock_alloc(ctx, &mem_36671, (int64_t) 80, "mem_36671")) {
            err = 1;
            goto cleanup;
        }
        for (int64_t i_33726 = 0; i_33726 < (int64_t) 10; i_33726++) {
            double x_28341 = ((double *) mem_param_35365.mem)[i_33726];
            double x_28342 = ((double *) mem_35955)[i_33726];
            double arg_28343 = 0.1 * x_28342;
            double defunc_0_f_res_28344 = x_28341 - arg_28343;
            
            ((double *) mem_36671.mem)[i_33726] = defunc_0_f_res_28344;
        }
        if (memblock_set(ctx, &mem_param_tmp_37400, &mem_36443, "mem_36443") != 0)
            return 1;
        if (memblock_set(ctx, &mem_param_tmp_37401, &mem_36411, "mem_36411") != 0)
            return 1;
        if (memblock_set(ctx, &mem_param_tmp_37402, &mem_36179, "mem_36179") != 0)
            return 1;
        if (memblock_set(ctx, &mem_param_tmp_37403, &mem_36515, "mem_36515") != 0)
            return 1;
        if (memblock_set(ctx, &mem_param_tmp_37404, &mem_36527, "mem_36527") != 0)
            return 1;
        if (memblock_set(ctx, &mem_param_tmp_37405, &mem_36567, "mem_36567") != 0)
            return 1;
        if (memblock_set(ctx, &mem_param_tmp_37406, &mem_36579, "mem_36579") != 0)
            return 1;
        if (memblock_set(ctx, &mem_param_tmp_37407, &mem_36619, "mem_36619") != 0)
            return 1;
        if (memblock_set(ctx, &mem_param_tmp_37408, &mem_36631, "mem_36631") != 0)
            return 1;
        if (memblock_set(ctx, &mem_param_tmp_37409, &mem_36671, "mem_36671") != 0)
            return 1;
        if (memblock_set(ctx, &mem_param_35290, &mem_param_tmp_37400, "mem_param_tmp_37400") != 0)
            return 1;
        if (memblock_set(ctx, &mem_param_35295, &mem_param_tmp_37401, "mem_param_tmp_37401") != 0)
            return 1;
        if (memblock_set(ctx, &mem_param_35312, &mem_param_tmp_37402, "mem_param_tmp_37402") != 0)
            return 1;
        if (memblock_set(ctx, &mem_param_35317, &mem_param_tmp_37403, "mem_param_tmp_37403") != 0)
            return 1;
        if (memblock_set(ctx, &mem_param_35328, &mem_param_tmp_37404, "mem_param_tmp_37404") != 0)
            return 1;
        if (memblock_set(ctx, &mem_param_35333, &mem_param_tmp_37405, "mem_param_tmp_37405") != 0)
            return 1;
        if (memblock_set(ctx, &mem_param_35344, &mem_param_tmp_37406, "mem_param_tmp_37406") != 0)
            return 1;
        if (memblock_set(ctx, &mem_param_35349, &mem_param_tmp_37407, "mem_param_tmp_37407") != 0)
            return 1;
        if (memblock_set(ctx, &mem_param_35360, &mem_param_tmp_37408, "mem_param_tmp_37408") != 0)
            return 1;
        if (memblock_set(ctx, &mem_param_35365, &mem_param_tmp_37409, "mem_param_tmp_37409") != 0)
            return 1;
    }
    if (memblock_set(ctx, &ext_mem_36758, &mem_param_35290, "mem_param_35290") != 0)
        return 1;
    if (memblock_set(ctx, &ext_mem_36757, &mem_param_35295, "mem_param_35295") != 0)
        return 1;
    if (memblock_set(ctx, &ext_mem_36756, &mem_param_35312, "mem_param_35312") != 0)
        return 1;
    if (memblock_set(ctx, &ext_mem_36755, &mem_param_35317, "mem_param_35317") != 0)
        return 1;
    if (memblock_set(ctx, &ext_mem_36754, &mem_param_35328, "mem_param_35328") != 0)
        return 1;
    if (memblock_set(ctx, &ext_mem_36753, &mem_param_35333, "mem_param_35333") != 0)
        return 1;
    if (memblock_set(ctx, &ext_mem_36752, &mem_param_35344, "mem_param_35344") != 0)
        return 1;
    if (memblock_set(ctx, &ext_mem_36751, &mem_param_35349, "mem_param_35349") != 0)
        return 1;
    if (memblock_set(ctx, &ext_mem_36750, &mem_param_35360, "mem_param_35360") != 0)
        return 1;
    if (memblock_set(ctx, &ext_mem_36749, &mem_param_35365, "mem_param_35365") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_35167, "mem_35167") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_35191, "mem_35191") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_35215, "mem_35215") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_35239, "mem_35239") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_35263, "mem_35263") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_35275, "mem_35275") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_35297, "mem_35297") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_35319, "mem_35319") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_35335, "mem_35335") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_35351, "mem_35351") != 0)
        return 1;
    
    bool y_28345 = slt64((int64_t) 300, dz2080U_26089);
    bool index_certs_28346;
    
    if (!y_28345) {
        set_error(ctx, msgprintf("Error: %s%lld%s%lld%s\n\nBacktrace:\n%s", "Index [", (long long) (int64_t) 300, "] out of bounds for array of shape [", (long long) dz2080U_26089, "].", "-> #0  cnn_playground.fut:20:32-43\n   #1  cnn_playground.fut:6:1-21:24\n"));
        err = FUTHARK_PROGRAM_ERROR;
        goto cleanup;
    }
    if (mem_36762_cached_sizze_37636 < bytes_36761) {
        err = lexical_realloc(ctx, &mem_36762, &mem_36762_cached_sizze_37636, bytes_36761);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    for (int64_t i_33734 = 0; i_33734 < arg_28836; i_33734++) {
        bool cond_29186 = slt64(i_33734, (int64_t) 2);
        bool cond_f_res_29187 = sle64(arg_28862, i_33734);
        bool x_29188 = !cond_29186;
        bool y_29189 = cond_f_res_29187 && x_29188;
        bool cond_29190 = cond_29186 || y_29189;
        bool x_29191 = !cond_29190;
        
        for (int64_t i_33730 = 0; i_33730 < arg_28840; i_33730++) {
            bool cond_f_res_29194 = slt64(i_33730, (int64_t) 2);
            bool y_29195 = x_29191 && cond_f_res_29194;
            bool cond_29196 = cond_29190 || y_29195;
            bool cond_f_res_29197 = sle64(arg_28863, i_33730);
            bool x_29198 = !cond_29196;
            bool y_29199 = cond_f_res_29197 && x_29198;
            bool cond_29200 = cond_29196 || y_29199;
            double defunc_0_f_res_29201;
            
            if (cond_29200 == 1) {
                defunc_0_f_res_29201 = 0.0;
            } else {
                int64_t i_29202 = sub64(i_33734, (int64_t) 2);
                int64_t i_29206 = sub64(i_33730, (int64_t) 2);
                double defunc_0_f_res_f_res_29212 = ((double *) x_train_mem_35080.mem)[(int64_t) 300 * (dz2082U_26091 * dz2081U_26090) + i_29202 * dz2082U_26091 + i_29206];
                
                defunc_0_f_res_29201 = defunc_0_f_res_f_res_29212;
            }
            ((double *) mem_36762)[i_33734 * arg_28840 + i_33730] = defunc_0_f_res_29201;
        }
    }
    if (mem_36807_cached_sizze_37637 < bytes_36761) {
        err = lexical_realloc(ctx, &mem_36807, &mem_36807_cached_sizze_37637, bytes_36761);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    for (int64_t nest_i_37542 = 0; nest_i_37542 < (int64_t) 1; nest_i_37542++) {
        if (arg_28836 * arg_28840 * (int64_t) 8 > 0)
            memmove(mem_36807 + nest_i_37542 * (arg_28840 * arg_28836) * (int64_t) 8, mem_36762 + (int64_t) 0, arg_28836 * arg_28840 * (int64_t) 8);
    }
    if (mem_36812_cached_sizze_37638 < bytes_36811) {
        err = lexical_realloc(ctx, &mem_36812, &mem_36812_cached_sizze_37638, bytes_36811);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    for (int64_t i_33742 = 0; i_33742 < new_n_28838; i_33742++) {
        int64_t j_29226 = add64((int64_t) 5, i_33742);
        int64_t i_p_m_t_s_29227 = add64((int64_t) 4, i_33742);
        bool zzero_leq_i_p_m_t_s_29228 = sle64((int64_t) 0, i_p_m_t_s_29227);
        bool i_p_m_t_s_leq_w_29229 = slt64(i_p_m_t_s_29227, arg_28836);
        bool i_lte_j_29231 = sle64(i_33742, j_29226);
        bool y_29233 = zzero_leq_i_p_m_t_s_29228 && i_p_m_t_s_leq_w_29229;
        bool y_29234 = i_lte_j_29231 && y_29233;
        
        for (int64_t i_33738 = 0; i_33738 < new_m_28842; i_33738++) {
            int64_t j_29239 = add64((int64_t) 5, i_33738);
            int64_t i_p_m_t_s_29240 = add64((int64_t) 4, i_33738);
            bool zzero_leq_i_p_m_t_s_29241 = sle64((int64_t) 0, i_p_m_t_s_29240);
            bool i_p_m_t_s_leq_w_29242 = slt64(i_p_m_t_s_29240, arg_28840);
            bool i_lte_j_29244 = sle64(i_33738, j_29239);
            bool y_29246 = zzero_leq_i_p_m_t_s_29241 && i_p_m_t_s_leq_w_29242;
            bool y_29247 = i_lte_j_29244 && y_29246;
            bool index_ok_29250 = y_29234 && y_29247;
            bool index_certs_29251;
            
            if (!index_ok_29250) {
                set_error(ctx, msgprintf("Error: %s%lld%s%lld%s%lld%s%lld%s%lld%s%lld%s\n\nBacktrace:\n%s", "Index [", (long long) i_33742, ":", (long long) j_29226, ", ", (long long) i_33738, ":", (long long) j_29239, "] out of bounds for array of shape [", (long long) arg_28836, "][", (long long) arg_28840, "].", "-> #0  ../layers/conv2d.fut:13:90-124\n   #1  ../layers/conv2d.fut:13:144-146\n   #2  /prelude/soacs.fut:59:9-10\n   #3  /prelude/array.fut:200:10-17\n   #4  /prelude/functional.fut:39:61-65\n   #5  /prelude/soacs.fut:59:9-10\n   #6  /prelude/array.fut:208:27-34\n   #7  ../layers/conv2d.fut:13:50-162\n   #8  ../layers/conv2d.fut:26:17-54\n"));
                err = FUTHARK_PROGRAM_ERROR;
                goto cleanup;
            }
            for (int64_t i_37545 = 0; i_37545 < (int64_t) 25; i_37545++) {
                double tmp_37546 = ((double *) mem_36807)[arg_28840 * i_33742 + i_33738 + (squot64(i_37545, (int64_t) 25) * (arg_28840 * arg_28836) + squot64(i_37545 - squot64(i_37545, (int64_t) 25) * (int64_t) 25, (int64_t) 5) * arg_28840 + (i_37545 - squot64(i_37545, (int64_t) 25) * (int64_t) 25 - squot64(i_37545 - squot64(i_37545, (int64_t) 25) * (int64_t) 25, (int64_t) 5) * (int64_t) 5))];
                
                ((double *) mem_36812)[i_33742 * binop_y_34785 + i_33738 * (int64_t) 25 + i_37545] = tmp_37546;
            }
        }
    }
    if (mem_36873_cached_sizze_37639 < bytes_35479) {
        err = lexical_realloc(ctx, &mem_36873, &mem_36873_cached_sizze_37639, bytes_35479);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    for (int64_t i_33752 = 0; i_33752 < (int64_t) 6; i_33752++) {
        double x_30231 = ((double *) ext_mem_36757.mem)[i_33752];
        int64_t binop_x_34147 = (int64_t) 25 * i_33752;
        
        for (int64_t i_33748 = 0; i_33748 < flat_dim_28947; i_33748++) {
            int64_t binop_x_34213 = (int64_t) 25 * i_33748;
            double defunc_0_reduce_res_33312;
            double redout_33744 = 0.0;
            
            for (int64_t i_33745 = 0; i_33745 < (int64_t) 25; i_33745++) {
                int64_t binop_x_34148 = i_33745 + binop_x_34147;
                int64_t new_index_34149 = squot64(binop_x_34148, (int64_t) 25);
                int64_t binop_y_34155 = (int64_t) 25 * new_index_34149;
                int64_t binop_x_34156 = binop_x_34148 - binop_y_34155;
                int64_t new_index_34157 = squot64(binop_x_34156, (int64_t) 25);
                int64_t binop_y_34173 = (int64_t) 25 * new_index_34157;
                int64_t binop_x_34174 = binop_x_34156 - binop_y_34173;
                int64_t new_index_34175 = squot64(binop_x_34174, (int64_t) 5);
                int64_t binop_y_34211 = (int64_t) 5 * new_index_34175;
                int64_t new_index_34212 = binop_x_34174 - binop_y_34211;
                double x_31518 = ((double *) ext_mem_36758.mem)[new_index_34149 * (int64_t) 25 + new_index_34157 * (int64_t) 25 + new_index_34175 * (int64_t) 5 + new_index_34212];
                int64_t binop_x_34214 = i_33745 + binop_x_34213;
                int64_t new_index_34216 = squot64(binop_x_34214, binop_y_34785);
                int64_t binop_y_34224 = new_index_34216 * binop_y_34785;
                int64_t binop_x_34225 = binop_x_34214 - binop_y_34224;
                int64_t new_index_34226 = squot64(binop_x_34225, (int64_t) 25);
                int64_t binop_y_34246 = (int64_t) 25 * new_index_34226;
                int64_t new_index_34247 = binop_x_34225 - binop_y_34246;
                double x_31519 = ((double *) mem_36812)[new_index_34216 * binop_y_34785 + new_index_34226 * (int64_t) 25 + new_index_34247];
                double defunc_0_f_res_31520 = x_31518 * x_31519;
                double defunc_0_op_res_31513 = defunc_0_f_res_31520 + redout_33744;
                double redout_tmp_37549 = defunc_0_op_res_31513;
                
                redout_33744 = redout_tmp_37549;
            }
            defunc_0_reduce_res_33312 = redout_33744;
            
            double defunc_0_f_res_31516 = x_30231 + defunc_0_reduce_res_33312;
            
            ((double *) mem_36873)[i_33752 * flat_dim_28947 + i_33748] = defunc_0_f_res_31516;
        }
    }
    if (memblock_unref(ctx, &ext_mem_36757, "ext_mem_36757") != 0)
        return 1;
    if (memblock_unref(ctx, &ext_mem_36758, "ext_mem_36758") != 0)
        return 1;
    
    bool empty_or_match_cert_28355;
    
    if (!match_28110) {
        set_error(ctx, msgprintf("Error: %s%lld%s%lld%s%lld%s%lld%s%lld%s%lld%s\n\nBacktrace:\n%s", "Value of (core language) shape (", (long long) (int64_t) 6, ", ", (long long) new_n_28838, ", ", (long long) new_m_28842, ") cannot match shape of type `[", (long long) (int64_t) 6, "][", (long long) (int64_t) 28, "][", (long long) (int64_t) 28, "]f64`.", "-> #0  ../lenet/lenet.fut:10:37-82\n   #1  cnn_playground.fut:20:18-62\n   #2  cnn_playground.fut:6:1-21:24\n"));
        err = FUTHARK_PROGRAM_ERROR;
        goto cleanup;
    }
    if (mem_36916_cached_sizze_37640 < (int64_t) 9408) {
        err = lexical_realloc(ctx, &mem_36916, &mem_36916_cached_sizze_37640, (int64_t) 9408);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_36929_cached_sizze_37641 < (int64_t) 6272) {
        err = lexical_realloc(ctx, &mem_36929, &mem_36929_cached_sizze_37641, (int64_t) 6272);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    for (int64_t i_33774 = 0; i_33774 < (int64_t) 6; i_33774++) {
        int64_t binop_x_34131 = (int64_t) 784 * i_33774;
        
        for (int64_t i_33760 = 0; i_33760 < (int64_t) 28; i_33760++) {
            int64_t binop_y_34132 = (int64_t) 28 * i_33760;
            int64_t binop_x_34133 = binop_x_34131 + binop_y_34132;
            
            for (int64_t i_33756 = 0; i_33756 < (int64_t) 28; i_33756++) {
                int64_t binop_x_34134 = i_33756 + binop_x_34133;
                int64_t new_index_34135 = squot64(binop_x_34134, flat_dim_28947);
                int64_t binop_y_34145 = flat_dim_28947 * new_index_34135;
                int64_t new_index_34146 = binop_x_34134 - binop_y_34145;
                double x_30190 = ((double *) mem_36873)[new_index_34135 * flat_dim_28947 + new_index_34146];
                double max_res_30191 = fmax64(0.0, x_30190);
                
                ((double *) mem_36929)[i_33760 * (int64_t) 28 + i_33756] = max_res_30191;
            }
        }
        for (int64_t i_33770 = 0; i_33770 < (int64_t) 14; i_33770++) {
            int64_t i_30195 = mul64((int64_t) 2, i_33770);
            int64_t j_30196 = add64((int64_t) 2, i_30195);
            int64_t i_p_m_t_s_30197 = add64((int64_t) 1, i_30195);
            bool zzero_leq_i_p_m_t_s_30198 = sle64((int64_t) 0, i_p_m_t_s_30197);
            bool i_p_m_t_s_leq_w_30199 = slt64(i_p_m_t_s_30197, (int64_t) 28);
            bool zzero_lte_i_30200 = sle64((int64_t) 0, i_30195);
            bool i_lte_j_30201 = sle64(i_30195, j_30196);
            bool y_30202 = i_p_m_t_s_leq_w_30199 && zzero_lte_i_30200;
            bool y_30203 = zzero_leq_i_p_m_t_s_30198 && y_30202;
            bool y_30204 = i_lte_j_30201 && y_30203;
            bool forwards_ok_30205 = zzero_lte_i_30200 && y_30204;
            
            for (int64_t i_33766 = 0; i_33766 < (int64_t) 14; i_33766++) {
                int64_t i_30208 = mul64((int64_t) 2, i_33766);
                int64_t j_30209 = add64((int64_t) 2, i_30208);
                int64_t i_p_m_t_s_30210 = add64((int64_t) 1, i_30208);
                bool zzero_leq_i_p_m_t_s_30211 = sle64((int64_t) 0, i_p_m_t_s_30210);
                bool i_p_m_t_s_leq_w_30212 = slt64(i_p_m_t_s_30210, (int64_t) 28);
                bool zzero_lte_i_30213 = sle64((int64_t) 0, i_30208);
                bool i_lte_j_30214 = sle64(i_30208, j_30209);
                bool y_30215 = i_p_m_t_s_leq_w_30212 && zzero_lte_i_30213;
                bool y_30216 = zzero_leq_i_p_m_t_s_30211 && y_30215;
                bool y_30217 = i_lte_j_30214 && y_30216;
                bool forwards_ok_30218 = zzero_lte_i_30213 && y_30217;
                bool index_ok_30219 = forwards_ok_30205 && forwards_ok_30218;
                bool index_certs_30220;
                
                if (!index_ok_30219) {
                    set_error(ctx, msgprintf("Error: %s%lld%s%lld%s%lld%s%lld%s%lld%s%lld%s\n\nBacktrace:\n%s", "Index [", (long long) i_30195, ":", (long long) j_30196, ", ", (long long) i_30208, ":", (long long) j_30209, "] out of bounds for array of shape [", (long long) (int64_t) 28, "][", (long long) (int64_t) 28, "].", "-> #0  ../layers/avgpool.fut:7:18-80\n   #1  /prelude/soacs.fut:59:9-10\n   #2  /prelude/array.fut:200:10-17\n   #3  /prelude/functional.fut:39:61-65\n   #4  /prelude/soacs.fut:59:9-10\n   #5  /prelude/array.fut:208:27-34\n   #6  ../layers/avgpool.fut:6:29-8:49\n   #7  ../layers/avgpool.fut:8:73-76\n"));
                    err = FUTHARK_PROGRAM_ERROR;
                    goto cleanup;
                }
                
                double defunc_0_reduce_res_33315;
                double redout_33762 = 0.0;
                
                for (int64_t i_33763 = 0; i_33763 < (int64_t) 4; i_33763++) {
                    int64_t new_index_33867 = squot64(i_33763, (int64_t) 2);
                    int64_t binop_y_33869 = (int64_t) 2 * new_index_33867;
                    int64_t new_index_33870 = i_33763 - binop_y_33869;
                    int64_t slice_33871 = i_30195 + new_index_33867;
                    int64_t slice_33872 = i_30208 + new_index_33870;
                    double x_30227 = ((double *) mem_36929)[slice_33871 * (int64_t) 28 + slice_33872];
                    double defunc_0_op_res_30226 = x_30227 + redout_33762;
                    double redout_tmp_37555 = defunc_0_op_res_30226;
                    
                    redout_33762 = redout_tmp_37555;
                }
                defunc_0_reduce_res_33315 = redout_33762;
                
                double defunc_0_f_res_30228 = defunc_0_reduce_res_33315 / 4.0;
                
                ((double *) mem_36916)[i_33774 * (int64_t) 196 + i_33770 * (int64_t) 14 + i_33766] = defunc_0_f_res_30228;
            }
        }
    }
    if (mem_37040_cached_sizze_37642 < (int64_t) 120000) {
        err = lexical_realloc(ctx, &mem_37040, &mem_37040_cached_sizze_37642, (int64_t) 120000);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    for (int64_t i_33782 = 0; i_33782 < (int64_t) 10; i_33782++) {
        int64_t j_29385 = add64((int64_t) 5, i_33782);
        int64_t i_p_m_t_s_29386 = add64((int64_t) 4, i_33782);
        bool zzero_leq_i_p_m_t_s_29387 = sle64((int64_t) 0, i_p_m_t_s_29386);
        bool i_p_m_t_s_leq_w_29388 = slt64(i_p_m_t_s_29386, (int64_t) 14);
        bool i_lte_j_29390 = sle64(i_33782, j_29385);
        bool y_29392 = zzero_leq_i_p_m_t_s_29387 && i_p_m_t_s_leq_w_29388;
        bool y_29393 = i_lte_j_29390 && y_29392;
        
        for (int64_t i_33778 = 0; i_33778 < (int64_t) 10; i_33778++) {
            int64_t j_29398 = add64((int64_t) 5, i_33778);
            int64_t i_p_m_t_s_29399 = add64((int64_t) 4, i_33778);
            bool zzero_leq_i_p_m_t_s_29400 = sle64((int64_t) 0, i_p_m_t_s_29399);
            bool i_p_m_t_s_leq_w_29401 = slt64(i_p_m_t_s_29399, (int64_t) 14);
            bool i_lte_j_29403 = sle64(i_33778, j_29398);
            bool y_29405 = zzero_leq_i_p_m_t_s_29400 && i_p_m_t_s_leq_w_29401;
            bool y_29406 = i_lte_j_29403 && y_29405;
            bool index_ok_29409 = y_29393 && y_29406;
            bool index_certs_29410;
            
            if (!index_ok_29409) {
                set_error(ctx, msgprintf("Error: %s%lld%s%lld%s%lld%s%lld%s%lld%s%lld%s\n\nBacktrace:\n%s", "Index [", (long long) i_33782, ":", (long long) j_29385, ", ", (long long) i_33778, ":", (long long) j_29398, "] out of bounds for array of shape [", (long long) (int64_t) 14, "][", (long long) (int64_t) 14, "].", "-> #0  ../layers/conv2d.fut:13:90-124\n   #1  ../layers/conv2d.fut:13:144-146\n   #2  /prelude/soacs.fut:59:9-10\n   #3  /prelude/array.fut:200:10-17\n   #4  /prelude/functional.fut:39:61-65\n   #5  /prelude/soacs.fut:59:9-10\n   #6  /prelude/array.fut:208:27-34\n   #7  ../layers/conv2d.fut:13:50-162\n   #8  ../layers/conv2d.fut:26:17-54\n"));
                err = FUTHARK_PROGRAM_ERROR;
                goto cleanup;
            }
            for (int64_t i_37558 = 0; i_37558 < (int64_t) 150; i_37558++) {
                double tmp_37559 = ((double *) mem_36916)[(int64_t) 14 * i_33782 + i_33778 + (squot64(i_37558, (int64_t) 25) * (int64_t) 196 + squot64(i_37558 - squot64(i_37558, (int64_t) 25) * (int64_t) 25, (int64_t) 5) * (int64_t) 14 + (i_37558 - squot64(i_37558, (int64_t) 25) * (int64_t) 25 - squot64(i_37558 - squot64(i_37558, (int64_t) 25) * (int64_t) 25, (int64_t) 5) * (int64_t) 5))];
                
                ((double *) mem_37040)[i_33782 * (int64_t) 1500 + i_33778 * (int64_t) 150 + i_37558] = tmp_37559;
            }
        }
    }
    if (mem_37092_cached_sizze_37643 < (int64_t) 12800) {
        err = lexical_realloc(ctx, &mem_37092, &mem_37092_cached_sizze_37643, (int64_t) 12800);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    for (int64_t i_33792 = 0; i_33792 < (int64_t) 16; i_33792++) {
        double x_30169 = ((double *) ext_mem_36755.mem)[i_33792];
        int64_t binop_x_34037 = (int64_t) 150 * i_33792;
        
        for (int64_t i_33788 = 0; i_33788 < (int64_t) 100; i_33788++) {
            int64_t binop_x_34103 = (int64_t) 150 * i_33788;
            double defunc_0_reduce_res_33321;
            double redout_33784 = 0.0;
            
            for (int64_t i_33785 = 0; i_33785 < (int64_t) 150; i_33785++) {
                int64_t binop_x_34038 = i_33785 + binop_x_34037;
                int64_t new_index_34039 = squot64(binop_x_34038, (int64_t) 150);
                int64_t binop_y_34045 = (int64_t) 150 * new_index_34039;
                int64_t binop_x_34046 = binop_x_34038 - binop_y_34045;
                int64_t new_index_34047 = squot64(binop_x_34046, (int64_t) 25);
                int64_t binop_y_34063 = (int64_t) 25 * new_index_34047;
                int64_t binop_x_34064 = binop_x_34046 - binop_y_34063;
                int64_t new_index_34065 = squot64(binop_x_34064, (int64_t) 5);
                int64_t binop_y_34101 = (int64_t) 5 * new_index_34065;
                int64_t new_index_34102 = binop_x_34064 - binop_y_34101;
                double x_31546 = ((double *) ext_mem_36756.mem)[new_index_34039 * (int64_t) 150 + new_index_34047 * (int64_t) 25 + new_index_34065 * (int64_t) 5 + new_index_34102];
                int64_t binop_x_34104 = i_33785 + binop_x_34103;
                int64_t new_index_34105 = squot64(binop_x_34104, (int64_t) 1500);
                int64_t binop_y_34111 = (int64_t) 1500 * new_index_34105;
                int64_t binop_x_34112 = binop_x_34104 - binop_y_34111;
                int64_t new_index_34113 = squot64(binop_x_34112, (int64_t) 150);
                int64_t binop_y_34129 = (int64_t) 150 * new_index_34113;
                int64_t new_index_34130 = binop_x_34112 - binop_y_34129;
                double x_31547 = ((double *) mem_37040)[new_index_34105 * (int64_t) 1500 + new_index_34113 * (int64_t) 150 + new_index_34130];
                double defunc_0_f_res_31548 = x_31546 * x_31547;
                double defunc_0_op_res_31541 = defunc_0_f_res_31548 + redout_33784;
                double redout_tmp_37562 = defunc_0_op_res_31541;
                
                redout_33784 = redout_tmp_37562;
            }
            defunc_0_reduce_res_33321 = redout_33784;
            
            double defunc_0_f_res_31544 = x_30169 + defunc_0_reduce_res_33321;
            
            ((double *) mem_37092)[i_33792 * (int64_t) 100 + i_33788] = defunc_0_f_res_31544;
        }
    }
    if (memblock_unref(ctx, &ext_mem_36755, "ext_mem_36755") != 0)
        return 1;
    if (memblock_unref(ctx, &ext_mem_36756, "ext_mem_36756") != 0)
        return 1;
    if (mem_37132_cached_sizze_37644 < (int64_t) 3200) {
        err = lexical_realloc(ctx, &mem_37132, &mem_37132_cached_sizze_37644, (int64_t) 3200);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_37145_cached_sizze_37645 < (int64_t) 800) {
        err = lexical_realloc(ctx, &mem_37145, &mem_37145_cached_sizze_37645, (int64_t) 800);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    for (int64_t i_33814 = 0; i_33814 < (int64_t) 16; i_33814++) {
        int64_t binop_x_34021 = (int64_t) 100 * i_33814;
        
        for (int64_t i_33800 = 0; i_33800 < (int64_t) 10; i_33800++) {
            int64_t binop_y_34022 = (int64_t) 10 * i_33800;
            int64_t binop_x_34023 = binop_x_34021 + binop_y_34022;
            
            for (int64_t i_33796 = 0; i_33796 < (int64_t) 10; i_33796++) {
                int64_t binop_x_34024 = i_33796 + binop_x_34023;
                int64_t new_index_34025 = squot64(binop_x_34024, (int64_t) 100);
                int64_t binop_y_34035 = (int64_t) 100 * new_index_34025;
                int64_t new_index_34036 = binop_x_34024 - binop_y_34035;
                double x_30128 = ((double *) mem_37092)[new_index_34025 * (int64_t) 100 + new_index_34036];
                double max_res_30129 = fmax64(0.0, x_30128);
                
                ((double *) mem_37145)[i_33800 * (int64_t) 10 + i_33796] = max_res_30129;
            }
        }
        for (int64_t i_33810 = 0; i_33810 < (int64_t) 5; i_33810++) {
            int64_t i_30133 = mul64((int64_t) 2, i_33810);
            int64_t j_30134 = add64((int64_t) 2, i_30133);
            int64_t i_p_m_t_s_30135 = add64((int64_t) 1, i_30133);
            bool zzero_leq_i_p_m_t_s_30136 = sle64((int64_t) 0, i_p_m_t_s_30135);
            bool i_p_m_t_s_leq_w_30137 = slt64(i_p_m_t_s_30135, (int64_t) 10);
            bool zzero_lte_i_30138 = sle64((int64_t) 0, i_30133);
            bool i_lte_j_30139 = sle64(i_30133, j_30134);
            bool y_30140 = i_p_m_t_s_leq_w_30137 && zzero_lte_i_30138;
            bool y_30141 = zzero_leq_i_p_m_t_s_30136 && y_30140;
            bool y_30142 = i_lte_j_30139 && y_30141;
            bool forwards_ok_30143 = zzero_lte_i_30138 && y_30142;
            
            for (int64_t i_33806 = 0; i_33806 < (int64_t) 5; i_33806++) {
                int64_t i_30146 = mul64((int64_t) 2, i_33806);
                int64_t j_30147 = add64((int64_t) 2, i_30146);
                int64_t i_p_m_t_s_30148 = add64((int64_t) 1, i_30146);
                bool zzero_leq_i_p_m_t_s_30149 = sle64((int64_t) 0, i_p_m_t_s_30148);
                bool i_p_m_t_s_leq_w_30150 = slt64(i_p_m_t_s_30148, (int64_t) 10);
                bool zzero_lte_i_30151 = sle64((int64_t) 0, i_30146);
                bool i_lte_j_30152 = sle64(i_30146, j_30147);
                bool y_30153 = i_p_m_t_s_leq_w_30150 && zzero_lte_i_30151;
                bool y_30154 = zzero_leq_i_p_m_t_s_30149 && y_30153;
                bool y_30155 = i_lte_j_30152 && y_30154;
                bool forwards_ok_30156 = zzero_lte_i_30151 && y_30155;
                bool index_ok_30157 = forwards_ok_30143 && forwards_ok_30156;
                bool index_certs_30158;
                
                if (!index_ok_30157) {
                    set_error(ctx, msgprintf("Error: %s%lld%s%lld%s%lld%s%lld%s%lld%s%lld%s\n\nBacktrace:\n%s", "Index [", (long long) i_30133, ":", (long long) j_30134, ", ", (long long) i_30146, ":", (long long) j_30147, "] out of bounds for array of shape [", (long long) (int64_t) 10, "][", (long long) (int64_t) 10, "].", "-> #0  ../layers/avgpool.fut:7:18-80\n   #1  /prelude/soacs.fut:59:9-10\n   #2  /prelude/array.fut:200:10-17\n   #3  /prelude/functional.fut:39:61-65\n   #4  /prelude/soacs.fut:59:9-10\n   #5  /prelude/array.fut:208:27-34\n   #6  ../layers/avgpool.fut:6:29-8:49\n   #7  ../layers/avgpool.fut:8:73-76\n"));
                    err = FUTHARK_PROGRAM_ERROR;
                    goto cleanup;
                }
                
                double defunc_0_reduce_res_33324;
                double redout_33802 = 0.0;
                
                for (int64_t i_33803 = 0; i_33803 < (int64_t) 4; i_33803++) {
                    int64_t new_index_33853 = squot64(i_33803, (int64_t) 2);
                    int64_t binop_y_33855 = (int64_t) 2 * new_index_33853;
                    int64_t new_index_33856 = i_33803 - binop_y_33855;
                    int64_t slice_33857 = i_30133 + new_index_33853;
                    int64_t slice_33858 = i_30146 + new_index_33856;
                    double x_30165 = ((double *) mem_37145)[slice_33857 * (int64_t) 10 + slice_33858];
                    double defunc_0_op_res_30164 = x_30165 + redout_33802;
                    double redout_tmp_37568 = defunc_0_op_res_30164;
                    
                    redout_33802 = redout_tmp_37568;
                }
                defunc_0_reduce_res_33324 = redout_33802;
                
                double defunc_0_f_res_30166 = defunc_0_reduce_res_33324 / 4.0;
                
                ((double *) mem_37132)[i_33814 * (int64_t) 25 + i_33810 * (int64_t) 5 + i_33806] = defunc_0_f_res_30166;
            }
        }
    }
    if (mem_37256_cached_sizze_37646 < (int64_t) 960) {
        err = lexical_realloc(ctx, &mem_37256, &mem_37256_cached_sizze_37646, (int64_t) 960);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    for (int64_t i_33820 = 0; i_33820 < (int64_t) 120; i_33820++) {
        double x_30109 = ((double *) ext_mem_36753.mem)[i_33820];
        double defunc_0_reduce_res_33329;
        double redout_33816 = 0.0;
        
        for (int64_t i_33817 = 0; i_33817 < (int64_t) 400; i_33817++) {
            int64_t new_index_33839 = squot64(i_33817, (int64_t) 25);
            int64_t binop_y_33841 = (int64_t) 25 * new_index_33839;
            int64_t binop_x_33842 = i_33817 - binop_y_33841;
            int64_t new_index_33843 = squot64(binop_x_33842, (int64_t) 5);
            int64_t binop_y_33851 = (int64_t) 5 * new_index_33843;
            int64_t new_index_33852 = binop_x_33842 - binop_y_33851;
            double x_31560 = ((double *) mem_37132)[new_index_33839 * (int64_t) 25 + new_index_33843 * (int64_t) 5 + new_index_33852];
            double x_31561 = ((double *) ext_mem_36754.mem)[i_33820 * (int64_t) 400 + i_33817];
            double defunc_0_f_res_31562 = x_31560 * x_31561;
            double defunc_0_op_res_30118 = defunc_0_f_res_31562 + redout_33816;
            double redout_tmp_37570 = defunc_0_op_res_30118;
            
            redout_33816 = redout_tmp_37570;
        }
        defunc_0_reduce_res_33329 = redout_33816;
        
        double defunc_0_f_res_30120 = x_30109 + defunc_0_reduce_res_33329;
        double max_res_30122 = fmax64(0.0, defunc_0_f_res_30120);
        
        ((double *) mem_37256)[i_33820] = max_res_30122;
    }
    if (memblock_unref(ctx, &ext_mem_36753, "ext_mem_36753") != 0)
        return 1;
    if (memblock_unref(ctx, &ext_mem_36754, "ext_mem_36754") != 0)
        return 1;
    if (mem_37268_cached_sizze_37647 < (int64_t) 672) {
        err = lexical_realloc(ctx, &mem_37268, &mem_37268_cached_sizze_37647, (int64_t) 672);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    for (int64_t i_33826 = 0; i_33826 < (int64_t) 84; i_33826++) {
        double x_30094 = ((double *) ext_mem_36751.mem)[i_33826];
        double defunc_0_reduce_res_33330;
        double redout_33822 = 0.0;
        
        for (int64_t i_33823 = 0; i_33823 < (int64_t) 120; i_33823++) {
            double x_31566 = ((double *) mem_37256)[i_33823];
            double x_31567 = ((double *) ext_mem_36752.mem)[i_33826 * (int64_t) 120 + i_33823];
            double defunc_0_f_res_31568 = x_31566 * x_31567;
            double defunc_0_op_res_30103 = defunc_0_f_res_31568 + redout_33822;
            double redout_tmp_37572 = defunc_0_op_res_30103;
            
            redout_33822 = redout_tmp_37572;
        }
        defunc_0_reduce_res_33330 = redout_33822;
        
        double defunc_0_f_res_30105 = x_30094 + defunc_0_reduce_res_33330;
        double max_res_30107 = fmax64(0.0, defunc_0_f_res_30105);
        
        ((double *) mem_37268)[i_33826] = max_res_30107;
    }
    if (memblock_unref(ctx, &ext_mem_36751, "ext_mem_36751") != 0)
        return 1;
    if (memblock_unref(ctx, &ext_mem_36752, "ext_mem_36752") != 0)
        return 1;
    if (mem_37280_cached_sizze_37648 < (int64_t) 80) {
        err = lexical_realloc(ctx, &mem_37280, &mem_37280_cached_sizze_37648, (int64_t) 80);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    
    double defunc_0_reduce_res_33361;
    double redout_33831 = 0.0;
    
    for (int64_t i_33833 = 0; i_33833 < (int64_t) 10; i_33833++) {
        double x_30078 = ((double *) ext_mem_36749.mem)[i_33833];
        double defunc_0_reduce_res_33331;
        double redout_33828 = 0.0;
        
        for (int64_t i_33829 = 0; i_33829 < (int64_t) 84; i_33829++) {
            double x_31572 = ((double *) mem_37268)[i_33829];
            double x_31573 = ((double *) ext_mem_36750.mem)[i_33833 * (int64_t) 84 + i_33829];
            double defunc_0_f_res_31574 = x_31572 * x_31573;
            double defunc_0_op_res_30087 = defunc_0_f_res_31574 + redout_33828;
            double redout_tmp_37575 = defunc_0_op_res_30087;
            
            redout_33828 = redout_tmp_37575;
        }
        defunc_0_reduce_res_33331 = redout_33828;
        
        double defunc_0_f_res_30089 = x_30078 + defunc_0_reduce_res_33331;
        double defunc_0_f_res_30091 = futrts_exp64(defunc_0_f_res_30089);
        double defunc_0_op_res_28572 = defunc_0_f_res_30091 + redout_33831;
        
        ((double *) mem_37280)[i_33833] = defunc_0_f_res_30091;
        
        double redout_tmp_37573 = defunc_0_op_res_28572;
        
        redout_33831 = redout_tmp_37573;
    }
    defunc_0_reduce_res_33361 = redout_33831;
    if (memblock_unref(ctx, &ext_mem_36749, "ext_mem_36749") != 0)
        return 1;
    if (memblock_unref(ctx, &ext_mem_36750, "ext_mem_36750") != 0)
        return 1;
    if (memblock_alloc(ctx, &mem_37292, (int64_t) 80, "mem_37292")) {
        err = 1;
        goto cleanup;
    }
    for (int64_t i_33837 = 0; i_33837 < (int64_t) 10; i_33837++) {
        double x_28575 = ((double *) mem_37280)[i_33837];
        double defunc_0_f_res_28576 = x_28575 / defunc_0_reduce_res_33361;
        
        ((double *) mem_37292.mem)[i_33837] = defunc_0_f_res_28576;
    }
    
    bool y_28412 = slt64((int64_t) 300, dz2083U_26092);
    bool index_certs_28413;
    
    if (!y_28412) {
        set_error(ctx, msgprintf("Error: %s%lld%s%lld%s\n\nBacktrace:\n%s", "Index [", (long long) (int64_t) 300, "] out of bounds for array of shape [", (long long) dz2083U_26092, "].", "-> #0  cnn_playground.fut:21:12-23\n   #1  cnn_playground.fut:6:1-21:24\n"));
        err = FUTHARK_PROGRAM_ERROR;
        goto cleanup;
    }
    if (memblock_alloc(ctx, &mem_37307, (int64_t) 80, "mem_37307")) {
        err = 1;
        goto cleanup;
    }
    if ((int64_t) 80 > 0)
        memmove(mem_37307.mem + (int64_t) 0, y_train_mem_35081.mem + (int64_t) 24000, (int64_t) 80);
    if (memblock_set(ctx, &mem_out_37364, &mem_37292, "mem_37292") != 0)
        return 1;
    if (memblock_set(ctx, &mem_out_37365, &mem_37307, "mem_37307") != 0)
        return 1;
    if (memblock_set(ctx, &*mem_out_p_37577, &mem_out_37364, "mem_out_37364") != 0)
        return 1;
    if (memblock_set(ctx, &*mem_out_p_37578, &mem_out_37365, "mem_out_37365") != 0)
        return 1;
    
  cleanup:
    {
        free(mem_35083);
        free(mem_35095);
        free(mem_35097);
        free(mem_35099);
        free(mem_35101);
        free(mem_35103);
        free(mem_35155);
        free(mem_35179);
        free(mem_35203);
        free(mem_35227);
        free(mem_35251);
        free(mem_35369);
        free(mem_35414);
        free(mem_35419);
        free(mem_35480);
        free(mem_35523);
        free(mem_35536);
        free(mem_35647);
        free(mem_35699);
        free(mem_35739);
        free(mem_35752);
        free(mem_35863);
        free(mem_35875);
        free(mem_35887);
        free(mem_35899);
        free(mem_35911);
        free(mem_35913);
        free(mem_35915);
        free(mem_35930);
        free(mem_35955);
        free(mem_35957);
        free(mem_35959);
        free(mem_35961);
        free(mem_35963);
        free(mem_35978);
        free(mem_36003);
        free(mem_36005);
        free(mem_36007);
        free(mem_36009);
        free(mem_36011);
        free(mem_36026);
        free(mem_36051);
        free(mem_36053);
        free(mem_36055);
        free(mem_36068);
        free(mem_36141);
        free(mem_36143);
        free(mem_36145);
        free(mem_36160);
        free(mem_36175);
        free(mem_36177);
        free(mem_36323);
        free(mem_36325);
        free(mem_36338);
        free(mem_36413);
        free(mem_36428);
        free(mem_36459);
        free(mem_36762);
        free(mem_36807);
        free(mem_36812);
        free(mem_36873);
        free(mem_36916);
        free(mem_36929);
        free(mem_37040);
        free(mem_37092);
        free(mem_37132);
        free(mem_37145);
        free(mem_37256);
        free(mem_37268);
        free(mem_37280);
        if (memblock_unref(ctx, &mem_37307, "mem_37307") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_37292, "mem_37292") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_param_tmp_37409, "mem_param_tmp_37409") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_param_tmp_37408, "mem_param_tmp_37408") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_param_tmp_37407, "mem_param_tmp_37407") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_param_tmp_37406, "mem_param_tmp_37406") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_param_tmp_37405, "mem_param_tmp_37405") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_param_tmp_37404, "mem_param_tmp_37404") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_param_tmp_37403, "mem_param_tmp_37403") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_param_tmp_37402, "mem_param_tmp_37402") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_param_tmp_37401, "mem_param_tmp_37401") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_param_tmp_37400, "mem_param_tmp_37400") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_36671, "mem_36671") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_36631, "mem_36631") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_36619, "mem_36619") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_36579, "mem_36579") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_36567, "mem_36567") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_36527, "mem_36527") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_36515, "mem_36515") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_36443, "mem_36443") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_36411, "mem_36411") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_36179, "mem_36179") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_param_35365, "mem_param_35365") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_param_35360, "mem_param_35360") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_param_35349, "mem_param_35349") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_param_35344, "mem_param_35344") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_param_35333, "mem_param_35333") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_param_35328, "mem_param_35328") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_param_35317, "mem_param_35317") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_param_35312, "mem_param_35312") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_param_35295, "mem_param_35295") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_param_35290, "mem_param_35290") != 0)
            return 1;
        if (memblock_unref(ctx, &ext_mem_36749, "ext_mem_36749") != 0)
            return 1;
        if (memblock_unref(ctx, &ext_mem_36750, "ext_mem_36750") != 0)
            return 1;
        if (memblock_unref(ctx, &ext_mem_36751, "ext_mem_36751") != 0)
            return 1;
        if (memblock_unref(ctx, &ext_mem_36752, "ext_mem_36752") != 0)
            return 1;
        if (memblock_unref(ctx, &ext_mem_36753, "ext_mem_36753") != 0)
            return 1;
        if (memblock_unref(ctx, &ext_mem_36754, "ext_mem_36754") != 0)
            return 1;
        if (memblock_unref(ctx, &ext_mem_36755, "ext_mem_36755") != 0)
            return 1;
        if (memblock_unref(ctx, &ext_mem_36756, "ext_mem_36756") != 0)
            return 1;
        if (memblock_unref(ctx, &ext_mem_36757, "ext_mem_36757") != 0)
            return 1;
        if (memblock_unref(ctx, &ext_mem_36758, "ext_mem_36758") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_35351, "mem_35351") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_35335, "mem_35335") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_35319, "mem_35319") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_35297, "mem_35297") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_35275, "mem_35275") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_35263, "mem_35263") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_35239, "mem_35239") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_35215, "mem_35215") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_35191, "mem_35191") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_35167, "mem_35167") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_out_37365, "mem_out_37365") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_out_37364, "mem_out_37364") != 0)
            return 1;
    }
    return err;
}

int futhark_entry_main(struct futhark_context *ctx, struct futhark_f64_1d **out0, struct futhark_f64_1d **out1, const struct futhark_f64_3d *in0, const struct futhark_f64_2d *in1)
{
    int64_t dz2080U_26089 = (int64_t) 0;
    int64_t dz2081U_26090 = (int64_t) 0;
    int64_t dz2082U_26091 = (int64_t) 0;
    int64_t dz2083U_26092 = (int64_t) 0;
    int ret = 0;
    
    lock_lock(&ctx->lock);
    
    struct memblock mem_out_37365;
    
    mem_out_37365.references = NULL;
    
    struct memblock mem_out_37364;
    
    mem_out_37364.references = NULL;
    
    struct memblock y_train_mem_35081;
    
    y_train_mem_35081.references = NULL;
    
    struct memblock x_train_mem_35080;
    
    x_train_mem_35080.references = NULL;
    x_train_mem_35080 = in0->mem;
    dz2080U_26089 = in0->shape[0];
    dz2081U_26090 = in0->shape[1];
    dz2082U_26091 = in0->shape[2];
    y_train_mem_35081 = in1->mem;
    dz2083U_26092 = in1->shape[0];
    if (!((dz2080U_26089 == in0->shape[0] && (dz2081U_26090 == in0->shape[1] && dz2082U_26091 == in0->shape[2])) && (dz2083U_26092 == in1->shape[0] && (int64_t) 10 == in1->shape[1]))) {
        ret = 1;
        set_error(ctx, msgprintf("Error: entry point arguments have invalid sizes.\n"));
    }
    if (ret == 0) {
        ret = futrts_entry_main(ctx, &mem_out_37364, &mem_out_37365, x_train_mem_35080, y_train_mem_35081, dz2080U_26089, dz2081U_26090, dz2082U_26091, dz2083U_26092);
        if (ret == 0) {
            assert((*out0 = (struct futhark_f64_1d *) malloc(sizeof(struct futhark_f64_1d))) != NULL);
            (*out0)->mem = mem_out_37364;
            (*out0)->shape[0] = (int64_t) 10;
            assert((*out1 = (struct futhark_f64_1d *) malloc(sizeof(struct futhark_f64_1d))) != NULL);
            (*out1)->mem = mem_out_37365;
            (*out1)->shape[0] = (int64_t) 10;
        }
    }
    lock_unlock(&ctx->lock);
    return ret;
}
  
