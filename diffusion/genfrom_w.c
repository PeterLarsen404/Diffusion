
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
int futhark_entry_main(struct futhark_context *ctx, struct futhark_f64_3d **out0, const struct futhark_f64_1d *in0, const struct futhark_f64_3d *in1, const struct futhark_f64_4d *in2, const struct futhark_f64_1d *in3, const struct futhark_f64_4d *in4, const struct futhark_f64_1d *in5, const struct futhark_f64_2d *in6, const struct futhark_f64_1d *in7, const struct futhark_f64_4d *in8, const struct futhark_f64_1d *in9, const struct futhark_f64_4d *in10, const struct futhark_f64_1d *in11, const struct futhark_f64_2d *in12, const struct futhark_f64_1d *in13, const struct futhark_f64_4d *in14, const struct futhark_f64_1d *in15, const struct futhark_f64_4d *in16, const struct futhark_f64_1d *in17, const struct futhark_f64_2d *in18, const struct futhark_f64_1d *in19, const struct futhark_f64_4d *in20, const struct futhark_f64_1d *in21, const struct futhark_f64_4d *in22, const struct futhark_f64_1d *in23, const struct futhark_f64_2d *in24, const struct futhark_f64_1d *in25, const struct futhark_f64_4d *in26, const struct futhark_f64_1d *in27, const struct futhark_f64_4d *in28, const struct futhark_f64_1d *in29);

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
    
    struct futhark_f64_1d * read_value_0;
    int64_t read_shape_0[1];
    double *read_arr_0 = NULL;
    
    errno = 0;
    if (read_array(stdin, &f64_info, (void **) &read_arr_0, read_shape_0, 1) != 0)
        futhark_panic(1, "Cannot read input #%d of type %s (errno: %s).\n", 0, "[]f64", strerror(errno));
    
    struct futhark_f64_3d * read_value_1;
    int64_t read_shape_1[3];
    double *read_arr_1 = NULL;
    
    errno = 0;
    if (read_array(stdin, &f64_info, (void **) &read_arr_1, read_shape_1, 3) != 0)
        futhark_panic(1, "Cannot read input #%d of type %s (errno: %s).\n", 1, "[][][]f64", strerror(errno));
    
    struct futhark_f64_4d * read_value_2;
    int64_t read_shape_2[4];
    double *read_arr_2 = NULL;
    
    errno = 0;
    if (read_array(stdin, &f64_info, (void **) &read_arr_2, read_shape_2, 4) != 0)
        futhark_panic(1, "Cannot read input #%d of type %s (errno: %s).\n", 2, "[][][][]f64", strerror(errno));
    
    struct futhark_f64_1d * read_value_3;
    int64_t read_shape_3[1];
    double *read_arr_3 = NULL;
    
    errno = 0;
    if (read_array(stdin, &f64_info, (void **) &read_arr_3, read_shape_3, 1) != 0)
        futhark_panic(1, "Cannot read input #%d of type %s (errno: %s).\n", 3, "[]f64", strerror(errno));
    
    struct futhark_f64_4d * read_value_4;
    int64_t read_shape_4[4];
    double *read_arr_4 = NULL;
    
    errno = 0;
    if (read_array(stdin, &f64_info, (void **) &read_arr_4, read_shape_4, 4) != 0)
        futhark_panic(1, "Cannot read input #%d of type %s (errno: %s).\n", 4, "[][][][]f64", strerror(errno));
    
    struct futhark_f64_1d * read_value_5;
    int64_t read_shape_5[1];
    double *read_arr_5 = NULL;
    
    errno = 0;
    if (read_array(stdin, &f64_info, (void **) &read_arr_5, read_shape_5, 1) != 0)
        futhark_panic(1, "Cannot read input #%d of type %s (errno: %s).\n", 5, "[]f64", strerror(errno));
    
    struct futhark_f64_2d * read_value_6;
    int64_t read_shape_6[2];
    double *read_arr_6 = NULL;
    
    errno = 0;
    if (read_array(stdin, &f64_info, (void **) &read_arr_6, read_shape_6, 2) != 0)
        futhark_panic(1, "Cannot read input #%d of type %s (errno: %s).\n", 6, "[][]f64", strerror(errno));
    
    struct futhark_f64_1d * read_value_7;
    int64_t read_shape_7[1];
    double *read_arr_7 = NULL;
    
    errno = 0;
    if (read_array(stdin, &f64_info, (void **) &read_arr_7, read_shape_7, 1) != 0)
        futhark_panic(1, "Cannot read input #%d of type %s (errno: %s).\n", 7, "[]f64", strerror(errno));
    
    struct futhark_f64_4d * read_value_8;
    int64_t read_shape_8[4];
    double *read_arr_8 = NULL;
    
    errno = 0;
    if (read_array(stdin, &f64_info, (void **) &read_arr_8, read_shape_8, 4) != 0)
        futhark_panic(1, "Cannot read input #%d of type %s (errno: %s).\n", 8, "[][][][]f64", strerror(errno));
    
    struct futhark_f64_1d * read_value_9;
    int64_t read_shape_9[1];
    double *read_arr_9 = NULL;
    
    errno = 0;
    if (read_array(stdin, &f64_info, (void **) &read_arr_9, read_shape_9, 1) != 0)
        futhark_panic(1, "Cannot read input #%d of type %s (errno: %s).\n", 9, "[]f64", strerror(errno));
    
    struct futhark_f64_4d * read_value_10;
    int64_t read_shape_10[4];
    double *read_arr_10 = NULL;
    
    errno = 0;
    if (read_array(stdin, &f64_info, (void **) &read_arr_10, read_shape_10, 4) != 0)
        futhark_panic(1, "Cannot read input #%d of type %s (errno: %s).\n", 10, "[][][][]f64", strerror(errno));
    
    struct futhark_f64_1d * read_value_11;
    int64_t read_shape_11[1];
    double *read_arr_11 = NULL;
    
    errno = 0;
    if (read_array(stdin, &f64_info, (void **) &read_arr_11, read_shape_11, 1) != 0)
        futhark_panic(1, "Cannot read input #%d of type %s (errno: %s).\n", 11, "[]f64", strerror(errno));
    
    struct futhark_f64_2d * read_value_12;
    int64_t read_shape_12[2];
    double *read_arr_12 = NULL;
    
    errno = 0;
    if (read_array(stdin, &f64_info, (void **) &read_arr_12, read_shape_12, 2) != 0)
        futhark_panic(1, "Cannot read input #%d of type %s (errno: %s).\n", 12, "[][]f64", strerror(errno));
    
    struct futhark_f64_1d * read_value_13;
    int64_t read_shape_13[1];
    double *read_arr_13 = NULL;
    
    errno = 0;
    if (read_array(stdin, &f64_info, (void **) &read_arr_13, read_shape_13, 1) != 0)
        futhark_panic(1, "Cannot read input #%d of type %s (errno: %s).\n", 13, "[]f64", strerror(errno));
    
    struct futhark_f64_4d * read_value_14;
    int64_t read_shape_14[4];
    double *read_arr_14 = NULL;
    
    errno = 0;
    if (read_array(stdin, &f64_info, (void **) &read_arr_14, read_shape_14, 4) != 0)
        futhark_panic(1, "Cannot read input #%d of type %s (errno: %s).\n", 14, "[][][][]f64", strerror(errno));
    
    struct futhark_f64_1d * read_value_15;
    int64_t read_shape_15[1];
    double *read_arr_15 = NULL;
    
    errno = 0;
    if (read_array(stdin, &f64_info, (void **) &read_arr_15, read_shape_15, 1) != 0)
        futhark_panic(1, "Cannot read input #%d of type %s (errno: %s).\n", 15, "[]f64", strerror(errno));
    
    struct futhark_f64_4d * read_value_16;
    int64_t read_shape_16[4];
    double *read_arr_16 = NULL;
    
    errno = 0;
    if (read_array(stdin, &f64_info, (void **) &read_arr_16, read_shape_16, 4) != 0)
        futhark_panic(1, "Cannot read input #%d of type %s (errno: %s).\n", 16, "[][][][]f64", strerror(errno));
    
    struct futhark_f64_1d * read_value_17;
    int64_t read_shape_17[1];
    double *read_arr_17 = NULL;
    
    errno = 0;
    if (read_array(stdin, &f64_info, (void **) &read_arr_17, read_shape_17, 1) != 0)
        futhark_panic(1, "Cannot read input #%d of type %s (errno: %s).\n", 17, "[]f64", strerror(errno));
    
    struct futhark_f64_2d * read_value_18;
    int64_t read_shape_18[2];
    double *read_arr_18 = NULL;
    
    errno = 0;
    if (read_array(stdin, &f64_info, (void **) &read_arr_18, read_shape_18, 2) != 0)
        futhark_panic(1, "Cannot read input #%d of type %s (errno: %s).\n", 18, "[][]f64", strerror(errno));
    
    struct futhark_f64_1d * read_value_19;
    int64_t read_shape_19[1];
    double *read_arr_19 = NULL;
    
    errno = 0;
    if (read_array(stdin, &f64_info, (void **) &read_arr_19, read_shape_19, 1) != 0)
        futhark_panic(1, "Cannot read input #%d of type %s (errno: %s).\n", 19, "[]f64", strerror(errno));
    
    struct futhark_f64_4d * read_value_20;
    int64_t read_shape_20[4];
    double *read_arr_20 = NULL;
    
    errno = 0;
    if (read_array(stdin, &f64_info, (void **) &read_arr_20, read_shape_20, 4) != 0)
        futhark_panic(1, "Cannot read input #%d of type %s (errno: %s).\n", 20, "[][][][]f64", strerror(errno));
    
    struct futhark_f64_1d * read_value_21;
    int64_t read_shape_21[1];
    double *read_arr_21 = NULL;
    
    errno = 0;
    if (read_array(stdin, &f64_info, (void **) &read_arr_21, read_shape_21, 1) != 0)
        futhark_panic(1, "Cannot read input #%d of type %s (errno: %s).\n", 21, "[]f64", strerror(errno));
    
    struct futhark_f64_4d * read_value_22;
    int64_t read_shape_22[4];
    double *read_arr_22 = NULL;
    
    errno = 0;
    if (read_array(stdin, &f64_info, (void **) &read_arr_22, read_shape_22, 4) != 0)
        futhark_panic(1, "Cannot read input #%d of type %s (errno: %s).\n", 22, "[][][][]f64", strerror(errno));
    
    struct futhark_f64_1d * read_value_23;
    int64_t read_shape_23[1];
    double *read_arr_23 = NULL;
    
    errno = 0;
    if (read_array(stdin, &f64_info, (void **) &read_arr_23, read_shape_23, 1) != 0)
        futhark_panic(1, "Cannot read input #%d of type %s (errno: %s).\n", 23, "[]f64", strerror(errno));
    
    struct futhark_f64_2d * read_value_24;
    int64_t read_shape_24[2];
    double *read_arr_24 = NULL;
    
    errno = 0;
    if (read_array(stdin, &f64_info, (void **) &read_arr_24, read_shape_24, 2) != 0)
        futhark_panic(1, "Cannot read input #%d of type %s (errno: %s).\n", 24, "[][]f64", strerror(errno));
    
    struct futhark_f64_1d * read_value_25;
    int64_t read_shape_25[1];
    double *read_arr_25 = NULL;
    
    errno = 0;
    if (read_array(stdin, &f64_info, (void **) &read_arr_25, read_shape_25, 1) != 0)
        futhark_panic(1, "Cannot read input #%d of type %s (errno: %s).\n", 25, "[]f64", strerror(errno));
    
    struct futhark_f64_4d * read_value_26;
    int64_t read_shape_26[4];
    double *read_arr_26 = NULL;
    
    errno = 0;
    if (read_array(stdin, &f64_info, (void **) &read_arr_26, read_shape_26, 4) != 0)
        futhark_panic(1, "Cannot read input #%d of type %s (errno: %s).\n", 26, "[][][][]f64", strerror(errno));
    
    struct futhark_f64_1d * read_value_27;
    int64_t read_shape_27[1];
    double *read_arr_27 = NULL;
    
    errno = 0;
    if (read_array(stdin, &f64_info, (void **) &read_arr_27, read_shape_27, 1) != 0)
        futhark_panic(1, "Cannot read input #%d of type %s (errno: %s).\n", 27, "[]f64", strerror(errno));
    
    struct futhark_f64_4d * read_value_28;
    int64_t read_shape_28[4];
    double *read_arr_28 = NULL;
    
    errno = 0;
    if (read_array(stdin, &f64_info, (void **) &read_arr_28, read_shape_28, 4) != 0)
        futhark_panic(1, "Cannot read input #%d of type %s (errno: %s).\n", 28, "[][][][]f64", strerror(errno));
    
    struct futhark_f64_1d * read_value_29;
    int64_t read_shape_29[1];
    double *read_arr_29 = NULL;
    
    errno = 0;
    if (read_array(stdin, &f64_info, (void **) &read_arr_29, read_shape_29, 1) != 0)
        futhark_panic(1, "Cannot read input #%d of type %s (errno: %s).\n", 29, "[]f64", strerror(errno));
    if (end_of_input(stdin) != 0)
        futhark_panic(1, "Expected EOF on stdin after reading input for \"%s\".\n", "main");
    
    struct futhark_f64_3d * result_0;
    
    if (perform_warmup) {
        int r;
        
        assert((read_value_0 = futhark_new_f64_1d(ctx, read_arr_0, read_shape_0[0])) != NULL);
        assert((read_value_1 = futhark_new_f64_3d(ctx, read_arr_1, read_shape_1[0], read_shape_1[1], read_shape_1[2])) != NULL);
        assert((read_value_2 = futhark_new_f64_4d(ctx, read_arr_2, read_shape_2[0], read_shape_2[1], read_shape_2[2], read_shape_2[3])) != NULL);
        assert((read_value_3 = futhark_new_f64_1d(ctx, read_arr_3, read_shape_3[0])) != NULL);
        assert((read_value_4 = futhark_new_f64_4d(ctx, read_arr_4, read_shape_4[0], read_shape_4[1], read_shape_4[2], read_shape_4[3])) != NULL);
        assert((read_value_5 = futhark_new_f64_1d(ctx, read_arr_5, read_shape_5[0])) != NULL);
        assert((read_value_6 = futhark_new_f64_2d(ctx, read_arr_6, read_shape_6[0], read_shape_6[1])) != NULL);
        assert((read_value_7 = futhark_new_f64_1d(ctx, read_arr_7, read_shape_7[0])) != NULL);
        assert((read_value_8 = futhark_new_f64_4d(ctx, read_arr_8, read_shape_8[0], read_shape_8[1], read_shape_8[2], read_shape_8[3])) != NULL);
        assert((read_value_9 = futhark_new_f64_1d(ctx, read_arr_9, read_shape_9[0])) != NULL);
        assert((read_value_10 = futhark_new_f64_4d(ctx, read_arr_10, read_shape_10[0], read_shape_10[1], read_shape_10[2], read_shape_10[3])) != NULL);
        assert((read_value_11 = futhark_new_f64_1d(ctx, read_arr_11, read_shape_11[0])) != NULL);
        assert((read_value_12 = futhark_new_f64_2d(ctx, read_arr_12, read_shape_12[0], read_shape_12[1])) != NULL);
        assert((read_value_13 = futhark_new_f64_1d(ctx, read_arr_13, read_shape_13[0])) != NULL);
        assert((read_value_14 = futhark_new_f64_4d(ctx, read_arr_14, read_shape_14[0], read_shape_14[1], read_shape_14[2], read_shape_14[3])) != NULL);
        assert((read_value_15 = futhark_new_f64_1d(ctx, read_arr_15, read_shape_15[0])) != NULL);
        assert((read_value_16 = futhark_new_f64_4d(ctx, read_arr_16, read_shape_16[0], read_shape_16[1], read_shape_16[2], read_shape_16[3])) != NULL);
        assert((read_value_17 = futhark_new_f64_1d(ctx, read_arr_17, read_shape_17[0])) != NULL);
        assert((read_value_18 = futhark_new_f64_2d(ctx, read_arr_18, read_shape_18[0], read_shape_18[1])) != NULL);
        assert((read_value_19 = futhark_new_f64_1d(ctx, read_arr_19, read_shape_19[0])) != NULL);
        assert((read_value_20 = futhark_new_f64_4d(ctx, read_arr_20, read_shape_20[0], read_shape_20[1], read_shape_20[2], read_shape_20[3])) != NULL);
        assert((read_value_21 = futhark_new_f64_1d(ctx, read_arr_21, read_shape_21[0])) != NULL);
        assert((read_value_22 = futhark_new_f64_4d(ctx, read_arr_22, read_shape_22[0], read_shape_22[1], read_shape_22[2], read_shape_22[3])) != NULL);
        assert((read_value_23 = futhark_new_f64_1d(ctx, read_arr_23, read_shape_23[0])) != NULL);
        assert((read_value_24 = futhark_new_f64_2d(ctx, read_arr_24, read_shape_24[0], read_shape_24[1])) != NULL);
        assert((read_value_25 = futhark_new_f64_1d(ctx, read_arr_25, read_shape_25[0])) != NULL);
        assert((read_value_26 = futhark_new_f64_4d(ctx, read_arr_26, read_shape_26[0], read_shape_26[1], read_shape_26[2], read_shape_26[3])) != NULL);
        assert((read_value_27 = futhark_new_f64_1d(ctx, read_arr_27, read_shape_27[0])) != NULL);
        assert((read_value_28 = futhark_new_f64_4d(ctx, read_arr_28, read_shape_28[0], read_shape_28[1], read_shape_28[2], read_shape_28[3])) != NULL);
        assert((read_value_29 = futhark_new_f64_1d(ctx, read_arr_29, read_shape_29[0])) != NULL);
        if (futhark_context_sync(ctx) != 0)
            futhark_panic(1, "%s", futhark_context_get_error(ctx));
        ;
        // Only profile last run.
        if (profile_run)
            futhark_context_unpause_profiling(ctx);
        t_start = get_wall_time();
        r = futhark_entry_main(ctx, &result_0, read_value_0, read_value_1, read_value_2, read_value_3, read_value_4, read_value_5, read_value_6, read_value_7, read_value_8, read_value_9, read_value_10, read_value_11, read_value_12, read_value_13, read_value_14, read_value_15, read_value_16, read_value_17, read_value_18, read_value_19, read_value_20, read_value_21, read_value_22, read_value_23, read_value_24, read_value_25, read_value_26, read_value_27, read_value_28, read_value_29);
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
        assert(futhark_free_f64_1d(ctx, read_value_0) == 0);
        assert(futhark_free_f64_3d(ctx, read_value_1) == 0);
        assert(futhark_free_f64_4d(ctx, read_value_2) == 0);
        assert(futhark_free_f64_1d(ctx, read_value_3) == 0);
        assert(futhark_free_f64_4d(ctx, read_value_4) == 0);
        assert(futhark_free_f64_1d(ctx, read_value_5) == 0);
        assert(futhark_free_f64_2d(ctx, read_value_6) == 0);
        assert(futhark_free_f64_1d(ctx, read_value_7) == 0);
        assert(futhark_free_f64_4d(ctx, read_value_8) == 0);
        assert(futhark_free_f64_1d(ctx, read_value_9) == 0);
        assert(futhark_free_f64_4d(ctx, read_value_10) == 0);
        assert(futhark_free_f64_1d(ctx, read_value_11) == 0);
        assert(futhark_free_f64_2d(ctx, read_value_12) == 0);
        assert(futhark_free_f64_1d(ctx, read_value_13) == 0);
        assert(futhark_free_f64_4d(ctx, read_value_14) == 0);
        assert(futhark_free_f64_1d(ctx, read_value_15) == 0);
        assert(futhark_free_f64_4d(ctx, read_value_16) == 0);
        assert(futhark_free_f64_1d(ctx, read_value_17) == 0);
        assert(futhark_free_f64_2d(ctx, read_value_18) == 0);
        assert(futhark_free_f64_1d(ctx, read_value_19) == 0);
        assert(futhark_free_f64_4d(ctx, read_value_20) == 0);
        assert(futhark_free_f64_1d(ctx, read_value_21) == 0);
        assert(futhark_free_f64_4d(ctx, read_value_22) == 0);
        assert(futhark_free_f64_1d(ctx, read_value_23) == 0);
        assert(futhark_free_f64_2d(ctx, read_value_24) == 0);
        assert(futhark_free_f64_1d(ctx, read_value_25) == 0);
        assert(futhark_free_f64_4d(ctx, read_value_26) == 0);
        assert(futhark_free_f64_1d(ctx, read_value_27) == 0);
        assert(futhark_free_f64_4d(ctx, read_value_28) == 0);
        assert(futhark_free_f64_1d(ctx, read_value_29) == 0);
        assert(futhark_free_f64_3d(ctx, result_0) == 0);
    }
    time_runs = 1;
    // Proper run.
    for (int run = 0; run < num_runs; run++) {
        // Only profile last run.
        profile_run = run == num_runs - 1;
        
        int r;
        
        assert((read_value_0 = futhark_new_f64_1d(ctx, read_arr_0, read_shape_0[0])) != NULL);
        assert((read_value_1 = futhark_new_f64_3d(ctx, read_arr_1, read_shape_1[0], read_shape_1[1], read_shape_1[2])) != NULL);
        assert((read_value_2 = futhark_new_f64_4d(ctx, read_arr_2, read_shape_2[0], read_shape_2[1], read_shape_2[2], read_shape_2[3])) != NULL);
        assert((read_value_3 = futhark_new_f64_1d(ctx, read_arr_3, read_shape_3[0])) != NULL);
        assert((read_value_4 = futhark_new_f64_4d(ctx, read_arr_4, read_shape_4[0], read_shape_4[1], read_shape_4[2], read_shape_4[3])) != NULL);
        assert((read_value_5 = futhark_new_f64_1d(ctx, read_arr_5, read_shape_5[0])) != NULL);
        assert((read_value_6 = futhark_new_f64_2d(ctx, read_arr_6, read_shape_6[0], read_shape_6[1])) != NULL);
        assert((read_value_7 = futhark_new_f64_1d(ctx, read_arr_7, read_shape_7[0])) != NULL);
        assert((read_value_8 = futhark_new_f64_4d(ctx, read_arr_8, read_shape_8[0], read_shape_8[1], read_shape_8[2], read_shape_8[3])) != NULL);
        assert((read_value_9 = futhark_new_f64_1d(ctx, read_arr_9, read_shape_9[0])) != NULL);
        assert((read_value_10 = futhark_new_f64_4d(ctx, read_arr_10, read_shape_10[0], read_shape_10[1], read_shape_10[2], read_shape_10[3])) != NULL);
        assert((read_value_11 = futhark_new_f64_1d(ctx, read_arr_11, read_shape_11[0])) != NULL);
        assert((read_value_12 = futhark_new_f64_2d(ctx, read_arr_12, read_shape_12[0], read_shape_12[1])) != NULL);
        assert((read_value_13 = futhark_new_f64_1d(ctx, read_arr_13, read_shape_13[0])) != NULL);
        assert((read_value_14 = futhark_new_f64_4d(ctx, read_arr_14, read_shape_14[0], read_shape_14[1], read_shape_14[2], read_shape_14[3])) != NULL);
        assert((read_value_15 = futhark_new_f64_1d(ctx, read_arr_15, read_shape_15[0])) != NULL);
        assert((read_value_16 = futhark_new_f64_4d(ctx, read_arr_16, read_shape_16[0], read_shape_16[1], read_shape_16[2], read_shape_16[3])) != NULL);
        assert((read_value_17 = futhark_new_f64_1d(ctx, read_arr_17, read_shape_17[0])) != NULL);
        assert((read_value_18 = futhark_new_f64_2d(ctx, read_arr_18, read_shape_18[0], read_shape_18[1])) != NULL);
        assert((read_value_19 = futhark_new_f64_1d(ctx, read_arr_19, read_shape_19[0])) != NULL);
        assert((read_value_20 = futhark_new_f64_4d(ctx, read_arr_20, read_shape_20[0], read_shape_20[1], read_shape_20[2], read_shape_20[3])) != NULL);
        assert((read_value_21 = futhark_new_f64_1d(ctx, read_arr_21, read_shape_21[0])) != NULL);
        assert((read_value_22 = futhark_new_f64_4d(ctx, read_arr_22, read_shape_22[0], read_shape_22[1], read_shape_22[2], read_shape_22[3])) != NULL);
        assert((read_value_23 = futhark_new_f64_1d(ctx, read_arr_23, read_shape_23[0])) != NULL);
        assert((read_value_24 = futhark_new_f64_2d(ctx, read_arr_24, read_shape_24[0], read_shape_24[1])) != NULL);
        assert((read_value_25 = futhark_new_f64_1d(ctx, read_arr_25, read_shape_25[0])) != NULL);
        assert((read_value_26 = futhark_new_f64_4d(ctx, read_arr_26, read_shape_26[0], read_shape_26[1], read_shape_26[2], read_shape_26[3])) != NULL);
        assert((read_value_27 = futhark_new_f64_1d(ctx, read_arr_27, read_shape_27[0])) != NULL);
        assert((read_value_28 = futhark_new_f64_4d(ctx, read_arr_28, read_shape_28[0], read_shape_28[1], read_shape_28[2], read_shape_28[3])) != NULL);
        assert((read_value_29 = futhark_new_f64_1d(ctx, read_arr_29, read_shape_29[0])) != NULL);
        if (futhark_context_sync(ctx) != 0)
            futhark_panic(1, "%s", futhark_context_get_error(ctx));
        ;
        // Only profile last run.
        if (profile_run)
            futhark_context_unpause_profiling(ctx);
        t_start = get_wall_time();
        r = futhark_entry_main(ctx, &result_0, read_value_0, read_value_1, read_value_2, read_value_3, read_value_4, read_value_5, read_value_6, read_value_7, read_value_8, read_value_9, read_value_10, read_value_11, read_value_12, read_value_13, read_value_14, read_value_15, read_value_16, read_value_17, read_value_18, read_value_19, read_value_20, read_value_21, read_value_22, read_value_23, read_value_24, read_value_25, read_value_26, read_value_27, read_value_28, read_value_29);
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
        assert(futhark_free_f64_1d(ctx, read_value_0) == 0);
        assert(futhark_free_f64_3d(ctx, read_value_1) == 0);
        assert(futhark_free_f64_4d(ctx, read_value_2) == 0);
        assert(futhark_free_f64_1d(ctx, read_value_3) == 0);
        assert(futhark_free_f64_4d(ctx, read_value_4) == 0);
        assert(futhark_free_f64_1d(ctx, read_value_5) == 0);
        assert(futhark_free_f64_2d(ctx, read_value_6) == 0);
        assert(futhark_free_f64_1d(ctx, read_value_7) == 0);
        assert(futhark_free_f64_4d(ctx, read_value_8) == 0);
        assert(futhark_free_f64_1d(ctx, read_value_9) == 0);
        assert(futhark_free_f64_4d(ctx, read_value_10) == 0);
        assert(futhark_free_f64_1d(ctx, read_value_11) == 0);
        assert(futhark_free_f64_2d(ctx, read_value_12) == 0);
        assert(futhark_free_f64_1d(ctx, read_value_13) == 0);
        assert(futhark_free_f64_4d(ctx, read_value_14) == 0);
        assert(futhark_free_f64_1d(ctx, read_value_15) == 0);
        assert(futhark_free_f64_4d(ctx, read_value_16) == 0);
        assert(futhark_free_f64_1d(ctx, read_value_17) == 0);
        assert(futhark_free_f64_2d(ctx, read_value_18) == 0);
        assert(futhark_free_f64_1d(ctx, read_value_19) == 0);
        assert(futhark_free_f64_4d(ctx, read_value_20) == 0);
        assert(futhark_free_f64_1d(ctx, read_value_21) == 0);
        assert(futhark_free_f64_4d(ctx, read_value_22) == 0);
        assert(futhark_free_f64_1d(ctx, read_value_23) == 0);
        assert(futhark_free_f64_2d(ctx, read_value_24) == 0);
        assert(futhark_free_f64_1d(ctx, read_value_25) == 0);
        assert(futhark_free_f64_4d(ctx, read_value_26) == 0);
        assert(futhark_free_f64_1d(ctx, read_value_27) == 0);
        assert(futhark_free_f64_4d(ctx, read_value_28) == 0);
        assert(futhark_free_f64_1d(ctx, read_value_29) == 0);
        if (run < num_runs - 1) {
            assert(futhark_free_f64_3d(ctx, result_0) == 0);
        }
    }
    free(read_arr_0);
    free(read_arr_1);
    free(read_arr_2);
    free(read_arr_3);
    free(read_arr_4);
    free(read_arr_5);
    free(read_arr_6);
    free(read_arr_7);
    free(read_arr_8);
    free(read_arr_9);
    free(read_arr_10);
    free(read_arr_11);
    free(read_arr_12);
    free(read_arr_13);
    free(read_arr_14);
    free(read_arr_15);
    free(read_arr_16);
    free(read_arr_17);
    free(read_arr_18);
    free(read_arr_19);
    free(read_arr_20);
    free(read_arr_21);
    free(read_arr_22);
    free(read_arr_23);
    free(read_arr_24);
    free(read_arr_25);
    free(read_arr_26);
    free(read_arr_27);
    free(read_arr_28);
    free(read_arr_29);
    if (print_result) {
        // Print the final result.
        if (binary_output)
            set_binary_mode(stdout);
        {
            double *arr = calloc(futhark_shape_f64_3d(ctx, result_0)[0] * futhark_shape_f64_3d(ctx, result_0)[1] * futhark_shape_f64_3d(ctx, result_0)[2], f64_info.size);
            
            assert(arr != NULL);
            assert(futhark_values_f64_3d(ctx, result_0, arr) == 0);
            assert(futhark_context_sync(ctx) == 0);
            write_array(stdout, binary_output, &f64_info, arr, futhark_shape_f64_3d(ctx, result_0), 3);
            free(arr);
        }
        printf("\n");
    }
    
  print_end:
    { }
    assert(futhark_free_f64_3d(ctx, result_0) == 0);
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

static int futrts_entry_main(struct futhark_context *ctx, struct memblock *mem_out_p_42952, struct memblock losses_mem_38943, struct memblock sampled_imgs_mem_38944, struct memblock c_in_w_mem_38945, struct memblock c_in_b_mem_38946, struct memblock b1_c1_w_mem_38947, struct memblock b1_c1_b_mem_38948, struct memblock b1_tw_mem_38949, struct memblock b1_tb_mem_38950, struct memblock b1_c2_w_mem_38951, struct memblock b1_c2_b_mem_38952, struct memblock b2_c1_w_mem_38953, struct memblock b2_c1_b_mem_38954, struct memblock b2_tw_mem_38955, struct memblock b2_tb_mem_38956, struct memblock b2_c2_w_mem_38957, struct memblock b2_c2_b_mem_38958, struct memblock b3_c1_w_mem_38959, struct memblock b3_c1_b_mem_38960, struct memblock b3_tw_mem_38961, struct memblock b3_tb_mem_38962, struct memblock b3_c2_w_mem_38963, struct memblock b3_c2_b_mem_38964, struct memblock b4_c1_w_mem_38965, struct memblock b4_c1_b_mem_38966, struct memblock b4_tw_mem_38967, struct memblock b4_tb_mem_38968, struct memblock b4_c2_w_mem_38969, struct memblock b4_c2_b_mem_38970, struct memblock c_out_w_mem_38971, struct memblock c_out_b_mem_38972, int64_t dz2080U_26613, int64_t dz2081U_26614, int64_t dz2082U_26615, int64_t dz2083U_26616, int64_t dz2086U_26617, int64_t dz2087U_26618, int64_t dz2088U_26619, int64_t dz2081Uz2081U_26620, int64_t dz2081Uz2082U_26621, int64_t dz2081Uz2083U_26622, int64_t dz2082Uz2083U_26623, int64_t dz2081Uz2089U_26624, int64_t dz2082Uz2080U_26625, int64_t dz2082Uz2081U_26626, int64_t dz2082Uz2082U_26627, int64_t dz2082Uz2084U_26628, int64_t dz2082Uz2085U_26629, int64_t dz2083Uz2081U_26630, int64_t dz2083Uz2080U_26631, int64_t dz2083Uz2082U_26632, int64_t dz2083Uz2083U_26633, int64_t dz2083Uz2087U_26634, int64_t dz2083Uz2088U_26635, int64_t dz2083Uz2089U_26636, int64_t dz2084Uz2084U_26637, int64_t dz2084Uz2085U_26638, int64_t dz2084Uz2086U_26639, int64_t dz2084Uz2087U_26640, int64_t dz2085Uz2080U_26641, int64_t dz2085Uz2081U_26642, int64_t dz2085Uz2082U_26643, int64_t dz2086Uz2082U_26644, int64_t dz2085Uz2088U_26645, int64_t dz2085Uz2089U_26646, int64_t dz2086Uz2080U_26647, int64_t dz2086Uz2083U_26648, int64_t dz2086Uz2084U_26649, int64_t dz2086Uz2085U_26650);

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

static int futrts_entry_main(struct futhark_context *ctx, struct memblock *mem_out_p_42952, struct memblock losses_mem_38943, struct memblock sampled_imgs_mem_38944, struct memblock c_in_w_mem_38945, struct memblock c_in_b_mem_38946, struct memblock b1_c1_w_mem_38947, struct memblock b1_c1_b_mem_38948, struct memblock b1_tw_mem_38949, struct memblock b1_tb_mem_38950, struct memblock b1_c2_w_mem_38951, struct memblock b1_c2_b_mem_38952, struct memblock b2_c1_w_mem_38953, struct memblock b2_c1_b_mem_38954, struct memblock b2_tw_mem_38955, struct memblock b2_tb_mem_38956, struct memblock b2_c2_w_mem_38957, struct memblock b2_c2_b_mem_38958, struct memblock b3_c1_w_mem_38959, struct memblock b3_c1_b_mem_38960, struct memblock b3_tw_mem_38961, struct memblock b3_tb_mem_38962, struct memblock b3_c2_w_mem_38963, struct memblock b3_c2_b_mem_38964, struct memblock b4_c1_w_mem_38965, struct memblock b4_c1_b_mem_38966, struct memblock b4_tw_mem_38967, struct memblock b4_tb_mem_38968, struct memblock b4_c2_w_mem_38969, struct memblock b4_c2_b_mem_38970, struct memblock c_out_w_mem_38971, struct memblock c_out_b_mem_38972, int64_t dz2080U_26613, int64_t dz2081U_26614, int64_t dz2082U_26615, int64_t dz2083U_26616, int64_t dz2086U_26617, int64_t dz2087U_26618, int64_t dz2088U_26619, int64_t dz2081Uz2081U_26620, int64_t dz2081Uz2082U_26621, int64_t dz2081Uz2083U_26622, int64_t dz2082Uz2083U_26623, int64_t dz2081Uz2089U_26624, int64_t dz2082Uz2080U_26625, int64_t dz2082Uz2081U_26626, int64_t dz2082Uz2082U_26627, int64_t dz2082Uz2084U_26628, int64_t dz2082Uz2085U_26629, int64_t dz2083Uz2081U_26630, int64_t dz2083Uz2080U_26631, int64_t dz2083Uz2082U_26632, int64_t dz2083Uz2083U_26633, int64_t dz2083Uz2087U_26634, int64_t dz2083Uz2088U_26635, int64_t dz2083Uz2089U_26636, int64_t dz2084Uz2084U_26637, int64_t dz2084Uz2085U_26638, int64_t dz2084Uz2086U_26639, int64_t dz2084Uz2087U_26640, int64_t dz2085Uz2080U_26641, int64_t dz2085Uz2081U_26642, int64_t dz2085Uz2082U_26643, int64_t dz2086Uz2082U_26644, int64_t dz2085Uz2088U_26645, int64_t dz2085Uz2089U_26646, int64_t dz2086Uz2080U_26647, int64_t dz2086Uz2083U_26648, int64_t dz2086Uz2084U_26649, int64_t dz2086Uz2085U_26650)
{
    (void) ctx;
    
    int err = 0;
    int64_t mem_38974_cached_sizze_42953 = 0;
    unsigned char *mem_38974 = NULL;
    int64_t mem_38976_cached_sizze_42954 = 0;
    unsigned char *mem_38976 = NULL;
    int64_t mem_39006_cached_sizze_42955 = 0;
    unsigned char *mem_39006 = NULL;
    int64_t mem_39031_cached_sizze_42956 = 0;
    unsigned char *mem_39031 = NULL;
    int64_t mem_39033_cached_sizze_42957 = 0;
    unsigned char *mem_39033 = NULL;
    int64_t mem_39055_cached_sizze_42958 = 0;
    unsigned char *mem_39055 = NULL;
    int64_t mem_39095_cached_sizze_42959 = 0;
    unsigned char *mem_39095 = NULL;
    int64_t mem_39100_cached_sizze_42960 = 0;
    unsigned char *mem_39100 = NULL;
    int64_t mem_39161_cached_sizze_42961 = 0;
    unsigned char *mem_39161 = NULL;
    int64_t mem_39204_cached_sizze_42962 = 0;
    unsigned char *mem_39204 = NULL;
    int64_t mem_39291_cached_sizze_42963 = 0;
    unsigned char *mem_39291 = NULL;
    int64_t mem_39352_cached_sizze_42964 = 0;
    unsigned char *mem_39352 = NULL;
    int64_t mem_39398_cached_sizze_42965 = 0;
    unsigned char *mem_39398 = NULL;
    int64_t mem_39486_cached_sizze_42966 = 0;
    unsigned char *mem_39486 = NULL;
    int64_t mem_39517_cached_sizze_42967 = 0;
    unsigned char *mem_39517 = NULL;
    int64_t mem_39519_cached_sizze_42968 = 0;
    unsigned char *mem_39519 = NULL;
    int64_t mem_39544_cached_sizze_42969 = 0;
    unsigned char *mem_39544 = NULL;
    int64_t mem_39557_cached_sizze_42970 = 0;
    unsigned char *mem_39557 = NULL;
    int64_t mem_39671_cached_sizze_42971 = 0;
    unsigned char *mem_39671 = NULL;
    int64_t mem_39732_cached_sizze_42972 = 0;
    unsigned char *mem_39732 = NULL;
    int64_t mem_39778_cached_sizze_42973 = 0;
    unsigned char *mem_39778 = NULL;
    int64_t mem_39866_cached_sizze_42974 = 0;
    unsigned char *mem_39866 = NULL;
    int64_t mem_39897_cached_sizze_42975 = 0;
    unsigned char *mem_39897 = NULL;
    int64_t mem_39899_cached_sizze_42976 = 0;
    unsigned char *mem_39899 = NULL;
    int64_t mem_39924_cached_sizze_42977 = 0;
    unsigned char *mem_39924 = NULL;
    int64_t mem_39929_cached_sizze_42978 = 0;
    unsigned char *mem_39929 = NULL;
    int64_t mem_40098_cached_sizze_42979 = 0;
    unsigned char *mem_40098 = NULL;
    int64_t mem_40159_cached_sizze_42980 = 0;
    unsigned char *mem_40159 = NULL;
    int64_t mem_40205_cached_sizze_42981 = 0;
    unsigned char *mem_40205 = NULL;
    int64_t mem_40293_cached_sizze_42982 = 0;
    unsigned char *mem_40293 = NULL;
    int64_t mem_40324_cached_sizze_42983 = 0;
    unsigned char *mem_40324 = NULL;
    int64_t mem_40326_cached_sizze_42984 = 0;
    unsigned char *mem_40326 = NULL;
    int64_t mem_40351_cached_sizze_42985 = 0;
    unsigned char *mem_40351 = NULL;
    int64_t mem_40364_cached_sizze_42986 = 0;
    unsigned char *mem_40364 = NULL;
    int64_t mem_40478_cached_sizze_42987 = 0;
    unsigned char *mem_40478 = NULL;
    int64_t mem_40539_cached_sizze_42988 = 0;
    unsigned char *mem_40539 = NULL;
    int64_t mem_40585_cached_sizze_42989 = 0;
    unsigned char *mem_40585 = NULL;
    int64_t mem_40673_cached_sizze_42990 = 0;
    unsigned char *mem_40673 = NULL;
    int64_t mem_40704_cached_sizze_42991 = 0;
    unsigned char *mem_40704 = NULL;
    int64_t mem_40706_cached_sizze_42992 = 0;
    unsigned char *mem_40706 = NULL;
    int64_t mem_40731_cached_sizze_42993 = 0;
    unsigned char *mem_40731 = NULL;
    int64_t mem_40815_cached_sizze_42994 = 0;
    unsigned char *mem_40815 = NULL;
    int64_t mem_40902_cached_sizze_42995 = 0;
    unsigned char *mem_40902 = NULL;
    int64_t mem_40963_cached_sizze_42996 = 0;
    unsigned char *mem_40963 = NULL;
    int64_t mem_41009_cached_sizze_42997 = 0;
    unsigned char *mem_41009 = NULL;
    int64_t mem_41097_cached_sizze_42998 = 0;
    unsigned char *mem_41097 = NULL;
    int64_t mem_41128_cached_sizze_42999 = 0;
    unsigned char *mem_41128 = NULL;
    int64_t mem_41130_cached_sizze_43000 = 0;
    unsigned char *mem_41130 = NULL;
    int64_t mem_41155_cached_sizze_43001 = 0;
    unsigned char *mem_41155 = NULL;
    int64_t mem_41168_cached_sizze_43002 = 0;
    unsigned char *mem_41168 = NULL;
    int64_t mem_41282_cached_sizze_43003 = 0;
    unsigned char *mem_41282 = NULL;
    int64_t mem_41343_cached_sizze_43004 = 0;
    unsigned char *mem_41343 = NULL;
    int64_t mem_41389_cached_sizze_43005 = 0;
    unsigned char *mem_41389 = NULL;
    int64_t mem_41477_cached_sizze_43006 = 0;
    unsigned char *mem_41477 = NULL;
    int64_t mem_41508_cached_sizze_43007 = 0;
    unsigned char *mem_41508 = NULL;
    int64_t mem_41510_cached_sizze_43008 = 0;
    unsigned char *mem_41510 = NULL;
    int64_t mem_41535_cached_sizze_43009 = 0;
    unsigned char *mem_41535 = NULL;
    int64_t mem_41619_cached_sizze_43010 = 0;
    unsigned char *mem_41619 = NULL;
    int64_t mem_41706_cached_sizze_43011 = 0;
    unsigned char *mem_41706 = NULL;
    int64_t mem_41767_cached_sizze_43012 = 0;
    unsigned char *mem_41767 = NULL;
    int64_t mem_41813_cached_sizze_43013 = 0;
    unsigned char *mem_41813 = NULL;
    int64_t mem_41901_cached_sizze_43014 = 0;
    unsigned char *mem_41901 = NULL;
    int64_t mem_41932_cached_sizze_43015 = 0;
    unsigned char *mem_41932 = NULL;
    int64_t mem_41934_cached_sizze_43016 = 0;
    unsigned char *mem_41934 = NULL;
    int64_t mem_41959_cached_sizze_43017 = 0;
    unsigned char *mem_41959 = NULL;
    int64_t mem_41972_cached_sizze_43018 = 0;
    unsigned char *mem_41972 = NULL;
    int64_t mem_42086_cached_sizze_43019 = 0;
    unsigned char *mem_42086 = NULL;
    int64_t mem_42147_cached_sizze_43020 = 0;
    unsigned char *mem_42147 = NULL;
    int64_t mem_42193_cached_sizze_43021 = 0;
    unsigned char *mem_42193 = NULL;
    int64_t mem_42281_cached_sizze_43022 = 0;
    unsigned char *mem_42281 = NULL;
    int64_t mem_42312_cached_sizze_43023 = 0;
    unsigned char *mem_42312 = NULL;
    int64_t mem_42314_cached_sizze_43024 = 0;
    unsigned char *mem_42314 = NULL;
    int64_t mem_42339_cached_sizze_43025 = 0;
    unsigned char *mem_42339 = NULL;
    int64_t mem_42426_cached_sizze_43026 = 0;
    unsigned char *mem_42426 = NULL;
    int64_t mem_42487_cached_sizze_43027 = 0;
    unsigned char *mem_42487 = NULL;
    int64_t mem_42532_cached_sizze_43028 = 0;
    unsigned char *mem_42532 = NULL;
    int64_t mem_42548_cached_sizze_43029 = 0;
    unsigned char *mem_42548 = NULL;
    int64_t mem_42601_cached_sizze_43030 = 0;
    unsigned char *mem_42601 = NULL;
    struct memblock mem_42641;
    
    mem_42641.references = NULL;
    
    struct memblock mem_param_tmp_42752;
    
    mem_param_tmp_42752.references = NULL;
    
    struct memblock mem_42588;
    
    mem_42588.references = NULL;
    
    struct memblock mem_42530;
    
    mem_42530.references = NULL;
    
    struct memblock mem_42544;
    
    mem_42544.references = NULL;
    
    struct memblock ext_mem_42546;
    
    ext_mem_42546.references = NULL;
    
    struct memblock mem_param_39029;
    
    mem_param_39029.references = NULL;
    
    struct memblock ext_mem_42599;
    
    ext_mem_42599.references = NULL;
    
    struct memblock mem_39018;
    
    mem_39018.references = NULL;
    
    struct memblock mem_out_42736;
    
    mem_out_42736.references = NULL;
    
    int64_t arg_29125 = sub64((int64_t) 28, dz2086Uz2083U_26648);
    int64_t new_n_29126 = add64((int64_t) 1, arg_29125);
    int64_t arg_29127 = mul64(dz2086Uz2082U_26644, dz2086Uz2083U_26648);
    int64_t total_29128 = mul64(dz2086Uz2084U_26649, arg_29127);
    int64_t x_29136 = new_n_29126 * new_n_29126;
    int64_t arg_29503 = sub64((int64_t) 30, dz2086U_26617);
    int64_t new_n_29504 = add64((int64_t) 1, arg_29503);
    int64_t total_29510 = mul64(dz2086U_26617, dz2087U_26618);
    int64_t flat_dim_29613 = new_n_29504 * new_n_29504;
    int64_t arg_30218 = sub64((int64_t) 30, dz2081Uz2081U_26620);
    int64_t new_n_30219 = add64((int64_t) 1, arg_30218);
    int64_t arg_30223 = mul64((int64_t) 64, dz2081Uz2081U_26620);
    int64_t total_30224 = mul64(dz2081Uz2082U_26621, arg_30223);
    int64_t flat_dim_30312 = new_n_30219 * new_n_30219;
    int64_t elem_groups_30357 = sdiv64(dz2082Uz2083U_26623, (int64_t) 32);
    int64_t arg_30467 = sub64((int64_t) 30, dz2081Uz2089U_26624);
    int64_t new_n_30468 = add64((int64_t) 1, arg_30467);
    int64_t arg_30471 = mul64(dz2082Uz2083U_26623, dz2081Uz2089U_26624);
    int64_t total_30472 = mul64(dz2082Uz2080U_26625, arg_30471);
    int64_t flat_dim_30550 = new_n_30468 * new_n_30468;
    int64_t arg_30691 = sub64((int64_t) 30, dz2082Uz2084U_26628);
    int64_t new_n_30692 = add64((int64_t) 1, arg_30691);
    int64_t arg_30696 = mul64(dz2082Uz2083U_26623, dz2082Uz2084U_26628);
    int64_t total_30697 = mul64(dz2082Uz2085U_26629, arg_30696);
    int64_t flat_dim_30785 = new_n_30692 * new_n_30692;
    int64_t elem_groups_30830 = sdiv64(dz2083Uz2081U_26630, (int64_t) 32);
    int64_t arg_30940 = sub64((int64_t) 30, dz2083Uz2082U_26632);
    int64_t new_n_30941 = add64((int64_t) 1, arg_30940);
    int64_t arg_30944 = mul64(dz2083Uz2081U_26630, dz2083Uz2082U_26632);
    int64_t total_30945 = mul64(dz2083Uz2083U_26633, arg_30944);
    int64_t flat_dim_31023 = new_n_30941 * new_n_30941;
    int64_t arg_31164 = sub64((int64_t) 30, dz2083Uz2087U_26634);
    int64_t new_n_31165 = add64((int64_t) 1, arg_31164);
    int64_t arg_31169 = mul64((int64_t) 512, dz2083Uz2087U_26634);
    int64_t total_31170 = mul64(dz2083Uz2088U_26635, arg_31169);
    int64_t flat_dim_31258 = new_n_31165 * new_n_31165;
    int64_t elem_groups_31303 = sdiv64(dz2084Uz2084U_26637, (int64_t) 32);
    int64_t arg_31413 = sub64((int64_t) 30, dz2084Uz2085U_26638);
    int64_t new_n_31414 = add64((int64_t) 1, arg_31413);
    int64_t arg_31417 = mul64(dz2084Uz2084U_26637, dz2084Uz2085U_26638);
    int64_t total_31418 = mul64(dz2084Uz2086U_26639, arg_31417);
    int64_t flat_dim_31496 = new_n_31414 * new_n_31414;
    int64_t arg_31637 = sub64((int64_t) 30, dz2085Uz2080U_26641);
    int64_t new_n_31638 = add64((int64_t) 1, arg_31637);
    int64_t arg_31642 = mul64((int64_t) 256, dz2085Uz2080U_26641);
    int64_t total_31643 = mul64(dz2085Uz2081U_26642, arg_31642);
    int64_t flat_dim_31731 = new_n_31638 * new_n_31638;
    int64_t elem_groups_31776 = sdiv64(dz2086Uz2082U_26644, (int64_t) 32);
    int64_t arg_31886 = sub64((int64_t) 30, dz2085Uz2088U_26645);
    int64_t new_n_31887 = add64((int64_t) 1, arg_31886);
    int64_t arg_31890 = mul64(dz2086Uz2082U_26644, dz2085Uz2088U_26645);
    int64_t total_31891 = mul64(dz2085Uz2089U_26646, arg_31890);
    int64_t flat_dim_31969 = new_n_31887 * new_n_31887;
    int64_t binop_x_39097 = total_29510 * flat_dim_29613;
    int64_t binop_y_39098 = (int64_t) 8 * binop_x_39097;
    int64_t bytes_39099 = smax64((int64_t) 0, binop_y_39098);
    int64_t binop_x_39158 = dz2088U_26619 * flat_dim_29613;
    int64_t binop_y_39159 = (int64_t) 8 * binop_x_39158;
    int64_t bytes_39160 = smax64((int64_t) 0, binop_y_39159);
    int64_t binop_x_39288 = total_30224 * flat_dim_30312;
    int64_t binop_y_39289 = (int64_t) 8 * binop_x_39288;
    int64_t bytes_39290 = smax64((int64_t) 0, binop_y_39289);
    int64_t binop_x_39349 = dz2081Uz2083U_26622 * flat_dim_30312;
    int64_t binop_y_39350 = (int64_t) 8 * binop_x_39349;
    int64_t bytes_39351 = smax64((int64_t) 0, binop_y_39350);
    int64_t binop_y_39396 = (int64_t) 6272 * dz2082Uz2083U_26623;
    int64_t bytes_39397 = smax64((int64_t) 0, binop_y_39396);
    int64_t binop_y_39484 = (int64_t) 200704 * elem_groups_30357;
    int64_t bytes_39485 = smax64((int64_t) 0, binop_y_39484);
    int64_t binop_y_39542 = (int64_t) 7200 * dz2082Uz2083U_26623;
    int64_t bytes_39543 = smax64((int64_t) 0, binop_y_39542);
    int64_t binop_x_39668 = total_30472 * flat_dim_30550;
    int64_t binop_y_39669 = (int64_t) 8 * binop_x_39668;
    int64_t bytes_39670 = smax64((int64_t) 0, binop_y_39669);
    int64_t binop_x_39729 = dz2082Uz2081U_26626 * flat_dim_30550;
    int64_t binop_y_39730 = (int64_t) 8 * binop_x_39729;
    int64_t bytes_39731 = smax64((int64_t) 0, binop_y_39730);
    int64_t binop_x_40095 = total_30697 * flat_dim_30785;
    int64_t binop_y_40096 = (int64_t) 8 * binop_x_40095;
    int64_t bytes_40097 = smax64((int64_t) 0, binop_y_40096);
    int64_t binop_x_40156 = dz2082Uz2082U_26627 * flat_dim_30785;
    int64_t binop_y_40157 = (int64_t) 8 * binop_x_40156;
    int64_t bytes_40158 = smax64((int64_t) 0, binop_y_40157);
    int64_t binop_y_40203 = (int64_t) 6272 * dz2083Uz2081U_26630;
    int64_t bytes_40204 = smax64((int64_t) 0, binop_y_40203);
    int64_t binop_y_40291 = (int64_t) 200704 * elem_groups_30830;
    int64_t bytes_40292 = smax64((int64_t) 0, binop_y_40291);
    int64_t binop_y_40349 = (int64_t) 7200 * dz2083Uz2081U_26630;
    int64_t bytes_40350 = smax64((int64_t) 0, binop_y_40349);
    int64_t binop_x_40475 = total_30945 * flat_dim_31023;
    int64_t binop_y_40476 = (int64_t) 8 * binop_x_40475;
    int64_t bytes_40477 = smax64((int64_t) 0, binop_y_40476);
    int64_t binop_x_40536 = dz2083Uz2080U_26631 * flat_dim_31023;
    int64_t binop_y_40537 = (int64_t) 8 * binop_x_40536;
    int64_t bytes_40538 = smax64((int64_t) 0, binop_y_40537);
    int64_t binop_x_40899 = total_31170 * flat_dim_31258;
    int64_t binop_y_40900 = (int64_t) 8 * binop_x_40899;
    int64_t bytes_40901 = smax64((int64_t) 0, binop_y_40900);
    int64_t binop_x_40960 = dz2083Uz2089U_26636 * flat_dim_31258;
    int64_t binop_y_40961 = (int64_t) 8 * binop_x_40960;
    int64_t bytes_40962 = smax64((int64_t) 0, binop_y_40961);
    int64_t binop_y_41007 = (int64_t) 6272 * dz2084Uz2084U_26637;
    int64_t bytes_41008 = smax64((int64_t) 0, binop_y_41007);
    int64_t binop_y_41095 = (int64_t) 200704 * elem_groups_31303;
    int64_t bytes_41096 = smax64((int64_t) 0, binop_y_41095);
    int64_t binop_y_41153 = (int64_t) 7200 * dz2084Uz2084U_26637;
    int64_t bytes_41154 = smax64((int64_t) 0, binop_y_41153);
    int64_t binop_x_41279 = total_31418 * flat_dim_31496;
    int64_t binop_y_41280 = (int64_t) 8 * binop_x_41279;
    int64_t bytes_41281 = smax64((int64_t) 0, binop_y_41280);
    int64_t binop_x_41340 = dz2084Uz2087U_26640 * flat_dim_31496;
    int64_t binop_y_41341 = (int64_t) 8 * binop_x_41340;
    int64_t bytes_41342 = smax64((int64_t) 0, binop_y_41341);
    int64_t binop_x_41703 = total_31643 * flat_dim_31731;
    int64_t binop_y_41704 = (int64_t) 8 * binop_x_41703;
    int64_t bytes_41705 = smax64((int64_t) 0, binop_y_41704);
    int64_t binop_x_41764 = dz2085Uz2082U_26643 * flat_dim_31731;
    int64_t binop_y_41765 = (int64_t) 8 * binop_x_41764;
    int64_t bytes_41766 = smax64((int64_t) 0, binop_y_41765);
    int64_t binop_y_41811 = (int64_t) 6272 * dz2086Uz2082U_26644;
    int64_t bytes_41812 = smax64((int64_t) 0, binop_y_41811);
    int64_t binop_y_41899 = (int64_t) 200704 * elem_groups_31776;
    int64_t bytes_41900 = smax64((int64_t) 0, binop_y_41899);
    int64_t binop_y_41957 = (int64_t) 7200 * dz2086Uz2082U_26644;
    int64_t bytes_41958 = smax64((int64_t) 0, binop_y_41957);
    int64_t binop_x_42083 = total_31891 * flat_dim_31969;
    int64_t binop_y_42084 = (int64_t) 8 * binop_x_42083;
    int64_t bytes_42085 = smax64((int64_t) 0, binop_y_42084);
    int64_t binop_x_42144 = dz2086Uz2080U_26647 * flat_dim_31969;
    int64_t binop_y_42145 = (int64_t) 8 * binop_x_42144;
    int64_t bytes_42146 = smax64((int64_t) 0, binop_y_42145);
    int64_t binop_x_42423 = total_29128 * x_29136;
    int64_t binop_y_42424 = (int64_t) 8 * binop_x_42423;
    int64_t bytes_42425 = smax64((int64_t) 0, binop_y_42424);
    int64_t binop_x_42484 = dz2086Uz2085U_26650 * x_29136;
    int64_t binop_y_42485 = (int64_t) 8 * binop_x_42484;
    int64_t bytes_42486 = smax64((int64_t) 0, binop_y_42485);
    
    if (mem_38974_cached_sizze_42953 < (int64_t) 8000) {
        err = lexical_realloc(ctx, &mem_38974, &mem_38974_cached_sizze_42953, (int64_t) 8000);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_38976_cached_sizze_42954 < (int64_t) 4000) {
        err = lexical_realloc(ctx, &mem_38976, &mem_38976_cached_sizze_42954, (int64_t) 4000);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    
    double discard_34536;
    double scanacc_34530 = 1.0;
    
    for (int64_t i_34533 = 0; i_34533 < (int64_t) 1000; i_34533++) {
        double i64_res_32376 = sitofp_i64_f64(i_34533);
        double arg_32377 = 1.991991991991992e-5 * i64_res_32376;
        double defunc_0_f_res_32378 = 1.0e-4 + arg_32377;
        double defunc_0_f_res_32380 = 1.0 - defunc_0_f_res_32378;
        int32_t i64_res_32382 = sext_i64_i32(i_34533);
        int32_t arg_32383 = lshr32(i64_res_32382, 16);
        int32_t arg_32384 = i64_res_32382 ^ arg_32383;
        int32_t x_32385 = mul32(73244475, arg_32384);
        int32_t arg_32386 = lshr32(x_32385, 16);
        int32_t arg_32387 = x_32385 ^ arg_32386;
        int32_t x_32388 = mul32(73244475, arg_32387);
        int32_t arg_32389 = lshr32(x_32388, 16);
        int32_t x_32390 = x_32388 ^ arg_32389;
        int32_t unsign_arg_32391 = 800209864 ^ x_32390;
        int32_t unsign_arg_32393 = mul32(48271, unsign_arg_32391);
        int32_t unsign_arg_32394 = umod32(unsign_arg_32393, 2147483647);
        bool zgze_res_32395 = ule32(2147000000, unsign_arg_32394);
        bool defunc_0_f_res_f_res_32396;
        int32_t defunc_0_f_res_f_res_32397;
        int32_t defunc_0_f_res_f_res_32398;
        bool loop_while_32399;
        int32_t rng_32400;
        int32_t x_32401;
        
        loop_while_32399 = zgze_res_32395;
        rng_32400 = unsign_arg_32394;
        x_32401 = unsign_arg_32394;
        while (loop_while_32399) {
            int32_t unsign_arg_32402 = mul32(48271, rng_32400);
            int32_t unsign_arg_32403 = umod32(unsign_arg_32402, 2147483647);
            bool zgze_res_32404 = ule32(2147000000, unsign_arg_32403);
            bool loop_while_tmp_42740 = zgze_res_32404;
            int32_t rng_tmp_42741 = unsign_arg_32403;
            int32_t x_tmp_42742 = unsign_arg_32403;
            
            loop_while_32399 = loop_while_tmp_42740;
            rng_32400 = rng_tmp_42741;
            x_32401 = x_tmp_42742;
        }
        defunc_0_f_res_f_res_32396 = loop_while_32399;
        defunc_0_f_res_f_res_32397 = rng_32400;
        defunc_0_f_res_f_res_32398 = x_32401;
        
        int32_t unsign_arg_32405 = umod32(defunc_0_f_res_f_res_32398, 1000000);
        int64_t to_i64_res_32406 = zext_i32_i64(unsign_arg_32405);
        int32_t defunc_0_f_res_32408 = sext_i64_i32(to_i64_res_32406);
        int32_t unsign_arg_32410 = 5460 ^ defunc_0_f_res_32408;
        int32_t unsign_arg_32411 = mul32(48271, unsign_arg_32410);
        int32_t unsign_arg_32412 = umod32(unsign_arg_32411, 2147483647);
        int32_t unsign_arg_32413 = mul32(48271, unsign_arg_32412);
        int32_t unsign_arg_32414 = umod32(unsign_arg_32413, 2147483647);
        int32_t unsign_arg_32415 = mul32(48271, unsign_arg_32414);
        int32_t unsign_arg_32416 = umod32(unsign_arg_32415, 2147483647);
        bool zgze_res_32417 = ule32(2147000000, unsign_arg_32416);
        bool defunc_0_f_res_f_res_32418;
        int32_t defunc_0_f_res_f_res_32419;
        int32_t defunc_0_f_res_f_res_32420;
        bool loop_while_32421;
        int32_t rng_32422;
        int32_t x_32423;
        
        loop_while_32421 = zgze_res_32417;
        rng_32422 = unsign_arg_32416;
        x_32423 = unsign_arg_32416;
        while (loop_while_32421) {
            int32_t unsign_arg_32424 = mul32(48271, rng_32422);
            int32_t unsign_arg_32425 = umod32(unsign_arg_32424, 2147483647);
            bool zgze_res_32426 = ule32(2147000000, unsign_arg_32425);
            bool loop_while_tmp_42743 = zgze_res_32426;
            int32_t rng_tmp_42744 = unsign_arg_32425;
            int32_t x_tmp_42745 = unsign_arg_32425;
            
            loop_while_32421 = loop_while_tmp_42743;
            rng_32422 = rng_tmp_42744;
            x_32423 = x_tmp_42745;
        }
        defunc_0_f_res_f_res_32418 = loop_while_32421;
        defunc_0_f_res_f_res_32419 = rng_32422;
        defunc_0_f_res_f_res_32420 = x_32423;
        
        int32_t unsign_arg_32427 = umod32(defunc_0_f_res_f_res_32420, 1000000);
        int64_t to_i64_res_32428 = zext_i32_i64(unsign_arg_32427);
        int32_t defunc_0_f_res_32429 = sext_i64_i32(to_i64_res_32428);
        
        for (int64_t nest_i_42746 = 0; nest_i_42746 < (int64_t) 1; nest_i_42746++) {
            ((int32_t *) mem_38976)[i_34533 + nest_i_42746] = defunc_0_f_res_32429;
        }
        
        double defunc_0_op_res_29057 = defunc_0_f_res_32380 * scanacc_34530;
        
        ((double *) mem_38974)[i_34533] = defunc_0_op_res_29057;
        
        double scanacc_tmp_42737 = defunc_0_op_res_29057;
        
        scanacc_34530 = scanacc_tmp_42737;
    }
    discard_34536 = scanacc_34530;
    
    bool defunc_0_f_res_f_res_30055;
    int32_t defunc_0_f_res_f_res_30056;
    int32_t defunc_0_f_res_f_res_30057;
    bool loop_while_30058;
    int32_t rng_30059;
    int32_t x_30060;
    
    loop_while_30058 = 0;
    rng_30059 = 1090636210;
    x_30060 = 1090636210;
    while (loop_while_30058) {
        int32_t unsign_arg_30061 = mul32(48271, rng_30059);
        int32_t unsign_arg_30062 = umod32(unsign_arg_30061, 2147483647);
        bool zgze_res_30063 = ule32(2147000000, unsign_arg_30062);
        bool loop_while_tmp_42747 = zgze_res_30063;
        int32_t rng_tmp_42748 = unsign_arg_30062;
        int32_t x_tmp_42749 = unsign_arg_30062;
        
        loop_while_30058 = loop_while_tmp_42747;
        rng_30059 = rng_tmp_42748;
        x_30060 = x_tmp_42749;
    }
    defunc_0_f_res_f_res_30055 = loop_while_30058;
    defunc_0_f_res_f_res_30056 = rng_30059;
    defunc_0_f_res_f_res_30057 = x_30060;
    
    int32_t unsign_arg_30064 = umod32(defunc_0_f_res_f_res_30057, 1000000);
    int64_t to_i64_res_30065 = zext_i32_i64(unsign_arg_30064);
    int32_t defunc_0_f_res_30068 = sext_i64_i32(to_i64_res_30065);
    int32_t unsign_arg_30072 = 5460 ^ defunc_0_f_res_30068;
    int32_t unsign_arg_30073 = mul32(48271, unsign_arg_30072);
    int32_t unsign_arg_30074 = umod32(unsign_arg_30073, 2147483647);
    int32_t unsign_arg_30076 = mul32(48271, unsign_arg_30074);
    int32_t unsign_arg_30077 = umod32(unsign_arg_30076, 2147483647);
    
    if (mem_39006_cached_sizze_42955 < (int64_t) 6272) {
        err = lexical_realloc(ctx, &mem_39006, &mem_39006_cached_sizze_42955, (int64_t) 6272);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    for (int64_t i_34539 = 0; i_34539 < (int64_t) 784; i_34539++) {
        int32_t i64_res_32336 = sext_i64_i32(i_34539);
        int32_t arg_32337 = lshr32(i64_res_32336, 16);
        int32_t arg_32338 = i64_res_32336 ^ arg_32337;
        int32_t x_32339 = mul32(73244475, arg_32338);
        int32_t arg_32340 = lshr32(x_32339, 16);
        int32_t arg_32341 = x_32339 ^ arg_32340;
        int32_t x_32342 = mul32(73244475, arg_32341);
        int32_t arg_32343 = lshr32(x_32342, 16);
        int32_t x_32344 = x_32342 ^ arg_32343;
        int32_t unsign_arg_32345 = unsign_arg_30077 ^ x_32344;
        int32_t unsign_arg_32347 = mul32(48271, unsign_arg_32345);
        int32_t unsign_arg_32348 = umod32(unsign_arg_32347, 2147483647);
        int32_t unsign_arg_32349 = mul32(48271, unsign_arg_32348);
        int32_t unsign_arg_32350 = umod32(unsign_arg_32349, 2147483647);
        double u64_res_32351 = uitofp_i32_f64(unsign_arg_32348);
        double zs_res_32352 = u64_res_32351 / 2.147483647e9;
        double u64_res_32353 = uitofp_i32_f64(unsign_arg_32350);
        double zs_res_32354 = u64_res_32353 / 2.147483647e9;
        double log_res_32355 = futrts_log64(zs_res_32352);
        double zt_res_32356 = -2.0 * log_res_32355;
        double sqrt_res_32357 = futrts_sqrt64(zt_res_32356);
        double zt_res_32358 = 6.283185307179586 * zs_res_32354;
        double cos_res_32359 = futrts_cos64(zt_res_32358);
        double zt_res_32360 = sqrt_res_32357 * cos_res_32359;
        
        ((double *) mem_39006)[i_34539] = zt_res_32360;
    }
    if (memblock_alloc(ctx, &mem_39018, (int64_t) 6272, "mem_39018")) {
        err = 1;
        goto cleanup;
    }
    for (int64_t nest_i_42751 = 0; nest_i_42751 < (int64_t) 1; nest_i_42751++) {
        if ((int64_t) 6272 > 0)
            memmove(mem_39018.mem + nest_i_42751 * (int64_t) 784 * (int64_t) 8, mem_39006 + (int64_t) 0, (int64_t) 6272);
    }
    
    bool dim_match_29122 = (int64_t) 64 == dz2088U_26619;
    bool dim_match_29123 = (int64_t) 128 == dz2084Uz2084U_26637;
    bool empty_or_match_cert_29124;
    
    if (!dim_match_29123) {
        set_error(ctx, msgprintf("Error: %s%lld%s%lld%s%lld%s%lld%s%lld%s%lld%s\n\nBacktrace:\n%s", "Value of (core language) shape (", (long long) dz2084Uz2084U_26637, ", ", (long long) (int64_t) 28, ", ", (long long) (int64_t) 28, ") cannot match shape of type `[", (long long) (int64_t) 128, "][", (long long) (int64_t) 28, "][", (long long) (int64_t) 28, "]f64`.", "-> #0  ../unet/unet.fut:47:19-47\n   #1  diffusion.fut:66:23-72\n   #2  diffusion.fut:88:60-152\n   #3  /prelude/soacs.fut:59:9-10\n   #4  /prelude/array.fut:200:10-17\n   #5  diffusion.fut:88:52-153\n   #6  genfrom_w.fut:12:6-71\n   #7  genfrom_w.fut:7:1-12:71\n"));
        err = FUTHARK_PROGRAM_ERROR;
        goto cleanup;
    }
    
    bool y_29137 = slt64((int64_t) 0, dz2086Uz2085U_26650);
    bool index_certs_29138;
    
    if (!y_29137) {
        set_error(ctx, msgprintf("Error: %s%lld%s%lld%s\n\nBacktrace:\n%s", "Index [", (long long) (int64_t) 0, "] out of bounds for array of shape [", (long long) dz2086Uz2085U_26650, "].", "-> #0  ../unet/unet.fut:51:18-28\n   #1  diffusion.fut:66:23-72\n   #2  diffusion.fut:88:60-152\n   #3  /prelude/soacs.fut:59:9-10\n   #4  /prelude/array.fut:200:10-17\n   #5  diffusion.fut:88:52-153\n   #6  genfrom_w.fut:12:6-71\n   #7  genfrom_w.fut:7:1-12:71\n"));
        err = FUTHARK_PROGRAM_ERROR;
        goto cleanup;
    }
    
    bool dim_match_29139 = (int64_t) 28 == new_n_29126;
    bool match_29140 = dim_match_29139 && dim_match_29139;
    bool empty_or_match_cert_29141;
    
    if (!match_29140) {
        set_error(ctx, msgprintf("Error: %s%lld%s%lld%s%lld%s%lld%s\n\nBacktrace:\n%s", "Value of (core language) shape (", (long long) new_n_29126, ", ", (long long) new_n_29126, ") cannot match shape of type `[", (long long) (int64_t) 28, "][", (long long) (int64_t) 28, "]f64`.", "-> #0  ../unet/unet.fut:51:18-41\n   #1  diffusion.fut:66:23-72\n   #2  diffusion.fut:88:60-152\n   #3  /prelude/soacs.fut:59:9-10\n   #4  /prelude/array.fut:200:10-17\n   #5  diffusion.fut:88:52-153\n   #6  genfrom_w.fut:12:6-71\n   #7  genfrom_w.fut:7:1-12:71\n"));
        err = FUTHARK_PROGRAM_ERROR;
        goto cleanup;
    }
    
    int64_t k_total_29561 = mul64(dz2086U_26617, dz2086U_26617);
    bool bounds_invalid_upwards_29562 = slt64(new_n_29504, (int64_t) 0);
    bool valid_29563 = !bounds_invalid_upwards_29562;
    bool range_valid_c_29564;
    
    if (!valid_29563) {
        set_error(ctx, msgprintf("Error: %s%lld%s%lld%s%lld%s\n\nBacktrace:\n%s", "Range ", (long long) (int64_t) 0, "..", (long long) (int64_t) 1, "..<", (long long) new_n_29504, " is invalid.", "-> #0  /prelude/array.fut:95:3-10\n   #1  /prelude/array.fut:208:28-33\n   #2  ../layers/conv2d.fut:11:50-162\n   #3  ../layers/conv2d.fut:24:17-54\n"));
        err = FUTHARK_PROGRAM_ERROR;
        goto cleanup;
    }
    
    bool empty_slice_29570 = dz2086U_26617 == (int64_t) 0;
    int64_t m_29571 = sub64(dz2086U_26617, (int64_t) 1);
    bool dim_match_29610 = total_29510 == k_total_29561;
    bool empty_or_match_cert_29611;
    
    if (!dim_match_29610) {
        set_error(ctx, msgprintf("Error: %s%lld%s%lld%s\n\nBacktrace:\n%s", "Value of (core language) shape (", (long long) k_total_29561, ") cannot match shape of type `[", (long long) total_29510, "]f64`.", "-> #0  ../layers/conv2d.fut:11:60-161\n   #1  /prelude/soacs.fut:59:9-10\n   #2  /prelude/array.fut:200:10-17\n   #3  /prelude/functional.fut:39:61-65\n   #4  /prelude/soacs.fut:59:9-10\n   #5  /prelude/array.fut:208:27-34\n   #6  ../layers/conv2d.fut:11:50-162\n   #7  ../layers/conv2d.fut:24:17-54\n"));
        err = FUTHARK_PROGRAM_ERROR;
        goto cleanup;
    }
    
    bool dim_match_29171 = (int64_t) 28 == new_n_29504;
    bool y_29173 = dim_match_29122 && dim_match_29171;
    bool match_29174 = dim_match_29171 && y_29173;
    bool empty_or_match_cert_29175;
    
    if (!match_29174) {
        set_error(ctx, msgprintf("Error: %s%lld%s%lld%s%lld%s%lld%s%lld%s%lld%s\n\nBacktrace:\n%s", "Value of (core language) shape (", (long long) dz2088U_26619, ", ", (long long) new_n_29504, ", ", (long long) new_n_29504, ") cannot match shape of type `[", (long long) (int64_t) 64, "][", (long long) (int64_t) 28, "][", (long long) (int64_t) 28, "]f64`.", "-> #0  ../unet/unet.fut:42:37-84\n   #1  diffusion.fut:66:23-72\n   #2  diffusion.fut:88:60-152\n   #3  /prelude/soacs.fut:59:9-10\n   #4  /prelude/array.fut:200:10-17\n   #5  diffusion.fut:88:52-153\n   #6  genfrom_w.fut:12:6-71\n   #7  genfrom_w.fut:7:1-12:71\n"));
        err = FUTHARK_PROGRAM_ERROR;
        goto cleanup;
    }
    
    int64_t conc_tmp_29337 = dz2083Uz2081U_26630 + dz2083Uz2081U_26630;
    bool dim_match_29205 = (int64_t) 512 == conc_tmp_29337;
    bool empty_or_match_cert_29206;
    
    if (!dim_match_29205) {
        set_error(ctx, msgprintf("Error: %s%lld%s%lld%s%lld%s%lld%s\n\nBacktrace:\n%s", "Value of (core language) shape (", (long long) conc_tmp_29337, ", ", (long long) (int64_t) 28, ", ", (long long) (int64_t) 28, ") cannot match shape of type `[", (long long) (int64_t) 512, "]t`.", "-> #0  /prelude/array.fut:73:66-81\n   #1  ../unet/unet.fut:45:26-62\n   #2  diffusion.fut:66:23-72\n   #3  diffusion.fut:88:60-152\n   #4  /prelude/soacs.fut:59:9-10\n   #5  /prelude/array.fut:200:10-17\n   #6  diffusion.fut:88:52-153\n   #7  genfrom_w.fut:12:6-71\n   #8  genfrom_w.fut:7:1-12:71\n"));
        err = FUTHARK_PROGRAM_ERROR;
        goto cleanup;
    }
    
    int64_t conc_tmp_29344 = (int64_t) 128 + dz2082Uz2083U_26623;
    bool dim_match_29224 = (int64_t) 256 == conc_tmp_29344;
    bool empty_or_match_cert_29225;
    
    if (!dim_match_29224) {
        set_error(ctx, msgprintf("Error: %s%lld%s%lld%s%lld%s%lld%s\n\nBacktrace:\n%s", "Value of (core language) shape (", (long long) conc_tmp_29344, ", ", (long long) (int64_t) 28, ", ", (long long) (int64_t) 28, ") cannot match shape of type `[", (long long) (int64_t) 256, "]t`.", "-> #0  /prelude/array.fut:73:66-81\n   #1  ../unet/unet.fut:48:24-58\n   #2  diffusion.fut:66:23-72\n   #3  diffusion.fut:88:60-152\n   #4  /prelude/soacs.fut:59:9-10\n   #5  /prelude/array.fut:200:10-17\n   #6  diffusion.fut:88:52-153\n   #7  genfrom_w.fut:12:6-71\n   #8  genfrom_w.fut:7:1-12:71\n"));
        err = FUTHARK_PROGRAM_ERROR;
        goto cleanup;
    }
    
    int64_t k_total_29386 = mul64(dz2086Uz2083U_26648, dz2086Uz2083U_26648);
    bool bounds_invalid_upwards_29387 = slt64(new_n_29126, (int64_t) 0);
    bool valid_29388 = !bounds_invalid_upwards_29387;
    bool range_valid_c_29389;
    
    if (!valid_29388) {
        set_error(ctx, msgprintf("Error: %s%lld%s%lld%s%lld%s\n\nBacktrace:\n%s", "Range ", (long long) (int64_t) 0, "..", (long long) (int64_t) 1, "..<", (long long) new_n_29126, " is invalid.", "-> #0  /prelude/array.fut:95:3-10\n   #1  /prelude/array.fut:208:28-33\n   #2  ../layers/conv2d.fut:11:50-162\n"));
        err = FUTHARK_PROGRAM_ERROR;
        goto cleanup;
    }
    
    bool empty_slice_29395 = dz2086Uz2083U_26648 == (int64_t) 0;
    int64_t m_29396 = sub64(dz2086Uz2083U_26648, (int64_t) 1);
    int64_t flat_dim_29433 = dz2086Uz2082U_26644 * k_total_29386;
    bool dim_match_29435 = total_29128 == flat_dim_29433;
    bool empty_or_match_cert_29436;
    
    if (!dim_match_29435) {
        set_error(ctx, msgprintf("Error: %s%lld%s%lld%s\n\nBacktrace:\n%s", "Value of (core language) shape (", (long long) flat_dim_29433, ") cannot match shape of type `[", (long long) total_29128, "]f64`.", "-> #0  ../layers/conv2d.fut:11:60-161\n   #1  /prelude/soacs.fut:59:9-10\n   #2  /prelude/array.fut:200:10-17\n   #3  /prelude/functional.fut:39:61-65\n   #4  /prelude/soacs.fut:59:9-10\n   #5  /prelude/array.fut:208:27-34\n   #6  ../layers/conv2d.fut:11:50-162\n"));
        err = FUTHARK_PROGRAM_ERROR;
        goto cleanup;
    }
    
    int64_t k_total_30266 = mul64(dz2081Uz2081U_26620, dz2081Uz2081U_26620);
    bool bounds_invalid_upwards_30267 = slt64(new_n_30219, (int64_t) 0);
    bool valid_30268 = !bounds_invalid_upwards_30267;
    bool range_valid_c_30269;
    
    if (!valid_30268) {
        set_error(ctx, msgprintf("Error: %s%lld%s%lld%s%lld%s\n\nBacktrace:\n%s", "Range ", (long long) (int64_t) 0, "..", (long long) (int64_t) 1, "..<", (long long) new_n_30219, " is invalid.", "-> #0  /prelude/array.fut:95:3-10\n   #1  /prelude/array.fut:208:28-33\n   #2  ../layers/conv2d.fut:11:50-162\n   #3  ../layers/conv2d.fut:24:17-54\n"));
        err = FUTHARK_PROGRAM_ERROR;
        goto cleanup;
    }
    
    bool empty_slice_30275 = dz2081Uz2081U_26620 == (int64_t) 0;
    int64_t m_30276 = sub64(dz2081Uz2081U_26620, (int64_t) 1);
    int64_t flat_dim_30279 = (int64_t) 64 * k_total_30266;
    bool dim_match_30280 = total_30224 == flat_dim_30279;
    bool empty_or_match_cert_30281;
    
    if (!dim_match_30280) {
        set_error(ctx, msgprintf("Error: %s%lld%s%lld%s\n\nBacktrace:\n%s", "Value of (core language) shape (", (long long) flat_dim_30279, ") cannot match shape of type `[", (long long) total_30224, "]f64`.", "-> #0  ../layers/conv2d.fut:11:60-161\n   #1  /prelude/soacs.fut:59:9-10\n   #2  /prelude/array.fut:200:10-17\n   #3  /prelude/functional.fut:39:61-65\n   #4  /prelude/soacs.fut:59:9-10\n   #5  /prelude/array.fut:208:27-34\n   #6  ../layers/conv2d.fut:11:50-162\n   #7  ../layers/conv2d.fut:24:17-54\n"));
        err = FUTHARK_PROGRAM_ERROR;
        goto cleanup;
    }
    
    bool dim_match_30340 = dz2082Uz2083U_26623 == dz2081Uz2083U_26622;
    bool dim_match_30341 = (int64_t) 28 == new_n_30219;
    bool y_30343 = dim_match_30340 && dim_match_30341;
    bool match_30344 = dim_match_30341 && y_30343;
    bool empty_or_match_cert_30345;
    
    if (!match_30344) {
        set_error(ctx, msgprintf("Error: %s%lld%s%lld%s%lld%s%lld%s%lld%s%lld%s\n\nBacktrace:\n%s", "Value of (core language) shape (", (long long) dz2081Uz2083U_26622, ", ", (long long) new_n_30219, ", ", (long long) new_n_30219, ") cannot match shape of type `[", (long long) dz2082Uz2083U_26623, "][", (long long) (int64_t) 28, "][", (long long) (int64_t) 28, "]f64`.", "-> #0  ../unet/unet.fut:10:30-78\n"));
        err = FUTHARK_PROGRAM_ERROR;
        goto cleanup;
    }
    
    int64_t flat_dim_30385 = (int64_t) 784 * elem_groups_30357;
    double i64_res_30386 = sitofp_i64_f64(flat_dim_30385);
    bool zzero_30410 = elem_groups_30357 == (int64_t) 0;
    bool nonzzero_30411 = !zzero_30410;
    bool nonzzero_cert_30412;
    
    if (!nonzzero_30411) {
        set_error(ctx, msgprintf("Error: %s\n\nBacktrace:\n%s", "division by zero", "-> #0  ../layers/groupnorm.fut:22:70-84\n   #1  /prelude/soacs.fut:59:9-10\n   #2  /prelude/array.fut:200:10-17\n   #3  /prelude/functional.fut:39:61-65\n   #4  /prelude/soacs.fut:59:9-10\n   #5  /prelude/array.fut:208:27-34\n   #6  /prelude/functional.fut:39:61-65\n   #7  /prelude/soacs.fut:59:9-10\n   #8  /prelude/array.fut:216:32-39\n   #9  ../layers/groupnorm.fut:22:31-135\n"));
        err = FUTHARK_PROGRAM_ERROR;
        goto cleanup;
    }
    
    int64_t k_total_30504 = mul64(dz2081Uz2089U_26624, dz2081Uz2089U_26624);
    bool bounds_invalid_upwards_30505 = slt64(new_n_30468, (int64_t) 0);
    bool valid_30506 = !bounds_invalid_upwards_30505;
    bool range_valid_c_30507;
    
    if (!valid_30506) {
        set_error(ctx, msgprintf("Error: %s%lld%s%lld%s%lld%s\n\nBacktrace:\n%s", "Range ", (long long) (int64_t) 0, "..", (long long) (int64_t) 1, "..<", (long long) new_n_30468, " is invalid.", "-> #0  /prelude/array.fut:95:3-10\n   #1  /prelude/array.fut:208:28-33\n   #2  ../layers/conv2d.fut:11:50-162\n   #3  ../layers/conv2d.fut:24:17-54\n"));
        err = FUTHARK_PROGRAM_ERROR;
        goto cleanup;
    }
    
    bool empty_slice_30513 = dz2081Uz2089U_26624 == (int64_t) 0;
    int64_t m_30514 = sub64(dz2081Uz2089U_26624, (int64_t) 1);
    int64_t flat_dim_30517 = dz2082Uz2083U_26623 * k_total_30504;
    bool dim_match_30518 = total_30472 == flat_dim_30517;
    bool empty_or_match_cert_30519;
    
    if (!dim_match_30518) {
        set_error(ctx, msgprintf("Error: %s%lld%s%lld%s\n\nBacktrace:\n%s", "Value of (core language) shape (", (long long) flat_dim_30517, ") cannot match shape of type `[", (long long) total_30472, "]f64`.", "-> #0  ../layers/conv2d.fut:11:60-161\n   #1  /prelude/soacs.fut:59:9-10\n   #2  /prelude/array.fut:200:10-17\n   #3  /prelude/functional.fut:39:61-65\n   #4  /prelude/soacs.fut:59:9-10\n   #5  /prelude/array.fut:208:27-34\n   #6  ../layers/conv2d.fut:11:50-162\n   #7  ../layers/conv2d.fut:24:17-54\n"));
        err = FUTHARK_PROGRAM_ERROR;
        goto cleanup;
    }
    
    bool dim_match_30578 = dz2082Uz2083U_26623 == dz2082Uz2081U_26626;
    bool dim_match_30579 = (int64_t) 28 == new_n_30468;
    bool y_30581 = dim_match_30578 && dim_match_30579;
    bool match_30582 = dim_match_30579 && y_30581;
    bool empty_or_match_cert_30583;
    
    if (!match_30582) {
        set_error(ctx, msgprintf("Error: %s%lld%s%lld%s%lld%s%lld%s%lld%s%lld%s\n\nBacktrace:\n%s", "Value of (core language) shape (", (long long) dz2082Uz2081U_26626, ", ", (long long) new_n_30468, ", ", (long long) new_n_30468, ") cannot match shape of type `[", (long long) dz2082Uz2083U_26623, "][", (long long) (int64_t) 28, "][", (long long) (int64_t) 28, "]f64`.", "-> #0  ../unet/unet.fut:16:30-78\n"));
        err = FUTHARK_PROGRAM_ERROR;
        goto cleanup;
    }
    
    int64_t k_total_30739 = mul64(dz2082Uz2084U_26628, dz2082Uz2084U_26628);
    bool bounds_invalid_upwards_30740 = slt64(new_n_30692, (int64_t) 0);
    bool valid_30741 = !bounds_invalid_upwards_30740;
    bool range_valid_c_30742;
    
    if (!valid_30741) {
        set_error(ctx, msgprintf("Error: %s%lld%s%lld%s%lld%s\n\nBacktrace:\n%s", "Range ", (long long) (int64_t) 0, "..", (long long) (int64_t) 1, "..<", (long long) new_n_30692, " is invalid.", "-> #0  /prelude/array.fut:95:3-10\n   #1  /prelude/array.fut:208:28-33\n   #2  ../layers/conv2d.fut:11:50-162\n   #3  ../layers/conv2d.fut:24:17-54\n"));
        err = FUTHARK_PROGRAM_ERROR;
        goto cleanup;
    }
    
    bool empty_slice_30748 = dz2082Uz2084U_26628 == (int64_t) 0;
    int64_t m_30749 = sub64(dz2082Uz2084U_26628, (int64_t) 1);
    int64_t flat_dim_30752 = dz2082Uz2083U_26623 * k_total_30739;
    bool dim_match_30753 = total_30697 == flat_dim_30752;
    bool empty_or_match_cert_30754;
    
    if (!dim_match_30753) {
        set_error(ctx, msgprintf("Error: %s%lld%s%lld%s\n\nBacktrace:\n%s", "Value of (core language) shape (", (long long) flat_dim_30752, ") cannot match shape of type `[", (long long) total_30697, "]f64`.", "-> #0  ../layers/conv2d.fut:11:60-161\n   #1  /prelude/soacs.fut:59:9-10\n   #2  /prelude/array.fut:200:10-17\n   #3  /prelude/functional.fut:39:61-65\n   #4  /prelude/soacs.fut:59:9-10\n   #5  /prelude/array.fut:208:27-34\n   #6  ../layers/conv2d.fut:11:50-162\n   #7  ../layers/conv2d.fut:24:17-54\n"));
        err = FUTHARK_PROGRAM_ERROR;
        goto cleanup;
    }
    
    bool dim_match_30813 = dz2083Uz2081U_26630 == dz2082Uz2082U_26627;
    bool dim_match_30814 = (int64_t) 28 == new_n_30692;
    bool y_30816 = dim_match_30813 && dim_match_30814;
    bool match_30817 = dim_match_30814 && y_30816;
    bool empty_or_match_cert_30818;
    
    if (!match_30817) {
        set_error(ctx, msgprintf("Error: %s%lld%s%lld%s%lld%s%lld%s%lld%s%lld%s\n\nBacktrace:\n%s", "Value of (core language) shape (", (long long) dz2082Uz2082U_26627, ", ", (long long) new_n_30692, ", ", (long long) new_n_30692, ") cannot match shape of type `[", (long long) dz2083Uz2081U_26630, "][", (long long) (int64_t) 28, "][", (long long) (int64_t) 28, "]f64`.", "-> #0  ../unet/unet.fut:10:30-78\n"));
        err = FUTHARK_PROGRAM_ERROR;
        goto cleanup;
    }
    
    int64_t flat_dim_30858 = (int64_t) 784 * elem_groups_30830;
    double i64_res_30859 = sitofp_i64_f64(flat_dim_30858);
    bool zzero_30883 = elem_groups_30830 == (int64_t) 0;
    bool nonzzero_30884 = !zzero_30883;
    bool nonzzero_cert_30885;
    
    if (!nonzzero_30884) {
        set_error(ctx, msgprintf("Error: %s\n\nBacktrace:\n%s", "division by zero", "-> #0  ../layers/groupnorm.fut:22:70-84\n   #1  /prelude/soacs.fut:59:9-10\n   #2  /prelude/array.fut:200:10-17\n   #3  /prelude/functional.fut:39:61-65\n   #4  /prelude/soacs.fut:59:9-10\n   #5  /prelude/array.fut:208:27-34\n   #6  /prelude/functional.fut:39:61-65\n   #7  /prelude/soacs.fut:59:9-10\n   #8  /prelude/array.fut:216:32-39\n   #9  ../layers/groupnorm.fut:22:31-135\n"));
        err = FUTHARK_PROGRAM_ERROR;
        goto cleanup;
    }
    
    int64_t k_total_30977 = mul64(dz2083Uz2082U_26632, dz2083Uz2082U_26632);
    bool bounds_invalid_upwards_30978 = slt64(new_n_30941, (int64_t) 0);
    bool valid_30979 = !bounds_invalid_upwards_30978;
    bool range_valid_c_30980;
    
    if (!valid_30979) {
        set_error(ctx, msgprintf("Error: %s%lld%s%lld%s%lld%s\n\nBacktrace:\n%s", "Range ", (long long) (int64_t) 0, "..", (long long) (int64_t) 1, "..<", (long long) new_n_30941, " is invalid.", "-> #0  /prelude/array.fut:95:3-10\n   #1  /prelude/array.fut:208:28-33\n   #2  ../layers/conv2d.fut:11:50-162\n   #3  ../layers/conv2d.fut:24:17-54\n"));
        err = FUTHARK_PROGRAM_ERROR;
        goto cleanup;
    }
    
    bool empty_slice_30986 = dz2083Uz2082U_26632 == (int64_t) 0;
    int64_t m_30987 = sub64(dz2083Uz2082U_26632, (int64_t) 1);
    int64_t flat_dim_30990 = dz2083Uz2081U_26630 * k_total_30977;
    bool dim_match_30991 = total_30945 == flat_dim_30990;
    bool empty_or_match_cert_30992;
    
    if (!dim_match_30991) {
        set_error(ctx, msgprintf("Error: %s%lld%s%lld%s\n\nBacktrace:\n%s", "Value of (core language) shape (", (long long) flat_dim_30990, ") cannot match shape of type `[", (long long) total_30945, "]f64`.", "-> #0  ../layers/conv2d.fut:11:60-161\n   #1  /prelude/soacs.fut:59:9-10\n   #2  /prelude/array.fut:200:10-17\n   #3  /prelude/functional.fut:39:61-65\n   #4  /prelude/soacs.fut:59:9-10\n   #5  /prelude/array.fut:208:27-34\n   #6  ../layers/conv2d.fut:11:50-162\n   #7  ../layers/conv2d.fut:24:17-54\n"));
        err = FUTHARK_PROGRAM_ERROR;
        goto cleanup;
    }
    
    bool dim_match_31051 = dz2083Uz2081U_26630 == dz2083Uz2080U_26631;
    bool dim_match_31052 = (int64_t) 28 == new_n_30941;
    bool y_31054 = dim_match_31051 && dim_match_31052;
    bool match_31055 = dim_match_31052 && y_31054;
    bool empty_or_match_cert_31056;
    
    if (!match_31055) {
        set_error(ctx, msgprintf("Error: %s%lld%s%lld%s%lld%s%lld%s%lld%s%lld%s\n\nBacktrace:\n%s", "Value of (core language) shape (", (long long) dz2083Uz2080U_26631, ", ", (long long) new_n_30941, ", ", (long long) new_n_30941, ") cannot match shape of type `[", (long long) dz2083Uz2081U_26630, "][", (long long) (int64_t) 28, "][", (long long) (int64_t) 28, "]f64`.", "-> #0  ../unet/unet.fut:16:30-78\n"));
        err = FUTHARK_PROGRAM_ERROR;
        goto cleanup;
    }
    
    int64_t k_total_31212 = mul64(dz2083Uz2087U_26634, dz2083Uz2087U_26634);
    bool bounds_invalid_upwards_31213 = slt64(new_n_31165, (int64_t) 0);
    bool valid_31214 = !bounds_invalid_upwards_31213;
    bool range_valid_c_31215;
    
    if (!valid_31214) {
        set_error(ctx, msgprintf("Error: %s%lld%s%lld%s%lld%s\n\nBacktrace:\n%s", "Range ", (long long) (int64_t) 0, "..", (long long) (int64_t) 1, "..<", (long long) new_n_31165, " is invalid.", "-> #0  /prelude/array.fut:95:3-10\n   #1  /prelude/array.fut:208:28-33\n   #2  ../layers/conv2d.fut:11:50-162\n   #3  ../layers/conv2d.fut:24:17-54\n"));
        err = FUTHARK_PROGRAM_ERROR;
        goto cleanup;
    }
    
    bool empty_slice_31221 = dz2083Uz2087U_26634 == (int64_t) 0;
    int64_t m_31222 = sub64(dz2083Uz2087U_26634, (int64_t) 1);
    int64_t flat_dim_31225 = (int64_t) 512 * k_total_31212;
    bool dim_match_31226 = total_31170 == flat_dim_31225;
    bool empty_or_match_cert_31227;
    
    if (!dim_match_31226) {
        set_error(ctx, msgprintf("Error: %s%lld%s%lld%s\n\nBacktrace:\n%s", "Value of (core language) shape (", (long long) flat_dim_31225, ") cannot match shape of type `[", (long long) total_31170, "]f64`.", "-> #0  ../layers/conv2d.fut:11:60-161\n   #1  /prelude/soacs.fut:59:9-10\n   #2  /prelude/array.fut:200:10-17\n   #3  /prelude/functional.fut:39:61-65\n   #4  /prelude/soacs.fut:59:9-10\n   #5  /prelude/array.fut:208:27-34\n   #6  ../layers/conv2d.fut:11:50-162\n   #7  ../layers/conv2d.fut:24:17-54\n"));
        err = FUTHARK_PROGRAM_ERROR;
        goto cleanup;
    }
    
    bool dim_match_31286 = dz2084Uz2084U_26637 == dz2083Uz2089U_26636;
    bool dim_match_31287 = (int64_t) 28 == new_n_31165;
    bool y_31289 = dim_match_31286 && dim_match_31287;
    bool match_31290 = dim_match_31287 && y_31289;
    bool empty_or_match_cert_31291;
    
    if (!match_31290) {
        set_error(ctx, msgprintf("Error: %s%lld%s%lld%s%lld%s%lld%s%lld%s%lld%s\n\nBacktrace:\n%s", "Value of (core language) shape (", (long long) dz2083Uz2089U_26636, ", ", (long long) new_n_31165, ", ", (long long) new_n_31165, ") cannot match shape of type `[", (long long) dz2084Uz2084U_26637, "][", (long long) (int64_t) 28, "][", (long long) (int64_t) 28, "]f64`.", "-> #0  ../unet/unet.fut:10:30-78\n"));
        err = FUTHARK_PROGRAM_ERROR;
        goto cleanup;
    }
    
    int64_t flat_dim_31331 = (int64_t) 784 * elem_groups_31303;
    double i64_res_31332 = sitofp_i64_f64(flat_dim_31331);
    bool zzero_31356 = elem_groups_31303 == (int64_t) 0;
    bool nonzzero_31357 = !zzero_31356;
    bool nonzzero_cert_31358;
    
    if (!nonzzero_31357) {
        set_error(ctx, msgprintf("Error: %s\n\nBacktrace:\n%s", "division by zero", "-> #0  ../layers/groupnorm.fut:22:70-84\n   #1  /prelude/soacs.fut:59:9-10\n   #2  /prelude/array.fut:200:10-17\n   #3  /prelude/functional.fut:39:61-65\n   #4  /prelude/soacs.fut:59:9-10\n   #5  /prelude/array.fut:208:27-34\n   #6  /prelude/functional.fut:39:61-65\n   #7  /prelude/soacs.fut:59:9-10\n   #8  /prelude/array.fut:216:32-39\n   #9  ../layers/groupnorm.fut:22:31-135\n"));
        err = FUTHARK_PROGRAM_ERROR;
        goto cleanup;
    }
    
    int64_t k_total_31450 = mul64(dz2084Uz2085U_26638, dz2084Uz2085U_26638);
    bool bounds_invalid_upwards_31451 = slt64(new_n_31414, (int64_t) 0);
    bool valid_31452 = !bounds_invalid_upwards_31451;
    bool range_valid_c_31453;
    
    if (!valid_31452) {
        set_error(ctx, msgprintf("Error: %s%lld%s%lld%s%lld%s\n\nBacktrace:\n%s", "Range ", (long long) (int64_t) 0, "..", (long long) (int64_t) 1, "..<", (long long) new_n_31414, " is invalid.", "-> #0  /prelude/array.fut:95:3-10\n   #1  /prelude/array.fut:208:28-33\n   #2  ../layers/conv2d.fut:11:50-162\n   #3  ../layers/conv2d.fut:24:17-54\n"));
        err = FUTHARK_PROGRAM_ERROR;
        goto cleanup;
    }
    
    bool empty_slice_31459 = dz2084Uz2085U_26638 == (int64_t) 0;
    int64_t m_31460 = sub64(dz2084Uz2085U_26638, (int64_t) 1);
    int64_t flat_dim_31463 = dz2084Uz2084U_26637 * k_total_31450;
    bool dim_match_31464 = total_31418 == flat_dim_31463;
    bool empty_or_match_cert_31465;
    
    if (!dim_match_31464) {
        set_error(ctx, msgprintf("Error: %s%lld%s%lld%s\n\nBacktrace:\n%s", "Value of (core language) shape (", (long long) flat_dim_31463, ") cannot match shape of type `[", (long long) total_31418, "]f64`.", "-> #0  ../layers/conv2d.fut:11:60-161\n   #1  /prelude/soacs.fut:59:9-10\n   #2  /prelude/array.fut:200:10-17\n   #3  /prelude/functional.fut:39:61-65\n   #4  /prelude/soacs.fut:59:9-10\n   #5  /prelude/array.fut:208:27-34\n   #6  ../layers/conv2d.fut:11:50-162\n   #7  ../layers/conv2d.fut:24:17-54\n"));
        err = FUTHARK_PROGRAM_ERROR;
        goto cleanup;
    }
    
    bool dim_match_31524 = dz2084Uz2084U_26637 == dz2084Uz2087U_26640;
    bool dim_match_31525 = (int64_t) 28 == new_n_31414;
    bool y_31527 = dim_match_31524 && dim_match_31525;
    bool match_31528 = dim_match_31525 && y_31527;
    bool empty_or_match_cert_31529;
    
    if (!match_31528) {
        set_error(ctx, msgprintf("Error: %s%lld%s%lld%s%lld%s%lld%s%lld%s%lld%s\n\nBacktrace:\n%s", "Value of (core language) shape (", (long long) dz2084Uz2087U_26640, ", ", (long long) new_n_31414, ", ", (long long) new_n_31414, ") cannot match shape of type `[", (long long) dz2084Uz2084U_26637, "][", (long long) (int64_t) 28, "][", (long long) (int64_t) 28, "]f64`.", "-> #0  ../unet/unet.fut:16:30-78\n"));
        err = FUTHARK_PROGRAM_ERROR;
        goto cleanup;
    }
    
    int64_t k_total_31685 = mul64(dz2085Uz2080U_26641, dz2085Uz2080U_26641);
    bool bounds_invalid_upwards_31686 = slt64(new_n_31638, (int64_t) 0);
    bool valid_31687 = !bounds_invalid_upwards_31686;
    bool range_valid_c_31688;
    
    if (!valid_31687) {
        set_error(ctx, msgprintf("Error: %s%lld%s%lld%s%lld%s\n\nBacktrace:\n%s", "Range ", (long long) (int64_t) 0, "..", (long long) (int64_t) 1, "..<", (long long) new_n_31638, " is invalid.", "-> #0  /prelude/array.fut:95:3-10\n   #1  /prelude/array.fut:208:28-33\n   #2  ../layers/conv2d.fut:11:50-162\n   #3  ../layers/conv2d.fut:24:17-54\n"));
        err = FUTHARK_PROGRAM_ERROR;
        goto cleanup;
    }
    
    bool empty_slice_31694 = dz2085Uz2080U_26641 == (int64_t) 0;
    int64_t m_31695 = sub64(dz2085Uz2080U_26641, (int64_t) 1);
    int64_t flat_dim_31698 = (int64_t) 256 * k_total_31685;
    bool dim_match_31699 = total_31643 == flat_dim_31698;
    bool empty_or_match_cert_31700;
    
    if (!dim_match_31699) {
        set_error(ctx, msgprintf("Error: %s%lld%s%lld%s\n\nBacktrace:\n%s", "Value of (core language) shape (", (long long) flat_dim_31698, ") cannot match shape of type `[", (long long) total_31643, "]f64`.", "-> #0  ../layers/conv2d.fut:11:60-161\n   #1  /prelude/soacs.fut:59:9-10\n   #2  /prelude/array.fut:200:10-17\n   #3  /prelude/functional.fut:39:61-65\n   #4  /prelude/soacs.fut:59:9-10\n   #5  /prelude/array.fut:208:27-34\n   #6  ../layers/conv2d.fut:11:50-162\n   #7  ../layers/conv2d.fut:24:17-54\n"));
        err = FUTHARK_PROGRAM_ERROR;
        goto cleanup;
    }
    
    bool dim_match_31759 = dz2086Uz2082U_26644 == dz2085Uz2082U_26643;
    bool dim_match_31760 = (int64_t) 28 == new_n_31638;
    bool y_31762 = dim_match_31759 && dim_match_31760;
    bool match_31763 = dim_match_31760 && y_31762;
    bool empty_or_match_cert_31764;
    
    if (!match_31763) {
        set_error(ctx, msgprintf("Error: %s%lld%s%lld%s%lld%s%lld%s%lld%s%lld%s\n\nBacktrace:\n%s", "Value of (core language) shape (", (long long) dz2085Uz2082U_26643, ", ", (long long) new_n_31638, ", ", (long long) new_n_31638, ") cannot match shape of type `[", (long long) dz2086Uz2082U_26644, "][", (long long) (int64_t) 28, "][", (long long) (int64_t) 28, "]f64`.", "-> #0  ../unet/unet.fut:10:30-78\n"));
        err = FUTHARK_PROGRAM_ERROR;
        goto cleanup;
    }
    
    int64_t flat_dim_31804 = (int64_t) 784 * elem_groups_31776;
    double i64_res_31805 = sitofp_i64_f64(flat_dim_31804);
    bool zzero_31829 = elem_groups_31776 == (int64_t) 0;
    bool nonzzero_31830 = !zzero_31829;
    bool nonzzero_cert_31831;
    
    if (!nonzzero_31830) {
        set_error(ctx, msgprintf("Error: %s\n\nBacktrace:\n%s", "division by zero", "-> #0  ../layers/groupnorm.fut:22:70-84\n   #1  /prelude/soacs.fut:59:9-10\n   #2  /prelude/array.fut:200:10-17\n   #3  /prelude/functional.fut:39:61-65\n   #4  /prelude/soacs.fut:59:9-10\n   #5  /prelude/array.fut:208:27-34\n   #6  /prelude/functional.fut:39:61-65\n   #7  /prelude/soacs.fut:59:9-10\n   #8  /prelude/array.fut:216:32-39\n   #9  ../layers/groupnorm.fut:22:31-135\n"));
        err = FUTHARK_PROGRAM_ERROR;
        goto cleanup;
    }
    
    int64_t k_total_31923 = mul64(dz2085Uz2088U_26645, dz2085Uz2088U_26645);
    bool bounds_invalid_upwards_31924 = slt64(new_n_31887, (int64_t) 0);
    bool valid_31925 = !bounds_invalid_upwards_31924;
    bool range_valid_c_31926;
    
    if (!valid_31925) {
        set_error(ctx, msgprintf("Error: %s%lld%s%lld%s%lld%s\n\nBacktrace:\n%s", "Range ", (long long) (int64_t) 0, "..", (long long) (int64_t) 1, "..<", (long long) new_n_31887, " is invalid.", "-> #0  /prelude/array.fut:95:3-10\n   #1  /prelude/array.fut:208:28-33\n   #2  ../layers/conv2d.fut:11:50-162\n   #3  ../layers/conv2d.fut:24:17-54\n"));
        err = FUTHARK_PROGRAM_ERROR;
        goto cleanup;
    }
    
    bool empty_slice_31932 = dz2085Uz2088U_26645 == (int64_t) 0;
    int64_t m_31933 = sub64(dz2085Uz2088U_26645, (int64_t) 1);
    int64_t flat_dim_31936 = dz2086Uz2082U_26644 * k_total_31923;
    bool dim_match_31937 = total_31891 == flat_dim_31936;
    bool empty_or_match_cert_31938;
    
    if (!dim_match_31937) {
        set_error(ctx, msgprintf("Error: %s%lld%s%lld%s\n\nBacktrace:\n%s", "Value of (core language) shape (", (long long) flat_dim_31936, ") cannot match shape of type `[", (long long) total_31891, "]f64`.", "-> #0  ../layers/conv2d.fut:11:60-161\n   #1  /prelude/soacs.fut:59:9-10\n   #2  /prelude/array.fut:200:10-17\n   #3  /prelude/functional.fut:39:61-65\n   #4  /prelude/soacs.fut:59:9-10\n   #5  /prelude/array.fut:208:27-34\n   #6  ../layers/conv2d.fut:11:50-162\n   #7  ../layers/conv2d.fut:24:17-54\n"));
        err = FUTHARK_PROGRAM_ERROR;
        goto cleanup;
    }
    
    bool dim_match_31997 = dz2086Uz2082U_26644 == dz2086Uz2080U_26647;
    bool dim_match_31998 = (int64_t) 28 == new_n_31887;
    bool y_32000 = dim_match_31997 && dim_match_31998;
    bool match_32001 = dim_match_31998 && y_32000;
    bool empty_or_match_cert_32002;
    
    if (!match_32001) {
        set_error(ctx, msgprintf("Error: %s%lld%s%lld%s%lld%s%lld%s%lld%s%lld%s\n\nBacktrace:\n%s", "Value of (core language) shape (", (long long) dz2086Uz2080U_26647, ", ", (long long) new_n_31887, ", ", (long long) new_n_31887, ") cannot match shape of type `[", (long long) dz2086Uz2082U_26644, "][", (long long) (int64_t) 28, "][", (long long) (int64_t) 28, "]f64`.", "-> #0  ../unet/unet.fut:16:30-78\n"));
        err = FUTHARK_PROGRAM_ERROR;
        goto cleanup;
    }
    
    int64_t binop_y_38368 = new_n_29504 * total_29510;
    int64_t binop_y_38140 = dz2081Uz2081U_26620 * dz2081Uz2082U_26621;
    int64_t binop_y_38229 = new_n_30219 * total_30224;
    int64_t binop_y_37794 = dz2081Uz2089U_26624 * dz2082Uz2080U_26625;
    int64_t binop_y_37883 = new_n_30468 * total_30472;
    int64_t binop_y_37448 = dz2082Uz2084U_26628 * dz2082Uz2085U_26629;
    int64_t binop_y_37537 = new_n_30692 * total_30697;
    int64_t binop_y_37102 = dz2083Uz2082U_26632 * dz2083Uz2083U_26633;
    int64_t binop_y_37191 = new_n_30941 * total_30945;
    int64_t binop_y_36756 = dz2083Uz2087U_26634 * dz2083Uz2088U_26635;
    int64_t binop_y_36845 = new_n_31165 * total_31170;
    int64_t binop_y_36410 = dz2084Uz2085U_26638 * dz2084Uz2086U_26639;
    int64_t binop_y_36499 = new_n_31414 * total_31418;
    int64_t binop_y_36064 = dz2085Uz2080U_26641 * dz2085Uz2081U_26642;
    int64_t binop_y_36153 = new_n_31638 * total_31643;
    int64_t binop_y_35718 = dz2085Uz2088U_26645 * dz2085Uz2089U_26646;
    int64_t binop_y_35807 = new_n_31887 * total_31891;
    int64_t binop_y_35372 = dz2086Uz2083U_26648 * dz2086Uz2084U_26649;
    int64_t binop_y_35461 = new_n_29126 * total_29128;
    
    if (mem_39031_cached_sizze_42956 < (int64_t) 1024) {
        err = lexical_realloc(ctx, &mem_39031, &mem_39031_cached_sizze_42956, (int64_t) 1024);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_39033_cached_sizze_42957 < (int64_t) 1024) {
        err = lexical_realloc(ctx, &mem_39033, &mem_39033_cached_sizze_42957, (int64_t) 1024);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_39055_cached_sizze_42958 < (int64_t) 7200) {
        err = lexical_realloc(ctx, &mem_39055, &mem_39055_cached_sizze_42958, (int64_t) 7200);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_39095_cached_sizze_42959 < (int64_t) 7200) {
        err = lexical_realloc(ctx, &mem_39095, &mem_39095_cached_sizze_42959, (int64_t) 7200);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_39100_cached_sizze_42960 < bytes_39099) {
        err = lexical_realloc(ctx, &mem_39100, &mem_39100_cached_sizze_42960, bytes_39099);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_39161_cached_sizze_42961 < bytes_39160) {
        err = lexical_realloc(ctx, &mem_39161, &mem_39161_cached_sizze_42961, bytes_39160);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_39204_cached_sizze_42962 < (int64_t) 460800) {
        err = lexical_realloc(ctx, &mem_39204, &mem_39204_cached_sizze_42962, (int64_t) 460800);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_39291_cached_sizze_42963 < bytes_39290) {
        err = lexical_realloc(ctx, &mem_39291, &mem_39291_cached_sizze_42963, bytes_39290);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_39352_cached_sizze_42964 < bytes_39351) {
        err = lexical_realloc(ctx, &mem_39352, &mem_39352_cached_sizze_42964, bytes_39351);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_39398_cached_sizze_42965 < bytes_39397) {
        err = lexical_realloc(ctx, &mem_39398, &mem_39398_cached_sizze_42965, bytes_39397);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_39486_cached_sizze_42966 < bytes_39485) {
        err = lexical_realloc(ctx, &mem_39486, &mem_39486_cached_sizze_42966, bytes_39485);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_39517_cached_sizze_42967 < (int64_t) 256) {
        err = lexical_realloc(ctx, &mem_39517, &mem_39517_cached_sizze_42967, (int64_t) 256);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_39519_cached_sizze_42968 < (int64_t) 256) {
        err = lexical_realloc(ctx, &mem_39519, &mem_39519_cached_sizze_42968, (int64_t) 256);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_39544_cached_sizze_42969 < bytes_39543) {
        err = lexical_realloc(ctx, &mem_39544, &mem_39544_cached_sizze_42969, bytes_39543);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_39557_cached_sizze_42970 < (int64_t) 6272) {
        err = lexical_realloc(ctx, &mem_39557, &mem_39557_cached_sizze_42970, (int64_t) 6272);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_39671_cached_sizze_42971 < bytes_39670) {
        err = lexical_realloc(ctx, &mem_39671, &mem_39671_cached_sizze_42971, bytes_39670);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_39732_cached_sizze_42972 < bytes_39731) {
        err = lexical_realloc(ctx, &mem_39732, &mem_39732_cached_sizze_42972, bytes_39731);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_39778_cached_sizze_42973 < bytes_39397) {
        err = lexical_realloc(ctx, &mem_39778, &mem_39778_cached_sizze_42973, bytes_39397);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_39866_cached_sizze_42974 < bytes_39485) {
        err = lexical_realloc(ctx, &mem_39866, &mem_39866_cached_sizze_42974, bytes_39485);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_39897_cached_sizze_42975 < (int64_t) 256) {
        err = lexical_realloc(ctx, &mem_39897, &mem_39897_cached_sizze_42975, (int64_t) 256);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_39899_cached_sizze_42976 < (int64_t) 256) {
        err = lexical_realloc(ctx, &mem_39899, &mem_39899_cached_sizze_42976, (int64_t) 256);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_39924_cached_sizze_42977 < bytes_39543) {
        err = lexical_realloc(ctx, &mem_39924, &mem_39924_cached_sizze_42977, bytes_39543);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_39929_cached_sizze_42978 < bytes_39397) {
        err = lexical_realloc(ctx, &mem_39929, &mem_39929_cached_sizze_42978, bytes_39397);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_40098_cached_sizze_42979 < bytes_40097) {
        err = lexical_realloc(ctx, &mem_40098, &mem_40098_cached_sizze_42979, bytes_40097);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_40159_cached_sizze_42980 < bytes_40158) {
        err = lexical_realloc(ctx, &mem_40159, &mem_40159_cached_sizze_42980, bytes_40158);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_40205_cached_sizze_42981 < bytes_40204) {
        err = lexical_realloc(ctx, &mem_40205, &mem_40205_cached_sizze_42981, bytes_40204);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_40293_cached_sizze_42982 < bytes_40292) {
        err = lexical_realloc(ctx, &mem_40293, &mem_40293_cached_sizze_42982, bytes_40292);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_40324_cached_sizze_42983 < (int64_t) 256) {
        err = lexical_realloc(ctx, &mem_40324, &mem_40324_cached_sizze_42983, (int64_t) 256);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_40326_cached_sizze_42984 < (int64_t) 256) {
        err = lexical_realloc(ctx, &mem_40326, &mem_40326_cached_sizze_42984, (int64_t) 256);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_40351_cached_sizze_42985 < bytes_40350) {
        err = lexical_realloc(ctx, &mem_40351, &mem_40351_cached_sizze_42985, bytes_40350);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_40364_cached_sizze_42986 < (int64_t) 6272) {
        err = lexical_realloc(ctx, &mem_40364, &mem_40364_cached_sizze_42986, (int64_t) 6272);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_40478_cached_sizze_42987 < bytes_40477) {
        err = lexical_realloc(ctx, &mem_40478, &mem_40478_cached_sizze_42987, bytes_40477);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_40539_cached_sizze_42988 < bytes_40538) {
        err = lexical_realloc(ctx, &mem_40539, &mem_40539_cached_sizze_42988, bytes_40538);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_40585_cached_sizze_42989 < bytes_40204) {
        err = lexical_realloc(ctx, &mem_40585, &mem_40585_cached_sizze_42989, bytes_40204);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_40673_cached_sizze_42990 < bytes_40292) {
        err = lexical_realloc(ctx, &mem_40673, &mem_40673_cached_sizze_42990, bytes_40292);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_40704_cached_sizze_42991 < (int64_t) 256) {
        err = lexical_realloc(ctx, &mem_40704, &mem_40704_cached_sizze_42991, (int64_t) 256);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_40706_cached_sizze_42992 < (int64_t) 256) {
        err = lexical_realloc(ctx, &mem_40706, &mem_40706_cached_sizze_42992, (int64_t) 256);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_40731_cached_sizze_42993 < bytes_40204) {
        err = lexical_realloc(ctx, &mem_40731, &mem_40731_cached_sizze_42993, bytes_40204);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_40815_cached_sizze_42994 < (int64_t) 3686400) {
        err = lexical_realloc(ctx, &mem_40815, &mem_40815_cached_sizze_42994, (int64_t) 3686400);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_40902_cached_sizze_42995 < bytes_40901) {
        err = lexical_realloc(ctx, &mem_40902, &mem_40902_cached_sizze_42995, bytes_40901);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_40963_cached_sizze_42996 < bytes_40962) {
        err = lexical_realloc(ctx, &mem_40963, &mem_40963_cached_sizze_42996, bytes_40962);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_41009_cached_sizze_42997 < bytes_41008) {
        err = lexical_realloc(ctx, &mem_41009, &mem_41009_cached_sizze_42997, bytes_41008);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_41097_cached_sizze_42998 < bytes_41096) {
        err = lexical_realloc(ctx, &mem_41097, &mem_41097_cached_sizze_42998, bytes_41096);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_41128_cached_sizze_42999 < (int64_t) 256) {
        err = lexical_realloc(ctx, &mem_41128, &mem_41128_cached_sizze_42999, (int64_t) 256);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_41130_cached_sizze_43000 < (int64_t) 256) {
        err = lexical_realloc(ctx, &mem_41130, &mem_41130_cached_sizze_43000, (int64_t) 256);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_41155_cached_sizze_43001 < bytes_41154) {
        err = lexical_realloc(ctx, &mem_41155, &mem_41155_cached_sizze_43001, bytes_41154);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_41168_cached_sizze_43002 < (int64_t) 6272) {
        err = lexical_realloc(ctx, &mem_41168, &mem_41168_cached_sizze_43002, (int64_t) 6272);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_41282_cached_sizze_43003 < bytes_41281) {
        err = lexical_realloc(ctx, &mem_41282, &mem_41282_cached_sizze_43003, bytes_41281);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_41343_cached_sizze_43004 < bytes_41342) {
        err = lexical_realloc(ctx, &mem_41343, &mem_41343_cached_sizze_43004, bytes_41342);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_41389_cached_sizze_43005 < bytes_41008) {
        err = lexical_realloc(ctx, &mem_41389, &mem_41389_cached_sizze_43005, bytes_41008);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_41477_cached_sizze_43006 < bytes_41096) {
        err = lexical_realloc(ctx, &mem_41477, &mem_41477_cached_sizze_43006, bytes_41096);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_41508_cached_sizze_43007 < (int64_t) 256) {
        err = lexical_realloc(ctx, &mem_41508, &mem_41508_cached_sizze_43007, (int64_t) 256);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_41510_cached_sizze_43008 < (int64_t) 256) {
        err = lexical_realloc(ctx, &mem_41510, &mem_41510_cached_sizze_43008, (int64_t) 256);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_41535_cached_sizze_43009 < bytes_41008) {
        err = lexical_realloc(ctx, &mem_41535, &mem_41535_cached_sizze_43009, bytes_41008);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_41619_cached_sizze_43010 < (int64_t) 1843200) {
        err = lexical_realloc(ctx, &mem_41619, &mem_41619_cached_sizze_43010, (int64_t) 1843200);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_41706_cached_sizze_43011 < bytes_41705) {
        err = lexical_realloc(ctx, &mem_41706, &mem_41706_cached_sizze_43011, bytes_41705);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_41767_cached_sizze_43012 < bytes_41766) {
        err = lexical_realloc(ctx, &mem_41767, &mem_41767_cached_sizze_43012, bytes_41766);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_41813_cached_sizze_43013 < bytes_41812) {
        err = lexical_realloc(ctx, &mem_41813, &mem_41813_cached_sizze_43013, bytes_41812);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_41901_cached_sizze_43014 < bytes_41900) {
        err = lexical_realloc(ctx, &mem_41901, &mem_41901_cached_sizze_43014, bytes_41900);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_41932_cached_sizze_43015 < (int64_t) 256) {
        err = lexical_realloc(ctx, &mem_41932, &mem_41932_cached_sizze_43015, (int64_t) 256);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_41934_cached_sizze_43016 < (int64_t) 256) {
        err = lexical_realloc(ctx, &mem_41934, &mem_41934_cached_sizze_43016, (int64_t) 256);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_41959_cached_sizze_43017 < bytes_41958) {
        err = lexical_realloc(ctx, &mem_41959, &mem_41959_cached_sizze_43017, bytes_41958);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_41972_cached_sizze_43018 < (int64_t) 6272) {
        err = lexical_realloc(ctx, &mem_41972, &mem_41972_cached_sizze_43018, (int64_t) 6272);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_42086_cached_sizze_43019 < bytes_42085) {
        err = lexical_realloc(ctx, &mem_42086, &mem_42086_cached_sizze_43019, bytes_42085);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_42147_cached_sizze_43020 < bytes_42146) {
        err = lexical_realloc(ctx, &mem_42147, &mem_42147_cached_sizze_43020, bytes_42146);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_42193_cached_sizze_43021 < bytes_41812) {
        err = lexical_realloc(ctx, &mem_42193, &mem_42193_cached_sizze_43021, bytes_41812);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_42281_cached_sizze_43022 < bytes_41900) {
        err = lexical_realloc(ctx, &mem_42281, &mem_42281_cached_sizze_43022, bytes_41900);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_42312_cached_sizze_43023 < (int64_t) 256) {
        err = lexical_realloc(ctx, &mem_42312, &mem_42312_cached_sizze_43023, (int64_t) 256);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_42314_cached_sizze_43024 < (int64_t) 256) {
        err = lexical_realloc(ctx, &mem_42314, &mem_42314_cached_sizze_43024, (int64_t) 256);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_42339_cached_sizze_43025 < bytes_41812) {
        err = lexical_realloc(ctx, &mem_42339, &mem_42339_cached_sizze_43025, bytes_41812);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_42426_cached_sizze_43026 < bytes_42425) {
        err = lexical_realloc(ctx, &mem_42426, &mem_42426_cached_sizze_43026, bytes_42425);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_42487_cached_sizze_43027 < bytes_42486) {
        err = lexical_realloc(ctx, &mem_42487, &mem_42487_cached_sizze_43027, bytes_42486);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (mem_42548_cached_sizze_43029 < (int64_t) 6272) {
        err = lexical_realloc(ctx, &mem_42548, &mem_42548_cached_sizze_43029, (int64_t) 6272);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    if (memblock_set(ctx, &mem_param_39029, &mem_39018, "mem_39018") != 0)
        return 1;
    for (int64_t t__29097 = 0; t__29097 < (int64_t) 1000; t__29097++) {
        int64_t arg_29099 = sub64((int64_t) 1000, t__29097);
        int64_t t_29100 = sub64(arg_29099, (int64_t) 1);
        double i64_res_29108 = sitofp_i64_f64(t_29100);
        
        for (int64_t i_34545 = 0; i_34545 < (int64_t) 128; i_34545++) {
            double i64_res_33520 = sitofp_i64_f64(i_34545);
            double exp_arg_33521 = -7.252236513367073e-2 * i64_res_33520;
            double exp_res_33522 = futrts_exp64(exp_arg_33521);
            double defunc_0_f_res_33523 = i64_res_29108 * exp_res_33522;
            double sin_res_33525 = futrts_sin64(defunc_0_f_res_33523);
            double cos_res_33526 = futrts_cos64(defunc_0_f_res_33523);
            
            ((double *) mem_39031)[i_34545] = sin_res_33525;
            ((double *) mem_39033)[i_34545] = cos_res_33526;
        }
        
        bool x_29142 = sle64((int64_t) 0, t_29100);
        bool y_29143 = slt64(t_29100, (int64_t) 1000);
        bool bounds_check_29144 = x_29142 && y_29143;
        bool index_certs_29145;
        
        if (!bounds_check_29144) {
            set_error(ctx, msgprintf("Error: %s%lld%s%lld%s\n\nBacktrace:\n%s", "Index [", (long long) t_29100, "] out of bounds for array of shape [", (long long) (int64_t) 1000, "].", "-> #0  diffusion.fut:68:21-32\n   #1  diffusion.fut:88:60-152\n   #2  /prelude/soacs.fut:59:9-10\n   #3  /prelude/array.fut:200:10-17\n   #4  diffusion.fut:88:52-153\n   #5  genfrom_w.fut:12:6-71\n   #6  genfrom_w.fut:7:1-12:71\n"));
            err = FUTHARK_PROGRAM_ERROR;
            goto cleanup;
        }
        
        double alpha_bar_t_29146 = ((double *) mem_38974)[t_29100];
        double binop_y_29660 = 1.991991991991992e-5 * i64_res_29108;
        double binop_y_29661 = 1.0e-4 + binop_y_29660;
        double index_primexp_29662 = 1.0 - binop_y_29661;
        double arg_29148 = 1.0 - index_primexp_29662;
        double sqrt_arg_29149 = 1.0 - alpha_bar_t_29146;
        double sqrt_res_29150 = futrts_sqrt64(sqrt_arg_29149);
        double eps_coef_29151 = arg_29148 / sqrt_res_29150;
        bool cond_29153 = slt64((int64_t) 1, t_29100);
        double sqrt_res_29154 = futrts_sqrt64(index_primexp_29662);
        double arg_29155 = 1.0 / sqrt_res_29154;
        double sqrt_res_29156 = futrts_sqrt64(binop_y_29661);
        int32_t p_sample_arg_29164 = ((int32_t *) mem_38976)[t__29097];
        
        for (int64_t i_34554 = 0; i_34554 < (int64_t) 30; i_34554++) {
            bool cond_29534 = slt64(i_34554, (int64_t) 1);
            bool cond_f_res_29535 = sle64((int64_t) 29, i_34554);
            bool x_29536 = !cond_29534;
            bool y_29537 = cond_f_res_29535 && x_29536;
            bool cond_29538 = cond_29534 || y_29537;
            bool x_29539 = !cond_29538;
            
            for (int64_t i_34550 = 0; i_34550 < (int64_t) 30; i_34550++) {
                bool cond_f_res_29542 = slt64(i_34550, (int64_t) 1);
                bool y_29543 = x_29539 && cond_f_res_29542;
                bool cond_29544 = cond_29538 || y_29543;
                bool cond_f_res_29545 = sle64((int64_t) 29, i_34550);
                bool x_29546 = !cond_29544;
                bool y_29547 = cond_f_res_29545 && x_29546;
                bool cond_29548 = cond_29544 || y_29547;
                double defunc_0_f_res_29549;
                
                if (cond_29548 == 1) {
                    defunc_0_f_res_29549 = 0.0;
                } else {
                    int64_t i_29550 = sub64(i_34554, (int64_t) 1);
                    int64_t i_29554 = sub64(i_34550, (int64_t) 1);
                    double defunc_0_f_res_f_res_29560 = ((double *) mem_param_39029.mem)[i_29550 * (int64_t) 28 + i_29554];
                    
                    defunc_0_f_res_29549 = defunc_0_f_res_f_res_29560;
                }
                ((double *) mem_39055)[i_34554 * (int64_t) 30 + i_34550] = defunc_0_f_res_29549;
            }
        }
        for (int64_t nest_i_42758 = 0; nest_i_42758 < (int64_t) 1; nest_i_42758++) {
            if ((int64_t) 7200 > 0)
                memmove(mem_39095 + nest_i_42758 * (int64_t) 900 * (int64_t) 8, mem_39055 + (int64_t) 0, (int64_t) 7200);
        }
        for (int64_t i_34562 = 0; i_34562 < new_n_29504; i_34562++) {
            int64_t j_29574 = add64(dz2086U_26617, i_34562);
            int64_t i_p_m_t_s_29575 = add64(m_29571, i_34562);
            bool zzero_leq_i_p_m_t_s_29576 = sle64((int64_t) 0, i_p_m_t_s_29575);
            bool i_p_m_t_s_leq_w_29577 = slt64(i_p_m_t_s_29575, (int64_t) 30);
            bool i_lte_j_29579 = sle64(i_34562, j_29574);
            bool y_29581 = zzero_leq_i_p_m_t_s_29576 && i_p_m_t_s_leq_w_29577;
            bool y_29582 = i_lte_j_29579 && y_29581;
            bool ok_or_empty_29584 = empty_slice_29570 || y_29582;
            
            for (int64_t i_34558 = 0; i_34558 < new_n_29504; i_34558++) {
                int64_t j_29587 = add64(dz2086U_26617, i_34558);
                int64_t i_p_m_t_s_29588 = add64(m_29571, i_34558);
                bool zzero_leq_i_p_m_t_s_29589 = sle64((int64_t) 0, i_p_m_t_s_29588);
                bool i_p_m_t_s_leq_w_29590 = slt64(i_p_m_t_s_29588, (int64_t) 30);
                bool i_lte_j_29592 = sle64(i_34558, j_29587);
                bool y_29594 = zzero_leq_i_p_m_t_s_29589 && i_p_m_t_s_leq_w_29590;
                bool y_29595 = i_lte_j_29592 && y_29594;
                bool ok_or_empty_29597 = empty_slice_29570 || y_29595;
                bool index_ok_29598 = ok_or_empty_29584 && ok_or_empty_29597;
                bool index_certs_29599;
                
                if (!index_ok_29598) {
                    set_error(ctx, msgprintf("Error: %s%lld%s%lld%s%lld%s%lld%s%lld%s%lld%s\n\nBacktrace:\n%s", "Index [", (long long) i_34562, ":", (long long) j_29574, ", ", (long long) i_34558, ":", (long long) j_29587, "] out of bounds for array of shape [", (long long) (int64_t) 30, "][", (long long) (int64_t) 30, "].", "-> #0  ../layers/conv2d.fut:11:90-124\n   #1  ../layers/conv2d.fut:11:144-146\n   #2  /prelude/soacs.fut:59:9-10\n   #3  /prelude/array.fut:200:10-17\n   #4  /prelude/functional.fut:39:61-65\n   #5  /prelude/soacs.fut:59:9-10\n   #6  /prelude/array.fut:208:27-34\n   #7  ../layers/conv2d.fut:11:50-162\n   #8  ../layers/conv2d.fut:24:17-54\n"));
                    err = FUTHARK_PROGRAM_ERROR;
                    goto cleanup;
                }
                for (int64_t i_42761 = 0; i_42761 < total_29510; i_42761++) {
                    double tmp_42762 = ((double *) mem_39095)[(int64_t) 30 * i_34562 + i_34558 + (squot64(i_42761, dz2086U_26617 * dz2086U_26617) * (int64_t) 900 + squot64(i_42761 - squot64(i_42761, dz2086U_26617 * dz2086U_26617) * (dz2086U_26617 * dz2086U_26617), dz2086U_26617) * (int64_t) 30 + (i_42761 - squot64(i_42761, dz2086U_26617 * dz2086U_26617) * (dz2086U_26617 * dz2086U_26617) - squot64(i_42761 - squot64(i_42761, dz2086U_26617 * dz2086U_26617) * (dz2086U_26617 * dz2086U_26617), dz2086U_26617) * dz2086U_26617))];
                    
                    ((double *) mem_39100)[i_34562 * binop_y_38368 + i_34558 * total_29510 + i_42761] = tmp_42762;
                }
            }
        }
        for (int64_t i_34572 = 0; i_34572 < dz2088U_26619; i_34572++) {
            double x_33502 = ((double *) c_in_b_mem_38946.mem)[i_34572];
            int64_t binop_x_38278 = total_29510 * i_34572;
            
            for (int64_t i_34568 = 0; i_34568 < flat_dim_29613; i_34568++) {
                int64_t binop_x_38366 = total_29510 * i_34568;
                double defunc_0_reduce_res_34301;
                double redout_34564 = 0.0;
                
                for (int64_t i_34565 = 0; i_34565 < total_29510; i_34565++) {
                    int64_t binop_x_38279 = i_34565 + binop_x_38278;
                    int64_t new_index_38281 = squot64(binop_x_38279, total_29510);
                    int64_t binop_y_38289 = total_29510 * new_index_38281;
                    int64_t binop_x_38290 = binop_x_38279 - binop_y_38289;
                    int64_t new_index_38292 = squot64(binop_x_38290, total_29510);
                    int64_t binop_y_38314 = total_29510 * new_index_38292;
                    int64_t binop_x_38315 = binop_x_38290 - binop_y_38314;
                    int64_t new_index_38316 = squot64(binop_x_38315, dz2087U_26618);
                    int64_t binop_y_38364 = dz2087U_26618 * new_index_38316;
                    int64_t new_index_38365 = binop_x_38315 - binop_y_38364;
                    double x_33543 = ((double *) c_in_w_mem_38945.mem)[new_index_38281 * (dz2087U_26618 * dz2086U_26617) + new_index_38292 * (dz2087U_26618 * dz2086U_26617) + new_index_38316 * dz2087U_26618 + new_index_38365];
                    int64_t binop_x_38367 = i_34565 + binop_x_38366;
                    int64_t new_index_38369 = squot64(binop_x_38367, binop_y_38368);
                    int64_t binop_y_38377 = binop_y_38368 * new_index_38369;
                    int64_t binop_x_38378 = binop_x_38367 - binop_y_38377;
                    int64_t new_index_38379 = squot64(binop_x_38378, total_29510);
                    int64_t binop_y_38399 = total_29510 * new_index_38379;
                    int64_t new_index_38400 = binop_x_38378 - binop_y_38399;
                    double x_33544 = ((double *) mem_39100)[new_index_38369 * binop_y_38368 + new_index_38379 * total_29510 + new_index_38400];
                    double defunc_0_f_res_33545 = x_33543 * x_33544;
                    double defunc_0_op_res_33538 = defunc_0_f_res_33545 + redout_34564;
                    double redout_tmp_42765 = defunc_0_op_res_33538;
                    
                    redout_34564 = redout_tmp_42765;
                }
                defunc_0_reduce_res_34301 = redout_34564;
                
                double defunc_0_f_res_33541 = x_33502 + defunc_0_reduce_res_34301;
                
                ((double *) mem_39161)[i_34572 * flat_dim_29613 + i_34568] = defunc_0_f_res_33541;
            }
        }
        for (int64_t i_34584 = 0; i_34584 < (int64_t) 64; i_34584++) {
            for (int64_t i_34580 = 0; i_34580 < (int64_t) 30; i_34580++) {
                bool cond_30239 = slt64(i_34580, (int64_t) 1);
                bool cond_f_res_30240 = sle64((int64_t) 29, i_34580);
                bool x_30241 = !cond_30239;
                bool y_30242 = cond_f_res_30240 && x_30241;
                bool cond_30243 = cond_30239 || y_30242;
                bool x_30244 = !cond_30243;
                
                for (int64_t i_34576 = 0; i_34576 < (int64_t) 30; i_34576++) {
                    bool cond_f_res_30247 = slt64(i_34576, (int64_t) 1);
                    bool y_30248 = x_30244 && cond_f_res_30247;
                    bool cond_30249 = cond_30243 || y_30248;
                    bool cond_f_res_30250 = sle64((int64_t) 29, i_34576);
                    bool x_30251 = !cond_30249;
                    bool y_30252 = cond_f_res_30250 && x_30251;
                    bool cond_30253 = cond_30249 || y_30252;
                    double defunc_0_f_res_30254;
                    
                    if (cond_30253 == 1) {
                        defunc_0_f_res_30254 = 0.0;
                    } else {
                        int64_t i_30255 = sub64(i_34580, (int64_t) 1);
                        int64_t i_30259 = sub64(i_34576, (int64_t) 1);
                        int64_t binop_x_38262 = (int64_t) 784 * i_34584;
                        int64_t binop_y_38263 = (int64_t) 28 * i_30255;
                        int64_t binop_x_38264 = binop_x_38262 + binop_y_38263;
                        int64_t binop_x_38265 = i_30259 + binop_x_38264;
                        int64_t new_index_38266 = squot64(binop_x_38265, flat_dim_29613);
                        int64_t binop_y_38276 = flat_dim_29613 * new_index_38266;
                        int64_t new_index_38277 = binop_x_38265 - binop_y_38276;
                        double defunc_0_f_res_f_res_30265 = ((double *) mem_39161)[new_index_38266 * flat_dim_29613 + new_index_38277];
                        
                        defunc_0_f_res_30254 = defunc_0_f_res_f_res_30265;
                    }
                    ((double *) mem_39204)[i_34584 * (int64_t) 900 + i_34580 * (int64_t) 30 + i_34576] = defunc_0_f_res_30254;
                }
            }
        }
        for (int64_t i_34592 = 0; i_34592 < new_n_30219; i_34592++) {
            int64_t j_30284 = add64(dz2081Uz2081U_26620, i_34592);
            int64_t i_p_m_t_s_30285 = add64(m_30276, i_34592);
            bool zzero_leq_i_p_m_t_s_30286 = sle64((int64_t) 0, i_p_m_t_s_30285);
            bool i_p_m_t_s_leq_w_30287 = slt64(i_p_m_t_s_30285, (int64_t) 30);
            bool i_lte_j_30289 = sle64(i_34592, j_30284);
            bool y_30291 = zzero_leq_i_p_m_t_s_30286 && i_p_m_t_s_leq_w_30287;
            bool y_30292 = i_lte_j_30289 && y_30291;
            bool ok_or_empty_30294 = empty_slice_30275 || y_30292;
            
            for (int64_t i_34588 = 0; i_34588 < new_n_30219; i_34588++) {
                int64_t j_30297 = add64(dz2081Uz2081U_26620, i_34588);
                int64_t i_p_m_t_s_30298 = add64(m_30276, i_34588);
                bool zzero_leq_i_p_m_t_s_30299 = sle64((int64_t) 0, i_p_m_t_s_30298);
                bool i_p_m_t_s_leq_w_30300 = slt64(i_p_m_t_s_30298, (int64_t) 30);
                bool i_lte_j_30302 = sle64(i_34588, j_30297);
                bool y_30304 = zzero_leq_i_p_m_t_s_30299 && i_p_m_t_s_leq_w_30300;
                bool y_30305 = i_lte_j_30302 && y_30304;
                bool ok_or_empty_30307 = empty_slice_30275 || y_30305;
                bool index_ok_30308 = ok_or_empty_30294 && ok_or_empty_30307;
                bool index_certs_30309;
                
                if (!index_ok_30308) {
                    set_error(ctx, msgprintf("Error: %s%lld%s%lld%s%lld%s%lld%s%lld%s%lld%s\n\nBacktrace:\n%s", "Index [", (long long) i_34592, ":", (long long) j_30284, ", ", (long long) i_34588, ":", (long long) j_30297, "] out of bounds for array of shape [", (long long) (int64_t) 30, "][", (long long) (int64_t) 30, "].", "-> #0  ../layers/conv2d.fut:11:90-124\n   #1  ../layers/conv2d.fut:11:144-146\n   #2  /prelude/soacs.fut:59:9-10\n   #3  /prelude/array.fut:200:10-17\n   #4  /prelude/functional.fut:39:61-65\n   #5  /prelude/soacs.fut:59:9-10\n   #6  /prelude/array.fut:208:27-34\n   #7  ../layers/conv2d.fut:11:50-162\n   #8  ../layers/conv2d.fut:24:17-54\n"));
                    err = FUTHARK_PROGRAM_ERROR;
                    goto cleanup;
                }
                for (int64_t i_42771 = 0; i_42771 < total_30224; i_42771++) {
                    double tmp_42772 = ((double *) mem_39204)[(int64_t) 30 * i_34592 + i_34588 + (squot64(i_42771, dz2081Uz2081U_26620 * dz2081Uz2081U_26620) * (int64_t) 900 + squot64(i_42771 - squot64(i_42771, dz2081Uz2081U_26620 * dz2081Uz2081U_26620) * (dz2081Uz2081U_26620 * dz2081Uz2081U_26620), dz2081Uz2081U_26620) * (int64_t) 30 + (i_42771 - squot64(i_42771, dz2081Uz2081U_26620 * dz2081Uz2081U_26620) * (dz2081Uz2081U_26620 * dz2081Uz2081U_26620) - squot64(i_42771 - squot64(i_42771, dz2081Uz2081U_26620 * dz2081Uz2081U_26620) * (dz2081Uz2081U_26620 * dz2081Uz2081U_26620), dz2081Uz2081U_26620) * dz2081Uz2081U_26620))];
                    
                    ((double *) mem_39291)[i_34592 * binop_y_38229 + i_34588 * total_30224 + i_42771] = tmp_42772;
                }
            }
        }
        for (int64_t i_34602 = 0; i_34602 < dz2081Uz2083U_26622; i_34602++) {
            double x_33484 = ((double *) b1_c1_b_mem_38948.mem)[i_34602];
            int64_t binop_x_38124 = total_30224 * i_34602;
            
            for (int64_t i_34598 = 0; i_34598 < flat_dim_30312; i_34598++) {
                int64_t binop_x_38227 = total_30224 * i_34598;
                double defunc_0_reduce_res_34306;
                double redout_34594 = 0.0;
                
                for (int64_t i_34595 = 0; i_34595 < total_30224; i_34595++) {
                    int64_t binop_x_38125 = i_34595 + binop_x_38124;
                    int64_t new_index_38128 = squot64(binop_x_38125, total_30224);
                    int64_t binop_y_38138 = total_30224 * new_index_38128;
                    int64_t binop_x_38139 = binop_x_38125 - binop_y_38138;
                    int64_t new_index_38141 = squot64(binop_x_38139, binop_y_38140);
                    int64_t binop_y_38167 = binop_y_38140 * new_index_38141;
                    int64_t binop_x_38168 = binop_x_38139 - binop_y_38167;
                    int64_t new_index_38169 = squot64(binop_x_38168, dz2081Uz2082U_26621);
                    int64_t binop_y_38225 = dz2081Uz2082U_26621 * new_index_38169;
                    int64_t new_index_38226 = binop_x_38168 - binop_y_38225;
                    double x_33567 = ((double *) b1_c1_w_mem_38947.mem)[new_index_38128 * (dz2081Uz2082U_26621 * dz2081Uz2081U_26620 * (int64_t) 64) + new_index_38141 * (dz2081Uz2082U_26621 * dz2081Uz2081U_26620) + new_index_38169 * dz2081Uz2082U_26621 + new_index_38226];
                    int64_t binop_x_38228 = i_34595 + binop_x_38227;
                    int64_t new_index_38230 = squot64(binop_x_38228, binop_y_38229);
                    int64_t binop_y_38238 = binop_y_38229 * new_index_38230;
                    int64_t binop_x_38239 = binop_x_38228 - binop_y_38238;
                    int64_t new_index_38240 = squot64(binop_x_38239, total_30224);
                    int64_t binop_y_38260 = total_30224 * new_index_38240;
                    int64_t new_index_38261 = binop_x_38239 - binop_y_38260;
                    double x_33568 = ((double *) mem_39291)[new_index_38230 * binop_y_38229 + new_index_38240 * total_30224 + new_index_38261];
                    double defunc_0_f_res_33569 = x_33567 * x_33568;
                    double defunc_0_op_res_33562 = defunc_0_f_res_33569 + redout_34594;
                    double redout_tmp_42775 = defunc_0_op_res_33562;
                    
                    redout_34594 = redout_tmp_42775;
                }
                defunc_0_reduce_res_34306 = redout_34594;
                
                double defunc_0_f_res_33565 = x_33484 + defunc_0_reduce_res_34306;
                
                ((double *) mem_39352)[i_34602 * flat_dim_30312 + i_34598] = defunc_0_f_res_33565;
            }
        }
        for (int64_t i_34614 = 0; i_34614 < dz2082Uz2083U_26623; i_34614++) {
            int64_t binop_x_38108 = (int64_t) 784 * i_34614;
            
            for (int64_t i_34610 = 0; i_34610 < (int64_t) 28; i_34610++) {
                int64_t binop_y_38109 = (int64_t) 28 * i_34610;
                int64_t binop_x_38110 = binop_x_38108 + binop_y_38109;
                
                for (int64_t i_34606 = 0; i_34606 < (int64_t) 28; i_34606++) {
                    int64_t binop_x_38111 = i_34606 + binop_x_38110;
                    int64_t new_index_38112 = squot64(binop_x_38111, flat_dim_30312);
                    int64_t binop_y_38122 = flat_dim_30312 * new_index_38112;
                    int64_t new_index_38123 = binop_x_38111 - binop_y_38122;
                    double x_30352 = ((double *) mem_39352)[new_index_38112 * flat_dim_30312 + new_index_38123];
                    double max_res_30353 = fmax64(0.0, x_30352);
                    
                    ((double *) mem_39398)[i_34614 * (int64_t) 784 + i_34610 * (int64_t) 28 + i_34606] = max_res_30353;
                }
            }
        }
        for (int64_t i_34618 = 0; i_34618 < (int64_t) 32; i_34618++) {
            int64_t i_30364 = mul64(elem_groups_30357, i_34618);
            int64_t arg_30365 = add64((int64_t) 1, i_34618);
            int64_t j_30366 = mul64(elem_groups_30357, arg_30365);
            int64_t j_m_i_30367 = sub64(j_30366, i_30364);
            bool empty_slice_30368 = j_m_i_30367 == (int64_t) 0;
            int64_t m_30369 = sub64(j_m_i_30367, (int64_t) 1);
            int64_t i_p_m_t_s_30370 = add64(i_30364, m_30369);
            bool zzero_leq_i_p_m_t_s_30371 = sle64((int64_t) 0, i_p_m_t_s_30370);
            bool i_p_m_t_s_leq_w_30372 = slt64(i_p_m_t_s_30370, dz2082Uz2083U_26623);
            bool zzero_lte_i_30373 = sle64((int64_t) 0, i_30364);
            bool i_lte_j_30374 = sle64(i_30364, j_30366);
            bool y_30375 = i_p_m_t_s_leq_w_30372 && zzero_lte_i_30373;
            bool y_30376 = zzero_leq_i_p_m_t_s_30371 && y_30375;
            bool y_30377 = i_lte_j_30374 && y_30376;
            bool forwards_ok_30378 = zzero_lte_i_30373 && y_30377;
            bool ok_or_empty_30379 = empty_slice_30368 || forwards_ok_30378;
            bool index_certs_30380;
            
            if (!ok_or_empty_30379) {
                set_error(ctx, msgprintf("Error: %s%lld%s%lld%s%lld%s\n\nBacktrace:\n%s", "Index [", (long long) i_30364, ":", (long long) j_30366, "] out of bounds for array of shape [", (long long) dz2082Uz2083U_26623, "].", "-> #0  ../layers/groupnorm.fut:2:31-70\n   #1  /prelude/soacs.fut:59:9-10\n   #2  /prelude/array.fut:200:10-17\n   #3  ../layers/groupnorm.fut:2:23-97\n   #4  ../layers/groupnorm.fut:20:19-54\n"));
                err = FUTHARK_PROGRAM_ERROR;
                goto cleanup;
            }
            
            bool dim_match_30381 = elem_groups_30357 == j_m_i_30367;
            bool empty_or_match_cert_30382;
            
            if (!dim_match_30381) {
                set_error(ctx, msgprintf("Error: %s%lld%s%lld%s%lld%s%lld%s%lld%s%lld%s\n\nBacktrace:\n%s", "Value of (core language) shape (", (long long) j_m_i_30367, ", ", (long long) (int64_t) 28, ", ", (long long) (int64_t) 28, ") cannot match shape of type `[", (long long) elem_groups_30357, "][", (long long) (int64_t) 28, "][", (long long) (int64_t) 28, "]f64`.", "-> #0  ../layers/groupnorm.fut:2:31-96\n   #1  /prelude/soacs.fut:59:9-10\n   #2  /prelude/array.fut:200:10-17\n   #3  ../layers/groupnorm.fut:2:23-97\n   #4  ../layers/groupnorm.fut:20:19-54\n"));
                err = FUTHARK_PROGRAM_ERROR;
                goto cleanup;
            }
            if (elem_groups_30357 * (int64_t) 28 * (int64_t) 28 * (int64_t) 8 > 0)
                memmove(mem_39486 + i_34618 * flat_dim_30385 * (int64_t) 8, mem_39398 + (int64_t) 784 * i_30364 * (int64_t) 8, elem_groups_30357 * (int64_t) 28 * (int64_t) 28 * (int64_t) 8);
        }
        for (int64_t i_34628 = 0; i_34628 < (int64_t) 32; i_34628++) {
            int64_t binop_x_38012 = flat_dim_30385 * i_34628;
            double defunc_0_reduce_res_34310;
            double redout_34620 = 0.0;
            
            for (int64_t i_34621 = 0; i_34621 < flat_dim_30385; i_34621++) {
                int64_t binop_x_38013 = i_34621 + binop_x_38012;
                int64_t new_index_38016 = squot64(binop_x_38013, flat_dim_30385);
                int64_t binop_y_38026 = flat_dim_30385 * new_index_38016;
                int64_t binop_x_38027 = binop_x_38013 - binop_y_38026;
                int64_t new_index_38028 = squot64(binop_x_38027, (int64_t) 784);
                int64_t binop_y_38052 = (int64_t) 784 * new_index_38028;
                int64_t binop_x_38053 = binop_x_38027 - binop_y_38052;
                int64_t new_index_38054 = squot64(binop_x_38053, (int64_t) 28);
                int64_t binop_y_38106 = (int64_t) 28 * new_index_38054;
                int64_t new_index_38107 = binop_x_38053 - binop_y_38106;
                double x_30395 = ((double *) mem_39486)[new_index_38016 * flat_dim_30385 + new_index_38028 * (int64_t) 784 + new_index_38054 * (int64_t) 28 + new_index_38107];
                double defunc_0_op_res_30394 = x_30395 + redout_34620;
                double redout_tmp_42782 = defunc_0_op_res_30394;
                
                redout_34620 = redout_tmp_42782;
            }
            defunc_0_reduce_res_34310 = redout_34620;
            
            double mean_res_30396 = defunc_0_reduce_res_34310 / i64_res_30386;
            double defunc_0_reduce_res_34311;
            double redout_34622 = 0.0;
            
            for (int64_t i_34623 = 0; i_34623 < flat_dim_30385; i_34623++) {
                int64_t binop_x_37917 = i_34623 + binop_x_38012;
                int64_t new_index_37920 = squot64(binop_x_37917, flat_dim_30385);
                int64_t binop_y_37930 = flat_dim_30385 * new_index_37920;
                int64_t binop_x_37931 = binop_x_37917 - binop_y_37930;
                int64_t new_index_37932 = squot64(binop_x_37931, (int64_t) 784);
                int64_t binop_y_37956 = (int64_t) 784 * new_index_37932;
                int64_t binop_x_37957 = binop_x_37931 - binop_y_37956;
                int64_t new_index_37958 = squot64(binop_x_37957, (int64_t) 28);
                int64_t binop_y_38010 = (int64_t) 28 * new_index_37958;
                int64_t new_index_38011 = binop_x_37957 - binop_y_38010;
                double x_33577 = ((double *) mem_39486)[new_index_37920 * flat_dim_30385 + new_index_37932 * (int64_t) 784 + new_index_37958 * (int64_t) 28 + new_index_38011];
                double arg_33578 = x_33577 - mean_res_30396;
                double defunc_0_f_res_33579 = arg_33578 * arg_33578;
                double defunc_0_op_res_30404 = defunc_0_f_res_33579 + redout_34622;
                double redout_tmp_42783 = defunc_0_op_res_30404;
                
                redout_34622 = redout_tmp_42783;
            }
            defunc_0_reduce_res_34311 = redout_34622;
            
            double variance_res_30406 = defunc_0_reduce_res_34311 / i64_res_30386;
            
            ((double *) mem_39517)[i_34628] = mean_res_30396;
            ((double *) mem_39519)[i_34628] = variance_res_30406;
        }
        for (int64_t i_34651 = 0; i_34651 < dz2082Uz2083U_26623; i_34651++) {
            double x_33403 = ((double *) b1_tb_mem_38950.mem)[i_34651];
            int64_t i_33408 = sdiv64(i_34651, elem_groups_30357);
            bool x_33409 = sle64((int64_t) 0, i_33408);
            bool y_33410 = slt64(i_33408, (int64_t) 32);
            bool bounds_check_33411 = x_33409 && y_33410;
            bool index_certs_33412;
            
            if (!bounds_check_33411) {
                set_error(ctx, msgprintf("Error: %s%lld%s%lld%s\n\nBacktrace:\n%s", "Index [", (long long) i_33408, "] out of bounds for array of shape [", (long long) (int64_t) 32, "].", "-> #0  ../layers/groupnorm.fut:22:57-85\n   #1  /prelude/soacs.fut:59:9-10\n   #2  /prelude/array.fut:200:10-17\n   #3  /prelude/functional.fut:39:61-65\n   #4  /prelude/soacs.fut:59:9-10\n   #5  /prelude/array.fut:208:27-34\n   #6  /prelude/functional.fut:39:61-65\n   #7  /prelude/soacs.fut:59:9-10\n   #8  /prelude/array.fut:216:32-39\n   #9  ../layers/groupnorm.fut:22:31-135\n"));
                err = FUTHARK_PROGRAM_ERROR;
                goto cleanup;
            }
            
            double arg_33413 = ((double *) mem_39517)[i_33408];
            double arg_33414 = ((double *) mem_39519)[i_33408];
            double sqrt_arg_33415 = 1.0e-5 + arg_33414;
            double sqrt_res_33416 = futrts_sqrt64(sqrt_arg_33415);
            double defunc_0_reduce_res_34314;
            double redout_34631 = 0.0;
            
            for (int64_t i_34632 = 0; i_34632 < (int64_t) 256; i_34632++) {
                bool index_concat_cmp_35315 = sle64((int64_t) 128, i_34632);
                double index_concat_branch_35319;
                
                if (index_concat_cmp_35315 == 1) {
                    int64_t index_concat_i_35316 = sub64(i_34632, (int64_t) 128);
                    double index_concat_35317 = ((double *) mem_39033)[index_concat_i_35316];
                    
                    index_concat_branch_35319 = index_concat_35317;
                } else {
                    double index_concat_35318 = ((double *) mem_39031)[i_34632];
                    
                    index_concat_branch_35319 = index_concat_35318;
                }
                
                double x_33585 = ((double *) b1_tw_mem_38949.mem)[i_34651 * (int64_t) 256 + i_34632];
                double defunc_0_f_res_33586 = x_33585 * index_concat_branch_35319;
                double defunc_0_op_res_33441 = defunc_0_f_res_33586 + redout_34631;
                double redout_tmp_42785 = defunc_0_op_res_33441;
                
                redout_34631 = redout_tmp_42785;
            }
            defunc_0_reduce_res_34314 = redout_34631;
            
            double defunc_0_f_res_33443 = x_33403 + defunc_0_reduce_res_34314;
            double max_res_33445 = fmax64(0.0, defunc_0_f_res_33443);
            
            for (int64_t i_34639 = 0; i_34639 < (int64_t) 28; i_34639++) {
                for (int64_t i_34635 = 0; i_34635 < (int64_t) 28; i_34635++) {
                    double arg_33616 = ((double *) mem_39398)[i_34651 * (int64_t) 784 + i_34639 * (int64_t) 28 + i_34635];
                    double arg_33617 = arg_33616 - arg_33413;
                    double defunc_0_f_res_33618 = arg_33617 / sqrt_res_33416;
                    double defunc_0_f_res_33620 = max_res_33445 + defunc_0_f_res_33618;
                    
                    ((double *) mem_39557)[i_34639 * (int64_t) 28 + i_34635] = defunc_0_f_res_33620;
                }
            }
            for (int64_t i_34647 = 0; i_34647 < (int64_t) 30; i_34647++) {
                bool cond_33455 = slt64(i_34647, (int64_t) 1);
                bool cond_f_res_33456 = sle64((int64_t) 29, i_34647);
                bool x_33457 = !cond_33455;
                bool y_33458 = cond_f_res_33456 && x_33457;
                bool cond_33459 = cond_33455 || y_33458;
                bool x_33460 = !cond_33459;
                
                for (int64_t i_34643 = 0; i_34643 < (int64_t) 30; i_34643++) {
                    bool cond_f_res_33463 = slt64(i_34643, (int64_t) 1);
                    bool y_33464 = x_33460 && cond_f_res_33463;
                    bool cond_33465 = cond_33459 || y_33464;
                    bool cond_f_res_33466 = sle64((int64_t) 29, i_34643);
                    bool x_33467 = !cond_33465;
                    bool y_33468 = cond_f_res_33466 && x_33467;
                    bool cond_33469 = cond_33465 || y_33468;
                    double defunc_0_f_res_33470;
                    
                    if (cond_33469 == 1) {
                        defunc_0_f_res_33470 = 0.0;
                    } else {
                        int64_t i_33471 = sub64(i_34647, (int64_t) 1);
                        bool x_33472 = sle64((int64_t) 0, i_33471);
                        bool y_33473 = slt64(i_33471, (int64_t) 28);
                        bool bounds_check_33474 = x_33472 && y_33473;
                        int64_t i_33475 = sub64(i_34643, (int64_t) 1);
                        bool x_33476 = sle64((int64_t) 0, i_33475);
                        bool y_33477 = slt64(i_33475, (int64_t) 28);
                        bool bounds_check_33478 = x_33476 && y_33477;
                        bool index_ok_33479 = bounds_check_33474 && bounds_check_33478;
                        bool index_certs_33480;
                        
                        if (!index_ok_33479) {
                            set_error(ctx, msgprintf("Error: %s%lld%s%lld%s%lld%s%lld%s\n\nBacktrace:\n%s", "Index [", (long long) i_33471, ", ", (long long) i_33475, "] out of bounds for array of shape [", (long long) (int64_t) 28, "][", (long long) (int64_t) 28, "].", "-> #0  ../layers/conv2d.fut:7:91-116\n   #1  /prelude/soacs.fut:59:9-10\n   #2  /prelude/array.fut:200:10-17\n   #3  /prelude/functional.fut:39:61-65\n   #4  /prelude/soacs.fut:59:9-10\n   #5  /prelude/array.fut:208:27-34\n   #6  ../layers/conv2d.fut:6:46-7:117\n   #7  ../layers/conv2d.fut:7:120-123\n   #8  ../layers/conv2d.fut:20:7-30\n"));
                            err = FUTHARK_PROGRAM_ERROR;
                            goto cleanup;
                        }
                        
                        double defunc_0_f_res_f_res_33481 = ((double *) mem_39557)[i_33471 * (int64_t) 28 + i_33475];
                        
                        defunc_0_f_res_33470 = defunc_0_f_res_f_res_33481;
                    }
                    ((double *) mem_39544)[i_34651 * (int64_t) 900 + i_34647 * (int64_t) 30 + i_34643] = defunc_0_f_res_33470;
                }
            }
        }
        for (int64_t i_34659 = 0; i_34659 < new_n_30468; i_34659++) {
            int64_t j_30522 = add64(dz2081Uz2089U_26624, i_34659);
            int64_t i_p_m_t_s_30523 = add64(m_30514, i_34659);
            bool zzero_leq_i_p_m_t_s_30524 = sle64((int64_t) 0, i_p_m_t_s_30523);
            bool i_p_m_t_s_leq_w_30525 = slt64(i_p_m_t_s_30523, (int64_t) 30);
            bool i_lte_j_30527 = sle64(i_34659, j_30522);
            bool y_30529 = zzero_leq_i_p_m_t_s_30524 && i_p_m_t_s_leq_w_30525;
            bool y_30530 = i_lte_j_30527 && y_30529;
            bool ok_or_empty_30532 = empty_slice_30513 || y_30530;
            
            for (int64_t i_34655 = 0; i_34655 < new_n_30468; i_34655++) {
                int64_t j_30535 = add64(dz2081Uz2089U_26624, i_34655);
                int64_t i_p_m_t_s_30536 = add64(m_30514, i_34655);
                bool zzero_leq_i_p_m_t_s_30537 = sle64((int64_t) 0, i_p_m_t_s_30536);
                bool i_p_m_t_s_leq_w_30538 = slt64(i_p_m_t_s_30536, (int64_t) 30);
                bool i_lte_j_30540 = sle64(i_34655, j_30535);
                bool y_30542 = zzero_leq_i_p_m_t_s_30537 && i_p_m_t_s_leq_w_30538;
                bool y_30543 = i_lte_j_30540 && y_30542;
                bool ok_or_empty_30545 = empty_slice_30513 || y_30543;
                bool index_ok_30546 = ok_or_empty_30532 && ok_or_empty_30545;
                bool index_certs_30547;
                
                if (!index_ok_30546) {
                    set_error(ctx, msgprintf("Error: %s%lld%s%lld%s%lld%s%lld%s%lld%s%lld%s\n\nBacktrace:\n%s", "Index [", (long long) i_34659, ":", (long long) j_30522, ", ", (long long) i_34655, ":", (long long) j_30535, "] out of bounds for array of shape [", (long long) (int64_t) 30, "][", (long long) (int64_t) 30, "].", "-> #0  ../layers/conv2d.fut:11:90-124\n   #1  ../layers/conv2d.fut:11:144-146\n   #2  /prelude/soacs.fut:59:9-10\n   #3  /prelude/array.fut:200:10-17\n   #4  /prelude/functional.fut:39:61-65\n   #5  /prelude/soacs.fut:59:9-10\n   #6  /prelude/array.fut:208:27-34\n   #7  ../layers/conv2d.fut:11:50-162\n   #8  ../layers/conv2d.fut:24:17-54\n"));
                    err = FUTHARK_PROGRAM_ERROR;
                    goto cleanup;
                }
                for (int64_t i_42792 = 0; i_42792 < total_30472; i_42792++) {
                    double tmp_42793 = ((double *) mem_39544)[(int64_t) 30 * i_34659 + i_34655 + (squot64(i_42792, dz2081Uz2089U_26624 * dz2081Uz2089U_26624) * (int64_t) 900 + squot64(i_42792 - squot64(i_42792, dz2081Uz2089U_26624 * dz2081Uz2089U_26624) * (dz2081Uz2089U_26624 * dz2081Uz2089U_26624), dz2081Uz2089U_26624) * (int64_t) 30 + (i_42792 - squot64(i_42792, dz2081Uz2089U_26624 * dz2081Uz2089U_26624) * (dz2081Uz2089U_26624 * dz2081Uz2089U_26624) - squot64(i_42792 - squot64(i_42792, dz2081Uz2089U_26624 * dz2081Uz2089U_26624) * (dz2081Uz2089U_26624 * dz2081Uz2089U_26624), dz2081Uz2089U_26624) * dz2081Uz2089U_26624))];
                    
                    ((double *) mem_39671)[i_34659 * binop_y_37883 + i_34655 * total_30472 + i_42792] = tmp_42793;
                }
            }
        }
        for (int64_t i_34669 = 0; i_34669 < dz2082Uz2081U_26626; i_34669++) {
            double x_33255 = ((double *) b1_c2_b_mem_38952.mem)[i_34669];
            int64_t binop_x_37778 = total_30472 * i_34669;
            
            for (int64_t i_34665 = 0; i_34665 < flat_dim_30550; i_34665++) {
                int64_t binop_x_37881 = total_30472 * i_34665;
                double defunc_0_reduce_res_34318;
                double redout_34661 = 0.0;
                
                for (int64_t i_34662 = 0; i_34662 < total_30472; i_34662++) {
                    int64_t binop_x_37779 = i_34662 + binop_x_37778;
                    int64_t new_index_37782 = squot64(binop_x_37779, total_30472);
                    int64_t binop_y_37792 = total_30472 * new_index_37782;
                    int64_t binop_x_37793 = binop_x_37779 - binop_y_37792;
                    int64_t new_index_37795 = squot64(binop_x_37793, binop_y_37794);
                    int64_t binop_y_37821 = binop_y_37794 * new_index_37795;
                    int64_t binop_x_37822 = binop_x_37793 - binop_y_37821;
                    int64_t new_index_37823 = squot64(binop_x_37822, dz2082Uz2080U_26625);
                    int64_t binop_y_37879 = dz2082Uz2080U_26625 * new_index_37823;
                    int64_t new_index_37880 = binop_x_37822 - binop_y_37879;
                    double x_33643 = ((double *) b1_c2_w_mem_38951.mem)[new_index_37782 * (dz2082Uz2080U_26625 * dz2081Uz2089U_26624 * dz2082Uz2083U_26623) + new_index_37795 * (dz2082Uz2080U_26625 * dz2081Uz2089U_26624) + new_index_37823 * dz2082Uz2080U_26625 + new_index_37880];
                    int64_t binop_x_37882 = i_34662 + binop_x_37881;
                    int64_t new_index_37884 = squot64(binop_x_37882, binop_y_37883);
                    int64_t binop_y_37892 = binop_y_37883 * new_index_37884;
                    int64_t binop_x_37893 = binop_x_37882 - binop_y_37892;
                    int64_t new_index_37894 = squot64(binop_x_37893, total_30472);
                    int64_t binop_y_37914 = total_30472 * new_index_37894;
                    int64_t new_index_37915 = binop_x_37893 - binop_y_37914;
                    double x_33644 = ((double *) mem_39671)[new_index_37884 * binop_y_37883 + new_index_37894 * total_30472 + new_index_37915];
                    double defunc_0_f_res_33645 = x_33643 * x_33644;
                    double defunc_0_op_res_33638 = defunc_0_f_res_33645 + redout_34661;
                    double redout_tmp_42796 = defunc_0_op_res_33638;
                    
                    redout_34661 = redout_tmp_42796;
                }
                defunc_0_reduce_res_34318 = redout_34661;
                
                double defunc_0_f_res_33641 = x_33255 + defunc_0_reduce_res_34318;
                
                ((double *) mem_39732)[i_34669 * flat_dim_30550 + i_34665] = defunc_0_f_res_33641;
            }
        }
        for (int64_t i_34681 = 0; i_34681 < dz2082Uz2083U_26623; i_34681++) {
            int64_t binop_x_37762 = (int64_t) 784 * i_34681;
            
            for (int64_t i_34677 = 0; i_34677 < (int64_t) 28; i_34677++) {
                int64_t binop_y_37763 = (int64_t) 28 * i_34677;
                int64_t binop_x_37764 = binop_x_37762 + binop_y_37763;
                
                for (int64_t i_34673 = 0; i_34673 < (int64_t) 28; i_34673++) {
                    int64_t binop_x_37765 = i_34673 + binop_x_37764;
                    int64_t new_index_37766 = squot64(binop_x_37765, flat_dim_30550);
                    int64_t binop_y_37776 = flat_dim_30550 * new_index_37766;
                    int64_t new_index_37777 = binop_x_37765 - binop_y_37776;
                    double x_30590 = ((double *) mem_39732)[new_index_37766 * flat_dim_30550 + new_index_37777];
                    double max_res_30591 = fmax64(0.0, x_30590);
                    
                    ((double *) mem_39778)[i_34681 * (int64_t) 784 + i_34677 * (int64_t) 28 + i_34673] = max_res_30591;
                }
            }
        }
        for (int64_t i_34685 = 0; i_34685 < (int64_t) 32; i_34685++) {
            int64_t i_30594 = mul64(elem_groups_30357, i_34685);
            int64_t arg_30595 = add64((int64_t) 1, i_34685);
            int64_t j_30596 = mul64(elem_groups_30357, arg_30595);
            int64_t j_m_i_30597 = sub64(j_30596, i_30594);
            bool empty_slice_30598 = j_m_i_30597 == (int64_t) 0;
            int64_t m_30599 = sub64(j_m_i_30597, (int64_t) 1);
            int64_t i_p_m_t_s_30600 = add64(i_30594, m_30599);
            bool zzero_leq_i_p_m_t_s_30601 = sle64((int64_t) 0, i_p_m_t_s_30600);
            bool i_p_m_t_s_leq_w_30602 = slt64(i_p_m_t_s_30600, dz2082Uz2083U_26623);
            bool zzero_lte_i_30603 = sle64((int64_t) 0, i_30594);
            bool i_lte_j_30604 = sle64(i_30594, j_30596);
            bool y_30605 = i_p_m_t_s_leq_w_30602 && zzero_lte_i_30603;
            bool y_30606 = zzero_leq_i_p_m_t_s_30601 && y_30605;
            bool y_30607 = i_lte_j_30604 && y_30606;
            bool forwards_ok_30608 = zzero_lte_i_30603 && y_30607;
            bool ok_or_empty_30609 = empty_slice_30598 || forwards_ok_30608;
            bool index_certs_30610;
            
            if (!ok_or_empty_30609) {
                set_error(ctx, msgprintf("Error: %s%lld%s%lld%s%lld%s\n\nBacktrace:\n%s", "Index [", (long long) i_30594, ":", (long long) j_30596, "] out of bounds for array of shape [", (long long) dz2082Uz2083U_26623, "].", "-> #0  ../layers/groupnorm.fut:2:31-70\n   #1  /prelude/soacs.fut:59:9-10\n   #2  /prelude/array.fut:200:10-17\n   #3  ../layers/groupnorm.fut:2:23-97\n   #4  ../layers/groupnorm.fut:20:19-54\n"));
                err = FUTHARK_PROGRAM_ERROR;
                goto cleanup;
            }
            
            bool dim_match_30611 = elem_groups_30357 == j_m_i_30597;
            bool empty_or_match_cert_30612;
            
            if (!dim_match_30611) {
                set_error(ctx, msgprintf("Error: %s%lld%s%lld%s%lld%s%lld%s%lld%s%lld%s\n\nBacktrace:\n%s", "Value of (core language) shape (", (long long) j_m_i_30597, ", ", (long long) (int64_t) 28, ", ", (long long) (int64_t) 28, ") cannot match shape of type `[", (long long) elem_groups_30357, "][", (long long) (int64_t) 28, "][", (long long) (int64_t) 28, "]f64`.", "-> #0  ../layers/groupnorm.fut:2:31-96\n   #1  /prelude/soacs.fut:59:9-10\n   #2  /prelude/array.fut:200:10-17\n   #3  ../layers/groupnorm.fut:2:23-97\n   #4  ../layers/groupnorm.fut:20:19-54\n"));
                err = FUTHARK_PROGRAM_ERROR;
                goto cleanup;
            }
            if (elem_groups_30357 * (int64_t) 28 * (int64_t) 28 * (int64_t) 8 > 0)
                memmove(mem_39866 + i_34685 * flat_dim_30385 * (int64_t) 8, mem_39778 + (int64_t) 784 * i_30594 * (int64_t) 8, elem_groups_30357 * (int64_t) 28 * (int64_t) 28 * (int64_t) 8);
        }
        for (int64_t i_34695 = 0; i_34695 < (int64_t) 32; i_34695++) {
            int64_t binop_x_37666 = flat_dim_30385 * i_34695;
            double defunc_0_reduce_res_34322;
            double redout_34687 = 0.0;
            
            for (int64_t i_34688 = 0; i_34688 < flat_dim_30385; i_34688++) {
                int64_t binop_x_37667 = i_34688 + binop_x_37666;
                int64_t new_index_37670 = squot64(binop_x_37667, flat_dim_30385);
                int64_t binop_y_37680 = flat_dim_30385 * new_index_37670;
                int64_t binop_x_37681 = binop_x_37667 - binop_y_37680;
                int64_t new_index_37682 = squot64(binop_x_37681, (int64_t) 784);
                int64_t binop_y_37706 = (int64_t) 784 * new_index_37682;
                int64_t binop_x_37707 = binop_x_37681 - binop_y_37706;
                int64_t new_index_37708 = squot64(binop_x_37707, (int64_t) 28);
                int64_t binop_y_37760 = (int64_t) 28 * new_index_37708;
                int64_t new_index_37761 = binop_x_37707 - binop_y_37760;
                double x_30625 = ((double *) mem_39866)[new_index_37670 * flat_dim_30385 + new_index_37682 * (int64_t) 784 + new_index_37708 * (int64_t) 28 + new_index_37761];
                double defunc_0_op_res_30624 = x_30625 + redout_34687;
                double redout_tmp_42803 = defunc_0_op_res_30624;
                
                redout_34687 = redout_tmp_42803;
            }
            defunc_0_reduce_res_34322 = redout_34687;
            
            double mean_res_30626 = defunc_0_reduce_res_34322 / i64_res_30386;
            double defunc_0_reduce_res_34323;
            double redout_34689 = 0.0;
            
            for (int64_t i_34690 = 0; i_34690 < flat_dim_30385; i_34690++) {
                int64_t binop_x_37571 = i_34690 + binop_x_37666;
                int64_t new_index_37574 = squot64(binop_x_37571, flat_dim_30385);
                int64_t binop_y_37584 = flat_dim_30385 * new_index_37574;
                int64_t binop_x_37585 = binop_x_37571 - binop_y_37584;
                int64_t new_index_37586 = squot64(binop_x_37585, (int64_t) 784);
                int64_t binop_y_37610 = (int64_t) 784 * new_index_37586;
                int64_t binop_x_37611 = binop_x_37585 - binop_y_37610;
                int64_t new_index_37612 = squot64(binop_x_37611, (int64_t) 28);
                int64_t binop_y_37664 = (int64_t) 28 * new_index_37612;
                int64_t new_index_37665 = binop_x_37611 - binop_y_37664;
                double x_33653 = ((double *) mem_39866)[new_index_37574 * flat_dim_30385 + new_index_37586 * (int64_t) 784 + new_index_37612 * (int64_t) 28 + new_index_37665];
                double arg_33654 = x_33653 - mean_res_30626;
                double defunc_0_f_res_33655 = arg_33654 * arg_33654;
                double defunc_0_op_res_30634 = defunc_0_f_res_33655 + redout_34689;
                double redout_tmp_42804 = defunc_0_op_res_30634;
                
                redout_34689 = redout_tmp_42804;
            }
            defunc_0_reduce_res_34323 = redout_34689;
            
            double variance_res_30636 = defunc_0_reduce_res_34323 / i64_res_30386;
            
            ((double *) mem_39897)[i_34695] = mean_res_30626;
            ((double *) mem_39899)[i_34695] = variance_res_30636;
        }
        for (int64_t i_34718 = 0; i_34718 < dz2082Uz2083U_26623; i_34718++) {
            int64_t i_33198 = sdiv64(i_34718, elem_groups_30357);
            bool x_33199 = sle64((int64_t) 0, i_33198);
            bool y_33200 = slt64(i_33198, (int64_t) 32);
            bool bounds_check_33201 = x_33199 && y_33200;
            bool index_certs_33202;
            
            if (!bounds_check_33201) {
                set_error(ctx, msgprintf("Error: %s%lld%s%lld%s\n\nBacktrace:\n%s", "Index [", (long long) i_33198, "] out of bounds for array of shape [", (long long) (int64_t) 32, "].", "-> #0  ../layers/groupnorm.fut:22:57-85\n   #1  /prelude/soacs.fut:59:9-10\n   #2  /prelude/array.fut:200:10-17\n   #3  /prelude/functional.fut:39:61-65\n   #4  /prelude/soacs.fut:59:9-10\n   #5  /prelude/array.fut:208:27-34\n   #6  /prelude/functional.fut:39:61-65\n   #7  /prelude/soacs.fut:59:9-10\n   #8  /prelude/array.fut:216:32-39\n   #9  ../layers/groupnorm.fut:22:31-135\n"));
                err = FUTHARK_PROGRAM_ERROR;
                goto cleanup;
            }
            
            double arg_33203 = ((double *) mem_39897)[i_33198];
            double arg_33204 = ((double *) mem_39899)[i_33198];
            double sqrt_arg_33205 = 1.0e-5 + arg_33204;
            double sqrt_res_33206 = futrts_sqrt64(sqrt_arg_33205);
            
            for (int64_t i_34704 = 0; i_34704 < (int64_t) 28; i_34704++) {
                for (int64_t i_34700 = 0; i_34700 < (int64_t) 28; i_34700++) {
                    double arg_33220 = ((double *) mem_39778)[i_34718 * (int64_t) 784 + i_34704 * (int64_t) 28 + i_34700];
                    double arg_33221 = arg_33220 - arg_33203;
                    double defunc_0_f_res_33222 = arg_33221 / sqrt_res_33206;
                    
                    ((double *) mem_39929)[i_34718 * (int64_t) 784 + i_34704 * (int64_t) 28 + i_34700] = defunc_0_f_res_33222;
                }
            }
            for (int64_t i_34712 = 0; i_34712 < (int64_t) 30; i_34712++) {
                bool cond_33226 = slt64(i_34712, (int64_t) 1);
                bool cond_f_res_33227 = sle64((int64_t) 29, i_34712);
                bool x_33228 = !cond_33226;
                bool y_33229 = cond_f_res_33227 && x_33228;
                bool cond_33230 = cond_33226 || y_33229;
                bool x_33231 = !cond_33230;
                
                for (int64_t i_34708 = 0; i_34708 < (int64_t) 30; i_34708++) {
                    bool cond_f_res_33234 = slt64(i_34708, (int64_t) 1);
                    bool y_33235 = x_33231 && cond_f_res_33234;
                    bool cond_33236 = cond_33230 || y_33235;
                    bool cond_f_res_33237 = sle64((int64_t) 29, i_34708);
                    bool x_33238 = !cond_33236;
                    bool y_33239 = cond_f_res_33237 && x_33238;
                    bool cond_33240 = cond_33236 || y_33239;
                    double defunc_0_f_res_33241;
                    
                    if (cond_33240 == 1) {
                        defunc_0_f_res_33241 = 0.0;
                    } else {
                        int64_t i_33242 = sub64(i_34712, (int64_t) 1);
                        int64_t i_33246 = sub64(i_34708, (int64_t) 1);
                        double defunc_0_f_res_f_res_33252 = ((double *) mem_39929)[i_34718 * (int64_t) 784 + i_33242 * (int64_t) 28 + i_33246];
                        
                        defunc_0_f_res_33241 = defunc_0_f_res_f_res_33252;
                    }
                    ((double *) mem_39924)[i_34718 * (int64_t) 900 + i_34712 * (int64_t) 30 + i_34708] = defunc_0_f_res_33241;
                }
            }
        }
        for (int64_t i_34727 = 0; i_34727 < new_n_30692; i_34727++) {
            int64_t j_30757 = add64(dz2082Uz2084U_26628, i_34727);
            int64_t i_p_m_t_s_30758 = add64(m_30749, i_34727);
            bool zzero_leq_i_p_m_t_s_30759 = sle64((int64_t) 0, i_p_m_t_s_30758);
            bool i_p_m_t_s_leq_w_30760 = slt64(i_p_m_t_s_30758, (int64_t) 30);
            bool i_lte_j_30762 = sle64(i_34727, j_30757);
            bool y_30764 = zzero_leq_i_p_m_t_s_30759 && i_p_m_t_s_leq_w_30760;
            bool y_30765 = i_lte_j_30762 && y_30764;
            bool ok_or_empty_30767 = empty_slice_30748 || y_30765;
            
            for (int64_t i_34723 = 0; i_34723 < new_n_30692; i_34723++) {
                int64_t j_30770 = add64(dz2082Uz2084U_26628, i_34723);
                int64_t i_p_m_t_s_30771 = add64(m_30749, i_34723);
                bool zzero_leq_i_p_m_t_s_30772 = sle64((int64_t) 0, i_p_m_t_s_30771);
                bool i_p_m_t_s_leq_w_30773 = slt64(i_p_m_t_s_30771, (int64_t) 30);
                bool i_lte_j_30775 = sle64(i_34723, j_30770);
                bool y_30777 = zzero_leq_i_p_m_t_s_30772 && i_p_m_t_s_leq_w_30773;
                bool y_30778 = i_lte_j_30775 && y_30777;
                bool ok_or_empty_30780 = empty_slice_30748 || y_30778;
                bool index_ok_30781 = ok_or_empty_30767 && ok_or_empty_30780;
                bool index_certs_30782;
                
                if (!index_ok_30781) {
                    set_error(ctx, msgprintf("Error: %s%lld%s%lld%s%lld%s%lld%s%lld%s%lld%s\n\nBacktrace:\n%s", "Index [", (long long) i_34727, ":", (long long) j_30757, ", ", (long long) i_34723, ":", (long long) j_30770, "] out of bounds for array of shape [", (long long) (int64_t) 30, "][", (long long) (int64_t) 30, "].", "-> #0  ../layers/conv2d.fut:11:90-124\n   #1  ../layers/conv2d.fut:11:144-146\n   #2  /prelude/soacs.fut:59:9-10\n   #3  /prelude/array.fut:200:10-17\n   #4  /prelude/functional.fut:39:61-65\n   #5  /prelude/soacs.fut:59:9-10\n   #6  /prelude/array.fut:208:27-34\n   #7  ../layers/conv2d.fut:11:50-162\n   #8  ../layers/conv2d.fut:24:17-54\n"));
                    err = FUTHARK_PROGRAM_ERROR;
                    goto cleanup;
                }
                for (int64_t i_42813 = 0; i_42813 < total_30697; i_42813++) {
                    double tmp_42814 = ((double *) mem_39924)[(int64_t) 30 * i_34727 + i_34723 + (squot64(i_42813, dz2082Uz2084U_26628 * dz2082Uz2084U_26628) * (int64_t) 900 + squot64(i_42813 - squot64(i_42813, dz2082Uz2084U_26628 * dz2082Uz2084U_26628) * (dz2082Uz2084U_26628 * dz2082Uz2084U_26628), dz2082Uz2084U_26628) * (int64_t) 30 + (i_42813 - squot64(i_42813, dz2082Uz2084U_26628 * dz2082Uz2084U_26628) * (dz2082Uz2084U_26628 * dz2082Uz2084U_26628) - squot64(i_42813 - squot64(i_42813, dz2082Uz2084U_26628 * dz2082Uz2084U_26628) * (dz2082Uz2084U_26628 * dz2082Uz2084U_26628), dz2082Uz2084U_26628) * dz2082Uz2084U_26628))];
                    
                    ((double *) mem_40098)[i_34727 * binop_y_37537 + i_34723 * total_30697 + i_42813] = tmp_42814;
                }
            }
        }
        for (int64_t i_34737 = 0; i_34737 < dz2082Uz2082U_26627; i_34737++) {
            double x_33177 = ((double *) b2_c1_b_mem_38954.mem)[i_34737];
            int64_t binop_x_37432 = total_30697 * i_34737;
            
            for (int64_t i_34733 = 0; i_34733 < flat_dim_30785; i_34733++) {
                int64_t binop_x_37535 = total_30697 * i_34733;
                double defunc_0_reduce_res_34329;
                double redout_34729 = 0.0;
                
                for (int64_t i_34730 = 0; i_34730 < total_30697; i_34730++) {
                    int64_t binop_x_37433 = i_34730 + binop_x_37432;
                    int64_t new_index_37436 = squot64(binop_x_37433, total_30697);
                    int64_t binop_y_37446 = total_30697 * new_index_37436;
                    int64_t binop_x_37447 = binop_x_37433 - binop_y_37446;
                    int64_t new_index_37449 = squot64(binop_x_37447, binop_y_37448);
                    int64_t binop_y_37475 = binop_y_37448 * new_index_37449;
                    int64_t binop_x_37476 = binop_x_37447 - binop_y_37475;
                    int64_t new_index_37477 = squot64(binop_x_37476, dz2082Uz2085U_26629);
                    int64_t binop_y_37533 = dz2082Uz2085U_26629 * new_index_37477;
                    int64_t new_index_37534 = binop_x_37476 - binop_y_37533;
                    double x_33678 = ((double *) b2_c1_w_mem_38953.mem)[new_index_37436 * (dz2082Uz2085U_26629 * dz2082Uz2084U_26628 * dz2082Uz2083U_26623) + new_index_37449 * (dz2082Uz2085U_26629 * dz2082Uz2084U_26628) + new_index_37477 * dz2082Uz2085U_26629 + new_index_37534];
                    int64_t binop_x_37536 = i_34730 + binop_x_37535;
                    int64_t new_index_37538 = squot64(binop_x_37536, binop_y_37537);
                    int64_t binop_y_37546 = binop_y_37537 * new_index_37538;
                    int64_t binop_x_37547 = binop_x_37536 - binop_y_37546;
                    int64_t new_index_37548 = squot64(binop_x_37547, total_30697);
                    int64_t binop_y_37568 = total_30697 * new_index_37548;
                    int64_t new_index_37569 = binop_x_37547 - binop_y_37568;
                    double x_33679 = ((double *) mem_40098)[new_index_37538 * binop_y_37537 + new_index_37548 * total_30697 + new_index_37569];
                    double defunc_0_f_res_33680 = x_33678 * x_33679;
                    double defunc_0_op_res_33673 = defunc_0_f_res_33680 + redout_34729;
                    double redout_tmp_42817 = defunc_0_op_res_33673;
                    
                    redout_34729 = redout_tmp_42817;
                }
                defunc_0_reduce_res_34329 = redout_34729;
                
                double defunc_0_f_res_33676 = x_33177 + defunc_0_reduce_res_34329;
                
                ((double *) mem_40159)[i_34737 * flat_dim_30785 + i_34733] = defunc_0_f_res_33676;
            }
        }
        for (int64_t i_34749 = 0; i_34749 < dz2083Uz2081U_26630; i_34749++) {
            int64_t binop_x_37416 = (int64_t) 784 * i_34749;
            
            for (int64_t i_34745 = 0; i_34745 < (int64_t) 28; i_34745++) {
                int64_t binop_y_37417 = (int64_t) 28 * i_34745;
                int64_t binop_x_37418 = binop_x_37416 + binop_y_37417;
                
                for (int64_t i_34741 = 0; i_34741 < (int64_t) 28; i_34741++) {
                    int64_t binop_x_37419 = i_34741 + binop_x_37418;
                    int64_t new_index_37420 = squot64(binop_x_37419, flat_dim_30785);
                    int64_t binop_y_37430 = flat_dim_30785 * new_index_37420;
                    int64_t new_index_37431 = binop_x_37419 - binop_y_37430;
                    double x_30825 = ((double *) mem_40159)[new_index_37420 * flat_dim_30785 + new_index_37431];
                    double max_res_30826 = fmax64(0.0, x_30825);
                    
                    ((double *) mem_40205)[i_34749 * (int64_t) 784 + i_34745 * (int64_t) 28 + i_34741] = max_res_30826;
                }
            }
        }
        for (int64_t i_34753 = 0; i_34753 < (int64_t) 32; i_34753++) {
            int64_t i_30837 = mul64(elem_groups_30830, i_34753);
            int64_t arg_30838 = add64((int64_t) 1, i_34753);
            int64_t j_30839 = mul64(elem_groups_30830, arg_30838);
            int64_t j_m_i_30840 = sub64(j_30839, i_30837);
            bool empty_slice_30841 = j_m_i_30840 == (int64_t) 0;
            int64_t m_30842 = sub64(j_m_i_30840, (int64_t) 1);
            int64_t i_p_m_t_s_30843 = add64(i_30837, m_30842);
            bool zzero_leq_i_p_m_t_s_30844 = sle64((int64_t) 0, i_p_m_t_s_30843);
            bool i_p_m_t_s_leq_w_30845 = slt64(i_p_m_t_s_30843, dz2083Uz2081U_26630);
            bool zzero_lte_i_30846 = sle64((int64_t) 0, i_30837);
            bool i_lte_j_30847 = sle64(i_30837, j_30839);
            bool y_30848 = i_p_m_t_s_leq_w_30845 && zzero_lte_i_30846;
            bool y_30849 = zzero_leq_i_p_m_t_s_30844 && y_30848;
            bool y_30850 = i_lte_j_30847 && y_30849;
            bool forwards_ok_30851 = zzero_lte_i_30846 && y_30850;
            bool ok_or_empty_30852 = empty_slice_30841 || forwards_ok_30851;
            bool index_certs_30853;
            
            if (!ok_or_empty_30852) {
                set_error(ctx, msgprintf("Error: %s%lld%s%lld%s%lld%s\n\nBacktrace:\n%s", "Index [", (long long) i_30837, ":", (long long) j_30839, "] out of bounds for array of shape [", (long long) dz2083Uz2081U_26630, "].", "-> #0  ../layers/groupnorm.fut:2:31-70\n   #1  /prelude/soacs.fut:59:9-10\n   #2  /prelude/array.fut:200:10-17\n   #3  ../layers/groupnorm.fut:2:23-97\n   #4  ../layers/groupnorm.fut:20:19-54\n"));
                err = FUTHARK_PROGRAM_ERROR;
                goto cleanup;
            }
            
            bool dim_match_30854 = elem_groups_30830 == j_m_i_30840;
            bool empty_or_match_cert_30855;
            
            if (!dim_match_30854) {
                set_error(ctx, msgprintf("Error: %s%lld%s%lld%s%lld%s%lld%s%lld%s%lld%s\n\nBacktrace:\n%s", "Value of (core language) shape (", (long long) j_m_i_30840, ", ", (long long) (int64_t) 28, ", ", (long long) (int64_t) 28, ") cannot match shape of type `[", (long long) elem_groups_30830, "][", (long long) (int64_t) 28, "][", (long long) (int64_t) 28, "]f64`.", "-> #0  ../layers/groupnorm.fut:2:31-96\n   #1  /prelude/soacs.fut:59:9-10\n   #2  /prelude/array.fut:200:10-17\n   #3  ../layers/groupnorm.fut:2:23-97\n   #4  ../layers/groupnorm.fut:20:19-54\n"));
                err = FUTHARK_PROGRAM_ERROR;
                goto cleanup;
            }
            if (elem_groups_30830 * (int64_t) 28 * (int64_t) 28 * (int64_t) 8 > 0)
                memmove(mem_40293 + i_34753 * flat_dim_30858 * (int64_t) 8, mem_40205 + (int64_t) 784 * i_30837 * (int64_t) 8, elem_groups_30830 * (int64_t) 28 * (int64_t) 28 * (int64_t) 8);
        }
        for (int64_t i_34763 = 0; i_34763 < (int64_t) 32; i_34763++) {
            int64_t binop_x_37320 = flat_dim_30858 * i_34763;
            double defunc_0_reduce_res_34333;
            double redout_34755 = 0.0;
            
            for (int64_t i_34756 = 0; i_34756 < flat_dim_30858; i_34756++) {
                int64_t binop_x_37321 = i_34756 + binop_x_37320;
                int64_t new_index_37324 = squot64(binop_x_37321, flat_dim_30858);
                int64_t binop_y_37334 = flat_dim_30858 * new_index_37324;
                int64_t binop_x_37335 = binop_x_37321 - binop_y_37334;
                int64_t new_index_37336 = squot64(binop_x_37335, (int64_t) 784);
                int64_t binop_y_37360 = (int64_t) 784 * new_index_37336;
                int64_t binop_x_37361 = binop_x_37335 - binop_y_37360;
                int64_t new_index_37362 = squot64(binop_x_37361, (int64_t) 28);
                int64_t binop_y_37414 = (int64_t) 28 * new_index_37362;
                int64_t new_index_37415 = binop_x_37361 - binop_y_37414;
                double x_30868 = ((double *) mem_40293)[new_index_37324 * flat_dim_30858 + new_index_37336 * (int64_t) 784 + new_index_37362 * (int64_t) 28 + new_index_37415];
                double defunc_0_op_res_30867 = x_30868 + redout_34755;
                double redout_tmp_42824 = defunc_0_op_res_30867;
                
                redout_34755 = redout_tmp_42824;
            }
            defunc_0_reduce_res_34333 = redout_34755;
            
            double mean_res_30869 = defunc_0_reduce_res_34333 / i64_res_30859;
            double defunc_0_reduce_res_34334;
            double redout_34757 = 0.0;
            
            for (int64_t i_34758 = 0; i_34758 < flat_dim_30858; i_34758++) {
                int64_t binop_x_37225 = i_34758 + binop_x_37320;
                int64_t new_index_37228 = squot64(binop_x_37225, flat_dim_30858);
                int64_t binop_y_37238 = flat_dim_30858 * new_index_37228;
                int64_t binop_x_37239 = binop_x_37225 - binop_y_37238;
                int64_t new_index_37240 = squot64(binop_x_37239, (int64_t) 784);
                int64_t binop_y_37264 = (int64_t) 784 * new_index_37240;
                int64_t binop_x_37265 = binop_x_37239 - binop_y_37264;
                int64_t new_index_37266 = squot64(binop_x_37265, (int64_t) 28);
                int64_t binop_y_37318 = (int64_t) 28 * new_index_37266;
                int64_t new_index_37319 = binop_x_37265 - binop_y_37318;
                double x_33688 = ((double *) mem_40293)[new_index_37228 * flat_dim_30858 + new_index_37240 * (int64_t) 784 + new_index_37266 * (int64_t) 28 + new_index_37319];
                double arg_33689 = x_33688 - mean_res_30869;
                double defunc_0_f_res_33690 = arg_33689 * arg_33689;
                double defunc_0_op_res_30877 = defunc_0_f_res_33690 + redout_34757;
                double redout_tmp_42825 = defunc_0_op_res_30877;
                
                redout_34757 = redout_tmp_42825;
            }
            defunc_0_reduce_res_34334 = redout_34757;
            
            double variance_res_30879 = defunc_0_reduce_res_34334 / i64_res_30859;
            
            ((double *) mem_40324)[i_34763] = mean_res_30869;
            ((double *) mem_40326)[i_34763] = variance_res_30879;
        }
        for (int64_t i_34786 = 0; i_34786 < dz2083Uz2081U_26630; i_34786++) {
            double x_33096 = ((double *) b2_tb_mem_38956.mem)[i_34786];
            int64_t i_33101 = sdiv64(i_34786, elem_groups_30830);
            bool x_33102 = sle64((int64_t) 0, i_33101);
            bool y_33103 = slt64(i_33101, (int64_t) 32);
            bool bounds_check_33104 = x_33102 && y_33103;
            bool index_certs_33105;
            
            if (!bounds_check_33104) {
                set_error(ctx, msgprintf("Error: %s%lld%s%lld%s\n\nBacktrace:\n%s", "Index [", (long long) i_33101, "] out of bounds for array of shape [", (long long) (int64_t) 32, "].", "-> #0  ../layers/groupnorm.fut:22:57-85\n   #1  /prelude/soacs.fut:59:9-10\n   #2  /prelude/array.fut:200:10-17\n   #3  /prelude/functional.fut:39:61-65\n   #4  /prelude/soacs.fut:59:9-10\n   #5  /prelude/array.fut:208:27-34\n   #6  /prelude/functional.fut:39:61-65\n   #7  /prelude/soacs.fut:59:9-10\n   #8  /prelude/array.fut:216:32-39\n   #9  ../layers/groupnorm.fut:22:31-135\n"));
                err = FUTHARK_PROGRAM_ERROR;
                goto cleanup;
            }
            
            double arg_33106 = ((double *) mem_40324)[i_33101];
            double arg_33107 = ((double *) mem_40326)[i_33101];
            double sqrt_arg_33108 = 1.0e-5 + arg_33107;
            double sqrt_res_33109 = futrts_sqrt64(sqrt_arg_33108);
            double defunc_0_reduce_res_34337;
            double redout_34766 = 0.0;
            
            for (int64_t i_34767 = 0; i_34767 < (int64_t) 256; i_34767++) {
                bool index_concat_cmp_35277 = sle64((int64_t) 128, i_34767);
                double index_concat_branch_35281;
                
                if (index_concat_cmp_35277 == 1) {
                    int64_t index_concat_i_35278 = sub64(i_34767, (int64_t) 128);
                    double index_concat_35279 = ((double *) mem_39033)[index_concat_i_35278];
                    
                    index_concat_branch_35281 = index_concat_35279;
                } else {
                    double index_concat_35280 = ((double *) mem_39031)[i_34767];
                    
                    index_concat_branch_35281 = index_concat_35280;
                }
                
                double x_33696 = ((double *) b2_tw_mem_38955.mem)[i_34786 * (int64_t) 256 + i_34767];
                double defunc_0_f_res_33697 = x_33696 * index_concat_branch_35281;
                double defunc_0_op_res_33134 = defunc_0_f_res_33697 + redout_34766;
                double redout_tmp_42827 = defunc_0_op_res_33134;
                
                redout_34766 = redout_tmp_42827;
            }
            defunc_0_reduce_res_34337 = redout_34766;
            
            double defunc_0_f_res_33136 = x_33096 + defunc_0_reduce_res_34337;
            double max_res_33138 = fmax64(0.0, defunc_0_f_res_33136);
            
            for (int64_t i_34774 = 0; i_34774 < (int64_t) 28; i_34774++) {
                for (int64_t i_34770 = 0; i_34770 < (int64_t) 28; i_34770++) {
                    double arg_33727 = ((double *) mem_40205)[i_34786 * (int64_t) 784 + i_34774 * (int64_t) 28 + i_34770];
                    double arg_33728 = arg_33727 - arg_33106;
                    double defunc_0_f_res_33729 = arg_33728 / sqrt_res_33109;
                    double defunc_0_f_res_33731 = max_res_33138 + defunc_0_f_res_33729;
                    
                    ((double *) mem_40364)[i_34774 * (int64_t) 28 + i_34770] = defunc_0_f_res_33731;
                }
            }
            for (int64_t i_34782 = 0; i_34782 < (int64_t) 30; i_34782++) {
                bool cond_33148 = slt64(i_34782, (int64_t) 1);
                bool cond_f_res_33149 = sle64((int64_t) 29, i_34782);
                bool x_33150 = !cond_33148;
                bool y_33151 = cond_f_res_33149 && x_33150;
                bool cond_33152 = cond_33148 || y_33151;
                bool x_33153 = !cond_33152;
                
                for (int64_t i_34778 = 0; i_34778 < (int64_t) 30; i_34778++) {
                    bool cond_f_res_33156 = slt64(i_34778, (int64_t) 1);
                    bool y_33157 = x_33153 && cond_f_res_33156;
                    bool cond_33158 = cond_33152 || y_33157;
                    bool cond_f_res_33159 = sle64((int64_t) 29, i_34778);
                    bool x_33160 = !cond_33158;
                    bool y_33161 = cond_f_res_33159 && x_33160;
                    bool cond_33162 = cond_33158 || y_33161;
                    double defunc_0_f_res_33163;
                    
                    if (cond_33162 == 1) {
                        defunc_0_f_res_33163 = 0.0;
                    } else {
                        int64_t i_33164 = sub64(i_34782, (int64_t) 1);
                        bool x_33165 = sle64((int64_t) 0, i_33164);
                        bool y_33166 = slt64(i_33164, (int64_t) 28);
                        bool bounds_check_33167 = x_33165 && y_33166;
                        int64_t i_33168 = sub64(i_34778, (int64_t) 1);
                        bool x_33169 = sle64((int64_t) 0, i_33168);
                        bool y_33170 = slt64(i_33168, (int64_t) 28);
                        bool bounds_check_33171 = x_33169 && y_33170;
                        bool index_ok_33172 = bounds_check_33167 && bounds_check_33171;
                        bool index_certs_33173;
                        
                        if (!index_ok_33172) {
                            set_error(ctx, msgprintf("Error: %s%lld%s%lld%s%lld%s%lld%s\n\nBacktrace:\n%s", "Index [", (long long) i_33164, ", ", (long long) i_33168, "] out of bounds for array of shape [", (long long) (int64_t) 28, "][", (long long) (int64_t) 28, "].", "-> #0  ../layers/conv2d.fut:7:91-116\n   #1  /prelude/soacs.fut:59:9-10\n   #2  /prelude/array.fut:200:10-17\n   #3  /prelude/functional.fut:39:61-65\n   #4  /prelude/soacs.fut:59:9-10\n   #5  /prelude/array.fut:208:27-34\n   #6  ../layers/conv2d.fut:6:46-7:117\n   #7  ../layers/conv2d.fut:7:120-123\n   #8  ../layers/conv2d.fut:20:7-30\n"));
                            err = FUTHARK_PROGRAM_ERROR;
                            goto cleanup;
                        }
                        
                        double defunc_0_f_res_f_res_33174 = ((double *) mem_40364)[i_33164 * (int64_t) 28 + i_33168];
                        
                        defunc_0_f_res_33163 = defunc_0_f_res_f_res_33174;
                    }
                    ((double *) mem_40351)[i_34786 * (int64_t) 900 + i_34782 * (int64_t) 30 + i_34778] = defunc_0_f_res_33163;
                }
            }
        }
        for (int64_t i_34794 = 0; i_34794 < new_n_30941; i_34794++) {
            int64_t j_30995 = add64(dz2083Uz2082U_26632, i_34794);
            int64_t i_p_m_t_s_30996 = add64(m_30987, i_34794);
            bool zzero_leq_i_p_m_t_s_30997 = sle64((int64_t) 0, i_p_m_t_s_30996);
            bool i_p_m_t_s_leq_w_30998 = slt64(i_p_m_t_s_30996, (int64_t) 30);
            bool i_lte_j_31000 = sle64(i_34794, j_30995);
            bool y_31002 = zzero_leq_i_p_m_t_s_30997 && i_p_m_t_s_leq_w_30998;
            bool y_31003 = i_lte_j_31000 && y_31002;
            bool ok_or_empty_31005 = empty_slice_30986 || y_31003;
            
            for (int64_t i_34790 = 0; i_34790 < new_n_30941; i_34790++) {
                int64_t j_31008 = add64(dz2083Uz2082U_26632, i_34790);
                int64_t i_p_m_t_s_31009 = add64(m_30987, i_34790);
                bool zzero_leq_i_p_m_t_s_31010 = sle64((int64_t) 0, i_p_m_t_s_31009);
                bool i_p_m_t_s_leq_w_31011 = slt64(i_p_m_t_s_31009, (int64_t) 30);
                bool i_lte_j_31013 = sle64(i_34790, j_31008);
                bool y_31015 = zzero_leq_i_p_m_t_s_31010 && i_p_m_t_s_leq_w_31011;
                bool y_31016 = i_lte_j_31013 && y_31015;
                bool ok_or_empty_31018 = empty_slice_30986 || y_31016;
                bool index_ok_31019 = ok_or_empty_31005 && ok_or_empty_31018;
                bool index_certs_31020;
                
                if (!index_ok_31019) {
                    set_error(ctx, msgprintf("Error: %s%lld%s%lld%s%lld%s%lld%s%lld%s%lld%s\n\nBacktrace:\n%s", "Index [", (long long) i_34794, ":", (long long) j_30995, ", ", (long long) i_34790, ":", (long long) j_31008, "] out of bounds for array of shape [", (long long) (int64_t) 30, "][", (long long) (int64_t) 30, "].", "-> #0  ../layers/conv2d.fut:11:90-124\n   #1  ../layers/conv2d.fut:11:144-146\n   #2  /prelude/soacs.fut:59:9-10\n   #3  /prelude/array.fut:200:10-17\n   #4  /prelude/functional.fut:39:61-65\n   #5  /prelude/soacs.fut:59:9-10\n   #6  /prelude/array.fut:208:27-34\n   #7  ../layers/conv2d.fut:11:50-162\n   #8  ../layers/conv2d.fut:24:17-54\n"));
                    err = FUTHARK_PROGRAM_ERROR;
                    goto cleanup;
                }
                for (int64_t i_42834 = 0; i_42834 < total_30945; i_42834++) {
                    double tmp_42835 = ((double *) mem_40351)[(int64_t) 30 * i_34794 + i_34790 + (squot64(i_42834, dz2083Uz2082U_26632 * dz2083Uz2082U_26632) * (int64_t) 900 + squot64(i_42834 - squot64(i_42834, dz2083Uz2082U_26632 * dz2083Uz2082U_26632) * (dz2083Uz2082U_26632 * dz2083Uz2082U_26632), dz2083Uz2082U_26632) * (int64_t) 30 + (i_42834 - squot64(i_42834, dz2083Uz2082U_26632 * dz2083Uz2082U_26632) * (dz2083Uz2082U_26632 * dz2083Uz2082U_26632) - squot64(i_42834 - squot64(i_42834, dz2083Uz2082U_26632 * dz2083Uz2082U_26632) * (dz2083Uz2082U_26632 * dz2083Uz2082U_26632), dz2083Uz2082U_26632) * dz2083Uz2082U_26632))];
                    
                    ((double *) mem_40478)[i_34794 * binop_y_37191 + i_34790 * total_30945 + i_42834] = tmp_42835;
                }
            }
        }
        for (int64_t i_34804 = 0; i_34804 < dz2083Uz2080U_26631; i_34804++) {
            double x_32948 = ((double *) b2_c2_b_mem_38958.mem)[i_34804];
            int64_t binop_x_37086 = total_30945 * i_34804;
            
            for (int64_t i_34800 = 0; i_34800 < flat_dim_31023; i_34800++) {
                int64_t binop_x_37189 = total_30945 * i_34800;
                double defunc_0_reduce_res_34341;
                double redout_34796 = 0.0;
                
                for (int64_t i_34797 = 0; i_34797 < total_30945; i_34797++) {
                    int64_t binop_x_37087 = i_34797 + binop_x_37086;
                    int64_t new_index_37090 = squot64(binop_x_37087, total_30945);
                    int64_t binop_y_37100 = total_30945 * new_index_37090;
                    int64_t binop_x_37101 = binop_x_37087 - binop_y_37100;
                    int64_t new_index_37103 = squot64(binop_x_37101, binop_y_37102);
                    int64_t binop_y_37129 = binop_y_37102 * new_index_37103;
                    int64_t binop_x_37130 = binop_x_37101 - binop_y_37129;
                    int64_t new_index_37131 = squot64(binop_x_37130, dz2083Uz2083U_26633);
                    int64_t binop_y_37187 = dz2083Uz2083U_26633 * new_index_37131;
                    int64_t new_index_37188 = binop_x_37130 - binop_y_37187;
                    double x_33754 = ((double *) b2_c2_w_mem_38957.mem)[new_index_37090 * (dz2083Uz2083U_26633 * dz2083Uz2082U_26632 * dz2083Uz2081U_26630) + new_index_37103 * (dz2083Uz2083U_26633 * dz2083Uz2082U_26632) + new_index_37131 * dz2083Uz2083U_26633 + new_index_37188];
                    int64_t binop_x_37190 = i_34797 + binop_x_37189;
                    int64_t new_index_37192 = squot64(binop_x_37190, binop_y_37191);
                    int64_t binop_y_37200 = binop_y_37191 * new_index_37192;
                    int64_t binop_x_37201 = binop_x_37190 - binop_y_37200;
                    int64_t new_index_37202 = squot64(binop_x_37201, total_30945);
                    int64_t binop_y_37222 = total_30945 * new_index_37202;
                    int64_t new_index_37223 = binop_x_37201 - binop_y_37222;
                    double x_33755 = ((double *) mem_40478)[new_index_37192 * binop_y_37191 + new_index_37202 * total_30945 + new_index_37223];
                    double defunc_0_f_res_33756 = x_33754 * x_33755;
                    double defunc_0_op_res_33749 = defunc_0_f_res_33756 + redout_34796;
                    double redout_tmp_42838 = defunc_0_op_res_33749;
                    
                    redout_34796 = redout_tmp_42838;
                }
                defunc_0_reduce_res_34341 = redout_34796;
                
                double defunc_0_f_res_33752 = x_32948 + defunc_0_reduce_res_34341;
                
                ((double *) mem_40539)[i_34804 * flat_dim_31023 + i_34800] = defunc_0_f_res_33752;
            }
        }
        for (int64_t i_34816 = 0; i_34816 < dz2083Uz2081U_26630; i_34816++) {
            int64_t binop_x_37070 = (int64_t) 784 * i_34816;
            
            for (int64_t i_34812 = 0; i_34812 < (int64_t) 28; i_34812++) {
                int64_t binop_y_37071 = (int64_t) 28 * i_34812;
                int64_t binop_x_37072 = binop_x_37070 + binop_y_37071;
                
                for (int64_t i_34808 = 0; i_34808 < (int64_t) 28; i_34808++) {
                    int64_t binop_x_37073 = i_34808 + binop_x_37072;
                    int64_t new_index_37074 = squot64(binop_x_37073, flat_dim_31023);
                    int64_t binop_y_37084 = flat_dim_31023 * new_index_37074;
                    int64_t new_index_37085 = binop_x_37073 - binop_y_37084;
                    double x_31063 = ((double *) mem_40539)[new_index_37074 * flat_dim_31023 + new_index_37085];
                    double max_res_31064 = fmax64(0.0, x_31063);
                    
                    ((double *) mem_40585)[i_34816 * (int64_t) 784 + i_34812 * (int64_t) 28 + i_34808] = max_res_31064;
                }
            }
        }
        for (int64_t i_34820 = 0; i_34820 < (int64_t) 32; i_34820++) {
            int64_t i_31067 = mul64(elem_groups_30830, i_34820);
            int64_t arg_31068 = add64((int64_t) 1, i_34820);
            int64_t j_31069 = mul64(elem_groups_30830, arg_31068);
            int64_t j_m_i_31070 = sub64(j_31069, i_31067);
            bool empty_slice_31071 = j_m_i_31070 == (int64_t) 0;
            int64_t m_31072 = sub64(j_m_i_31070, (int64_t) 1);
            int64_t i_p_m_t_s_31073 = add64(i_31067, m_31072);
            bool zzero_leq_i_p_m_t_s_31074 = sle64((int64_t) 0, i_p_m_t_s_31073);
            bool i_p_m_t_s_leq_w_31075 = slt64(i_p_m_t_s_31073, dz2083Uz2081U_26630);
            bool zzero_lte_i_31076 = sle64((int64_t) 0, i_31067);
            bool i_lte_j_31077 = sle64(i_31067, j_31069);
            bool y_31078 = i_p_m_t_s_leq_w_31075 && zzero_lte_i_31076;
            bool y_31079 = zzero_leq_i_p_m_t_s_31074 && y_31078;
            bool y_31080 = i_lte_j_31077 && y_31079;
            bool forwards_ok_31081 = zzero_lte_i_31076 && y_31080;
            bool ok_or_empty_31082 = empty_slice_31071 || forwards_ok_31081;
            bool index_certs_31083;
            
            if (!ok_or_empty_31082) {
                set_error(ctx, msgprintf("Error: %s%lld%s%lld%s%lld%s\n\nBacktrace:\n%s", "Index [", (long long) i_31067, ":", (long long) j_31069, "] out of bounds for array of shape [", (long long) dz2083Uz2081U_26630, "].", "-> #0  ../layers/groupnorm.fut:2:31-70\n   #1  /prelude/soacs.fut:59:9-10\n   #2  /prelude/array.fut:200:10-17\n   #3  ../layers/groupnorm.fut:2:23-97\n   #4  ../layers/groupnorm.fut:20:19-54\n"));
                err = FUTHARK_PROGRAM_ERROR;
                goto cleanup;
            }
            
            bool dim_match_31084 = elem_groups_30830 == j_m_i_31070;
            bool empty_or_match_cert_31085;
            
            if (!dim_match_31084) {
                set_error(ctx, msgprintf("Error: %s%lld%s%lld%s%lld%s%lld%s%lld%s%lld%s\n\nBacktrace:\n%s", "Value of (core language) shape (", (long long) j_m_i_31070, ", ", (long long) (int64_t) 28, ", ", (long long) (int64_t) 28, ") cannot match shape of type `[", (long long) elem_groups_30830, "][", (long long) (int64_t) 28, "][", (long long) (int64_t) 28, "]f64`.", "-> #0  ../layers/groupnorm.fut:2:31-96\n   #1  /prelude/soacs.fut:59:9-10\n   #2  /prelude/array.fut:200:10-17\n   #3  ../layers/groupnorm.fut:2:23-97\n   #4  ../layers/groupnorm.fut:20:19-54\n"));
                err = FUTHARK_PROGRAM_ERROR;
                goto cleanup;
            }
            if (elem_groups_30830 * (int64_t) 28 * (int64_t) 28 * (int64_t) 8 > 0)
                memmove(mem_40673 + i_34820 * flat_dim_30858 * (int64_t) 8, mem_40585 + (int64_t) 784 * i_31067 * (int64_t) 8, elem_groups_30830 * (int64_t) 28 * (int64_t) 28 * (int64_t) 8);
        }
        for (int64_t i_34830 = 0; i_34830 < (int64_t) 32; i_34830++) {
            int64_t binop_x_36974 = flat_dim_30858 * i_34830;
            double defunc_0_reduce_res_34345;
            double redout_34822 = 0.0;
            
            for (int64_t i_34823 = 0; i_34823 < flat_dim_30858; i_34823++) {
                int64_t binop_x_36975 = i_34823 + binop_x_36974;
                int64_t new_index_36978 = squot64(binop_x_36975, flat_dim_30858);
                int64_t binop_y_36988 = flat_dim_30858 * new_index_36978;
                int64_t binop_x_36989 = binop_x_36975 - binop_y_36988;
                int64_t new_index_36990 = squot64(binop_x_36989, (int64_t) 784);
                int64_t binop_y_37014 = (int64_t) 784 * new_index_36990;
                int64_t binop_x_37015 = binop_x_36989 - binop_y_37014;
                int64_t new_index_37016 = squot64(binop_x_37015, (int64_t) 28);
                int64_t binop_y_37068 = (int64_t) 28 * new_index_37016;
                int64_t new_index_37069 = binop_x_37015 - binop_y_37068;
                double x_31098 = ((double *) mem_40673)[new_index_36978 * flat_dim_30858 + new_index_36990 * (int64_t) 784 + new_index_37016 * (int64_t) 28 + new_index_37069];
                double defunc_0_op_res_31097 = x_31098 + redout_34822;
                double redout_tmp_42845 = defunc_0_op_res_31097;
                
                redout_34822 = redout_tmp_42845;
            }
            defunc_0_reduce_res_34345 = redout_34822;
            
            double mean_res_31099 = defunc_0_reduce_res_34345 / i64_res_30859;
            double defunc_0_reduce_res_34346;
            double redout_34824 = 0.0;
            
            for (int64_t i_34825 = 0; i_34825 < flat_dim_30858; i_34825++) {
                int64_t binop_x_36879 = i_34825 + binop_x_36974;
                int64_t new_index_36882 = squot64(binop_x_36879, flat_dim_30858);
                int64_t binop_y_36892 = flat_dim_30858 * new_index_36882;
                int64_t binop_x_36893 = binop_x_36879 - binop_y_36892;
                int64_t new_index_36894 = squot64(binop_x_36893, (int64_t) 784);
                int64_t binop_y_36918 = (int64_t) 784 * new_index_36894;
                int64_t binop_x_36919 = binop_x_36893 - binop_y_36918;
                int64_t new_index_36920 = squot64(binop_x_36919, (int64_t) 28);
                int64_t binop_y_36972 = (int64_t) 28 * new_index_36920;
                int64_t new_index_36973 = binop_x_36919 - binop_y_36972;
                double x_33764 = ((double *) mem_40673)[new_index_36882 * flat_dim_30858 + new_index_36894 * (int64_t) 784 + new_index_36920 * (int64_t) 28 + new_index_36973];
                double arg_33765 = x_33764 - mean_res_31099;
                double defunc_0_f_res_33766 = arg_33765 * arg_33765;
                double defunc_0_op_res_31107 = defunc_0_f_res_33766 + redout_34824;
                double redout_tmp_42846 = defunc_0_op_res_31107;
                
                redout_34824 = redout_tmp_42846;
            }
            defunc_0_reduce_res_34346 = redout_34824;
            
            double variance_res_31109 = defunc_0_reduce_res_34346 / i64_res_30859;
            
            ((double *) mem_40704)[i_34830] = mean_res_31099;
            ((double *) mem_40706)[i_34830] = variance_res_31109;
        }
        for (int64_t i_34843 = 0; i_34843 < dz2083Uz2081U_26630; i_34843++) {
            int64_t i_31118 = sdiv64(i_34843, elem_groups_30830);
            bool x_31119 = sle64((int64_t) 0, i_31118);
            bool y_31120 = slt64(i_31118, (int64_t) 32);
            bool bounds_check_31121 = x_31119 && y_31120;
            bool index_certs_31122;
            
            if (!bounds_check_31121) {
                set_error(ctx, msgprintf("Error: %s%lld%s%lld%s\n\nBacktrace:\n%s", "Index [", (long long) i_31118, "] out of bounds for array of shape [", (long long) (int64_t) 32, "].", "-> #0  ../layers/groupnorm.fut:22:57-85\n   #1  /prelude/soacs.fut:59:9-10\n   #2  /prelude/array.fut:200:10-17\n   #3  /prelude/functional.fut:39:61-65\n   #4  /prelude/soacs.fut:59:9-10\n   #5  /prelude/array.fut:208:27-34\n   #6  /prelude/functional.fut:39:61-65\n   #7  /prelude/soacs.fut:59:9-10\n   #8  /prelude/array.fut:216:32-39\n   #9  ../layers/groupnorm.fut:22:31-135\n"));
                err = FUTHARK_PROGRAM_ERROR;
                goto cleanup;
            }
            
            double arg_31123 = ((double *) mem_40704)[i_31118];
            double arg_31124 = ((double *) mem_40706)[i_31118];
            double sqrt_arg_31125 = 1.0e-5 + arg_31124;
            double sqrt_res_31126 = futrts_sqrt64(sqrt_arg_31125);
            
            for (int64_t i_34839 = 0; i_34839 < (int64_t) 28; i_34839++) {
                for (int64_t i_34835 = 0; i_34835 < (int64_t) 28; i_34835++) {
                    double arg_31140 = ((double *) mem_40585)[i_34843 * (int64_t) 784 + i_34839 * (int64_t) 28 + i_34835];
                    double arg_31141 = arg_31140 - arg_31123;
                    double defunc_0_f_res_31142 = arg_31141 / sqrt_res_31126;
                    
                    ((double *) mem_40731)[i_34843 * (int64_t) 784 + i_34839 * (int64_t) 28 + i_34835] = defunc_0_f_res_31142;
                }
            }
        }
        for (int64_t i_34855 = 0; i_34855 < (int64_t) 512; i_34855++) {
            for (int64_t i_34851 = 0; i_34851 < (int64_t) 30; i_34851++) {
                bool cond_31185 = slt64(i_34851, (int64_t) 1);
                bool cond_f_res_31186 = sle64((int64_t) 29, i_34851);
                bool x_31187 = !cond_31185;
                bool y_31188 = cond_f_res_31186 && x_31187;
                bool cond_31189 = cond_31185 || y_31188;
                bool x_31190 = !cond_31189;
                
                for (int64_t i_34847 = 0; i_34847 < (int64_t) 30; i_34847++) {
                    bool cond_f_res_31193 = slt64(i_34847, (int64_t) 1);
                    bool y_31194 = x_31190 && cond_f_res_31193;
                    bool cond_31195 = cond_31189 || y_31194;
                    bool cond_f_res_31196 = sle64((int64_t) 29, i_34847);
                    bool x_31197 = !cond_31195;
                    bool y_31198 = cond_f_res_31196 && x_31197;
                    bool cond_31199 = cond_31195 || y_31198;
                    double defunc_0_f_res_31200;
                    
                    if (cond_31199 == 1) {
                        defunc_0_f_res_31200 = 0.0;
                    } else {
                        int64_t i_31201 = sub64(i_34851, (int64_t) 1);
                        int64_t i_31205 = sub64(i_34847, (int64_t) 1);
                        bool index_concat_cmp_35247 = sle64(dz2083Uz2081U_26630, i_34855);
                        double index_concat_branch_35251;
                        
                        if (index_concat_cmp_35247 == 1) {
                            int64_t index_concat_i_35248 = sub64(i_34855, dz2083Uz2081U_26630);
                            double index_concat_35249 = ((double *) mem_40731)[index_concat_i_35248 * (int64_t) 784 + i_31201 * (int64_t) 28 + i_31205];
                            
                            index_concat_branch_35251 = index_concat_35249;
                        } else {
                            double index_concat_35250 = ((double *) mem_40731)[i_34855 * (int64_t) 784 + i_31201 * (int64_t) 28 + i_31205];
                            
                            index_concat_branch_35251 = index_concat_35250;
                        }
                        defunc_0_f_res_31200 = index_concat_branch_35251;
                    }
                    ((double *) mem_40815)[i_34855 * (int64_t) 900 + i_34851 * (int64_t) 30 + i_34847] = defunc_0_f_res_31200;
                }
            }
        }
        for (int64_t i_34863 = 0; i_34863 < new_n_31165; i_34863++) {
            int64_t j_31230 = add64(dz2083Uz2087U_26634, i_34863);
            int64_t i_p_m_t_s_31231 = add64(m_31222, i_34863);
            bool zzero_leq_i_p_m_t_s_31232 = sle64((int64_t) 0, i_p_m_t_s_31231);
            bool i_p_m_t_s_leq_w_31233 = slt64(i_p_m_t_s_31231, (int64_t) 30);
            bool i_lte_j_31235 = sle64(i_34863, j_31230);
            bool y_31237 = zzero_leq_i_p_m_t_s_31232 && i_p_m_t_s_leq_w_31233;
            bool y_31238 = i_lte_j_31235 && y_31237;
            bool ok_or_empty_31240 = empty_slice_31221 || y_31238;
            
            for (int64_t i_34859 = 0; i_34859 < new_n_31165; i_34859++) {
                int64_t j_31243 = add64(dz2083Uz2087U_26634, i_34859);
                int64_t i_p_m_t_s_31244 = add64(m_31222, i_34859);
                bool zzero_leq_i_p_m_t_s_31245 = sle64((int64_t) 0, i_p_m_t_s_31244);
                bool i_p_m_t_s_leq_w_31246 = slt64(i_p_m_t_s_31244, (int64_t) 30);
                bool i_lte_j_31248 = sle64(i_34859, j_31243);
                bool y_31250 = zzero_leq_i_p_m_t_s_31245 && i_p_m_t_s_leq_w_31246;
                bool y_31251 = i_lte_j_31248 && y_31250;
                bool ok_or_empty_31253 = empty_slice_31221 || y_31251;
                bool index_ok_31254 = ok_or_empty_31240 && ok_or_empty_31253;
                bool index_certs_31255;
                
                if (!index_ok_31254) {
                    set_error(ctx, msgprintf("Error: %s%lld%s%lld%s%lld%s%lld%s%lld%s%lld%s\n\nBacktrace:\n%s", "Index [", (long long) i_34863, ":", (long long) j_31230, ", ", (long long) i_34859, ":", (long long) j_31243, "] out of bounds for array of shape [", (long long) (int64_t) 30, "][", (long long) (int64_t) 30, "].", "-> #0  ../layers/conv2d.fut:11:90-124\n   #1  ../layers/conv2d.fut:11:144-146\n   #2  /prelude/soacs.fut:59:9-10\n   #3  /prelude/array.fut:200:10-17\n   #4  /prelude/functional.fut:39:61-65\n   #5  /prelude/soacs.fut:59:9-10\n   #6  /prelude/array.fut:208:27-34\n   #7  ../layers/conv2d.fut:11:50-162\n   #8  ../layers/conv2d.fut:24:17-54\n"));
                    err = FUTHARK_PROGRAM_ERROR;
                    goto cleanup;
                }
                for (int64_t i_42855 = 0; i_42855 < total_31170; i_42855++) {
                    double tmp_42856 = ((double *) mem_40815)[(int64_t) 30 * i_34863 + i_34859 + (squot64(i_42855, dz2083Uz2087U_26634 * dz2083Uz2087U_26634) * (int64_t) 900 + squot64(i_42855 - squot64(i_42855, dz2083Uz2087U_26634 * dz2083Uz2087U_26634) * (dz2083Uz2087U_26634 * dz2083Uz2087U_26634), dz2083Uz2087U_26634) * (int64_t) 30 + (i_42855 - squot64(i_42855, dz2083Uz2087U_26634 * dz2083Uz2087U_26634) * (dz2083Uz2087U_26634 * dz2083Uz2087U_26634) - squot64(i_42855 - squot64(i_42855, dz2083Uz2087U_26634 * dz2083Uz2087U_26634) * (dz2083Uz2087U_26634 * dz2083Uz2087U_26634), dz2083Uz2087U_26634) * dz2083Uz2087U_26634))];
                    
                    ((double *) mem_40902)[i_34863 * binop_y_36845 + i_34859 * total_31170 + i_42855] = tmp_42856;
                }
            }
        }
        for (int64_t i_34873 = 0; i_34873 < dz2083Uz2089U_26636; i_34873++) {
            double x_32930 = ((double *) b3_c1_b_mem_38960.mem)[i_34873];
            int64_t binop_x_36740 = total_31170 * i_34873;
            
            for (int64_t i_34869 = 0; i_34869 < flat_dim_31258; i_34869++) {
                int64_t binop_x_36843 = total_31170 * i_34869;
                double defunc_0_reduce_res_34352;
                double redout_34865 = 0.0;
                
                for (int64_t i_34866 = 0; i_34866 < total_31170; i_34866++) {
                    int64_t binop_x_36741 = i_34866 + binop_x_36740;
                    int64_t new_index_36744 = squot64(binop_x_36741, total_31170);
                    int64_t binop_y_36754 = total_31170 * new_index_36744;
                    int64_t binop_x_36755 = binop_x_36741 - binop_y_36754;
                    int64_t new_index_36757 = squot64(binop_x_36755, binop_y_36756);
                    int64_t binop_y_36783 = binop_y_36756 * new_index_36757;
                    int64_t binop_x_36784 = binop_x_36755 - binop_y_36783;
                    int64_t new_index_36785 = squot64(binop_x_36784, dz2083Uz2088U_26635);
                    int64_t binop_y_36841 = dz2083Uz2088U_26635 * new_index_36785;
                    int64_t new_index_36842 = binop_x_36784 - binop_y_36841;
                    double x_33789 = ((double *) b3_c1_w_mem_38959.mem)[new_index_36744 * (dz2083Uz2088U_26635 * dz2083Uz2087U_26634 * (int64_t) 512) + new_index_36757 * (dz2083Uz2088U_26635 * dz2083Uz2087U_26634) + new_index_36785 * dz2083Uz2088U_26635 + new_index_36842];
                    int64_t binop_x_36844 = i_34866 + binop_x_36843;
                    int64_t new_index_36846 = squot64(binop_x_36844, binop_y_36845);
                    int64_t binop_y_36854 = binop_y_36845 * new_index_36846;
                    int64_t binop_x_36855 = binop_x_36844 - binop_y_36854;
                    int64_t new_index_36856 = squot64(binop_x_36855, total_31170);
                    int64_t binop_y_36876 = total_31170 * new_index_36856;
                    int64_t new_index_36877 = binop_x_36855 - binop_y_36876;
                    double x_33790 = ((double *) mem_40902)[new_index_36846 * binop_y_36845 + new_index_36856 * total_31170 + new_index_36877];
                    double defunc_0_f_res_33791 = x_33789 * x_33790;
                    double defunc_0_op_res_33784 = defunc_0_f_res_33791 + redout_34865;
                    double redout_tmp_42859 = defunc_0_op_res_33784;
                    
                    redout_34865 = redout_tmp_42859;
                }
                defunc_0_reduce_res_34352 = redout_34865;
                
                double defunc_0_f_res_33787 = x_32930 + defunc_0_reduce_res_34352;
                
                ((double *) mem_40963)[i_34873 * flat_dim_31258 + i_34869] = defunc_0_f_res_33787;
            }
        }
        for (int64_t i_34885 = 0; i_34885 < dz2084Uz2084U_26637; i_34885++) {
            int64_t binop_x_36724 = (int64_t) 784 * i_34885;
            
            for (int64_t i_34881 = 0; i_34881 < (int64_t) 28; i_34881++) {
                int64_t binop_y_36725 = (int64_t) 28 * i_34881;
                int64_t binop_x_36726 = binop_x_36724 + binop_y_36725;
                
                for (int64_t i_34877 = 0; i_34877 < (int64_t) 28; i_34877++) {
                    int64_t binop_x_36727 = i_34877 + binop_x_36726;
                    int64_t new_index_36728 = squot64(binop_x_36727, flat_dim_31258);
                    int64_t binop_y_36738 = flat_dim_31258 * new_index_36728;
                    int64_t new_index_36739 = binop_x_36727 - binop_y_36738;
                    double x_31298 = ((double *) mem_40963)[new_index_36728 * flat_dim_31258 + new_index_36739];
                    double max_res_31299 = fmax64(0.0, x_31298);
                    
                    ((double *) mem_41009)[i_34885 * (int64_t) 784 + i_34881 * (int64_t) 28 + i_34877] = max_res_31299;
                }
            }
        }
        for (int64_t i_34889 = 0; i_34889 < (int64_t) 32; i_34889++) {
            int64_t i_31310 = mul64(elem_groups_31303, i_34889);
            int64_t arg_31311 = add64((int64_t) 1, i_34889);
            int64_t j_31312 = mul64(elem_groups_31303, arg_31311);
            int64_t j_m_i_31313 = sub64(j_31312, i_31310);
            bool empty_slice_31314 = j_m_i_31313 == (int64_t) 0;
            int64_t m_31315 = sub64(j_m_i_31313, (int64_t) 1);
            int64_t i_p_m_t_s_31316 = add64(i_31310, m_31315);
            bool zzero_leq_i_p_m_t_s_31317 = sle64((int64_t) 0, i_p_m_t_s_31316);
            bool i_p_m_t_s_leq_w_31318 = slt64(i_p_m_t_s_31316, dz2084Uz2084U_26637);
            bool zzero_lte_i_31319 = sle64((int64_t) 0, i_31310);
            bool i_lte_j_31320 = sle64(i_31310, j_31312);
            bool y_31321 = i_p_m_t_s_leq_w_31318 && zzero_lte_i_31319;
            bool y_31322 = zzero_leq_i_p_m_t_s_31317 && y_31321;
            bool y_31323 = i_lte_j_31320 && y_31322;
            bool forwards_ok_31324 = zzero_lte_i_31319 && y_31323;
            bool ok_or_empty_31325 = empty_slice_31314 || forwards_ok_31324;
            bool index_certs_31326;
            
            if (!ok_or_empty_31325) {
                set_error(ctx, msgprintf("Error: %s%lld%s%lld%s%lld%s\n\nBacktrace:\n%s", "Index [", (long long) i_31310, ":", (long long) j_31312, "] out of bounds for array of shape [", (long long) dz2084Uz2084U_26637, "].", "-> #0  ../layers/groupnorm.fut:2:31-70\n   #1  /prelude/soacs.fut:59:9-10\n   #2  /prelude/array.fut:200:10-17\n   #3  ../layers/groupnorm.fut:2:23-97\n   #4  ../layers/groupnorm.fut:20:19-54\n"));
                err = FUTHARK_PROGRAM_ERROR;
                goto cleanup;
            }
            
            bool dim_match_31327 = elem_groups_31303 == j_m_i_31313;
            bool empty_or_match_cert_31328;
            
            if (!dim_match_31327) {
                set_error(ctx, msgprintf("Error: %s%lld%s%lld%s%lld%s%lld%s%lld%s%lld%s\n\nBacktrace:\n%s", "Value of (core language) shape (", (long long) j_m_i_31313, ", ", (long long) (int64_t) 28, ", ", (long long) (int64_t) 28, ") cannot match shape of type `[", (long long) elem_groups_31303, "][", (long long) (int64_t) 28, "][", (long long) (int64_t) 28, "]f64`.", "-> #0  ../layers/groupnorm.fut:2:31-96\n   #1  /prelude/soacs.fut:59:9-10\n   #2  /prelude/array.fut:200:10-17\n   #3  ../layers/groupnorm.fut:2:23-97\n   #4  ../layers/groupnorm.fut:20:19-54\n"));
                err = FUTHARK_PROGRAM_ERROR;
                goto cleanup;
            }
            if (elem_groups_31303 * (int64_t) 28 * (int64_t) 28 * (int64_t) 8 > 0)
                memmove(mem_41097 + i_34889 * flat_dim_31331 * (int64_t) 8, mem_41009 + (int64_t) 784 * i_31310 * (int64_t) 8, elem_groups_31303 * (int64_t) 28 * (int64_t) 28 * (int64_t) 8);
        }
        for (int64_t i_34899 = 0; i_34899 < (int64_t) 32; i_34899++) {
            int64_t binop_x_36628 = flat_dim_31331 * i_34899;
            double defunc_0_reduce_res_34356;
            double redout_34891 = 0.0;
            
            for (int64_t i_34892 = 0; i_34892 < flat_dim_31331; i_34892++) {
                int64_t binop_x_36629 = i_34892 + binop_x_36628;
                int64_t new_index_36632 = squot64(binop_x_36629, flat_dim_31331);
                int64_t binop_y_36642 = flat_dim_31331 * new_index_36632;
                int64_t binop_x_36643 = binop_x_36629 - binop_y_36642;
                int64_t new_index_36644 = squot64(binop_x_36643, (int64_t) 784);
                int64_t binop_y_36668 = (int64_t) 784 * new_index_36644;
                int64_t binop_x_36669 = binop_x_36643 - binop_y_36668;
                int64_t new_index_36670 = squot64(binop_x_36669, (int64_t) 28);
                int64_t binop_y_36722 = (int64_t) 28 * new_index_36670;
                int64_t new_index_36723 = binop_x_36669 - binop_y_36722;
                double x_31341 = ((double *) mem_41097)[new_index_36632 * flat_dim_31331 + new_index_36644 * (int64_t) 784 + new_index_36670 * (int64_t) 28 + new_index_36723];
                double defunc_0_op_res_31340 = x_31341 + redout_34891;
                double redout_tmp_42866 = defunc_0_op_res_31340;
                
                redout_34891 = redout_tmp_42866;
            }
            defunc_0_reduce_res_34356 = redout_34891;
            
            double mean_res_31342 = defunc_0_reduce_res_34356 / i64_res_31332;
            double defunc_0_reduce_res_34357;
            double redout_34893 = 0.0;
            
            for (int64_t i_34894 = 0; i_34894 < flat_dim_31331; i_34894++) {
                int64_t binop_x_36533 = i_34894 + binop_x_36628;
                int64_t new_index_36536 = squot64(binop_x_36533, flat_dim_31331);
                int64_t binop_y_36546 = flat_dim_31331 * new_index_36536;
                int64_t binop_x_36547 = binop_x_36533 - binop_y_36546;
                int64_t new_index_36548 = squot64(binop_x_36547, (int64_t) 784);
                int64_t binop_y_36572 = (int64_t) 784 * new_index_36548;
                int64_t binop_x_36573 = binop_x_36547 - binop_y_36572;
                int64_t new_index_36574 = squot64(binop_x_36573, (int64_t) 28);
                int64_t binop_y_36626 = (int64_t) 28 * new_index_36574;
                int64_t new_index_36627 = binop_x_36573 - binop_y_36626;
                double x_33799 = ((double *) mem_41097)[new_index_36536 * flat_dim_31331 + new_index_36548 * (int64_t) 784 + new_index_36574 * (int64_t) 28 + new_index_36627];
                double arg_33800 = x_33799 - mean_res_31342;
                double defunc_0_f_res_33801 = arg_33800 * arg_33800;
                double defunc_0_op_res_31350 = defunc_0_f_res_33801 + redout_34893;
                double redout_tmp_42867 = defunc_0_op_res_31350;
                
                redout_34893 = redout_tmp_42867;
            }
            defunc_0_reduce_res_34357 = redout_34893;
            
            double variance_res_31352 = defunc_0_reduce_res_34357 / i64_res_31332;
            
            ((double *) mem_41128)[i_34899] = mean_res_31342;
            ((double *) mem_41130)[i_34899] = variance_res_31352;
        }
        for (int64_t i_34922 = 0; i_34922 < dz2084Uz2084U_26637; i_34922++) {
            double x_32849 = ((double *) b3_tb_mem_38962.mem)[i_34922];
            int64_t i_32854 = sdiv64(i_34922, elem_groups_31303);
            bool x_32855 = sle64((int64_t) 0, i_32854);
            bool y_32856 = slt64(i_32854, (int64_t) 32);
            bool bounds_check_32857 = x_32855 && y_32856;
            bool index_certs_32858;
            
            if (!bounds_check_32857) {
                set_error(ctx, msgprintf("Error: %s%lld%s%lld%s\n\nBacktrace:\n%s", "Index [", (long long) i_32854, "] out of bounds for array of shape [", (long long) (int64_t) 32, "].", "-> #0  ../layers/groupnorm.fut:22:57-85\n   #1  /prelude/soacs.fut:59:9-10\n   #2  /prelude/array.fut:200:10-17\n   #3  /prelude/functional.fut:39:61-65\n   #4  /prelude/soacs.fut:59:9-10\n   #5  /prelude/array.fut:208:27-34\n   #6  /prelude/functional.fut:39:61-65\n   #7  /prelude/soacs.fut:59:9-10\n   #8  /prelude/array.fut:216:32-39\n   #9  ../layers/groupnorm.fut:22:31-135\n"));
                err = FUTHARK_PROGRAM_ERROR;
                goto cleanup;
            }
            
            double arg_32859 = ((double *) mem_41128)[i_32854];
            double arg_32860 = ((double *) mem_41130)[i_32854];
            double sqrt_arg_32861 = 1.0e-5 + arg_32860;
            double sqrt_res_32862 = futrts_sqrt64(sqrt_arg_32861);
            double defunc_0_reduce_res_34360;
            double redout_34902 = 0.0;
            
            for (int64_t i_34903 = 0; i_34903 < (int64_t) 256; i_34903++) {
                bool index_concat_cmp_35233 = sle64((int64_t) 128, i_34903);
                double index_concat_branch_35237;
                
                if (index_concat_cmp_35233 == 1) {
                    int64_t index_concat_i_35234 = sub64(i_34903, (int64_t) 128);
                    double index_concat_35235 = ((double *) mem_39033)[index_concat_i_35234];
                    
                    index_concat_branch_35237 = index_concat_35235;
                } else {
                    double index_concat_35236 = ((double *) mem_39031)[i_34903];
                    
                    index_concat_branch_35237 = index_concat_35236;
                }
                
                double x_33807 = ((double *) b3_tw_mem_38961.mem)[i_34922 * (int64_t) 256 + i_34903];
                double defunc_0_f_res_33808 = x_33807 * index_concat_branch_35237;
                double defunc_0_op_res_32887 = defunc_0_f_res_33808 + redout_34902;
                double redout_tmp_42869 = defunc_0_op_res_32887;
                
                redout_34902 = redout_tmp_42869;
            }
            defunc_0_reduce_res_34360 = redout_34902;
            
            double defunc_0_f_res_32889 = x_32849 + defunc_0_reduce_res_34360;
            double max_res_32891 = fmax64(0.0, defunc_0_f_res_32889);
            
            for (int64_t i_34910 = 0; i_34910 < (int64_t) 28; i_34910++) {
                for (int64_t i_34906 = 0; i_34906 < (int64_t) 28; i_34906++) {
                    double arg_33838 = ((double *) mem_41009)[i_34922 * (int64_t) 784 + i_34910 * (int64_t) 28 + i_34906];
                    double arg_33839 = arg_33838 - arg_32859;
                    double defunc_0_f_res_33840 = arg_33839 / sqrt_res_32862;
                    double defunc_0_f_res_33842 = max_res_32891 + defunc_0_f_res_33840;
                    
                    ((double *) mem_41168)[i_34910 * (int64_t) 28 + i_34906] = defunc_0_f_res_33842;
                }
            }
            for (int64_t i_34918 = 0; i_34918 < (int64_t) 30; i_34918++) {
                bool cond_32901 = slt64(i_34918, (int64_t) 1);
                bool cond_f_res_32902 = sle64((int64_t) 29, i_34918);
                bool x_32903 = !cond_32901;
                bool y_32904 = cond_f_res_32902 && x_32903;
                bool cond_32905 = cond_32901 || y_32904;
                bool x_32906 = !cond_32905;
                
                for (int64_t i_34914 = 0; i_34914 < (int64_t) 30; i_34914++) {
                    bool cond_f_res_32909 = slt64(i_34914, (int64_t) 1);
                    bool y_32910 = x_32906 && cond_f_res_32909;
                    bool cond_32911 = cond_32905 || y_32910;
                    bool cond_f_res_32912 = sle64((int64_t) 29, i_34914);
                    bool x_32913 = !cond_32911;
                    bool y_32914 = cond_f_res_32912 && x_32913;
                    bool cond_32915 = cond_32911 || y_32914;
                    double defunc_0_f_res_32916;
                    
                    if (cond_32915 == 1) {
                        defunc_0_f_res_32916 = 0.0;
                    } else {
                        int64_t i_32917 = sub64(i_34918, (int64_t) 1);
                        bool x_32918 = sle64((int64_t) 0, i_32917);
                        bool y_32919 = slt64(i_32917, (int64_t) 28);
                        bool bounds_check_32920 = x_32918 && y_32919;
                        int64_t i_32921 = sub64(i_34914, (int64_t) 1);
                        bool x_32922 = sle64((int64_t) 0, i_32921);
                        bool y_32923 = slt64(i_32921, (int64_t) 28);
                        bool bounds_check_32924 = x_32922 && y_32923;
                        bool index_ok_32925 = bounds_check_32920 && bounds_check_32924;
                        bool index_certs_32926;
                        
                        if (!index_ok_32925) {
                            set_error(ctx, msgprintf("Error: %s%lld%s%lld%s%lld%s%lld%s\n\nBacktrace:\n%s", "Index [", (long long) i_32917, ", ", (long long) i_32921, "] out of bounds for array of shape [", (long long) (int64_t) 28, "][", (long long) (int64_t) 28, "].", "-> #0  ../layers/conv2d.fut:7:91-116\n   #1  /prelude/soacs.fut:59:9-10\n   #2  /prelude/array.fut:200:10-17\n   #3  /prelude/functional.fut:39:61-65\n   #4  /prelude/soacs.fut:59:9-10\n   #5  /prelude/array.fut:208:27-34\n   #6  ../layers/conv2d.fut:6:46-7:117\n   #7  ../layers/conv2d.fut:7:120-123\n   #8  ../layers/conv2d.fut:20:7-30\n"));
                            err = FUTHARK_PROGRAM_ERROR;
                            goto cleanup;
                        }
                        
                        double defunc_0_f_res_f_res_32927 = ((double *) mem_41168)[i_32917 * (int64_t) 28 + i_32921];
                        
                        defunc_0_f_res_32916 = defunc_0_f_res_f_res_32927;
                    }
                    ((double *) mem_41155)[i_34922 * (int64_t) 900 + i_34918 * (int64_t) 30 + i_34914] = defunc_0_f_res_32916;
                }
            }
        }
        for (int64_t i_34930 = 0; i_34930 < new_n_31414; i_34930++) {
            int64_t j_31468 = add64(dz2084Uz2085U_26638, i_34930);
            int64_t i_p_m_t_s_31469 = add64(m_31460, i_34930);
            bool zzero_leq_i_p_m_t_s_31470 = sle64((int64_t) 0, i_p_m_t_s_31469);
            bool i_p_m_t_s_leq_w_31471 = slt64(i_p_m_t_s_31469, (int64_t) 30);
            bool i_lte_j_31473 = sle64(i_34930, j_31468);
            bool y_31475 = zzero_leq_i_p_m_t_s_31470 && i_p_m_t_s_leq_w_31471;
            bool y_31476 = i_lte_j_31473 && y_31475;
            bool ok_or_empty_31478 = empty_slice_31459 || y_31476;
            
            for (int64_t i_34926 = 0; i_34926 < new_n_31414; i_34926++) {
                int64_t j_31481 = add64(dz2084Uz2085U_26638, i_34926);
                int64_t i_p_m_t_s_31482 = add64(m_31460, i_34926);
                bool zzero_leq_i_p_m_t_s_31483 = sle64((int64_t) 0, i_p_m_t_s_31482);
                bool i_p_m_t_s_leq_w_31484 = slt64(i_p_m_t_s_31482, (int64_t) 30);
                bool i_lte_j_31486 = sle64(i_34926, j_31481);
                bool y_31488 = zzero_leq_i_p_m_t_s_31483 && i_p_m_t_s_leq_w_31484;
                bool y_31489 = i_lte_j_31486 && y_31488;
                bool ok_or_empty_31491 = empty_slice_31459 || y_31489;
                bool index_ok_31492 = ok_or_empty_31478 && ok_or_empty_31491;
                bool index_certs_31493;
                
                if (!index_ok_31492) {
                    set_error(ctx, msgprintf("Error: %s%lld%s%lld%s%lld%s%lld%s%lld%s%lld%s\n\nBacktrace:\n%s", "Index [", (long long) i_34930, ":", (long long) j_31468, ", ", (long long) i_34926, ":", (long long) j_31481, "] out of bounds for array of shape [", (long long) (int64_t) 30, "][", (long long) (int64_t) 30, "].", "-> #0  ../layers/conv2d.fut:11:90-124\n   #1  ../layers/conv2d.fut:11:144-146\n   #2  /prelude/soacs.fut:59:9-10\n   #3  /prelude/array.fut:200:10-17\n   #4  /prelude/functional.fut:39:61-65\n   #5  /prelude/soacs.fut:59:9-10\n   #6  /prelude/array.fut:208:27-34\n   #7  ../layers/conv2d.fut:11:50-162\n   #8  ../layers/conv2d.fut:24:17-54\n"));
                    err = FUTHARK_PROGRAM_ERROR;
                    goto cleanup;
                }
                for (int64_t i_42876 = 0; i_42876 < total_31418; i_42876++) {
                    double tmp_42877 = ((double *) mem_41155)[(int64_t) 30 * i_34930 + i_34926 + (squot64(i_42876, dz2084Uz2085U_26638 * dz2084Uz2085U_26638) * (int64_t) 900 + squot64(i_42876 - squot64(i_42876, dz2084Uz2085U_26638 * dz2084Uz2085U_26638) * (dz2084Uz2085U_26638 * dz2084Uz2085U_26638), dz2084Uz2085U_26638) * (int64_t) 30 + (i_42876 - squot64(i_42876, dz2084Uz2085U_26638 * dz2084Uz2085U_26638) * (dz2084Uz2085U_26638 * dz2084Uz2085U_26638) - squot64(i_42876 - squot64(i_42876, dz2084Uz2085U_26638 * dz2084Uz2085U_26638) * (dz2084Uz2085U_26638 * dz2084Uz2085U_26638), dz2084Uz2085U_26638) * dz2084Uz2085U_26638))];
                    
                    ((double *) mem_41282)[i_34930 * binop_y_36499 + i_34926 * total_31418 + i_42876] = tmp_42877;
                }
            }
        }
        for (int64_t i_34940 = 0; i_34940 < dz2084Uz2087U_26640; i_34940++) {
            double x_32701 = ((double *) b3_c2_b_mem_38964.mem)[i_34940];
            int64_t binop_x_36394 = total_31418 * i_34940;
            
            for (int64_t i_34936 = 0; i_34936 < flat_dim_31496; i_34936++) {
                int64_t binop_x_36497 = total_31418 * i_34936;
                double defunc_0_reduce_res_34364;
                double redout_34932 = 0.0;
                
                for (int64_t i_34933 = 0; i_34933 < total_31418; i_34933++) {
                    int64_t binop_x_36395 = i_34933 + binop_x_36394;
                    int64_t new_index_36398 = squot64(binop_x_36395, total_31418);
                    int64_t binop_y_36408 = total_31418 * new_index_36398;
                    int64_t binop_x_36409 = binop_x_36395 - binop_y_36408;
                    int64_t new_index_36411 = squot64(binop_x_36409, binop_y_36410);
                    int64_t binop_y_36437 = binop_y_36410 * new_index_36411;
                    int64_t binop_x_36438 = binop_x_36409 - binop_y_36437;
                    int64_t new_index_36439 = squot64(binop_x_36438, dz2084Uz2086U_26639);
                    int64_t binop_y_36495 = dz2084Uz2086U_26639 * new_index_36439;
                    int64_t new_index_36496 = binop_x_36438 - binop_y_36495;
                    double x_33865 = ((double *) b3_c2_w_mem_38963.mem)[new_index_36398 * (dz2084Uz2086U_26639 * dz2084Uz2085U_26638 * dz2084Uz2084U_26637) + new_index_36411 * (dz2084Uz2086U_26639 * dz2084Uz2085U_26638) + new_index_36439 * dz2084Uz2086U_26639 + new_index_36496];
                    int64_t binop_x_36498 = i_34933 + binop_x_36497;
                    int64_t new_index_36500 = squot64(binop_x_36498, binop_y_36499);
                    int64_t binop_y_36508 = binop_y_36499 * new_index_36500;
                    int64_t binop_x_36509 = binop_x_36498 - binop_y_36508;
                    int64_t new_index_36510 = squot64(binop_x_36509, total_31418);
                    int64_t binop_y_36530 = total_31418 * new_index_36510;
                    int64_t new_index_36531 = binop_x_36509 - binop_y_36530;
                    double x_33866 = ((double *) mem_41282)[new_index_36500 * binop_y_36499 + new_index_36510 * total_31418 + new_index_36531];
                    double defunc_0_f_res_33867 = x_33865 * x_33866;
                    double defunc_0_op_res_33860 = defunc_0_f_res_33867 + redout_34932;
                    double redout_tmp_42880 = defunc_0_op_res_33860;
                    
                    redout_34932 = redout_tmp_42880;
                }
                defunc_0_reduce_res_34364 = redout_34932;
                
                double defunc_0_f_res_33863 = x_32701 + defunc_0_reduce_res_34364;
                
                ((double *) mem_41343)[i_34940 * flat_dim_31496 + i_34936] = defunc_0_f_res_33863;
            }
        }
        for (int64_t i_34952 = 0; i_34952 < dz2084Uz2084U_26637; i_34952++) {
            int64_t binop_x_36378 = (int64_t) 784 * i_34952;
            
            for (int64_t i_34948 = 0; i_34948 < (int64_t) 28; i_34948++) {
                int64_t binop_y_36379 = (int64_t) 28 * i_34948;
                int64_t binop_x_36380 = binop_x_36378 + binop_y_36379;
                
                for (int64_t i_34944 = 0; i_34944 < (int64_t) 28; i_34944++) {
                    int64_t binop_x_36381 = i_34944 + binop_x_36380;
                    int64_t new_index_36382 = squot64(binop_x_36381, flat_dim_31496);
                    int64_t binop_y_36392 = flat_dim_31496 * new_index_36382;
                    int64_t new_index_36393 = binop_x_36381 - binop_y_36392;
                    double x_31536 = ((double *) mem_41343)[new_index_36382 * flat_dim_31496 + new_index_36393];
                    double max_res_31537 = fmax64(0.0, x_31536);
                    
                    ((double *) mem_41389)[i_34952 * (int64_t) 784 + i_34948 * (int64_t) 28 + i_34944] = max_res_31537;
                }
            }
        }
        for (int64_t i_34956 = 0; i_34956 < (int64_t) 32; i_34956++) {
            int64_t i_31540 = mul64(elem_groups_31303, i_34956);
            int64_t arg_31541 = add64((int64_t) 1, i_34956);
            int64_t j_31542 = mul64(elem_groups_31303, arg_31541);
            int64_t j_m_i_31543 = sub64(j_31542, i_31540);
            bool empty_slice_31544 = j_m_i_31543 == (int64_t) 0;
            int64_t m_31545 = sub64(j_m_i_31543, (int64_t) 1);
            int64_t i_p_m_t_s_31546 = add64(i_31540, m_31545);
            bool zzero_leq_i_p_m_t_s_31547 = sle64((int64_t) 0, i_p_m_t_s_31546);
            bool i_p_m_t_s_leq_w_31548 = slt64(i_p_m_t_s_31546, dz2084Uz2084U_26637);
            bool zzero_lte_i_31549 = sle64((int64_t) 0, i_31540);
            bool i_lte_j_31550 = sle64(i_31540, j_31542);
            bool y_31551 = i_p_m_t_s_leq_w_31548 && zzero_lte_i_31549;
            bool y_31552 = zzero_leq_i_p_m_t_s_31547 && y_31551;
            bool y_31553 = i_lte_j_31550 && y_31552;
            bool forwards_ok_31554 = zzero_lte_i_31549 && y_31553;
            bool ok_or_empty_31555 = empty_slice_31544 || forwards_ok_31554;
            bool index_certs_31556;
            
            if (!ok_or_empty_31555) {
                set_error(ctx, msgprintf("Error: %s%lld%s%lld%s%lld%s\n\nBacktrace:\n%s", "Index [", (long long) i_31540, ":", (long long) j_31542, "] out of bounds for array of shape [", (long long) dz2084Uz2084U_26637, "].", "-> #0  ../layers/groupnorm.fut:2:31-70\n   #1  /prelude/soacs.fut:59:9-10\n   #2  /prelude/array.fut:200:10-17\n   #3  ../layers/groupnorm.fut:2:23-97\n   #4  ../layers/groupnorm.fut:20:19-54\n"));
                err = FUTHARK_PROGRAM_ERROR;
                goto cleanup;
            }
            
            bool dim_match_31557 = elem_groups_31303 == j_m_i_31543;
            bool empty_or_match_cert_31558;
            
            if (!dim_match_31557) {
                set_error(ctx, msgprintf("Error: %s%lld%s%lld%s%lld%s%lld%s%lld%s%lld%s\n\nBacktrace:\n%s", "Value of (core language) shape (", (long long) j_m_i_31543, ", ", (long long) (int64_t) 28, ", ", (long long) (int64_t) 28, ") cannot match shape of type `[", (long long) elem_groups_31303, "][", (long long) (int64_t) 28, "][", (long long) (int64_t) 28, "]f64`.", "-> #0  ../layers/groupnorm.fut:2:31-96\n   #1  /prelude/soacs.fut:59:9-10\n   #2  /prelude/array.fut:200:10-17\n   #3  ../layers/groupnorm.fut:2:23-97\n   #4  ../layers/groupnorm.fut:20:19-54\n"));
                err = FUTHARK_PROGRAM_ERROR;
                goto cleanup;
            }
            if (elem_groups_31303 * (int64_t) 28 * (int64_t) 28 * (int64_t) 8 > 0)
                memmove(mem_41477 + i_34956 * flat_dim_31331 * (int64_t) 8, mem_41389 + (int64_t) 784 * i_31540 * (int64_t) 8, elem_groups_31303 * (int64_t) 28 * (int64_t) 28 * (int64_t) 8);
        }
        for (int64_t i_34966 = 0; i_34966 < (int64_t) 32; i_34966++) {
            int64_t binop_x_36282 = flat_dim_31331 * i_34966;
            double defunc_0_reduce_res_34368;
            double redout_34958 = 0.0;
            
            for (int64_t i_34959 = 0; i_34959 < flat_dim_31331; i_34959++) {
                int64_t binop_x_36283 = i_34959 + binop_x_36282;
                int64_t new_index_36286 = squot64(binop_x_36283, flat_dim_31331);
                int64_t binop_y_36296 = flat_dim_31331 * new_index_36286;
                int64_t binop_x_36297 = binop_x_36283 - binop_y_36296;
                int64_t new_index_36298 = squot64(binop_x_36297, (int64_t) 784);
                int64_t binop_y_36322 = (int64_t) 784 * new_index_36298;
                int64_t binop_x_36323 = binop_x_36297 - binop_y_36322;
                int64_t new_index_36324 = squot64(binop_x_36323, (int64_t) 28);
                int64_t binop_y_36376 = (int64_t) 28 * new_index_36324;
                int64_t new_index_36377 = binop_x_36323 - binop_y_36376;
                double x_31571 = ((double *) mem_41477)[new_index_36286 * flat_dim_31331 + new_index_36298 * (int64_t) 784 + new_index_36324 * (int64_t) 28 + new_index_36377];
                double defunc_0_op_res_31570 = x_31571 + redout_34958;
                double redout_tmp_42887 = defunc_0_op_res_31570;
                
                redout_34958 = redout_tmp_42887;
            }
            defunc_0_reduce_res_34368 = redout_34958;
            
            double mean_res_31572 = defunc_0_reduce_res_34368 / i64_res_31332;
            double defunc_0_reduce_res_34369;
            double redout_34960 = 0.0;
            
            for (int64_t i_34961 = 0; i_34961 < flat_dim_31331; i_34961++) {
                int64_t binop_x_36187 = i_34961 + binop_x_36282;
                int64_t new_index_36190 = squot64(binop_x_36187, flat_dim_31331);
                int64_t binop_y_36200 = flat_dim_31331 * new_index_36190;
                int64_t binop_x_36201 = binop_x_36187 - binop_y_36200;
                int64_t new_index_36202 = squot64(binop_x_36201, (int64_t) 784);
                int64_t binop_y_36226 = (int64_t) 784 * new_index_36202;
                int64_t binop_x_36227 = binop_x_36201 - binop_y_36226;
                int64_t new_index_36228 = squot64(binop_x_36227, (int64_t) 28);
                int64_t binop_y_36280 = (int64_t) 28 * new_index_36228;
                int64_t new_index_36281 = binop_x_36227 - binop_y_36280;
                double x_33875 = ((double *) mem_41477)[new_index_36190 * flat_dim_31331 + new_index_36202 * (int64_t) 784 + new_index_36228 * (int64_t) 28 + new_index_36281];
                double arg_33876 = x_33875 - mean_res_31572;
                double defunc_0_f_res_33877 = arg_33876 * arg_33876;
                double defunc_0_op_res_31580 = defunc_0_f_res_33877 + redout_34960;
                double redout_tmp_42888 = defunc_0_op_res_31580;
                
                redout_34960 = redout_tmp_42888;
            }
            defunc_0_reduce_res_34369 = redout_34960;
            
            double variance_res_31582 = defunc_0_reduce_res_34369 / i64_res_31332;
            
            ((double *) mem_41508)[i_34966] = mean_res_31572;
            ((double *) mem_41510)[i_34966] = variance_res_31582;
        }
        for (int64_t i_34979 = 0; i_34979 < dz2084Uz2084U_26637; i_34979++) {
            int64_t i_31591 = sdiv64(i_34979, elem_groups_31303);
            bool x_31592 = sle64((int64_t) 0, i_31591);
            bool y_31593 = slt64(i_31591, (int64_t) 32);
            bool bounds_check_31594 = x_31592 && y_31593;
            bool index_certs_31595;
            
            if (!bounds_check_31594) {
                set_error(ctx, msgprintf("Error: %s%lld%s%lld%s\n\nBacktrace:\n%s", "Index [", (long long) i_31591, "] out of bounds for array of shape [", (long long) (int64_t) 32, "].", "-> #0  ../layers/groupnorm.fut:22:57-85\n   #1  /prelude/soacs.fut:59:9-10\n   #2  /prelude/array.fut:200:10-17\n   #3  /prelude/functional.fut:39:61-65\n   #4  /prelude/soacs.fut:59:9-10\n   #5  /prelude/array.fut:208:27-34\n   #6  /prelude/functional.fut:39:61-65\n   #7  /prelude/soacs.fut:59:9-10\n   #8  /prelude/array.fut:216:32-39\n   #9  ../layers/groupnorm.fut:22:31-135\n"));
                err = FUTHARK_PROGRAM_ERROR;
                goto cleanup;
            }
            
            double arg_31596 = ((double *) mem_41508)[i_31591];
            double arg_31597 = ((double *) mem_41510)[i_31591];
            double sqrt_arg_31598 = 1.0e-5 + arg_31597;
            double sqrt_res_31599 = futrts_sqrt64(sqrt_arg_31598);
            
            for (int64_t i_34975 = 0; i_34975 < (int64_t) 28; i_34975++) {
                for (int64_t i_34971 = 0; i_34971 < (int64_t) 28; i_34971++) {
                    double arg_31613 = ((double *) mem_41389)[i_34979 * (int64_t) 784 + i_34975 * (int64_t) 28 + i_34971];
                    double arg_31614 = arg_31613 - arg_31596;
                    double defunc_0_f_res_31615 = arg_31614 / sqrt_res_31599;
                    
                    ((double *) mem_41535)[i_34979 * (int64_t) 784 + i_34975 * (int64_t) 28 + i_34971] = defunc_0_f_res_31615;
                }
            }
        }
        for (int64_t i_34991 = 0; i_34991 < (int64_t) 256; i_34991++) {
            for (int64_t i_34987 = 0; i_34987 < (int64_t) 30; i_34987++) {
                bool cond_31658 = slt64(i_34987, (int64_t) 1);
                bool cond_f_res_31659 = sle64((int64_t) 29, i_34987);
                bool x_31660 = !cond_31658;
                bool y_31661 = cond_f_res_31659 && x_31660;
                bool cond_31662 = cond_31658 || y_31661;
                bool x_31663 = !cond_31662;
                
                for (int64_t i_34983 = 0; i_34983 < (int64_t) 30; i_34983++) {
                    bool cond_f_res_31666 = slt64(i_34983, (int64_t) 1);
                    bool y_31667 = x_31663 && cond_f_res_31666;
                    bool cond_31668 = cond_31662 || y_31667;
                    bool cond_f_res_31669 = sle64((int64_t) 29, i_34983);
                    bool x_31670 = !cond_31668;
                    bool y_31671 = cond_f_res_31669 && x_31670;
                    bool cond_31672 = cond_31668 || y_31671;
                    double defunc_0_f_res_31673;
                    
                    if (cond_31672 == 1) {
                        defunc_0_f_res_31673 = 0.0;
                    } else {
                        int64_t i_31674 = sub64(i_34987, (int64_t) 1);
                        int64_t i_31678 = sub64(i_34983, (int64_t) 1);
                        bool index_concat_cmp_35203 = sle64((int64_t) 128, i_34991);
                        double index_concat_branch_35207;
                        
                        if (index_concat_cmp_35203 == 1) {
                            int64_t index_concat_i_35204 = sub64(i_34991, (int64_t) 128);
                            double index_concat_35205 = ((double *) mem_39929)[index_concat_i_35204 * (int64_t) 784 + i_31674 * (int64_t) 28 + i_31678];
                            
                            index_concat_branch_35207 = index_concat_35205;
                        } else {
                            double index_concat_35206 = ((double *) mem_41535)[i_34991 * (int64_t) 784 + i_31674 * (int64_t) 28 + i_31678];
                            
                            index_concat_branch_35207 = index_concat_35206;
                        }
                        defunc_0_f_res_31673 = index_concat_branch_35207;
                    }
                    ((double *) mem_41619)[i_34991 * (int64_t) 900 + i_34987 * (int64_t) 30 + i_34983] = defunc_0_f_res_31673;
                }
            }
        }
        for (int64_t i_34999 = 0; i_34999 < new_n_31638; i_34999++) {
            int64_t j_31703 = add64(dz2085Uz2080U_26641, i_34999);
            int64_t i_p_m_t_s_31704 = add64(m_31695, i_34999);
            bool zzero_leq_i_p_m_t_s_31705 = sle64((int64_t) 0, i_p_m_t_s_31704);
            bool i_p_m_t_s_leq_w_31706 = slt64(i_p_m_t_s_31704, (int64_t) 30);
            bool i_lte_j_31708 = sle64(i_34999, j_31703);
            bool y_31710 = zzero_leq_i_p_m_t_s_31705 && i_p_m_t_s_leq_w_31706;
            bool y_31711 = i_lte_j_31708 && y_31710;
            bool ok_or_empty_31713 = empty_slice_31694 || y_31711;
            
            for (int64_t i_34995 = 0; i_34995 < new_n_31638; i_34995++) {
                int64_t j_31716 = add64(dz2085Uz2080U_26641, i_34995);
                int64_t i_p_m_t_s_31717 = add64(m_31695, i_34995);
                bool zzero_leq_i_p_m_t_s_31718 = sle64((int64_t) 0, i_p_m_t_s_31717);
                bool i_p_m_t_s_leq_w_31719 = slt64(i_p_m_t_s_31717, (int64_t) 30);
                bool i_lte_j_31721 = sle64(i_34995, j_31716);
                bool y_31723 = zzero_leq_i_p_m_t_s_31718 && i_p_m_t_s_leq_w_31719;
                bool y_31724 = i_lte_j_31721 && y_31723;
                bool ok_or_empty_31726 = empty_slice_31694 || y_31724;
                bool index_ok_31727 = ok_or_empty_31713 && ok_or_empty_31726;
                bool index_certs_31728;
                
                if (!index_ok_31727) {
                    set_error(ctx, msgprintf("Error: %s%lld%s%lld%s%lld%s%lld%s%lld%s%lld%s\n\nBacktrace:\n%s", "Index [", (long long) i_34999, ":", (long long) j_31703, ", ", (long long) i_34995, ":", (long long) j_31716, "] out of bounds for array of shape [", (long long) (int64_t) 30, "][", (long long) (int64_t) 30, "].", "-> #0  ../layers/conv2d.fut:11:90-124\n   #1  ../layers/conv2d.fut:11:144-146\n   #2  /prelude/soacs.fut:59:9-10\n   #3  /prelude/array.fut:200:10-17\n   #4  /prelude/functional.fut:39:61-65\n   #5  /prelude/soacs.fut:59:9-10\n   #6  /prelude/array.fut:208:27-34\n   #7  ../layers/conv2d.fut:11:50-162\n   #8  ../layers/conv2d.fut:24:17-54\n"));
                    err = FUTHARK_PROGRAM_ERROR;
                    goto cleanup;
                }
                for (int64_t i_42897 = 0; i_42897 < total_31643; i_42897++) {
                    double tmp_42898 = ((double *) mem_41619)[(int64_t) 30 * i_34999 + i_34995 + (squot64(i_42897, dz2085Uz2080U_26641 * dz2085Uz2080U_26641) * (int64_t) 900 + squot64(i_42897 - squot64(i_42897, dz2085Uz2080U_26641 * dz2085Uz2080U_26641) * (dz2085Uz2080U_26641 * dz2085Uz2080U_26641), dz2085Uz2080U_26641) * (int64_t) 30 + (i_42897 - squot64(i_42897, dz2085Uz2080U_26641 * dz2085Uz2080U_26641) * (dz2085Uz2080U_26641 * dz2085Uz2080U_26641) - squot64(i_42897 - squot64(i_42897, dz2085Uz2080U_26641 * dz2085Uz2080U_26641) * (dz2085Uz2080U_26641 * dz2085Uz2080U_26641), dz2085Uz2080U_26641) * dz2085Uz2080U_26641))];
                    
                    ((double *) mem_41706)[i_34999 * binop_y_36153 + i_34995 * total_31643 + i_42897] = tmp_42898;
                }
            }
        }
        for (int64_t i_35009 = 0; i_35009 < dz2085Uz2082U_26643; i_35009++) {
            double x_32683 = ((double *) b4_c1_b_mem_38966.mem)[i_35009];
            int64_t binop_x_36048 = total_31643 * i_35009;
            
            for (int64_t i_35005 = 0; i_35005 < flat_dim_31731; i_35005++) {
                int64_t binop_x_36151 = total_31643 * i_35005;
                double defunc_0_reduce_res_34375;
                double redout_35001 = 0.0;
                
                for (int64_t i_35002 = 0; i_35002 < total_31643; i_35002++) {
                    int64_t binop_x_36049 = i_35002 + binop_x_36048;
                    int64_t new_index_36052 = squot64(binop_x_36049, total_31643);
                    int64_t binop_y_36062 = total_31643 * new_index_36052;
                    int64_t binop_x_36063 = binop_x_36049 - binop_y_36062;
                    int64_t new_index_36065 = squot64(binop_x_36063, binop_y_36064);
                    int64_t binop_y_36091 = binop_y_36064 * new_index_36065;
                    int64_t binop_x_36092 = binop_x_36063 - binop_y_36091;
                    int64_t new_index_36093 = squot64(binop_x_36092, dz2085Uz2081U_26642);
                    int64_t binop_y_36149 = dz2085Uz2081U_26642 * new_index_36093;
                    int64_t new_index_36150 = binop_x_36092 - binop_y_36149;
                    double x_33900 = ((double *) b4_c1_w_mem_38965.mem)[new_index_36052 * (dz2085Uz2081U_26642 * dz2085Uz2080U_26641 * (int64_t) 256) + new_index_36065 * (dz2085Uz2081U_26642 * dz2085Uz2080U_26641) + new_index_36093 * dz2085Uz2081U_26642 + new_index_36150];
                    int64_t binop_x_36152 = i_35002 + binop_x_36151;
                    int64_t new_index_36154 = squot64(binop_x_36152, binop_y_36153);
                    int64_t binop_y_36162 = binop_y_36153 * new_index_36154;
                    int64_t binop_x_36163 = binop_x_36152 - binop_y_36162;
                    int64_t new_index_36164 = squot64(binop_x_36163, total_31643);
                    int64_t binop_y_36184 = total_31643 * new_index_36164;
                    int64_t new_index_36185 = binop_x_36163 - binop_y_36184;
                    double x_33901 = ((double *) mem_41706)[new_index_36154 * binop_y_36153 + new_index_36164 * total_31643 + new_index_36185];
                    double defunc_0_f_res_33902 = x_33900 * x_33901;
                    double defunc_0_op_res_33895 = defunc_0_f_res_33902 + redout_35001;
                    double redout_tmp_42901 = defunc_0_op_res_33895;
                    
                    redout_35001 = redout_tmp_42901;
                }
                defunc_0_reduce_res_34375 = redout_35001;
                
                double defunc_0_f_res_33898 = x_32683 + defunc_0_reduce_res_34375;
                
                ((double *) mem_41767)[i_35009 * flat_dim_31731 + i_35005] = defunc_0_f_res_33898;
            }
        }
        for (int64_t i_35021 = 0; i_35021 < dz2086Uz2082U_26644; i_35021++) {
            int64_t binop_x_36032 = (int64_t) 784 * i_35021;
            
            for (int64_t i_35017 = 0; i_35017 < (int64_t) 28; i_35017++) {
                int64_t binop_y_36033 = (int64_t) 28 * i_35017;
                int64_t binop_x_36034 = binop_x_36032 + binop_y_36033;
                
                for (int64_t i_35013 = 0; i_35013 < (int64_t) 28; i_35013++) {
                    int64_t binop_x_36035 = i_35013 + binop_x_36034;
                    int64_t new_index_36036 = squot64(binop_x_36035, flat_dim_31731);
                    int64_t binop_y_36046 = flat_dim_31731 * new_index_36036;
                    int64_t new_index_36047 = binop_x_36035 - binop_y_36046;
                    double x_31771 = ((double *) mem_41767)[new_index_36036 * flat_dim_31731 + new_index_36047];
                    double max_res_31772 = fmax64(0.0, x_31771);
                    
                    ((double *) mem_41813)[i_35021 * (int64_t) 784 + i_35017 * (int64_t) 28 + i_35013] = max_res_31772;
                }
            }
        }
        for (int64_t i_35025 = 0; i_35025 < (int64_t) 32; i_35025++) {
            int64_t i_31783 = mul64(elem_groups_31776, i_35025);
            int64_t arg_31784 = add64((int64_t) 1, i_35025);
            int64_t j_31785 = mul64(elem_groups_31776, arg_31784);
            int64_t j_m_i_31786 = sub64(j_31785, i_31783);
            bool empty_slice_31787 = j_m_i_31786 == (int64_t) 0;
            int64_t m_31788 = sub64(j_m_i_31786, (int64_t) 1);
            int64_t i_p_m_t_s_31789 = add64(i_31783, m_31788);
            bool zzero_leq_i_p_m_t_s_31790 = sle64((int64_t) 0, i_p_m_t_s_31789);
            bool i_p_m_t_s_leq_w_31791 = slt64(i_p_m_t_s_31789, dz2086Uz2082U_26644);
            bool zzero_lte_i_31792 = sle64((int64_t) 0, i_31783);
            bool i_lte_j_31793 = sle64(i_31783, j_31785);
            bool y_31794 = i_p_m_t_s_leq_w_31791 && zzero_lte_i_31792;
            bool y_31795 = zzero_leq_i_p_m_t_s_31790 && y_31794;
            bool y_31796 = i_lte_j_31793 && y_31795;
            bool forwards_ok_31797 = zzero_lte_i_31792 && y_31796;
            bool ok_or_empty_31798 = empty_slice_31787 || forwards_ok_31797;
            bool index_certs_31799;
            
            if (!ok_or_empty_31798) {
                set_error(ctx, msgprintf("Error: %s%lld%s%lld%s%lld%s\n\nBacktrace:\n%s", "Index [", (long long) i_31783, ":", (long long) j_31785, "] out of bounds for array of shape [", (long long) dz2086Uz2082U_26644, "].", "-> #0  ../layers/groupnorm.fut:2:31-70\n   #1  /prelude/soacs.fut:59:9-10\n   #2  /prelude/array.fut:200:10-17\n   #3  ../layers/groupnorm.fut:2:23-97\n   #4  ../layers/groupnorm.fut:20:19-54\n"));
                err = FUTHARK_PROGRAM_ERROR;
                goto cleanup;
            }
            
            bool dim_match_31800 = elem_groups_31776 == j_m_i_31786;
            bool empty_or_match_cert_31801;
            
            if (!dim_match_31800) {
                set_error(ctx, msgprintf("Error: %s%lld%s%lld%s%lld%s%lld%s%lld%s%lld%s\n\nBacktrace:\n%s", "Value of (core language) shape (", (long long) j_m_i_31786, ", ", (long long) (int64_t) 28, ", ", (long long) (int64_t) 28, ") cannot match shape of type `[", (long long) elem_groups_31776, "][", (long long) (int64_t) 28, "][", (long long) (int64_t) 28, "]f64`.", "-> #0  ../layers/groupnorm.fut:2:31-96\n   #1  /prelude/soacs.fut:59:9-10\n   #2  /prelude/array.fut:200:10-17\n   #3  ../layers/groupnorm.fut:2:23-97\n   #4  ../layers/groupnorm.fut:20:19-54\n"));
                err = FUTHARK_PROGRAM_ERROR;
                goto cleanup;
            }
            if (elem_groups_31776 * (int64_t) 28 * (int64_t) 28 * (int64_t) 8 > 0)
                memmove(mem_41901 + i_35025 * flat_dim_31804 * (int64_t) 8, mem_41813 + (int64_t) 784 * i_31783 * (int64_t) 8, elem_groups_31776 * (int64_t) 28 * (int64_t) 28 * (int64_t) 8);
        }
        for (int64_t i_35035 = 0; i_35035 < (int64_t) 32; i_35035++) {
            int64_t binop_x_35936 = flat_dim_31804 * i_35035;
            double defunc_0_reduce_res_34379;
            double redout_35027 = 0.0;
            
            for (int64_t i_35028 = 0; i_35028 < flat_dim_31804; i_35028++) {
                int64_t binop_x_35937 = i_35028 + binop_x_35936;
                int64_t new_index_35940 = squot64(binop_x_35937, flat_dim_31804);
                int64_t binop_y_35950 = flat_dim_31804 * new_index_35940;
                int64_t binop_x_35951 = binop_x_35937 - binop_y_35950;
                int64_t new_index_35952 = squot64(binop_x_35951, (int64_t) 784);
                int64_t binop_y_35976 = (int64_t) 784 * new_index_35952;
                int64_t binop_x_35977 = binop_x_35951 - binop_y_35976;
                int64_t new_index_35978 = squot64(binop_x_35977, (int64_t) 28);
                int64_t binop_y_36030 = (int64_t) 28 * new_index_35978;
                int64_t new_index_36031 = binop_x_35977 - binop_y_36030;
                double x_31814 = ((double *) mem_41901)[new_index_35940 * flat_dim_31804 + new_index_35952 * (int64_t) 784 + new_index_35978 * (int64_t) 28 + new_index_36031];
                double defunc_0_op_res_31813 = x_31814 + redout_35027;
                double redout_tmp_42908 = defunc_0_op_res_31813;
                
                redout_35027 = redout_tmp_42908;
            }
            defunc_0_reduce_res_34379 = redout_35027;
            
            double mean_res_31815 = defunc_0_reduce_res_34379 / i64_res_31805;
            double defunc_0_reduce_res_34380;
            double redout_35029 = 0.0;
            
            for (int64_t i_35030 = 0; i_35030 < flat_dim_31804; i_35030++) {
                int64_t binop_x_35841 = i_35030 + binop_x_35936;
                int64_t new_index_35844 = squot64(binop_x_35841, flat_dim_31804);
                int64_t binop_y_35854 = flat_dim_31804 * new_index_35844;
                int64_t binop_x_35855 = binop_x_35841 - binop_y_35854;
                int64_t new_index_35856 = squot64(binop_x_35855, (int64_t) 784);
                int64_t binop_y_35880 = (int64_t) 784 * new_index_35856;
                int64_t binop_x_35881 = binop_x_35855 - binop_y_35880;
                int64_t new_index_35882 = squot64(binop_x_35881, (int64_t) 28);
                int64_t binop_y_35934 = (int64_t) 28 * new_index_35882;
                int64_t new_index_35935 = binop_x_35881 - binop_y_35934;
                double x_33910 = ((double *) mem_41901)[new_index_35844 * flat_dim_31804 + new_index_35856 * (int64_t) 784 + new_index_35882 * (int64_t) 28 + new_index_35935];
                double arg_33911 = x_33910 - mean_res_31815;
                double defunc_0_f_res_33912 = arg_33911 * arg_33911;
                double defunc_0_op_res_31823 = defunc_0_f_res_33912 + redout_35029;
                double redout_tmp_42909 = defunc_0_op_res_31823;
                
                redout_35029 = redout_tmp_42909;
            }
            defunc_0_reduce_res_34380 = redout_35029;
            
            double variance_res_31825 = defunc_0_reduce_res_34380 / i64_res_31805;
            
            ((double *) mem_41932)[i_35035] = mean_res_31815;
            ((double *) mem_41934)[i_35035] = variance_res_31825;
        }
        for (int64_t i_35058 = 0; i_35058 < dz2086Uz2082U_26644; i_35058++) {
            double x_32602 = ((double *) b4_tb_mem_38968.mem)[i_35058];
            int64_t i_32607 = sdiv64(i_35058, elem_groups_31776);
            bool x_32608 = sle64((int64_t) 0, i_32607);
            bool y_32609 = slt64(i_32607, (int64_t) 32);
            bool bounds_check_32610 = x_32608 && y_32609;
            bool index_certs_32611;
            
            if (!bounds_check_32610) {
                set_error(ctx, msgprintf("Error: %s%lld%s%lld%s\n\nBacktrace:\n%s", "Index [", (long long) i_32607, "] out of bounds for array of shape [", (long long) (int64_t) 32, "].", "-> #0  ../layers/groupnorm.fut:22:57-85\n   #1  /prelude/soacs.fut:59:9-10\n   #2  /prelude/array.fut:200:10-17\n   #3  /prelude/functional.fut:39:61-65\n   #4  /prelude/soacs.fut:59:9-10\n   #5  /prelude/array.fut:208:27-34\n   #6  /prelude/functional.fut:39:61-65\n   #7  /prelude/soacs.fut:59:9-10\n   #8  /prelude/array.fut:216:32-39\n   #9  ../layers/groupnorm.fut:22:31-135\n"));
                err = FUTHARK_PROGRAM_ERROR;
                goto cleanup;
            }
            
            double arg_32612 = ((double *) mem_41932)[i_32607];
            double arg_32613 = ((double *) mem_41934)[i_32607];
            double sqrt_arg_32614 = 1.0e-5 + arg_32613;
            double sqrt_res_32615 = futrts_sqrt64(sqrt_arg_32614);
            double defunc_0_reduce_res_34383;
            double redout_35038 = 0.0;
            
            for (int64_t i_35039 = 0; i_35039 < (int64_t) 256; i_35039++) {
                bool index_concat_cmp_35189 = sle64((int64_t) 128, i_35039);
                double index_concat_branch_35193;
                
                if (index_concat_cmp_35189 == 1) {
                    int64_t index_concat_i_35190 = sub64(i_35039, (int64_t) 128);
                    double index_concat_35191 = ((double *) mem_39033)[index_concat_i_35190];
                    
                    index_concat_branch_35193 = index_concat_35191;
                } else {
                    double index_concat_35192 = ((double *) mem_39031)[i_35039];
                    
                    index_concat_branch_35193 = index_concat_35192;
                }
                
                double x_33918 = ((double *) b4_tw_mem_38967.mem)[i_35058 * (int64_t) 256 + i_35039];
                double defunc_0_f_res_33919 = x_33918 * index_concat_branch_35193;
                double defunc_0_op_res_32640 = defunc_0_f_res_33919 + redout_35038;
                double redout_tmp_42911 = defunc_0_op_res_32640;
                
                redout_35038 = redout_tmp_42911;
            }
            defunc_0_reduce_res_34383 = redout_35038;
            
            double defunc_0_f_res_32642 = x_32602 + defunc_0_reduce_res_34383;
            double max_res_32644 = fmax64(0.0, defunc_0_f_res_32642);
            
            for (int64_t i_35046 = 0; i_35046 < (int64_t) 28; i_35046++) {
                for (int64_t i_35042 = 0; i_35042 < (int64_t) 28; i_35042++) {
                    double arg_33949 = ((double *) mem_41813)[i_35058 * (int64_t) 784 + i_35046 * (int64_t) 28 + i_35042];
                    double arg_33950 = arg_33949 - arg_32612;
                    double defunc_0_f_res_33951 = arg_33950 / sqrt_res_32615;
                    double defunc_0_f_res_33953 = max_res_32644 + defunc_0_f_res_33951;
                    
                    ((double *) mem_41972)[i_35046 * (int64_t) 28 + i_35042] = defunc_0_f_res_33953;
                }
            }
            for (int64_t i_35054 = 0; i_35054 < (int64_t) 30; i_35054++) {
                bool cond_32654 = slt64(i_35054, (int64_t) 1);
                bool cond_f_res_32655 = sle64((int64_t) 29, i_35054);
                bool x_32656 = !cond_32654;
                bool y_32657 = cond_f_res_32655 && x_32656;
                bool cond_32658 = cond_32654 || y_32657;
                bool x_32659 = !cond_32658;
                
                for (int64_t i_35050 = 0; i_35050 < (int64_t) 30; i_35050++) {
                    bool cond_f_res_32662 = slt64(i_35050, (int64_t) 1);
                    bool y_32663 = x_32659 && cond_f_res_32662;
                    bool cond_32664 = cond_32658 || y_32663;
                    bool cond_f_res_32665 = sle64((int64_t) 29, i_35050);
                    bool x_32666 = !cond_32664;
                    bool y_32667 = cond_f_res_32665 && x_32666;
                    bool cond_32668 = cond_32664 || y_32667;
                    double defunc_0_f_res_32669;
                    
                    if (cond_32668 == 1) {
                        defunc_0_f_res_32669 = 0.0;
                    } else {
                        int64_t i_32670 = sub64(i_35054, (int64_t) 1);
                        bool x_32671 = sle64((int64_t) 0, i_32670);
                        bool y_32672 = slt64(i_32670, (int64_t) 28);
                        bool bounds_check_32673 = x_32671 && y_32672;
                        int64_t i_32674 = sub64(i_35050, (int64_t) 1);
                        bool x_32675 = sle64((int64_t) 0, i_32674);
                        bool y_32676 = slt64(i_32674, (int64_t) 28);
                        bool bounds_check_32677 = x_32675 && y_32676;
                        bool index_ok_32678 = bounds_check_32673 && bounds_check_32677;
                        bool index_certs_32679;
                        
                        if (!index_ok_32678) {
                            set_error(ctx, msgprintf("Error: %s%lld%s%lld%s%lld%s%lld%s\n\nBacktrace:\n%s", "Index [", (long long) i_32670, ", ", (long long) i_32674, "] out of bounds for array of shape [", (long long) (int64_t) 28, "][", (long long) (int64_t) 28, "].", "-> #0  ../layers/conv2d.fut:7:91-116\n   #1  /prelude/soacs.fut:59:9-10\n   #2  /prelude/array.fut:200:10-17\n   #3  /prelude/functional.fut:39:61-65\n   #4  /prelude/soacs.fut:59:9-10\n   #5  /prelude/array.fut:208:27-34\n   #6  ../layers/conv2d.fut:6:46-7:117\n   #7  ../layers/conv2d.fut:7:120-123\n   #8  ../layers/conv2d.fut:20:7-30\n"));
                            err = FUTHARK_PROGRAM_ERROR;
                            goto cleanup;
                        }
                        
                        double defunc_0_f_res_f_res_32680 = ((double *) mem_41972)[i_32670 * (int64_t) 28 + i_32674];
                        
                        defunc_0_f_res_32669 = defunc_0_f_res_f_res_32680;
                    }
                    ((double *) mem_41959)[i_35058 * (int64_t) 900 + i_35054 * (int64_t) 30 + i_35050] = defunc_0_f_res_32669;
                }
            }
        }
        for (int64_t i_35066 = 0; i_35066 < new_n_31887; i_35066++) {
            int64_t j_31941 = add64(dz2085Uz2088U_26645, i_35066);
            int64_t i_p_m_t_s_31942 = add64(m_31933, i_35066);
            bool zzero_leq_i_p_m_t_s_31943 = sle64((int64_t) 0, i_p_m_t_s_31942);
            bool i_p_m_t_s_leq_w_31944 = slt64(i_p_m_t_s_31942, (int64_t) 30);
            bool i_lte_j_31946 = sle64(i_35066, j_31941);
            bool y_31948 = zzero_leq_i_p_m_t_s_31943 && i_p_m_t_s_leq_w_31944;
            bool y_31949 = i_lte_j_31946 && y_31948;
            bool ok_or_empty_31951 = empty_slice_31932 || y_31949;
            
            for (int64_t i_35062 = 0; i_35062 < new_n_31887; i_35062++) {
                int64_t j_31954 = add64(dz2085Uz2088U_26645, i_35062);
                int64_t i_p_m_t_s_31955 = add64(m_31933, i_35062);
                bool zzero_leq_i_p_m_t_s_31956 = sle64((int64_t) 0, i_p_m_t_s_31955);
                bool i_p_m_t_s_leq_w_31957 = slt64(i_p_m_t_s_31955, (int64_t) 30);
                bool i_lte_j_31959 = sle64(i_35062, j_31954);
                bool y_31961 = zzero_leq_i_p_m_t_s_31956 && i_p_m_t_s_leq_w_31957;
                bool y_31962 = i_lte_j_31959 && y_31961;
                bool ok_or_empty_31964 = empty_slice_31932 || y_31962;
                bool index_ok_31965 = ok_or_empty_31951 && ok_or_empty_31964;
                bool index_certs_31966;
                
                if (!index_ok_31965) {
                    set_error(ctx, msgprintf("Error: %s%lld%s%lld%s%lld%s%lld%s%lld%s%lld%s\n\nBacktrace:\n%s", "Index [", (long long) i_35066, ":", (long long) j_31941, ", ", (long long) i_35062, ":", (long long) j_31954, "] out of bounds for array of shape [", (long long) (int64_t) 30, "][", (long long) (int64_t) 30, "].", "-> #0  ../layers/conv2d.fut:11:90-124\n   #1  ../layers/conv2d.fut:11:144-146\n   #2  /prelude/soacs.fut:59:9-10\n   #3  /prelude/array.fut:200:10-17\n   #4  /prelude/functional.fut:39:61-65\n   #5  /prelude/soacs.fut:59:9-10\n   #6  /prelude/array.fut:208:27-34\n   #7  ../layers/conv2d.fut:11:50-162\n   #8  ../layers/conv2d.fut:24:17-54\n"));
                    err = FUTHARK_PROGRAM_ERROR;
                    goto cleanup;
                }
                for (int64_t i_42918 = 0; i_42918 < total_31891; i_42918++) {
                    double tmp_42919 = ((double *) mem_41959)[(int64_t) 30 * i_35066 + i_35062 + (squot64(i_42918, dz2085Uz2088U_26645 * dz2085Uz2088U_26645) * (int64_t) 900 + squot64(i_42918 - squot64(i_42918, dz2085Uz2088U_26645 * dz2085Uz2088U_26645) * (dz2085Uz2088U_26645 * dz2085Uz2088U_26645), dz2085Uz2088U_26645) * (int64_t) 30 + (i_42918 - squot64(i_42918, dz2085Uz2088U_26645 * dz2085Uz2088U_26645) * (dz2085Uz2088U_26645 * dz2085Uz2088U_26645) - squot64(i_42918 - squot64(i_42918, dz2085Uz2088U_26645 * dz2085Uz2088U_26645) * (dz2085Uz2088U_26645 * dz2085Uz2088U_26645), dz2085Uz2088U_26645) * dz2085Uz2088U_26645))];
                    
                    ((double *) mem_42086)[i_35066 * binop_y_35807 + i_35062 * total_31891 + i_42918] = tmp_42919;
                }
            }
        }
        for (int64_t i_35076 = 0; i_35076 < dz2086Uz2080U_26647; i_35076++) {
            double x_32454 = ((double *) b4_c2_b_mem_38970.mem)[i_35076];
            int64_t binop_x_35702 = total_31891 * i_35076;
            
            for (int64_t i_35072 = 0; i_35072 < flat_dim_31969; i_35072++) {
                int64_t binop_x_35805 = total_31891 * i_35072;
                double defunc_0_reduce_res_34387;
                double redout_35068 = 0.0;
                
                for (int64_t i_35069 = 0; i_35069 < total_31891; i_35069++) {
                    int64_t binop_x_35703 = i_35069 + binop_x_35702;
                    int64_t new_index_35706 = squot64(binop_x_35703, total_31891);
                    int64_t binop_y_35716 = total_31891 * new_index_35706;
                    int64_t binop_x_35717 = binop_x_35703 - binop_y_35716;
                    int64_t new_index_35719 = squot64(binop_x_35717, binop_y_35718);
                    int64_t binop_y_35745 = binop_y_35718 * new_index_35719;
                    int64_t binop_x_35746 = binop_x_35717 - binop_y_35745;
                    int64_t new_index_35747 = squot64(binop_x_35746, dz2085Uz2089U_26646);
                    int64_t binop_y_35803 = dz2085Uz2089U_26646 * new_index_35747;
                    int64_t new_index_35804 = binop_x_35746 - binop_y_35803;
                    double x_33976 = ((double *) b4_c2_w_mem_38969.mem)[new_index_35706 * (dz2085Uz2089U_26646 * dz2085Uz2088U_26645 * dz2086Uz2082U_26644) + new_index_35719 * (dz2085Uz2089U_26646 * dz2085Uz2088U_26645) + new_index_35747 * dz2085Uz2089U_26646 + new_index_35804];
                    int64_t binop_x_35806 = i_35069 + binop_x_35805;
                    int64_t new_index_35808 = squot64(binop_x_35806, binop_y_35807);
                    int64_t binop_y_35816 = binop_y_35807 * new_index_35808;
                    int64_t binop_x_35817 = binop_x_35806 - binop_y_35816;
                    int64_t new_index_35818 = squot64(binop_x_35817, total_31891);
                    int64_t binop_y_35838 = total_31891 * new_index_35818;
                    int64_t new_index_35839 = binop_x_35817 - binop_y_35838;
                    double x_33977 = ((double *) mem_42086)[new_index_35808 * binop_y_35807 + new_index_35818 * total_31891 + new_index_35839];
                    double defunc_0_f_res_33978 = x_33976 * x_33977;
                    double defunc_0_op_res_33971 = defunc_0_f_res_33978 + redout_35068;
                    double redout_tmp_42922 = defunc_0_op_res_33971;
                    
                    redout_35068 = redout_tmp_42922;
                }
                defunc_0_reduce_res_34387 = redout_35068;
                
                double defunc_0_f_res_33974 = x_32454 + defunc_0_reduce_res_34387;
                
                ((double *) mem_42147)[i_35076 * flat_dim_31969 + i_35072] = defunc_0_f_res_33974;
            }
        }
        for (int64_t i_35088 = 0; i_35088 < dz2086Uz2082U_26644; i_35088++) {
            int64_t binop_x_35686 = (int64_t) 784 * i_35088;
            
            for (int64_t i_35084 = 0; i_35084 < (int64_t) 28; i_35084++) {
                int64_t binop_y_35687 = (int64_t) 28 * i_35084;
                int64_t binop_x_35688 = binop_x_35686 + binop_y_35687;
                
                for (int64_t i_35080 = 0; i_35080 < (int64_t) 28; i_35080++) {
                    int64_t binop_x_35689 = i_35080 + binop_x_35688;
                    int64_t new_index_35690 = squot64(binop_x_35689, flat_dim_31969);
                    int64_t binop_y_35700 = flat_dim_31969 * new_index_35690;
                    int64_t new_index_35701 = binop_x_35689 - binop_y_35700;
                    double x_32009 = ((double *) mem_42147)[new_index_35690 * flat_dim_31969 + new_index_35701];
                    double max_res_32010 = fmax64(0.0, x_32009);
                    
                    ((double *) mem_42193)[i_35088 * (int64_t) 784 + i_35084 * (int64_t) 28 + i_35080] = max_res_32010;
                }
            }
        }
        for (int64_t i_35092 = 0; i_35092 < (int64_t) 32; i_35092++) {
            int64_t i_32013 = mul64(elem_groups_31776, i_35092);
            int64_t arg_32014 = add64((int64_t) 1, i_35092);
            int64_t j_32015 = mul64(elem_groups_31776, arg_32014);
            int64_t j_m_i_32016 = sub64(j_32015, i_32013);
            bool empty_slice_32017 = j_m_i_32016 == (int64_t) 0;
            int64_t m_32018 = sub64(j_m_i_32016, (int64_t) 1);
            int64_t i_p_m_t_s_32019 = add64(i_32013, m_32018);
            bool zzero_leq_i_p_m_t_s_32020 = sle64((int64_t) 0, i_p_m_t_s_32019);
            bool i_p_m_t_s_leq_w_32021 = slt64(i_p_m_t_s_32019, dz2086Uz2082U_26644);
            bool zzero_lte_i_32022 = sle64((int64_t) 0, i_32013);
            bool i_lte_j_32023 = sle64(i_32013, j_32015);
            bool y_32024 = i_p_m_t_s_leq_w_32021 && zzero_lte_i_32022;
            bool y_32025 = zzero_leq_i_p_m_t_s_32020 && y_32024;
            bool y_32026 = i_lte_j_32023 && y_32025;
            bool forwards_ok_32027 = zzero_lte_i_32022 && y_32026;
            bool ok_or_empty_32028 = empty_slice_32017 || forwards_ok_32027;
            bool index_certs_32029;
            
            if (!ok_or_empty_32028) {
                set_error(ctx, msgprintf("Error: %s%lld%s%lld%s%lld%s\n\nBacktrace:\n%s", "Index [", (long long) i_32013, ":", (long long) j_32015, "] out of bounds for array of shape [", (long long) dz2086Uz2082U_26644, "].", "-> #0  ../layers/groupnorm.fut:2:31-70\n   #1  /prelude/soacs.fut:59:9-10\n   #2  /prelude/array.fut:200:10-17\n   #3  ../layers/groupnorm.fut:2:23-97\n   #4  ../layers/groupnorm.fut:20:19-54\n"));
                err = FUTHARK_PROGRAM_ERROR;
                goto cleanup;
            }
            
            bool dim_match_32030 = elem_groups_31776 == j_m_i_32016;
            bool empty_or_match_cert_32031;
            
            if (!dim_match_32030) {
                set_error(ctx, msgprintf("Error: %s%lld%s%lld%s%lld%s%lld%s%lld%s%lld%s\n\nBacktrace:\n%s", "Value of (core language) shape (", (long long) j_m_i_32016, ", ", (long long) (int64_t) 28, ", ", (long long) (int64_t) 28, ") cannot match shape of type `[", (long long) elem_groups_31776, "][", (long long) (int64_t) 28, "][", (long long) (int64_t) 28, "]f64`.", "-> #0  ../layers/groupnorm.fut:2:31-96\n   #1  /prelude/soacs.fut:59:9-10\n   #2  /prelude/array.fut:200:10-17\n   #3  ../layers/groupnorm.fut:2:23-97\n   #4  ../layers/groupnorm.fut:20:19-54\n"));
                err = FUTHARK_PROGRAM_ERROR;
                goto cleanup;
            }
            if (elem_groups_31776 * (int64_t) 28 * (int64_t) 28 * (int64_t) 8 > 0)
                memmove(mem_42281 + i_35092 * flat_dim_31804 * (int64_t) 8, mem_42193 + (int64_t) 784 * i_32013 * (int64_t) 8, elem_groups_31776 * (int64_t) 28 * (int64_t) 28 * (int64_t) 8);
        }
        for (int64_t i_35102 = 0; i_35102 < (int64_t) 32; i_35102++) {
            int64_t binop_x_35590 = flat_dim_31804 * i_35102;
            double defunc_0_reduce_res_34391;
            double redout_35094 = 0.0;
            
            for (int64_t i_35095 = 0; i_35095 < flat_dim_31804; i_35095++) {
                int64_t binop_x_35591 = i_35095 + binop_x_35590;
                int64_t new_index_35594 = squot64(binop_x_35591, flat_dim_31804);
                int64_t binop_y_35604 = flat_dim_31804 * new_index_35594;
                int64_t binop_x_35605 = binop_x_35591 - binop_y_35604;
                int64_t new_index_35606 = squot64(binop_x_35605, (int64_t) 784);
                int64_t binop_y_35630 = (int64_t) 784 * new_index_35606;
                int64_t binop_x_35631 = binop_x_35605 - binop_y_35630;
                int64_t new_index_35632 = squot64(binop_x_35631, (int64_t) 28);
                int64_t binop_y_35684 = (int64_t) 28 * new_index_35632;
                int64_t new_index_35685 = binop_x_35631 - binop_y_35684;
                double x_32044 = ((double *) mem_42281)[new_index_35594 * flat_dim_31804 + new_index_35606 * (int64_t) 784 + new_index_35632 * (int64_t) 28 + new_index_35685];
                double defunc_0_op_res_32043 = x_32044 + redout_35094;
                double redout_tmp_42929 = defunc_0_op_res_32043;
                
                redout_35094 = redout_tmp_42929;
            }
            defunc_0_reduce_res_34391 = redout_35094;
            
            double mean_res_32045 = defunc_0_reduce_res_34391 / i64_res_31805;
            double defunc_0_reduce_res_34392;
            double redout_35096 = 0.0;
            
            for (int64_t i_35097 = 0; i_35097 < flat_dim_31804; i_35097++) {
                int64_t binop_x_35495 = i_35097 + binop_x_35590;
                int64_t new_index_35498 = squot64(binop_x_35495, flat_dim_31804);
                int64_t binop_y_35508 = flat_dim_31804 * new_index_35498;
                int64_t binop_x_35509 = binop_x_35495 - binop_y_35508;
                int64_t new_index_35510 = squot64(binop_x_35509, (int64_t) 784);
                int64_t binop_y_35534 = (int64_t) 784 * new_index_35510;
                int64_t binop_x_35535 = binop_x_35509 - binop_y_35534;
                int64_t new_index_35536 = squot64(binop_x_35535, (int64_t) 28);
                int64_t binop_y_35588 = (int64_t) 28 * new_index_35536;
                int64_t new_index_35589 = binop_x_35535 - binop_y_35588;
                double x_33986 = ((double *) mem_42281)[new_index_35498 * flat_dim_31804 + new_index_35510 * (int64_t) 784 + new_index_35536 * (int64_t) 28 + new_index_35589];
                double arg_33987 = x_33986 - mean_res_32045;
                double defunc_0_f_res_33988 = arg_33987 * arg_33987;
                double defunc_0_op_res_32053 = defunc_0_f_res_33988 + redout_35096;
                double redout_tmp_42930 = defunc_0_op_res_32053;
                
                redout_35096 = redout_tmp_42930;
            }
            defunc_0_reduce_res_34392 = redout_35096;
            
            double variance_res_32055 = defunc_0_reduce_res_34392 / i64_res_31805;
            
            ((double *) mem_42312)[i_35102] = mean_res_32045;
            ((double *) mem_42314)[i_35102] = variance_res_32055;
        }
        for (int64_t i_35115 = 0; i_35115 < dz2086Uz2082U_26644; i_35115++) {
            int64_t i_32064 = sdiv64(i_35115, elem_groups_31776);
            bool x_32065 = sle64((int64_t) 0, i_32064);
            bool y_32066 = slt64(i_32064, (int64_t) 32);
            bool bounds_check_32067 = x_32065 && y_32066;
            bool index_certs_32068;
            
            if (!bounds_check_32067) {
                set_error(ctx, msgprintf("Error: %s%lld%s%lld%s\n\nBacktrace:\n%s", "Index [", (long long) i_32064, "] out of bounds for array of shape [", (long long) (int64_t) 32, "].", "-> #0  ../layers/groupnorm.fut:22:57-85\n   #1  /prelude/soacs.fut:59:9-10\n   #2  /prelude/array.fut:200:10-17\n   #3  /prelude/functional.fut:39:61-65\n   #4  /prelude/soacs.fut:59:9-10\n   #5  /prelude/array.fut:208:27-34\n   #6  /prelude/functional.fut:39:61-65\n   #7  /prelude/soacs.fut:59:9-10\n   #8  /prelude/array.fut:216:32-39\n   #9  ../layers/groupnorm.fut:22:31-135\n"));
                err = FUTHARK_PROGRAM_ERROR;
                goto cleanup;
            }
            
            double arg_32069 = ((double *) mem_42312)[i_32064];
            double arg_32070 = ((double *) mem_42314)[i_32064];
            double sqrt_arg_32071 = 1.0e-5 + arg_32070;
            double sqrt_res_32072 = futrts_sqrt64(sqrt_arg_32071);
            
            for (int64_t i_35111 = 0; i_35111 < (int64_t) 28; i_35111++) {
                for (int64_t i_35107 = 0; i_35107 < (int64_t) 28; i_35107++) {
                    double arg_32086 = ((double *) mem_42193)[i_35115 * (int64_t) 784 + i_35111 * (int64_t) 28 + i_35107];
                    double arg_32087 = arg_32086 - arg_32069;
                    double defunc_0_f_res_32088 = arg_32087 / sqrt_res_32072;
                    
                    ((double *) mem_42339)[i_35115 * (int64_t) 784 + i_35111 * (int64_t) 28 + i_35107] = defunc_0_f_res_32088;
                }
            }
        }
        for (int64_t i_35123 = 0; i_35123 < new_n_29126; i_35123++) {
            int64_t j_29399 = add64(dz2086Uz2083U_26648, i_35123);
            int64_t i_p_m_t_s_29400 = add64(m_29396, i_35123);
            bool zzero_leq_i_p_m_t_s_29401 = sle64((int64_t) 0, i_p_m_t_s_29400);
            bool i_p_m_t_s_leq_w_29402 = slt64(i_p_m_t_s_29400, (int64_t) 28);
            bool i_lte_j_29404 = sle64(i_35123, j_29399);
            bool y_29406 = zzero_leq_i_p_m_t_s_29401 && i_p_m_t_s_leq_w_29402;
            bool y_29407 = i_lte_j_29404 && y_29406;
            bool ok_or_empty_29409 = empty_slice_29395 || y_29407;
            
            for (int64_t i_35119 = 0; i_35119 < new_n_29126; i_35119++) {
                int64_t j_29412 = add64(dz2086Uz2083U_26648, i_35119);
                int64_t i_p_m_t_s_29413 = add64(m_29396, i_35119);
                bool zzero_leq_i_p_m_t_s_29414 = sle64((int64_t) 0, i_p_m_t_s_29413);
                bool i_p_m_t_s_leq_w_29415 = slt64(i_p_m_t_s_29413, (int64_t) 28);
                bool i_lte_j_29417 = sle64(i_35119, j_29412);
                bool y_29419 = zzero_leq_i_p_m_t_s_29414 && i_p_m_t_s_leq_w_29415;
                bool y_29420 = i_lte_j_29417 && y_29419;
                bool ok_or_empty_29422 = empty_slice_29395 || y_29420;
                bool index_ok_29423 = ok_or_empty_29409 && ok_or_empty_29422;
                bool index_certs_29424;
                
                if (!index_ok_29423) {
                    set_error(ctx, msgprintf("Error: %s%lld%s%lld%s%lld%s%lld%s%lld%s%lld%s\n\nBacktrace:\n%s", "Index [", (long long) i_35123, ":", (long long) j_29399, ", ", (long long) i_35119, ":", (long long) j_29412, "] out of bounds for array of shape [", (long long) (int64_t) 28, "][", (long long) (int64_t) 28, "].", "-> #0  ../layers/conv2d.fut:11:90-124\n   #1  ../layers/conv2d.fut:11:144-146\n   #2  /prelude/soacs.fut:59:9-10\n   #3  /prelude/array.fut:200:10-17\n   #4  /prelude/functional.fut:39:61-65\n   #5  /prelude/soacs.fut:59:9-10\n   #6  /prelude/array.fut:208:27-34\n   #7  ../layers/conv2d.fut:11:50-162\n"));
                    err = FUTHARK_PROGRAM_ERROR;
                    goto cleanup;
                }
                for (int64_t i_42936 = 0; i_42936 < total_29128; i_42936++) {
                    double tmp_42937 = ((double *) mem_42339)[(int64_t) 28 * i_35123 + i_35119 + (squot64(i_42936, dz2086Uz2083U_26648 * dz2086Uz2083U_26648) * (int64_t) 784 + squot64(i_42936 - squot64(i_42936, dz2086Uz2083U_26648 * dz2086Uz2083U_26648) * (dz2086Uz2083U_26648 * dz2086Uz2083U_26648), dz2086Uz2083U_26648) * (int64_t) 28 + (i_42936 - squot64(i_42936, dz2086Uz2083U_26648 * dz2086Uz2083U_26648) * (dz2086Uz2083U_26648 * dz2086Uz2083U_26648) - squot64(i_42936 - squot64(i_42936, dz2086Uz2083U_26648 * dz2086Uz2083U_26648) * (dz2086Uz2083U_26648 * dz2086Uz2083U_26648), dz2086Uz2083U_26648) * dz2086Uz2083U_26648))];
                    
                    ((double *) mem_42426)[i_35123 * binop_y_35461 + i_35119 * total_29128 + i_42936] = tmp_42937;
                }
            }
        }
        for (int64_t i_35133 = 0; i_35133 < dz2086Uz2085U_26650; i_35133++) {
            double x_32435 = ((double *) c_out_b_mem_38972.mem)[i_35133];
            int64_t binop_x_35356 = total_29128 * i_35133;
            
            for (int64_t i_35129 = 0; i_35129 < x_29136; i_35129++) {
                int64_t binop_x_35459 = total_29128 * i_35129;
                double defunc_0_reduce_res_34396;
                double redout_35125 = 0.0;
                
                for (int64_t i_35126 = 0; i_35126 < total_29128; i_35126++) {
                    int64_t binop_x_35357 = i_35126 + binop_x_35356;
                    int64_t new_index_35360 = squot64(binop_x_35357, total_29128);
                    int64_t binop_y_35370 = total_29128 * new_index_35360;
                    int64_t binop_x_35371 = binop_x_35357 - binop_y_35370;
                    int64_t new_index_35373 = squot64(binop_x_35371, binop_y_35372);
                    int64_t binop_y_35399 = binop_y_35372 * new_index_35373;
                    int64_t binop_x_35400 = binop_x_35371 - binop_y_35399;
                    int64_t new_index_35401 = squot64(binop_x_35400, dz2086Uz2084U_26649);
                    int64_t binop_y_35457 = dz2086Uz2084U_26649 * new_index_35401;
                    int64_t new_index_35458 = binop_x_35400 - binop_y_35457;
                    double x_34009 = ((double *) c_out_w_mem_38971.mem)[new_index_35360 * (dz2086Uz2084U_26649 * dz2086Uz2083U_26648 * dz2086Uz2082U_26644) + new_index_35373 * (dz2086Uz2084U_26649 * dz2086Uz2083U_26648) + new_index_35401 * dz2086Uz2084U_26649 + new_index_35458];
                    int64_t binop_x_35460 = i_35126 + binop_x_35459;
                    int64_t new_index_35462 = squot64(binop_x_35460, binop_y_35461);
                    int64_t binop_y_35470 = binop_y_35461 * new_index_35462;
                    int64_t binop_x_35471 = binop_x_35460 - binop_y_35470;
                    int64_t new_index_35472 = squot64(binop_x_35471, total_29128);
                    int64_t binop_y_35492 = total_29128 * new_index_35472;
                    int64_t new_index_35493 = binop_x_35471 - binop_y_35492;
                    double x_34010 = ((double *) mem_42426)[new_index_35462 * binop_y_35461 + new_index_35472 * total_29128 + new_index_35493];
                    double defunc_0_f_res_34011 = x_34009 * x_34010;
                    double defunc_0_op_res_34004 = defunc_0_f_res_34011 + redout_35125;
                    double redout_tmp_42940 = defunc_0_op_res_34004;
                    
                    redout_35125 = redout_tmp_42940;
                }
                defunc_0_reduce_res_34396 = redout_35125;
                
                double defunc_0_f_res_34007 = x_32435 + defunc_0_reduce_res_34396;
                
                ((double *) mem_42487)[i_35133 * x_29136 + i_35129] = defunc_0_f_res_34007;
            }
        }
        if (cond_29153 == 1) {
            int32_t unsign_arg_34399 = 5460 ^ p_sample_arg_29164;
            int32_t unsign_arg_34400 = mul32(48271, unsign_arg_34399);
            int32_t unsign_arg_34401 = umod32(unsign_arg_34400, 2147483647);
            int32_t unsign_arg_34402 = mul32(48271, unsign_arg_34401);
            int32_t unsign_arg_34403 = umod32(unsign_arg_34402, 2147483647);
            
            if (mem_42532_cached_sizze_43028 < (int64_t) 6272) {
                err = lexical_realloc(ctx, &mem_42532, &mem_42532_cached_sizze_43028, (int64_t) 6272);
                if (err != FUTHARK_SUCCESS)
                    goto cleanup;
            }
            for (int64_t i_35137 = 0; i_35137 < (int64_t) 784; i_35137++) {
                int32_t i64_res_34406 = sext_i64_i32(i_35137);
                int32_t arg_34407 = lshr32(i64_res_34406, 16);
                int32_t arg_34408 = i64_res_34406 ^ arg_34407;
                int32_t x_34409 = mul32(73244475, arg_34408);
                int32_t arg_34410 = lshr32(x_34409, 16);
                int32_t arg_34411 = x_34409 ^ arg_34410;
                int32_t x_34412 = mul32(73244475, arg_34411);
                int32_t arg_34413 = lshr32(x_34412, 16);
                int32_t x_34414 = x_34412 ^ arg_34413;
                int32_t unsign_arg_34415 = unsign_arg_34403 ^ x_34414;
                int32_t unsign_arg_34416 = mul32(48271, unsign_arg_34415);
                int32_t unsign_arg_34417 = umod32(unsign_arg_34416, 2147483647);
                int32_t unsign_arg_34418 = mul32(48271, unsign_arg_34417);
                int32_t unsign_arg_34419 = umod32(unsign_arg_34418, 2147483647);
                double u64_res_34420 = uitofp_i32_f64(unsign_arg_34417);
                double zs_res_34421 = u64_res_34420 / 2.147483647e9;
                double u64_res_34422 = uitofp_i32_f64(unsign_arg_34419);
                double zs_res_34423 = u64_res_34422 / 2.147483647e9;
                double log_res_34424 = futrts_log64(zs_res_34421);
                double zt_res_34425 = -2.0 * log_res_34424;
                double sqrt_res_34426 = futrts_sqrt64(zt_res_34425);
                double zt_res_34427 = 6.283185307179586 * zs_res_34423;
                double cos_res_34428 = futrts_cos64(zt_res_34427);
                double zt_res_34429 = sqrt_res_34426 * cos_res_34428;
                
                ((double *) mem_42532)[i_35137] = zt_res_34429;
            }
            if (memblock_alloc(ctx, &mem_42544, (int64_t) 6272, "mem_42544")) {
                err = 1;
                goto cleanup;
            }
            if ((int64_t) 6272 > 0)
                memmove(mem_42544.mem + (int64_t) 0, mem_42532 + (int64_t) 0, (int64_t) 6272);
            if (memblock_set(ctx, &ext_mem_42546, &mem_42544, "mem_42544") != 0)
                return 1;
        } else {
            if (memblock_alloc(ctx, &mem_42530, (int64_t) 6272, "mem_42530")) {
                err = 1;
                goto cleanup;
            }
            for (int64_t nest_i_42942 = 0; nest_i_42942 < (int64_t) 28; nest_i_42942++) {
                for (int64_t nest_i_42943 = 0; nest_i_42943 < (int64_t) 28; nest_i_42943++) {
                    ((double *) mem_42530.mem)[nest_i_42942 * (int64_t) 28 + nest_i_42943] = 0.0;
                }
            }
            if (memblock_set(ctx, &ext_mem_42546, &mem_42530, "mem_42530") != 0)
                return 1;
        }
        for (int64_t i_35145 = 0; i_35145 < (int64_t) 28; i_35145++) {
            int64_t binop_x_35346 = new_n_29126 * i_35145;
            
            for (int64_t i_35141 = 0; i_35141 < (int64_t) 28; i_35141++) {
                double x_29261 = ((double *) mem_param_39029.mem)[i_35145 * (int64_t) 28 + i_35141];
                int64_t binop_x_35347 = i_35141 + binop_x_35346;
                int64_t new_index_35348 = squot64(binop_x_35347, x_29136);
                int64_t binop_y_35354 = x_29136 * new_index_35348;
                int64_t new_index_35355 = binop_x_35347 - binop_y_35354;
                double x_29262 = ((double *) mem_42487)[new_index_35348 * x_29136 + new_index_35355];
                double x_29263 = ((double *) ext_mem_42546.mem)[i_35145 * (int64_t) 28 + i_35141];
                double arg_29264 = eps_coef_29151 * x_29262;
                double arg_29265 = x_29261 - arg_29264;
                double mean_29266 = arg_29155 * arg_29265;
                double arg_29267 = sqrt_res_29156 * x_29263;
                double defunc_0_f_res_29268 = mean_29266 + arg_29267;
                
                ((double *) mem_42548)[i_35145 * (int64_t) 28 + i_35141] = defunc_0_f_res_29268;
            }
        }
        if (memblock_unref(ctx, &ext_mem_42546, "ext_mem_42546") != 0)
            return 1;
        if (memblock_alloc(ctx, &mem_42588, (int64_t) 6272, "mem_42588")) {
            err = 1;
            goto cleanup;
        }
        for (int64_t nest_i_42946 = 0; nest_i_42946 < (int64_t) 1; nest_i_42946++) {
            if ((int64_t) 6272 > 0)
                memmove(mem_42588.mem + nest_i_42946 * (int64_t) 784 * (int64_t) 8, mem_42548 + (int64_t) 0, (int64_t) 6272);
        }
        if (memblock_set(ctx, &mem_param_tmp_42752, &mem_42588, "mem_42588") != 0)
            return 1;
        if (memblock_set(ctx, &mem_param_39029, &mem_param_tmp_42752, "mem_param_tmp_42752") != 0)
            return 1;
    }
    if (memblock_set(ctx, &ext_mem_42599, &mem_param_39029, "mem_param_39029") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_39018, "mem_39018") != 0)
        return 1;
    
    double defunc_0_reduce_res_34524;
    double defunc_0_reduce_res_34525;
    double redout_35147;
    double redout_35148;
    
    redout_35147 = -INFINITY;
    redout_35148 = INFINITY;
    for (int64_t i_35149 = 0; i_35149 < (int64_t) 784; i_35149++) {
        int64_t new_index_35158 = squot64(i_35149, (int64_t) 28);
        int64_t binop_y_35160 = (int64_t) 28 * new_index_35158;
        int64_t new_index_35161 = i_35149 - binop_y_35160;
        double x_32432 = ((double *) ext_mem_42599.mem)[new_index_35158 * (int64_t) 28 + new_index_35161];
        double defunc_0_op_res_29286 = fmax64(x_32432, redout_35147);
        double defunc_0_op_res_29291 = fmin64(x_32432, redout_35148);
        double redout_tmp_42947 = defunc_0_op_res_29286;
        double redout_tmp_42948 = defunc_0_op_res_29291;
        
        redout_35147 = redout_tmp_42947;
        redout_35148 = redout_tmp_42948;
    }
    defunc_0_reduce_res_34524 = redout_35147;
    defunc_0_reduce_res_34525 = redout_35148;
    
    double arg_29293 = defunc_0_reduce_res_34524 - defunc_0_reduce_res_34525;
    
    if (mem_42601_cached_sizze_43030 < (int64_t) 6272) {
        err = lexical_realloc(ctx, &mem_42601, &mem_42601_cached_sizze_43030, (int64_t) 6272);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    for (int64_t i_35156 = 0; i_35156 < (int64_t) 28; i_35156++) {
        for (int64_t i_35152 = 0; i_35152 < (int64_t) 28; i_35152++) {
            double x_29297 = ((double *) ext_mem_42599.mem)[i_35156 * (int64_t) 28 + i_35152];
            double arg_29298 = x_29297 - defunc_0_reduce_res_34525;
            double arg_29299 = arg_29298 / arg_29293;
            double arg_29300 = 2.0 * arg_29299;
            double defunc_0_f_res_29301 = -1.0 + arg_29300;
            
            ((double *) mem_42601)[i_35156 * (int64_t) 28 + i_35152] = defunc_0_f_res_29301;
        }
    }
    if (memblock_unref(ctx, &ext_mem_42599, "ext_mem_42599") != 0)
        return 1;
    if (memblock_alloc(ctx, &mem_42641, (int64_t) 6272, "mem_42641")) {
        err = 1;
        goto cleanup;
    }
    for (int64_t nest_i_42951 = 0; nest_i_42951 < (int64_t) 1; nest_i_42951++) {
        if ((int64_t) 6272 > 0)
            memmove(mem_42641.mem + nest_i_42951 * (int64_t) 784 * (int64_t) 8, mem_42601 + (int64_t) 0, (int64_t) 6272);
    }
    if (memblock_set(ctx, &mem_out_42736, &mem_42641, "mem_42641") != 0)
        return 1;
    if (memblock_set(ctx, &*mem_out_p_42952, &mem_out_42736, "mem_out_42736") != 0)
        return 1;
    
  cleanup:
    {
        free(mem_38974);
        free(mem_38976);
        free(mem_39006);
        free(mem_39031);
        free(mem_39033);
        free(mem_39055);
        free(mem_39095);
        free(mem_39100);
        free(mem_39161);
        free(mem_39204);
        free(mem_39291);
        free(mem_39352);
        free(mem_39398);
        free(mem_39486);
        free(mem_39517);
        free(mem_39519);
        free(mem_39544);
        free(mem_39557);
        free(mem_39671);
        free(mem_39732);
        free(mem_39778);
        free(mem_39866);
        free(mem_39897);
        free(mem_39899);
        free(mem_39924);
        free(mem_39929);
        free(mem_40098);
        free(mem_40159);
        free(mem_40205);
        free(mem_40293);
        free(mem_40324);
        free(mem_40326);
        free(mem_40351);
        free(mem_40364);
        free(mem_40478);
        free(mem_40539);
        free(mem_40585);
        free(mem_40673);
        free(mem_40704);
        free(mem_40706);
        free(mem_40731);
        free(mem_40815);
        free(mem_40902);
        free(mem_40963);
        free(mem_41009);
        free(mem_41097);
        free(mem_41128);
        free(mem_41130);
        free(mem_41155);
        free(mem_41168);
        free(mem_41282);
        free(mem_41343);
        free(mem_41389);
        free(mem_41477);
        free(mem_41508);
        free(mem_41510);
        free(mem_41535);
        free(mem_41619);
        free(mem_41706);
        free(mem_41767);
        free(mem_41813);
        free(mem_41901);
        free(mem_41932);
        free(mem_41934);
        free(mem_41959);
        free(mem_41972);
        free(mem_42086);
        free(mem_42147);
        free(mem_42193);
        free(mem_42281);
        free(mem_42312);
        free(mem_42314);
        free(mem_42339);
        free(mem_42426);
        free(mem_42487);
        free(mem_42532);
        free(mem_42548);
        free(mem_42601);
        if (memblock_unref(ctx, &mem_42641, "mem_42641") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_param_tmp_42752, "mem_param_tmp_42752") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_42588, "mem_42588") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_42530, "mem_42530") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_42544, "mem_42544") != 0)
            return 1;
        if (memblock_unref(ctx, &ext_mem_42546, "ext_mem_42546") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_param_39029, "mem_param_39029") != 0)
            return 1;
        if (memblock_unref(ctx, &ext_mem_42599, "ext_mem_42599") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_39018, "mem_39018") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_out_42736, "mem_out_42736") != 0)
            return 1;
    }
    return err;
}

int futhark_entry_main(struct futhark_context *ctx, struct futhark_f64_3d **out0, const struct futhark_f64_1d *in0, const struct futhark_f64_3d *in1, const struct futhark_f64_4d *in2, const struct futhark_f64_1d *in3, const struct futhark_f64_4d *in4, const struct futhark_f64_1d *in5, const struct futhark_f64_2d *in6, const struct futhark_f64_1d *in7, const struct futhark_f64_4d *in8, const struct futhark_f64_1d *in9, const struct futhark_f64_4d *in10, const struct futhark_f64_1d *in11, const struct futhark_f64_2d *in12, const struct futhark_f64_1d *in13, const struct futhark_f64_4d *in14, const struct futhark_f64_1d *in15, const struct futhark_f64_4d *in16, const struct futhark_f64_1d *in17, const struct futhark_f64_2d *in18, const struct futhark_f64_1d *in19, const struct futhark_f64_4d *in20, const struct futhark_f64_1d *in21, const struct futhark_f64_4d *in22, const struct futhark_f64_1d *in23, const struct futhark_f64_2d *in24, const struct futhark_f64_1d *in25, const struct futhark_f64_4d *in26, const struct futhark_f64_1d *in27, const struct futhark_f64_4d *in28, const struct futhark_f64_1d *in29)
{
    int64_t dz2080U_26613 = (int64_t) 0;
    int64_t dz2081U_26614 = (int64_t) 0;
    int64_t dz2082U_26615 = (int64_t) 0;
    int64_t dz2083U_26616 = (int64_t) 0;
    int64_t dz2086U_26617 = (int64_t) 0;
    int64_t dz2087U_26618 = (int64_t) 0;
    int64_t dz2088U_26619 = (int64_t) 0;
    int64_t dz2081Uz2081U_26620 = (int64_t) 0;
    int64_t dz2081Uz2082U_26621 = (int64_t) 0;
    int64_t dz2081Uz2083U_26622 = (int64_t) 0;
    int64_t dz2082Uz2083U_26623 = (int64_t) 0;
    int64_t dz2081Uz2089U_26624 = (int64_t) 0;
    int64_t dz2082Uz2080U_26625 = (int64_t) 0;
    int64_t dz2082Uz2081U_26626 = (int64_t) 0;
    int64_t dz2082Uz2082U_26627 = (int64_t) 0;
    int64_t dz2082Uz2084U_26628 = (int64_t) 0;
    int64_t dz2082Uz2085U_26629 = (int64_t) 0;
    int64_t dz2083Uz2081U_26630 = (int64_t) 0;
    int64_t dz2083Uz2080U_26631 = (int64_t) 0;
    int64_t dz2083Uz2082U_26632 = (int64_t) 0;
    int64_t dz2083Uz2083U_26633 = (int64_t) 0;
    int64_t dz2083Uz2087U_26634 = (int64_t) 0;
    int64_t dz2083Uz2088U_26635 = (int64_t) 0;
    int64_t dz2083Uz2089U_26636 = (int64_t) 0;
    int64_t dz2084Uz2084U_26637 = (int64_t) 0;
    int64_t dz2084Uz2085U_26638 = (int64_t) 0;
    int64_t dz2084Uz2086U_26639 = (int64_t) 0;
    int64_t dz2084Uz2087U_26640 = (int64_t) 0;
    int64_t dz2085Uz2080U_26641 = (int64_t) 0;
    int64_t dz2085Uz2081U_26642 = (int64_t) 0;
    int64_t dz2085Uz2082U_26643 = (int64_t) 0;
    int64_t dz2086Uz2082U_26644 = (int64_t) 0;
    int64_t dz2085Uz2088U_26645 = (int64_t) 0;
    int64_t dz2085Uz2089U_26646 = (int64_t) 0;
    int64_t dz2086Uz2080U_26647 = (int64_t) 0;
    int64_t dz2086Uz2083U_26648 = (int64_t) 0;
    int64_t dz2086Uz2084U_26649 = (int64_t) 0;
    int64_t dz2086Uz2085U_26650 = (int64_t) 0;
    int ret = 0;
    
    lock_lock(&ctx->lock);
    
    struct memblock mem_out_42736;
    
    mem_out_42736.references = NULL;
    
    struct memblock c_out_b_mem_38972;
    
    c_out_b_mem_38972.references = NULL;
    
    struct memblock c_out_w_mem_38971;
    
    c_out_w_mem_38971.references = NULL;
    
    struct memblock b4_c2_b_mem_38970;
    
    b4_c2_b_mem_38970.references = NULL;
    
    struct memblock b4_c2_w_mem_38969;
    
    b4_c2_w_mem_38969.references = NULL;
    
    struct memblock b4_tb_mem_38968;
    
    b4_tb_mem_38968.references = NULL;
    
    struct memblock b4_tw_mem_38967;
    
    b4_tw_mem_38967.references = NULL;
    
    struct memblock b4_c1_b_mem_38966;
    
    b4_c1_b_mem_38966.references = NULL;
    
    struct memblock b4_c1_w_mem_38965;
    
    b4_c1_w_mem_38965.references = NULL;
    
    struct memblock b3_c2_b_mem_38964;
    
    b3_c2_b_mem_38964.references = NULL;
    
    struct memblock b3_c2_w_mem_38963;
    
    b3_c2_w_mem_38963.references = NULL;
    
    struct memblock b3_tb_mem_38962;
    
    b3_tb_mem_38962.references = NULL;
    
    struct memblock b3_tw_mem_38961;
    
    b3_tw_mem_38961.references = NULL;
    
    struct memblock b3_c1_b_mem_38960;
    
    b3_c1_b_mem_38960.references = NULL;
    
    struct memblock b3_c1_w_mem_38959;
    
    b3_c1_w_mem_38959.references = NULL;
    
    struct memblock b2_c2_b_mem_38958;
    
    b2_c2_b_mem_38958.references = NULL;
    
    struct memblock b2_c2_w_mem_38957;
    
    b2_c2_w_mem_38957.references = NULL;
    
    struct memblock b2_tb_mem_38956;
    
    b2_tb_mem_38956.references = NULL;
    
    struct memblock b2_tw_mem_38955;
    
    b2_tw_mem_38955.references = NULL;
    
    struct memblock b2_c1_b_mem_38954;
    
    b2_c1_b_mem_38954.references = NULL;
    
    struct memblock b2_c1_w_mem_38953;
    
    b2_c1_w_mem_38953.references = NULL;
    
    struct memblock b1_c2_b_mem_38952;
    
    b1_c2_b_mem_38952.references = NULL;
    
    struct memblock b1_c2_w_mem_38951;
    
    b1_c2_w_mem_38951.references = NULL;
    
    struct memblock b1_tb_mem_38950;
    
    b1_tb_mem_38950.references = NULL;
    
    struct memblock b1_tw_mem_38949;
    
    b1_tw_mem_38949.references = NULL;
    
    struct memblock b1_c1_b_mem_38948;
    
    b1_c1_b_mem_38948.references = NULL;
    
    struct memblock b1_c1_w_mem_38947;
    
    b1_c1_w_mem_38947.references = NULL;
    
    struct memblock c_in_b_mem_38946;
    
    c_in_b_mem_38946.references = NULL;
    
    struct memblock c_in_w_mem_38945;
    
    c_in_w_mem_38945.references = NULL;
    
    struct memblock sampled_imgs_mem_38944;
    
    sampled_imgs_mem_38944.references = NULL;
    
    struct memblock losses_mem_38943;
    
    losses_mem_38943.references = NULL;
    losses_mem_38943 = in0->mem;
    dz2080U_26613 = in0->shape[0];
    sampled_imgs_mem_38944 = in1->mem;
    dz2081U_26614 = in1->shape[0];
    dz2082U_26615 = in1->shape[1];
    dz2083U_26616 = in1->shape[2];
    c_in_w_mem_38945 = in2->mem;
    dz2088U_26619 = in2->shape[0];
    dz2086U_26617 = in2->shape[2];
    dz2087U_26618 = in2->shape[3];
    c_in_b_mem_38946 = in3->mem;
    dz2088U_26619 = in3->shape[0];
    b1_c1_w_mem_38947 = in4->mem;
    dz2081Uz2083U_26622 = in4->shape[0];
    dz2081Uz2081U_26620 = in4->shape[2];
    dz2081Uz2082U_26621 = in4->shape[3];
    b1_c1_b_mem_38948 = in5->mem;
    dz2081Uz2083U_26622 = in5->shape[0];
    b1_tw_mem_38949 = in6->mem;
    dz2082Uz2083U_26623 = in6->shape[0];
    b1_tb_mem_38950 = in7->mem;
    dz2082Uz2083U_26623 = in7->shape[0];
    b1_c2_w_mem_38951 = in8->mem;
    dz2082Uz2081U_26626 = in8->shape[0];
    dz2082Uz2083U_26623 = in8->shape[1];
    dz2081Uz2089U_26624 = in8->shape[2];
    dz2082Uz2080U_26625 = in8->shape[3];
    b1_c2_b_mem_38952 = in9->mem;
    dz2082Uz2081U_26626 = in9->shape[0];
    b2_c1_w_mem_38953 = in10->mem;
    dz2082Uz2082U_26627 = in10->shape[0];
    dz2082Uz2083U_26623 = in10->shape[1];
    dz2082Uz2084U_26628 = in10->shape[2];
    dz2082Uz2085U_26629 = in10->shape[3];
    b2_c1_b_mem_38954 = in11->mem;
    dz2082Uz2082U_26627 = in11->shape[0];
    b2_tw_mem_38955 = in12->mem;
    dz2083Uz2081U_26630 = in12->shape[0];
    b2_tb_mem_38956 = in13->mem;
    dz2083Uz2081U_26630 = in13->shape[0];
    b2_c2_w_mem_38957 = in14->mem;
    dz2083Uz2080U_26631 = in14->shape[0];
    dz2083Uz2081U_26630 = in14->shape[1];
    dz2083Uz2082U_26632 = in14->shape[2];
    dz2083Uz2083U_26633 = in14->shape[3];
    b2_c2_b_mem_38958 = in15->mem;
    dz2083Uz2080U_26631 = in15->shape[0];
    b3_c1_w_mem_38959 = in16->mem;
    dz2083Uz2089U_26636 = in16->shape[0];
    dz2083Uz2087U_26634 = in16->shape[2];
    dz2083Uz2088U_26635 = in16->shape[3];
    b3_c1_b_mem_38960 = in17->mem;
    dz2083Uz2089U_26636 = in17->shape[0];
    b3_tw_mem_38961 = in18->mem;
    dz2084Uz2084U_26637 = in18->shape[0];
    b3_tb_mem_38962 = in19->mem;
    dz2084Uz2084U_26637 = in19->shape[0];
    b3_c2_w_mem_38963 = in20->mem;
    dz2084Uz2087U_26640 = in20->shape[0];
    dz2084Uz2084U_26637 = in20->shape[1];
    dz2084Uz2085U_26638 = in20->shape[2];
    dz2084Uz2086U_26639 = in20->shape[3];
    b3_c2_b_mem_38964 = in21->mem;
    dz2084Uz2087U_26640 = in21->shape[0];
    b4_c1_w_mem_38965 = in22->mem;
    dz2085Uz2082U_26643 = in22->shape[0];
    dz2085Uz2080U_26641 = in22->shape[2];
    dz2085Uz2081U_26642 = in22->shape[3];
    b4_c1_b_mem_38966 = in23->mem;
    dz2085Uz2082U_26643 = in23->shape[0];
    b4_tw_mem_38967 = in24->mem;
    dz2086Uz2082U_26644 = in24->shape[0];
    b4_tb_mem_38968 = in25->mem;
    dz2086Uz2082U_26644 = in25->shape[0];
    b4_c2_w_mem_38969 = in26->mem;
    dz2086Uz2080U_26647 = in26->shape[0];
    dz2086Uz2082U_26644 = in26->shape[1];
    dz2085Uz2088U_26645 = in26->shape[2];
    dz2085Uz2089U_26646 = in26->shape[3];
    b4_c2_b_mem_38970 = in27->mem;
    dz2086Uz2080U_26647 = in27->shape[0];
    c_out_w_mem_38971 = in28->mem;
    dz2086Uz2085U_26650 = in28->shape[0];
    dz2086Uz2082U_26644 = in28->shape[1];
    dz2086Uz2083U_26648 = in28->shape[2];
    dz2086Uz2084U_26649 = in28->shape[3];
    c_out_b_mem_38972 = in29->mem;
    dz2086Uz2085U_26650 = in29->shape[0];
    if (!(dz2080U_26613 == in0->shape[0] && ((dz2081U_26614 == in1->shape[0] && (dz2082U_26615 == in1->shape[1] && dz2083U_26616 == in1->shape[2])) && ((dz2088U_26619 == in2->shape[0] && ((int64_t) 1 == in2->shape[1] && (dz2086U_26617 == in2->shape[2] && dz2087U_26618 == in2->shape[3]))) && (dz2088U_26619 == in3->shape[0] && ((dz2081Uz2083U_26622 == in4->shape[0] && ((int64_t) 64 == in4->shape[1] && (dz2081Uz2081U_26620 == in4->shape[2] && dz2081Uz2082U_26621 == in4->shape[3]))) && (dz2081Uz2083U_26622 == in5->shape[0] && ((dz2082Uz2083U_26623 == in6->shape[0] && (int64_t) 256 == in6->shape[1]) && (dz2082Uz2083U_26623 == in7->shape[0] && ((dz2082Uz2081U_26626 == in8->shape[0] && (dz2082Uz2083U_26623 == in8->shape[1] && (dz2081Uz2089U_26624 == in8->shape[2] && dz2082Uz2080U_26625 == in8->shape[3]))) && (dz2082Uz2081U_26626 == in9->shape[0] && ((dz2082Uz2082U_26627 == in10->shape[0] && (dz2082Uz2083U_26623 == in10->shape[1] && (dz2082Uz2084U_26628 == in10->shape[2] && dz2082Uz2085U_26629 == in10->shape[3]))) && (dz2082Uz2082U_26627 == in11->shape[0] && ((dz2083Uz2081U_26630 == in12->shape[0] && (int64_t) 256 == in12->shape[1]) && (dz2083Uz2081U_26630 == in13->shape[0] && ((dz2083Uz2080U_26631 == in14->shape[0] && (dz2083Uz2081U_26630 == in14->shape[1] && (dz2083Uz2082U_26632 == in14->shape[2] && dz2083Uz2083U_26633 == in14->shape[3]))) && (dz2083Uz2080U_26631 == in15->shape[0] && ((dz2083Uz2089U_26636 == in16->shape[0] && ((int64_t) 512 == in16->shape[1] && (dz2083Uz2087U_26634 == in16->shape[2] && dz2083Uz2088U_26635 == in16->shape[3]))) && (dz2083Uz2089U_26636 == in17->shape[0] && ((dz2084Uz2084U_26637 == in18->shape[0] && (int64_t) 256 == in18->shape[1]) && (dz2084Uz2084U_26637 == in19->shape[0] && ((dz2084Uz2087U_26640 == in20->shape[0] && (dz2084Uz2084U_26637 == in20->shape[1] && (dz2084Uz2085U_26638 == in20->shape[2] && dz2084Uz2086U_26639 == in20->shape[3]))) && (dz2084Uz2087U_26640 == in21->shape[0] && ((dz2085Uz2082U_26643 == in22->shape[0] && ((int64_t) 256 == in22->shape[1] && (dz2085Uz2080U_26641 == in22->shape[2] && dz2085Uz2081U_26642 == in22->shape[3]))) && (dz2085Uz2082U_26643 == in23->shape[0] && ((dz2086Uz2082U_26644 == in24->shape[0] && (int64_t) 256 == in24->shape[1]) && (dz2086Uz2082U_26644 == in25->shape[0] && ((dz2086Uz2080U_26647 == in26->shape[0] && (dz2086Uz2082U_26644 == in26->shape[1] && (dz2085Uz2088U_26645 == in26->shape[2] && dz2085Uz2089U_26646 == in26->shape[3]))) && (dz2086Uz2080U_26647 == in27->shape[0] && ((dz2086Uz2085U_26650 == in28->shape[0] && (dz2086Uz2082U_26644 == in28->shape[1] && (dz2086Uz2083U_26648 == in28->shape[2] && dz2086Uz2084U_26649 == in28->shape[3]))) && dz2086Uz2085U_26650 == in29->shape[0])))))))))))))))))))))))))))))) {
        ret = 1;
        set_error(ctx, msgprintf("Error: entry point arguments have invalid sizes.\n"));
    }
    if (ret == 0) {
        ret = futrts_entry_main(ctx, &mem_out_42736, losses_mem_38943, sampled_imgs_mem_38944, c_in_w_mem_38945, c_in_b_mem_38946, b1_c1_w_mem_38947, b1_c1_b_mem_38948, b1_tw_mem_38949, b1_tb_mem_38950, b1_c2_w_mem_38951, b1_c2_b_mem_38952, b2_c1_w_mem_38953, b2_c1_b_mem_38954, b2_tw_mem_38955, b2_tb_mem_38956, b2_c2_w_mem_38957, b2_c2_b_mem_38958, b3_c1_w_mem_38959, b3_c1_b_mem_38960, b3_tw_mem_38961, b3_tb_mem_38962, b3_c2_w_mem_38963, b3_c2_b_mem_38964, b4_c1_w_mem_38965, b4_c1_b_mem_38966, b4_tw_mem_38967, b4_tb_mem_38968, b4_c2_w_mem_38969, b4_c2_b_mem_38970, c_out_w_mem_38971, c_out_b_mem_38972, dz2080U_26613, dz2081U_26614, dz2082U_26615, dz2083U_26616, dz2086U_26617, dz2087U_26618, dz2088U_26619, dz2081Uz2081U_26620, dz2081Uz2082U_26621, dz2081Uz2083U_26622, dz2082Uz2083U_26623, dz2081Uz2089U_26624, dz2082Uz2080U_26625, dz2082Uz2081U_26626, dz2082Uz2082U_26627, dz2082Uz2084U_26628, dz2082Uz2085U_26629, dz2083Uz2081U_26630, dz2083Uz2080U_26631, dz2083Uz2082U_26632, dz2083Uz2083U_26633, dz2083Uz2087U_26634, dz2083Uz2088U_26635, dz2083Uz2089U_26636, dz2084Uz2084U_26637, dz2084Uz2085U_26638, dz2084Uz2086U_26639, dz2084Uz2087U_26640, dz2085Uz2080U_26641, dz2085Uz2081U_26642, dz2085Uz2082U_26643, dz2086Uz2082U_26644, dz2085Uz2088U_26645, dz2085Uz2089U_26646, dz2086Uz2080U_26647, dz2086Uz2083U_26648, dz2086Uz2084U_26649, dz2086Uz2085U_26650);
        if (ret == 0) {
            assert((*out0 = (struct futhark_f64_3d *) malloc(sizeof(struct futhark_f64_3d))) != NULL);
            (*out0)->mem = mem_out_42736;
            (*out0)->shape[0] = (int64_t) 1;
            (*out0)->shape[1] = (int64_t) 28;
            (*out0)->shape[2] = (int64_t) 28;
        }
    }
    lock_unlock(&ctx->lock);
    return ret;
}
  
