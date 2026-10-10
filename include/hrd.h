#ifndef HRD_H
#define HRD_H
/*
 * hrd — Heuristic Recursive Decompressor
 * Stable C ABI (v1). Cross-platform: Windows / Linux / macOS.
 *
 * Define HRD_STATIC before including this header when the implementation is
 * statically linked into the host (cpp/ host engine built by CMake). Without
 * it, Windows hosts expect a DLL import.
 *
 * Threading: one hrd_ctx_t* may be used from one thread at a time.
 * Multiple contexts may be used concurrently. All strings are UTF-8.
 */
#ifdef __cplusplus
extern "C" {
#endif

#if defined(HRD_STATIC)
#  define HRD_API
#  define HRD_CALL
#elif defined(_WIN32) || defined(__CYGWIN__)
#  ifdef HRD_BUILDING_DLL
#    define HRD_API __declspec(dllexport)
#  else
#    define HRD_API __declspec(dllimport)
#  endif
#  define HRD_CALL __cdecl
#else
#  define HRD_API __attribute__((visibility("default")))
#  define HRD_CALL
#endif

#include <stddef.h>
#include <stdint.h>

#define HRD_ABI_VERSION_MAJOR 1u
#define HRD_ABI_VERSION_MINOR 0u
#define HRD_ABI_VERSION_PATCH 0u

typedef struct hrd_ctx_s hrd_ctx_t;

typedef enum hrd_status_e {
    HRD_OK = 0,
    HRD_ERR_INVALID_ARG      = 1,
    HRD_ERR_IO               = 2,
    HRD_ERR_UNSUPPORTED      = 3,   /* not an archive / unknown format        */
    HRD_ERR_ENCRYPTED        = 4,   /* needs password (see HRD_CB_NEED_PASS)  */
    HRD_ERR_PASSWORD         = 5,   /* wrong password                         */
    HRD_ERR_BOMB             = 6,   /* safety circuit-breaker tripped         */
    HRD_ERR_DEPTH            = 7,   /* max recursion depth reached            */
    HRD_ERR_ARCHIVE          = 8,   /* archive open/extract backend failure   */
    HRD_ERR_NOMEM            = 9,
    HRD_ERR_CANCELLED        = 10,  /* cancelled by callback                  */
    HRD_ERR_INTERNAL         = 255
} hrd_status_t;

typedef enum hrd_event_e {
    HRD_EV_GROUPED      = 1,  /* module 1: volume group locked              */
    HRD_EV_SNIFFED      = 2,  /* module 2: format/offset detected           */
    HRD_EV_PROBE        = 3,  /* module 3: encryption probe result          */
    HRD_EV_EXTRACTING   = 4,  /* module 4: archive extraction begin         */
    HRD_EV_EXTRACTED    = 5,  /* module 4: archive extraction done          */
    HRD_EV_DELIVERED    = 6,  /* module 5: final file delivered             */
    HRD_EV_KEPT         = 7,  /* module 2: non-archive carrier kept as-is   */
    HRD_EV_CIRCUIT      = 8   /* module 5: circuit breaker warning          */
} hrd_event_t;

typedef enum hrd_format_e {
    HRD_FMT_NONE = 0,
    HRD_FMT_ZIP  = 1,
    HRD_FMT_RAR4 = 2,
    HRD_FMT_RAR5 = 3,
    HRD_FMT_7Z   = 4,
    HRD_FMT_GZ   = 5,
    HRD_FMT_BZ2  = 6,
    HRD_FMT_XZ   = 7,
    HRD_FMT_TAR  = 8,
    HRD_FMT_CAB  = 9
} hrd_format_t;

typedef struct hrd_options_s {
    uint32_t struct_size;      /* sizeof(hrd_options_t) — ABI guard          */
    uint32_t max_depth;        /* default 8                                  */
    uint32_t max_ratio;        /* default 100 (0 disables)                   */
    uint64_t max_total_bytes;  /* default 32 GiB (0 disables)                */
    uint32_t flatten;          /* 0 keep tree, 1 flatten                     */
    uint32_t overwrite;        /* 0 skip, 1 overwrite                        */
    uint32_t interactive;      /* 1 = HRD_CB_NEED_PASS may be invoked        */
    const char *password_db;   /* optional extra DB file (UTF-8 path)        */
    const char *temp_dir;      /* optional scratch dir (default: out/.hrd_tmp) */
} hrd_options_t;

/* Password request: fill `out_password` (UTF-8, NUL-terminated) and return 1,
 * or return 0 to cancel. Returning 0 yields HRD_ERR_CANCELLED for that item. */
typedef int (HRD_CALL *hrd_need_pass_cb)(const char *archive_path,
                                         char *out_password,
                                         size_t out_cap,
                                         void *user);

typedef void (HRD_CALL *hrd_event_cb)(hrd_event_t event,
                                      const char *path,
                                      uint32_t depth,
                                      hrd_format_t fmt,
                                      uint64_t aux,      /* e.g. offset / file size */
                                      void *user);

HRD_API uint32_t     HRD_CALL hrd_abi_version(void);
HRD_API const char * HRD_CALL hrd_status_string(hrd_status_t st);

HRD_API hrd_ctx_t *  HRD_CALL hrd_ctx_create(const hrd_options_t *opts);
HRD_API void         HRD_CALL hrd_ctx_destroy(hrd_ctx_t *ctx);

HRD_API void         HRD_CALL hrd_ctx_set_need_password_cb(hrd_ctx_t *ctx,
                                                           hrd_need_pass_cb cb,
                                                           void *user);
HRD_API void         HRD_CALL hrd_ctx_set_event_cb(hrd_ctx_t *ctx,
                                                   hrd_event_cb cb,
                                                   void *user);

/* Learn a password into the persistent local DB (highest priority first). */
HRD_API hrd_status_t HRD_CALL hrd_ctx_add_password(hrd_ctx_t *ctx, const char *password);

/* `inputs` may be files or directories (UTF-8). Directories are walked.
 * `out_dir` is created if needed. Returns first error or HRD_OK.
 * `out_report` (optional) receives a malloc'ed JSON summary string;
 * free with hrd_free(). */
HRD_API hrd_status_t HRD_CALL hrd_process(hrd_ctx_t *ctx,
                                          const char *const *inputs,
                                          size_t input_count,
                                          const char *out_dir,
                                          char **out_report);

HRD_API void         HRD_CALL hrd_free(void *p);

#ifdef __cplusplus
}
#endif
#endif /* HRD_H */
