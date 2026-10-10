// abi.cpp — C ABI implementation of include/hrd.h for the statically linked
// host engine (port of src/abi.zig).

#include "hrd.h"

#include "engine.h"
#include "hrd_internal.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <new>
#include <string>
#include <vector>

namespace {

using namespace hrd;

struct HrdCtx {
    Engine *engine = nullptr;
    hrd_need_pass_cb need_pass = nullptr;
    hrd_event_cb event = nullptr;
    void *user = nullptr;
};

// Install the engine callbacks that mirror this context's C callbacks.
// Both are refreshed together so registering one never clears the other.
void ApplyCallbacks(HrdCtx *ctx) {
    if (ctx == nullptr || ctx->engine == nullptr) return;
    NeedPasswordFn need;
    if (ctx->need_pass != nullptr) {
        need = [ctx](const std::string &archive_path,
                     std::string &out_password) {
            char buffer[512] = {};
            const int result =
                ctx->need_pass(archive_path.c_str(), buffer, sizeof(buffer),
                               ctx->user);
            if (result == 0) return false;
            out_password = buffer;
            return true;
        };
    }
    EventFn event;
    if (ctx->event != nullptr) {
        event = [ctx](const EventInfo &info) {
            ctx->event(static_cast<hrd_event_t>(info.event), info.path,
                       info.depth, static_cast<hrd_format_t>(info.fmt),
                       info.aux, ctx->user);
        };
    }
    ctx->engine->SetCallbacks(std::move(need), std::move(event));
}

}  // namespace

extern "C" {

HRD_API uint32_t HRD_CALL hrd_abi_version(void) {
    return (1u << 16) | 0u;  // v1.0
}

HRD_API const char *HRD_CALL hrd_status_string(int st) {
    switch (st) {
        case HRD_OK: return "ok";
        case HRD_ERR_INVALID_ARG: return "invalid argument";
        case HRD_ERR_IO: return "I/O error";
        case HRD_ERR_UNSUPPORTED: return "unsupported format";
        case HRD_ERR_ENCRYPTED: return "encrypted (password needed)";
        case HRD_ERR_PASSWORD: return "wrong password";
        case HRD_ERR_BOMB: return "bomb limit exceeded";
        case HRD_ERR_DEPTH: return "max recursion depth";
        case HRD_ERR_ARCHIVE: return "archive error";
        case HRD_ERR_NOMEM: return "out of memory";
        case HRD_ERR_CANCELLED: return "cancelled";
        default: return "unknown error";
    }
}

HRD_API hrd_ctx_t *HRD_CALL hrd_ctx_create(const hrd_options_t *opts) {
    auto *ctx = new (std::nothrow) HrdCtx;
    if (ctx == nullptr) return nullptr;
    EngineOptions options;
    if (opts != nullptr && opts->struct_size >= sizeof(hrd_options_t)) {
        if (opts->max_depth != 0) options.max_depth = opts->max_depth;
        options.max_ratio = opts->max_ratio;
        options.max_total_bytes = opts->max_total_bytes;
        options.flatten = opts->flatten != 0;
        options.overwrite = opts->overwrite != 0;
        options.interactive = opts->interactive != 0;
        if (opts->password_db != nullptr) {
            options.password_db = opts->password_db;
        }
        if (opts->temp_dir != nullptr) {
            options.temp_dir = opts->temp_dir;
        }
    }
    ctx->engine = new (std::nothrow) Engine(options);
    if (ctx->engine == nullptr) {
        delete ctx;
        return nullptr;
    }
    return reinterpret_cast<hrd_ctx_t *>(ctx);
}

HRD_API void HRD_CALL hrd_ctx_destroy(hrd_ctx_t *ctx) {
    if (ctx == nullptr) return;
    auto *self = reinterpret_cast<HrdCtx *>(ctx);
    delete self->engine;
    delete self;
}

HRD_API void HRD_CALL hrd_ctx_set_need_password_cb(hrd_ctx_t *ctx,
                                                   hrd_need_pass_cb cb,
                                                   void *user) {
    if (ctx == nullptr) return;
    auto *self = reinterpret_cast<HrdCtx *>(ctx);
    self->need_pass = cb;
    self->user = user;
    ApplyCallbacks(self);
}

HRD_API void HRD_CALL hrd_ctx_set_event_cb(hrd_ctx_t *ctx, hrd_event_cb cb,
                                           void *user) {
    if (ctx == nullptr) return;
    auto *self = reinterpret_cast<HrdCtx *>(ctx);
    self->event = cb;
    self->user = user;
    ApplyCallbacks(self);
}

HRD_API int HRD_CALL hrd_ctx_add_password(hrd_ctx_t *ctx,
                                          const char *password) {
    if (ctx == nullptr || password == nullptr) return HRD_ERR_INVALID_ARG;
    auto *self = reinterpret_cast<HrdCtx *>(ctx);
    if (self->engine == nullptr) return HRD_ERR_INTERNAL;
    self->engine->book().Learn(password);
    return HRD_OK;
}

HRD_API int HRD_CALL hrd_process(hrd_ctx_t *ctx, const char *const *inputs,
                                 size_t input_count, const char *out_dir,
                                 char **out_report) {
    if (ctx == nullptr || inputs == nullptr || out_dir == nullptr) {
        return HRD_ERR_INVALID_ARG;
    }
    auto *self = reinterpret_cast<HrdCtx *>(ctx);
    if (self->engine == nullptr) return HRD_ERR_INTERNAL;
    std::vector<std::string> input_list;
    input_list.reserve(input_count);
    for (size_t i = 0; i < input_count; ++i) {
        if (inputs[i] == nullptr) return HRD_ERR_INVALID_ARG;
        input_list.emplace_back(inputs[i]);
    }
    const int status = self->engine->Process(input_list, out_dir);
    if (out_report != nullptr) {
        *out_report = nullptr;
        const Report &report = self->engine->report();
        char buffer[256];
        const int n = std::snprintf(
            buffer, sizeof(buffer),
            "{\"archives\":%llu,\"delivered_files\":%llu,\"delivered_bytes\":"
            "%llu,\"errors\":%llu,\"passwords_used\":%llu}",
            static_cast<unsigned long long>(report.archives),
            static_cast<unsigned long long>(report.delivered_files),
            static_cast<unsigned long long>(report.delivered_bytes),
            static_cast<unsigned long long>(report.errors),
            static_cast<unsigned long long>(report.passwords_used));
        if (n > 0) {
            *out_report =
                static_cast<char *>(std::malloc(static_cast<size_t>(n) + 1));
            if (*out_report != nullptr) {
                std::memcpy(*out_report, buffer,
                            static_cast<size_t>(n) + 1);
            }
        }
    }
    return status;
}

HRD_API void HRD_CALL hrd_free(void *p) { std::free(p); }

}  // extern "C"
