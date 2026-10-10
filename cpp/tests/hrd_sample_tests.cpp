// hrd_sample_tests.cpp — end-to-end real-sample tests for the C++ host
// engine, driven through the public hrd.h C ABI against the repository's
// test_samples/ fixtures.
//
// Run: hrd_sample_tests <path-to-test_samples>

#include "hrd.h"

#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

namespace {

namespace fs = std::filesystem;

int g_failures = 0;

std::string Slurp(const std::string &path) {
    std::ifstream stream(path, std::ios::binary);
    std::ostringstream buffer;
    buffer << stream.rdbuf();
    return buffer.str();
}

bool FileExists(const std::string &root, const std::string &relative) {
    std::error_code ec;
    return fs::is_regular_file(fs::u8path(root) / fs::u8path(relative), ec);
}

void Check(bool condition, const std::string &label) {
    if (condition) {
        std::cout << "[PASS] " << label << "\n";
    } else {
        ++g_failures;
        std::cout << "[FAIL] " << label << "\n";
    }
}

struct RunResult {
    int status = -1;
    std::string report;
};

RunResult RunHrd(const std::string &input, const std::string &out_dir,
                 const hrd_options_t *options, const char *password = nullptr,
                 hrd_need_pass_cb need_pass = nullptr, void *user = nullptr) {
    RunResult result;
    std::error_code ec;
    fs::remove_all(fs::u8path(out_dir), ec);
    hrd_ctx_t *ctx = hrd_ctx_create(options);
    if (ctx == nullptr) {
        result.status = -1;
        return result;
    }
    if (password != nullptr) hrd_ctx_add_password(ctx, password);
    hrd_ctx_set_need_password_cb(ctx, need_pass, user);
    const char *inputs[] = {input.c_str()};
    char *report = nullptr;
    result.status = hrd_process(ctx, inputs, 1, out_dir.c_str(), &report);
    if (report != nullptr) {
        result.report = report;
        hrd_free(report);
    }
    hrd_ctx_destroy(ctx);
    return result;
}

// Interactive password callback used by the encrypted-archive tests.
struct InteractiveState {
    const char *password;
    int calls = 0;
};

int HRD_CALL NeedPassword(const char * /*archive_path*/, char *out_password,
                          size_t out_cap, void *user) {
    auto *state = static_cast<InteractiveState *>(user);
    state->calls += 1;
    if (state->password == nullptr) return 0;  // cancel
    const size_t n = std::strlen(state->password);
    if (n + 1 > out_cap) return 0;
    std::memcpy(out_password, state->password, n + 1);
    return 1;
}

void TestPlainZip(const std::string &samples, const std::string &work) {
    const RunResult run = RunHrd(samples + "/e45_single.zip",
                                 work + "/e45", nullptr);
    Check(run.status == HRD_OK, "plain zip extracts");
    Check(FileExists(work + "/e45", "_e45.txt"), "plain zip delivers entry");
    Check(!FileExists(work + "/e45", "_0_e45_single.zip"),
          "plain zip leaves no depth temp dir");
}

void TestZipWithDirs(const std::string &samples, const std::string &work) {
    const RunResult run = RunHrd(samples + "/e46_dirs.zip",
                                 work + "/e46", nullptr);
    Check(run.status == HRD_OK, "zip with directories extracts");
    Check(FileExists(work + "/e46", "subdir/deep.txt"),
          "zip directory structure is preserved");
}

void TestNestedRecursion(const std::string &samples, const std::string &work) {
    const RunResult run = RunHrd(samples + "/n31_2level.zip",
                                 work + "/n31", nullptr);
    Check(run.status == HRD_OK, "nested zip extracts");
    Check(FileExists(work + "/n31", "_nn31_2level.zip.txt"),
          "nested zip delivers inner content");
}

void TestMp4Steg(const std::string &samples, const std::string &work) {
    const RunResult run = RunHrd(samples + "/d11.mp4", work + "/d11",
                                 nullptr);
    Check(run.status == HRD_OK, "mp4 steg carrier extracts");
    Check(FileExists(work + "/d11", "_carrier.txt"),
          "mp4 steg delivers embedded zip entry");
}

void TestNoExtensionZip(const std::string &samples, const std::string &work) {
    const RunResult run = RunHrd(samples + "/d13_noext", work + "/d13",
                                 nullptr);
    Check(run.status == HRD_OK, "extension-less zip extracts");
    const std::string report_note =
        run.status == HRD_OK ? "delivered something" : "failed";
    Check(fs::is_empty(fs::u8path(work + "/d13")) == false,
          "extension-less zip delivers content (" + report_note + ")");
}

void TestDisguisedChain(const std::string &samples, const std::string &work) {
    const RunResult run = RunHrd(samples + "/n39_disguised_chain.zip",
                                 work + "/n39", nullptr);
    Check(run.status == HRD_OK, "disguised chain extracts");
}

void TestPasswordFromContext(const std::string &samples,
                             const std::string &work) {
    // The whole real_enc directory is processed; the password book harvests
    // pw.txt (hunter2) from the sibling files.
    const RunResult run = RunHrd(samples + "/real_enc", work + "/enc",
                                 nullptr);
    Check(run.status == HRD_OK, "encrypted set extracts via context");
    Check(FileExists(work + "/enc", "secret.txt"),
          "encrypted zip delivers secret.txt");
}

void TestPasswordInteractive(const std::string &samples,
                             const std::string &work) {
    hrd_options_t options{};
    options.struct_size = sizeof(options);
    options.interactive = 1;
    InteractiveState state{"hunter2", 0};
    const RunResult run = RunHrd(samples + "/real_enc/enc.zip",
                                 work + "/interactive", &options, nullptr,
                                 NeedPassword, &state);
    Check(run.status == HRD_OK, "interactive password extracts encrypted zip");
    Check(FileExists(work + "/interactive", "secret.txt"),
          "interactive password delivers secret.txt");
}

void TestEncryptedWithoutPassword(const std::string &samples,
                                  const std::string &work) {
    // Isolate enc.7z from its password hint (pw.txt) and interactive input;
    // the engine must report a password error instead of extracting.
    std::error_code ec;
    const fs::path isolated = fs::u8path(work) / "isolated";
    fs::create_directories(isolated, ec);
    fs::copy_file(fs::u8path(samples) / "real_enc" / "enc.7z",
                  isolated / "enc.7z", fs::copy_options::overwrite_existing,
                  ec);
    hrd_options_t options{};
    options.struct_size = sizeof(options);
    options.interactive = 0;
    const RunResult run =
        RunHrd((isolated / "enc.7z").u8string(), work + "/nopass", &options);
    Check(run.status == HRD_ERR_ENCRYPTED || run.status == HRD_ERR_PASSWORD,
          "encrypted archive without password reports a password error");
}

void TestMultiVolume(const std::string &samples, const std::string &work) {
    const RunResult run = RunHrd(samples + "/real_vol", work + "/vol",
                                 nullptr);
    Check(run.status == HRD_OK, "103-volume 7z split extracts");
    Check(FileExists(work + "/vol", "payload.txt"),
          "multi-volume delivers payload.txt");
    const std::string payload = Slurp(work + "/vol/payload.txt");
    Check(payload.find("hello volume world") != std::string::npos,
          "multi-volume payload content matches");
}

void TestBombProtection(const std::string &samples, const std::string &work) {
    hrd_options_t options{};
    options.struct_size = sizeof(options);
    options.max_total_bytes = 4096;  // force the circuit breaker
    options.interactive = 0;
    const RunResult run = RunHrd(samples + "/b41_bomb.zip", work + "/bomb",
                                 &options);
    Check(run.status == HRD_ERR_BOMB, "bomb limit trips");
}

void TestPlainFileKept(const std::string &samples, const std::string &work) {
    const RunResult run = RunHrd(samples + "/d20_pure.png", work + "/kept",
                                 nullptr);
    Check(run.status == HRD_OK, "non-archive carrier reports success");
    Check(FileExists(work + "/kept", "d20_pure.png"),
          "non-archive file is kept as-is");
}

}  // namespace

int main(int argc, char **argv) {
    if (argc < 3) {
        std::cerr << "usage: " << argv[0]
                  << " <test_samples-dir> <work-dir>\n";
        return 2;
    }
    const std::string samples = argv[1];
    const std::string work = argv[2];
    std::error_code ec;
    fs::create_directories(fs::u8path(work), ec);

    std::cout << "hrd_abi_version: " << hrd_abi_version() << "\n";

    TestPlainZip(samples, work);
    TestZipWithDirs(samples, work);
    TestNestedRecursion(samples, work);
    TestMp4Steg(samples, work);
    TestNoExtensionZip(samples, work);
    TestDisguisedChain(samples, work);
    TestPasswordFromContext(samples, work);
    TestPasswordInteractive(samples, work);
    TestEncryptedWithoutPassword(samples, work);
    TestMultiVolume(samples, work);
    TestBombProtection(samples, work);
    TestPlainFileKept(samples, work);

    if (g_failures != 0) {
        std::cout << g_failures << " failure(s)\n";
        return 1;
    }
    std::cout << "all sample tests passed\n";
    return 0;
}
