// sevenzip_backend.cpp — 7-Zip SDK glue (port of ffi_bridge.zig).
//
// Entry points consumed from the statically-linked SDK bundle:
//   CreateObject      (CPP/7zip/Archive/DllExports2.cpp)
//   GetNumberOfFormats / GetHandlerProperty2 (CPP/7zip/Archive/ArchiveExports.cpp)
// The SDK's COM emulation layer (CPP/Common/MyWindows.cpp) provides BSTR
// helpers on non-Windows platforms, so this file compiles unchanged on
// Windows, Linux, macOS, iOS and Android.

#include "sevenzip_backend.h"

#include <7zip/Archive/IArchive.h>
#include <7zip/IPassword.h>
#include <7zip/PropID.h>
#include <Common/MyCom.h>
#include <Common/MyWindows.h>
#include <Common/StringConvert.h>
#include <Windows/PropVariant.h>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <filesystem>

namespace hrd {
namespace {

namespace fs = std::filesystem;

// Entry points supplied by the statically linked 7-Zip archive bundle. They
// are the same ABI used by 7z.dll, but no DLL is loaded here.
extern "C" HRESULT CreateObject(const GUID *clsid, const GUID *iid,
                                void **outObject);
extern "C" HRESULT GetNumberOfFormats(UInt32 *numFormats);
extern "C" HRESULT GetHandlerProperty2(UInt32 formatIndex, PROPID propID,
                                        PROPVARIANT *value);

// BSTR is OLECHAR* (wchar_t*) on every platform the SDK supports; UString
// shares that representation, so this conversion is portable.
std::string BstrToUtf8(BSTR bstr) {
    if (bstr == nullptr) return "";
    const UString wide(bstr);
    return UnicodeStringToMultiByte(wide, CP_UTF8).Ptr();
}

bool EqualsNoCase(const std::string &a, const std::string &b) {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i) {
        if (std::tolower(static_cast<unsigned char>(a[i])) !=
            std::tolower(static_cast<unsigned char>(b[i]))) {
            return false;
        }
    }
    return true;
}

std::string Basename(const std::string &path) {
    const size_t slash = path.find_last_of("/\\");
    return slash == std::string::npos ? path : path.substr(slash + 1);
}

// Sanitize an archive-internal path for safe extraction (zip-slip guard):
// strips drive letters, leading slashes, `.`/`..` segments.
bool SafePath(const std::string &raw, fs::path &relative) {
    if (raw.empty()) return false;
    std::string normalized = raw;
    std::replace(normalized.begin(), normalized.end(), '\\', '/');
    const fs::path raw_path = fs::u8path(normalized);
    for (const fs::path &part : raw_path) {
        if (part == "..") return false;
    }
    relative = raw_path.lexically_normal();
    if (relative.empty() || relative.is_absolute() || relative.has_root_name() ||
        relative.has_root_directory()) {
        return false;
    }
    for (const fs::path &part : relative) {
        if (part == ".." || part == ".") return false;
    }
    return true;
}

fs::path Utf8ToPath(const std::string &utf8) { return fs::u8path(utf8); }

std::string PathToUtf8(const fs::path &p) { return p.u8string(); }

UString Utf8ToUString(const std::string &utf8) {
    return MultiByteToUnicodeString(utf8.c_str(), CP_UTF8);
}

BSTR UStringToBstr(const UString &wide) {
    return SysAllocStringLen(wide, static_cast<UINT>(wide.Len()));
}

// ---------------------------------------------------------------------------
// FileInStream — IInStream over a std::FILE
// ---------------------------------------------------------------------------
class FileInStream final : public IInStream, public CMyUnknownImp {
    Z7_IFACES_IMP_UNK_2(IInStream, ISequentialInStream)

public:
    explicit FileInStream(const std::string &path) {
        file_ = std::fopen(path.c_str(), "rb");
        if (file_ != nullptr) {
            std::error_code ec;
            size_ = fs::file_size(fs::u8path(path), ec);
            if (ec) size_ = 0;
        }
    }

    ~FileInStream();

    bool ok() const { return file_ != nullptr; }

private:
    std::FILE *file_ = nullptr;
    uint64_t size_ = 0;
};

Z7_COM7F_IMF(FileInStream::Read(void *data, UInt32 size,
                                UInt32 *processedSize)) {
    if (processedSize != nullptr) *processedSize = 0;
    if (file_ == nullptr || size == 0) return S_OK;
    const size_t n = std::fread(data, 1, size, file_);
    if (processedSize != nullptr) *processedSize = static_cast<UInt32>(n);
    return S_OK;
}

Z7_COM7F_IMF(FileInStream::Seek(Int64 offset, UInt32 seekOrigin,
                                UInt64 *newPosition)) {
    if (file_ == nullptr) return E_FAIL;
    int origin = SEEK_SET;
    switch (seekOrigin) {
        case 0: origin = SEEK_SET; break;  // STREAM_SEEK_SET
        case 1: origin = SEEK_CUR; break;  // STREAM_SEEK_CUR
        case 2: origin = SEEK_END; break;  // STREAM_SEEK_END
        default: return E_INVALIDARG;
    }
#ifdef _WIN32
    if (_fseeki64(file_, offset, origin) != 0) return E_FAIL;
#else
    if (fseeko(file_, static_cast<off_t>(offset), origin) != 0) {
        return E_FAIL;
    }
#endif
    if (newPosition != nullptr) {
#ifdef _WIN32
        *newPosition = static_cast<UInt64>(_ftelli64(file_));
#else
        *newPosition = static_cast<UInt64>(ftello(file_));
#endif
    }
    return S_OK;
}

FileInStream::~FileInStream() {
    if (file_ != nullptr) std::fclose(file_);
}

// ---------------------------------------------------------------------------
// OpenCallback — open + volume resolution + password supply
// ---------------------------------------------------------------------------
class OpenCallback final : public IArchiveOpenCallback,
                           public IArchiveOpenVolumeCallback,
                           public ICryptoGetTextPassword,
                           public CMyUnknownImp {
    Z7_IFACES_IMP_UNK_3(IArchiveOpenCallback, IArchiveOpenVolumeCallback,
                        ICryptoGetTextPassword)

public:
    OpenCallback(const std::string &input_path,
                 const std::vector<std::string> &volumes,
                 const std::string &password)
        : input_path_(input_path), volumes_(volumes), password_(password) {}

    ~OpenCallback();

    bool password_requested() const { return password_requested_; }

private:
    const std::string *FindVolume(const std::string &want_name) const {
        for (const std::string &volume : volumes_) {
            if (volume == want_name) return &volume;
            if (EqualsNoCase(Basename(volume), want_name)) return &volume;
        }
        return nullptr;
    }

    std::string input_path_;
    std::vector<std::string> volumes_;
    std::string password_;
    bool password_requested_ = false;
};

Z7_COM7F_IMF(OpenCallback::SetTotal(const UInt64 *, const UInt64 *)) {
    return S_OK;
}

Z7_COM7F_IMF(OpenCallback::SetCompleted(const UInt64 *, const UInt64 *)) {
    return S_OK;
}

Z7_COM7F_IMF(OpenCallback::GetStream(const wchar_t *name,
                                     IInStream **inStream)) {
    *inStream = nullptr;
    if (name == nullptr) return S_FALSE;
    const std::string want =
        UnicodeStringToMultiByte(UString(name), CP_UTF8).Ptr();
    const std::string *volume = FindVolume(want);
    if (volume == nullptr) return S_FALSE;
    auto *raw = new FileInStream(*volume);
    if (!raw->ok()) {
        // Release through the interface pointer; the macro-generated
        // override on the concrete class is private.
        CMyComPtr<IInStream> dead(static_cast<IInStream *>(raw));
        dead.Release();
        return S_FALSE;
    }
    *inStream = static_cast<IInStream *>(raw);
    return S_OK;
}

Z7_COM7F_IMF(OpenCallback::GetProperty(PROPID propID, PROPVARIANT *value)) {
    NWindows::NCOM::PropVariant_Clear(value);
    if (propID == kpidName) {
        // 7z derives sibling volume names from the archive name.
        value->bstrVal = UStringToBstr(Utf8ToUString(input_path_));
        if (value->bstrVal != nullptr) value->vt = VT_BSTR;
    } else if (propID == kpidSize) {
        value->vt = VT_UI8;
        value->uhVal.QuadPart = 0;
    }
    return S_OK;
}

Z7_COM7F_IMF(OpenCallback::CryptoGetTextPassword(BSTR *password)) {
    *password = nullptr;
    // The handler asking for a password proves the archive headers are
    // encrypted (7z -mhe, rar5 with encrypted names); the engine uses
    // this to separate "needs a password" from "not an archive".
    password_requested_ = true;
    if (password_.empty()) return E_FAIL;
    *password = UStringToBstr(Utf8ToUString(password_));
    if (*password == nullptr) return E_OUTOFMEMORY;
    return S_OK;
}

OpenCallback::~OpenCallback() = default;

// ---------------------------------------------------------------------------
// ExtractStream — ISequentialOutStream writing into a std::FILE
// ---------------------------------------------------------------------------
class ExtractStream final : public ISequentialOutStream, public CMyUnknownImp {
    Z7_IFACES_IMP_UNK_1(ISequentialOutStream)

public:
    ExtractStream(std::FILE *file, uint64_t *total_written,
                  uint64_t bomb_limit, bool *bomb_tripped)
        : file_(file),
          total_written_(total_written),
          bomb_limit_(bomb_limit),
          bomb_tripped_(bomb_tripped) {}

    ~ExtractStream();

private:
    std::FILE *file_;
    uint64_t *total_written_;
    uint64_t bomb_limit_;
    bool *bomb_tripped_;
    uint64_t bytes_ = 0;
};

Z7_COM7F_IMF(ExtractStream::Write(const void *data, UInt32 size,
                                  UInt32 *processedSize)) {
    if (processedSize != nullptr) *processedSize = 0;
    if (bomb_limit_ > 0 &&
        *total_written_ + bytes_ + size > bomb_limit_) {
        *bomb_tripped_ = true;
        return E_FAIL;
    }
    if (size == 0) return S_OK;
    if (file_ == nullptr) return E_FAIL;
    if (std::fwrite(data, 1, size, file_) != size) return E_FAIL;
    bytes_ += size;
    if (processedSize != nullptr) *processedSize = size;
    return S_OK;
}

ExtractStream::~ExtractStream() = default;

// ---------------------------------------------------------------------------
// ExtractCallback — IArchiveExtractCallback + password supply
// ---------------------------------------------------------------------------
class ExtractCallback final : public IArchiveExtractCallback,
                              public ICryptoGetTextPassword,
                              public CMyUnknownImp {
    Z7_IFACES_IMP_UNK_2(IArchiveExtractCallback, ICryptoGetTextPassword)
    Z7_IFACE_COM7_IMP(IProgress)

public:
    ExtractCallback(IInArchive *archive, const std::string &out_dir,
                    const std::string &password, uint64_t bomb_limit)
        : archive_(archive),
          out_dir_(out_dir),
          password_(password),
          bomb_limit_(bomb_limit) {}

    ~ExtractCallback();

    bool wrong_password = false;
    bool data_error = false;
    bool bomb_tripped = false;
    uint64_t total_written = 0;
    uint64_t files_written = 0;

private:
    void CloseFile() {
        if (out_file_ != nullptr) {
            std::fclose(out_file_);
            out_file_ = nullptr;
        }
        out_stream_.Release();
    }

    IInArchive *archive_;
    std::string out_dir_;
    std::string password_;
    uint64_t bomb_limit_;
    std::FILE *out_file_ = nullptr;
    CMyComPtr<ISequentialOutStream> out_stream_;
};

Z7_COM7F_IMF(ExtractCallback::SetTotal(UInt64)) { return S_OK; }
Z7_COM7F_IMF(ExtractCallback::SetCompleted(const UInt64 *)) { return S_OK; }

Z7_COM7F_IMF(ExtractCallback::GetStream(UInt32 index,
                                        ISequentialOutStream **outStream,
                                        Int32 askExtractMode)) {
    *outStream = nullptr;
    CloseFile();
    // Only kExtract mode produces an output stream.
    if (askExtractMode != NArchive::NExtract::NAskMode::kExtract) {
        return S_OK;
    }

    NWindows::NCOM::CPropVariant path_prop;
    if (archive_->GetProperty(index, kpidPath, &path_prop) != S_OK ||
        path_prop.vt != VT_BSTR) {
        return S_OK;
    }
    const std::string raw_path = BstrToUtf8(path_prop.bstrVal);
    fs::path relative;
    if (!SafePath(raw_path, relative)) return E_INVALIDARG;

    NWindows::NCOM::CPropVariant dir_prop;
    if (archive_->GetProperty(index, kpidIsDir, &dir_prop) == S_OK &&
        dir_prop.vt == VT_BOOL && dir_prop.boolVal != VARIANT_FALSE) {
        std::error_code ec;
        fs::create_directories(Utf8ToPath(out_dir_) / relative, ec);
        return S_OK;
    }

    std::error_code ec;
    const fs::path target = Utf8ToPath(out_dir_) / relative;
    fs::create_directories(target.parent_path(), ec);
    out_file_ = std::fopen(PathToUtf8(target).c_str(), "wb");
    if (out_file_ == nullptr) return E_FAIL;
    auto *stream = new ExtractStream(out_file_, &total_written,
                                     bomb_limit_, &bomb_tripped);
    CMyComPtr<ISequentialOutStream> local(
        static_cast<ISequentialOutStream *>(stream));
    out_stream_ = local;
    *outStream = local.Detach();
    return S_OK;
}

Z7_COM7F_IMF(ExtractCallback::PrepareOperation(Int32)) { return S_OK; }

Z7_COM7F_IMF(ExtractCallback::SetOperationResult(Int32 operationResult)) {
    CloseFile();
    files_written += 1;
    const int32_t result = operationResult;
    if (result == NArchive::NExtract::NOperationResult::kOK) return S_OK;
    if (result == NArchive::NExtract::NOperationResult::kWrongPassword) {
        wrong_password = true;
    } else {
        // kDataError, kCrcError, kUnsupportedMethod, kUnexpectedEnd, ...
        data_error = true;
    }
    return S_OK;
}

Z7_COM7F_IMF(ExtractCallback::CryptoGetTextPassword(BSTR *password)) {
    *password = nullptr;
    if (password_.empty()) return E_FAIL;
    *password = UStringToBstr(Utf8ToUString(password_));
    if (*password == nullptr) return E_OUTOFMEMORY;
    return S_OK;
}

ExtractCallback::~ExtractCallback() { CloseFile(); }

}  // namespace

struct ArchiveHandle {
    CMyComPtr<IInArchive> archive;
    CMyComPtr<IInStream> stream;
    uint32_t num_items = 0;
};

bool FindHandlerSig(const std::string &ext_want, const std::string &sig_want,
                    BackendGuid &out_clsid) {
    UInt32 formats = 0;
    if (GetNumberOfFormats(&formats) != S_OK) return false;
    for (UInt32 format = 0; format < formats; ++format) {
        NWindows::NCOM::CPropVariant ext_prop;
        if (GetHandlerProperty2(format, NArchive::NHandlerPropID::kExtension,
                                &ext_prop) != S_OK ||
            ext_prop.vt != VT_BSTR) {
            continue;
        }
        const std::string ext_list = BstrToUtf8(ext_prop.bstrVal);
        bool matched = false;
        size_t start = 0;
        while (start <= ext_list.size()) {
            const size_t end = ext_list.find(' ', start);
            const std::string token = ext_list.substr(
                start,
                end == std::string::npos ? std::string::npos : end - start);
            if (!token.empty() && EqualsNoCase(token, ext_want)) {
                matched = true;
                break;
            }
            if (end == std::string::npos) break;
            start = end + 1;
        }
        if (!matched) continue;

        // Optional disambiguation by handler name (Rar vs Rar5 share the
        // "rar" extension).
        if (!sig_want.empty()) {
            NWindows::NCOM::CPropVariant name_prop;
            if (GetHandlerProperty2(format, NArchive::NHandlerPropID::kName,
                                    &name_prop) != S_OK ||
                name_prop.vt != VT_BSTR) {
                continue;
            }
            const std::string name = BstrToUtf8(name_prop.bstrVal);
            if (!EqualsNoCase(name, sig_want)) continue;
        }

        // kClassID returns the raw 16-byte GUID as a BSTR (not a string).
        NWindows::NCOM::CPropVariant cls_prop;
        if (GetHandlerProperty2(format, NArchive::NHandlerPropID::kClassID,
                                &cls_prop) != S_OK ||
            cls_prop.vt != VT_BSTR) {
            continue;
        }
        const BSTR bstr = cls_prop.bstrVal;
        if (SysStringByteLen(bstr) != sizeof(GUID)) continue;
        std::memcpy(out_clsid.value.data(), bstr, sizeof(GUID));
        return true;
    }
    return false;
}

ArchiveHandle *OpenArchive(const std::string &path, const BackendGuid &clsid,
                           const std::vector<std::string> &volumes,
                           const std::string &password,
                           bool *password_requested) {
    CMyComPtr<IInArchive> archive;
    const GUID *clsid_guid = reinterpret_cast<const GUID *>(&clsid.value);
    if (CreateObject(clsid_guid, &IID_IInArchive,
                     reinterpret_cast<void **>(&archive)) != S_OK) {
        return nullptr;
    }
    auto *raw_stream = new FileInStream(path);
    CMyComPtr<IInStream> stream(static_cast<IInStream *>(raw_stream));
    if (!raw_stream->ok()) {
        stream.Release();  // refcount drops to zero and deletes the object
        return nullptr;
    }
    auto *open_cb = new OpenCallback(path, volumes, password);
    CMyComPtr<IArchiveOpenCallback> open(open_cb);
    if (password_requested != nullptr) *password_requested = false;
    // Only S_OK means fully opened. S_FALSE (partial open / wrong password
    // on encrypted headers) must be treated as failure.
    const HRESULT open_result = archive->Open(stream, nullptr, open);
    if (password_requested != nullptr && open_cb->password_requested()) {
        *password_requested = true;
    }
    if (open_result != S_OK) {
        return nullptr;
    }
    UInt32 num_items = 0;
    if (archive->GetNumberOfItems(&num_items) != S_OK) {
        archive->Close();
        return nullptr;
    }
    auto *handle = new ArchiveHandle;
    handle->archive = archive;
    handle->stream = stream;
    handle->num_items = num_items;
    return handle;
}

void CloseArchive(ArchiveHandle *handle) { delete handle; }

ProbeResult ListEntries(ArchiveHandle *handle) {
    ProbeResult result;
    for (UInt32 index = 0; index < handle->num_items; ++index) {
        ProbeEntry entry;
        entry.index = index;

        NWindows::NCOM::CPropVariant path_prop;
        if (handle->archive->GetProperty(index, kpidPath, &path_prop) == S_OK &&
            path_prop.vt == VT_BSTR) {
            entry.path = BstrToUtf8(path_prop.bstrVal);
        } else {
            entry.path = "unnamed";
        }

        NWindows::NCOM::CPropVariant dir_prop;
        if (handle->archive->GetProperty(index, kpidIsDir, &dir_prop) == S_OK &&
            dir_prop.vt == VT_BOOL) {
            entry.is_dir = dir_prop.boolVal != VARIANT_FALSE;
        }

        NWindows::NCOM::CPropVariant enc_prop;
        if (handle->archive->GetProperty(index, kpidEncrypted, &enc_prop) ==
                S_OK &&
            enc_prop.vt == VT_BOOL) {
            entry.encrypted = enc_prop.boolVal != VARIANT_FALSE;
        }

        NWindows::NCOM::CPropVariant size_prop;
        if (handle->archive->GetProperty(index, kpidSize, &size_prop) == S_OK) {
            if (size_prop.vt == VT_UI8) {
                entry.size = size_prop.uhVal.QuadPart;
            } else if (size_prop.vt == VT_UI4) {
                entry.size = size_prop.ulVal;
            } else if (size_prop.vt == VT_I4) {
                entry.size = size_prop.lVal > 0
                                 ? static_cast<uint64_t>(size_prop.lVal)
                                 : 0;
            }
        }

        if (entry.encrypted) result.any_encrypted = true;
        result.entries.push_back(std::move(entry));
    }
    return result;
}

ExtractOutcome ExtractAll(ArchiveHandle *handle, const std::string &out_dir,
                          uint64_t bomb_limit, const std::string &password) {
    ExtractOutcome outcome;
    std::error_code ec;
    fs::create_directories(fs::u8path(out_dir), ec);

    auto *callback = new ExtractCallback(handle->archive, out_dir, password,
                                         bomb_limit);
    CMyComPtr<IArchiveExtractCallback> extract(callback);
    // indices=null + numItems=(UInt32)-1 => extract ALL items (7-Zip
    // convention).
    const HRESULT hr = handle->archive->Extract(
        nullptr, static_cast<UInt32>(-1), 0, extract);
    outcome.files = callback->files_written;
    outcome.bytes = callback->total_written;
    outcome.wrong_password = callback->wrong_password;
    outcome.data_error = callback->data_error;
    outcome.bomb_tripped = callback->bomb_tripped;
    handle->archive->Close();
    if (hr != S_OK && !outcome.wrong_password && !outcome.data_error &&
        !outcome.bomb_tripped) {
        outcome.data_error = true;
    }
    return outcome;
}

}  // namespace hrd
