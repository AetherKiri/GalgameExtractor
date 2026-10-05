#include "../third_party/7zip-sdk/CPP/Common/MyInitGuid.h"
#include "../third_party/7zip-sdk/CPP/7zip/Archive/IArchive.h"
#include "../third_party/7zip-sdk/CPP/7zip/ICoder.h"
#include "../third_party/7zip-sdk/CPP/7zip/IStream.h"
#include "../third_party/7zip-sdk/CPP/7zip/IPassword.h"

Z7_DEFINE_GUID(CLSID_CArchiveHandler,
    k_7zip_GUID_Data1,
    k_7zip_GUID_Data2,
    k_7zip_GUID_Data3_Common,
    0x10, 0x00, 0x00, 0x01, 0x10, 0x00, 0x00, 0x00);
