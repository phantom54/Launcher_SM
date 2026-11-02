#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>
#include <string.h>

typedef unsigned long long u64;
typedef unsigned char u8;
#define MAX_PATCH_BYTES 5
#define MAX_PATTERN_BYTES 213
#define MAX_EXPECT_VARIANTS 2
#define MAX_AOB_RESULTS 100

struct PatchOffset {
    SSIZE_T offset;
    u8 bytes[MAX_PATCH_BYTES];
    SIZE_T bytes_len;
    u8 expect[MAX_EXPECT_VARIANTS][MAX_PATCH_BYTES];
    SIZE_T expect_len;
    SIZE_T expect_count;
};

struct PatchAOB {
    u8 pattern[MAX_PATTERN_BYTES];
    SIZE_T pattern_len;
    const PatchOffset* writes;
    SIZE_T writes_count;
};

struct Patch {
    u64 offset;
    u8 expect[MAX_PATCH_BYTES];
    SIZE_T expect_len;
    u8 bytes[MAX_PATCH_BYTES];
    SIZE_T bytes_len;
};

struct Version {
    const Patch* patches;
    SIZE_T patch_count;
};

BOOL GetModuleInfo(DWORD pid, const wchar_t* moduleName, u64* base, SIZE_T* size) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap == INVALID_HANDLE_VALUE) return FALSE;
    MODULEENTRY32W me; me.dwSize = sizeof(me);
    BOOL found = FALSE;
    if (Module32FirstW(snap, &me)) {
        do {
            if (_wcsicmp(me.szModule, moduleName) == 0) {
                if (base) *base = (u64)me.modBaseAddr;
                if (size) *size = me.modBaseSize;
                found = TRUE;
                break;
            }
        } while (Module32NextW(snap, &me));
    }
    CloseHandle(snap);
    return found;
}

BOOL ReadAndCompare(HANDLE hProc, u64 addr, const u8* expected, SIZE_T expected_len) {
    if (!expected || expected_len == 0 || expected_len > MAX_PATCH_BYTES) return FALSE;
    u8 buf[MAX_PATCH_BYTES] = { 0 };
    SIZE_T rd = 0;
    if (!ReadProcessMemory(hProc, (LPCVOID)addr, buf, expected_len, &rd)) return FALSE;
    if (rd != expected_len) return FALSE;
    for (SIZE_T i = 0; i < expected_len; ++i) if (buf[i] != expected[i]) return FALSE;
    return TRUE;
}

BOOL WriteBytes(HANDLE hProc, u64 addr, const u8* data, SIZE_T data_len) {
    if (!data || data_len == 0) return FALSE;
    DWORD oldProt = 0;
    if (!VirtualProtectEx(hProc, (LPVOID)addr, data_len, PAGE_EXECUTE_READWRITE, &oldProt))
        return FALSE;
    SIZE_T written = 0;
    BOOL ok = WriteProcessMemory(hProc, (LPVOID)addr, data, data_len, &written);
    VirtualProtectEx(hProc, (LPVOID)addr, data_len, oldProt, &oldProt);
    return ok && written == data_len;
}

BOOL PatchDirectAddresses(HANDLE hProc, u64 moduleBase, const Version* ver) {
    if (!ver) return FALSE;
    BOOL allAlreadyApplied = TRUE;
    for (SIZE_T i = 0; i < ver->patch_count; ++i) {
        const Patch* p = &ver->patches[i];
        if (p->bytes_len == 0 || !ReadAndCompare(hProc, moduleBase + p->offset, p->bytes, p->bytes_len)) {
            allAlreadyApplied = FALSE;
            break;
        }
    }
    if (allAlreadyApplied) return TRUE;

    for (SIZE_T i = 0; i < ver->patch_count; ++i) {
        const Patch* p = &ver->patches[i];
        if (p->expect_len == 0 || !ReadAndCompare(hProc, moduleBase + p->offset, p->expect, p->expect_len)) return FALSE;
    }

    for (SIZE_T i = 0; i < ver->patch_count; ++i) {
        const Patch* p = &ver->patches[i];
        if (!WriteBytes(hProc, moduleBase + p->offset, p->bytes, p->bytes_len)) return FALSE;
    }
    return TRUE;
}

struct AOBResults {
    u64* results;
    SIZE_T count;
};

AOBResults AOBScanBuffer(const u8* buffer, SIZE_T size, u64 base, const u8* pattern, SIZE_T pattern_len) {
    AOBResults results = {0};
    if (!buffer || size < pattern_len || pattern_len == 0 || pattern_len > MAX_PATTERN_BYTES) return results;

    SIZE_T cap = 4;
    results.results = (u64*)LocalAlloc(LPTR, cap * sizeof(u64));
    if (!results.results) return results;

    const u8* bufEnd = buffer + size;
    const u8* lastStart = bufEnd - pattern_len;
    const u8 first = pattern[0];
    const u8* p = buffer;

    while (p <= lastStart) {
        const u8* hit = (const u8*)memchr(p, first, (SIZE_T)(lastStart - p) + 1);
        if (!hit) break;

        BOOL match = TRUE;
        for (SIZE_T j = 1; j < pattern_len; j++) {
            if (pattern[j] != 0xCC && hit[j] != pattern[j]) { match = FALSE; break; }
        }
        if (match) {
            if (results.count == cap) {
                if (cap >= MAX_AOB_RESULTS) break;
                SIZE_T newCap = cap * 2;
                if (newCap > MAX_AOB_RESULTS) newCap = MAX_AOB_RESULTS;
                u64* grown = (u64*)LocalAlloc(LPTR, newCap * sizeof(u64));
                if (!grown) break;
                RtlCopyMemory(grown, results.results, results.count * sizeof(u64));
                LocalFree(results.results);
                results.results = grown;
                cap = newCap;
            }
            results.results[results.count++] = base + (u64)(hit - buffer);
        }
        p = hit + 1;
    }

    if (results.count == 0) { LocalFree(results.results); results.results = NULL; }
    return results;
}

void FreeAOBResults(AOBResults* results) {
    if (results && results->results) {
        LocalFree(results->results);
        results->results = NULL;
        results->count = 0;
    }
}

static void ToggleProcessThreads(HANDLE hProcess, BOOL suspend) {
    DWORD pid = GetProcessId(hProcess);
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return;
    THREADENTRY32 te; te.dwSize = sizeof(te);
    if (Thread32First(hSnap, &te)) {
        do {
            if (te.th32OwnerProcessID == pid) {
                HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
                if (hThread) {
                    if (suspend) SuspendThread(hThread);
                    else ResumeThread(hThread);
                    CloseHandle(hThread);
                }
            }
        } while (Thread32Next(hSnap, &te));
    }
    CloseHandle(hSnap);
}

void SuspendProcess(HANDLE hProcess) { ToggleProcessThreads(hProcess, TRUE); }
void ResumeProcess(HANDLE hProcess)  { ToggleProcessThreads(hProcess, FALSE); }

static const PatchOffset patch1_writes[] = {
    { 0xA6,   {0x48,0xE9}, 2, {{0x0F,0x84}, {0x48,0xE9}}, 2, 2 },
    { -0x80,  {0x48,0xE9}, 2, {{0x0F,0x84}, {0x48,0xE9}}, 2, 2 }
};

static const PatchOffset patch2_writes[] = {
    { 0xA, {0xEB}, 1, {{0x74}, {0xEB}}, 1, 2 } //save/load (in game)
};

static const PatchOffset patch3_writes[] = {
    { 0x1A,   {0xE9,0x25,0x00,0x00,0x00}, 5, {{0xE8}, {0xE9}}, 1, 2 }, //load (in game)
    { -0x357, {0xE9,0x1E,0x03,0x00,0x00}, 5, {{0xE8}, {0xE9}}, 1, 2 }  //load (in game) system.smg
};

static const PatchAOB aob_patches[] = {
    {
       {0xE8, 0xCC, 0xCC, 0xCC, 0xCC, 0x45, 0x33, 0xC0, 0xBA, 0x03, 0x00, 0x00, 0x00, 0x48, 0x8B, 0xC8, 0xE8, 0xCC, 0xCC, 0xCC, 0xCC, 0x41, 0xB1, 0x01, 0x48, 0x89, 0x74, 0x24, 0x20, 0x45,
        0x33, 0xC0, 0x48, 0x8B, 0xD0, 0x48, 0x8B, 0xCB, 0x4C, 0x8B, 0xF0, 0xE8, 0xCC, 0xCC, 0xCC, 0xCC, 0x48, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0x48, 0x8B, 0xD8, 0x48, 0x85, 0xC0, 0x75,
        0xCC, 0x48, 0x8B, 0xDE, 0xEB, 0xCC, 0x4C, 0x8B, 0x00, 0x0F, 0xB6, 0x82, 0x30, 0x01, 0x00, 0x00, 0x41, 0x38, 0x80, 0x30, 0x01, 0x00, 0x00, 0x0F, 0x82, 0xCC, 0xCC, 0xCC, 0xCC, 0x0F,
        0xB6, 0xC8, 0x49, 0x8B, 0x80, 0xC8, 0x00, 0x00, 0x00, 0x48, 0x39, 0x54, 0xC8, 0xF8, 0x0F, 0x85, 0xCC, 0xCC, 0xCC, 0xCC, 0x4D, 0x85, 0xF6, 0x0F, 0x84, 0xCC, 0xCC, 0xCC, 0xCC, 0x49,
        0x8B, 0x16, 0x49, 0x8B, 0xCE, 0x48, 0x8B, 0x82, 0x58, 0x02, 0x00, 0x00, 0x48, 0x8B, 0x92, 0x60, 0x02, 0x00, 0x00, 0xFF, 0xD0, 0x48, 0x85, 0xDB, 0x0F, 0x84, 0xCC, 0xCC, 0xCC, 0xCC,
        0x8B, 0x43, 0x10, 0x89, 0x47, 0x60, 0x8B, 0x47, 0x5C, 0x48, 0x8B, 0x4F, 0x78, 0x39, 0x47, 0x60, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0x48, 0x85, 0xC9, 0x0F, 0x84, 0xCC, 0xCC, 0xCC,
        0xCC, 0x45, 0x33, 0xC0, 0x33, 0xD2, 0xE8, 0xCC, 0xCC, 0xCC, 0x02, 0x48, 0x8B, 0x8F, 0x88, 0x00, 0x00, 0x00, 0x48, 0x85, 0xC9, 0x0F, 0x84, 0xCC, 0xCC, 0xCC, 0xCC, 0x45, 0x33, 0xC0,
        0xB2, 0x01, 0xE8},
        213,
        patch1_writes,
        sizeof(patch1_writes) / sizeof(patch1_writes[0])
    },
    {
       {0x8B, 0x43, 0x54, 0x48, 0x8B, 0x4B, 0x28, 0x39, 0x43, 0x50, 0xCC, 0x7A, 0x48, 0x85, 0xC9, 0x0F, 0x84, 0xD0, 0x03, 0x00, 0x00, 0x45, 0x33, 0xC0, 0x33, 0xD2, 0xE8, 0xCC, 0xCC, 0xCC,
        0x03, 0x48, 0x8B, 0x4B, 0x30, 0x48, 0x85, 0xC9, 0x0F, 0x84, 0xB9, 0x03, 0x00, 0x00, 0x45, 0x33, 0xC0, 0xB2, 0x01, 0xE8, 0xCC, 0xCC, 0xCC, 0x03, 0x48, 0x8B, 0x4B, 0x38, 0x48, 0x85,
        0xC9, 0x0F, 0x84, 0xA2, 0x03, 0x00, 0x00, 0x45, 0x33, 0xC0, 0x33, 0xD2, 0xE8, 0xCC, 0xCC, 0xCC, 0x03, 0x48, 0x8B, 0x4B, 0x40, 0x48, 0x85, 0xC9, 0x0F, 0x84, 0x8B, 0x03, 0x00, 0x00,
        0x45, 0x33, 0xC0, 0xB2, 0x01},
        95,
        patch2_writes,
        sizeof(patch2_writes) / sizeof(patch2_writes[0])
    },
    {
        {0x33, 0xC9, 0xE8, 0xCC, 0xCC, 0xCC, 0xFF, 0x45, 0x33, 0xC0, 0x48, 0x8B, 0xD0, 0x48, 0x8B, 0xCF, 0xE8, 0xCC, 0xCC, 0xCC, 0x01, 0x33, 0xD2, 0x48, 0x8B, 0xC8, 0xCC, 0xCC, 0xCC, 0xCC,
         0xCC, 0x84, 0xC0, 0x0F, 0x84, 0xF2, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x05, 0xCC, 0xCC, 0xCC, 0x03},
        46,
        patch3_writes,
        sizeof(patch3_writes) / sizeof(patch3_writes[0])
    }
};

static const SIZE_T aob_patches_count = sizeof(aob_patches) / sizeof(aob_patches[0]);

void FallbackAOB(HANDLE hProc, u64 moduleBase, SIZE_T moduleSize) {
    if (!moduleSize) return;
    SuspendProcess(hProc);

    u8* buffer = (u8*)LocalAlloc(LMEM_FIXED, moduleSize);
    if (buffer) {
        SIZE_T bytesRead = 0;
        if (ReadProcessMemory(hProc, (LPCVOID)moduleBase, buffer, moduleSize, &bytesRead)
            && bytesRead >= MAX_PATTERN_BYTES) {
            for (SIZE_T i = 0; i < aob_patches_count; i++) {
                const PatchAOB* patch = &aob_patches[i];
                AOBResults results = AOBScanBuffer(buffer, bytesRead, moduleBase, patch->pattern, patch->pattern_len);

                if (results.count == 0) {
                    FreeAOBResults(&results);
                    continue;
                }

                for (SIZE_T j = 0; j < results.count; j++) {
                    u64 addr = results.results[j];

                    for (SIZE_T k = 0; k < patch->writes_count; k++) {
                        const PatchOffset* w = &patch->writes[k];
                        BOOL shouldPatch = FALSE;

                        if (w->expect_count == 0) {
                            shouldPatch = TRUE;
                        } else {
                            for (SIZE_T m = 0; m < w->expect_count; m++) {
                                if (w->expect_len == 0) { shouldPatch = TRUE; break; }
                                if (ReadAndCompare(hProc, addr + w->offset, w->expect[m], w->expect_len)) {
                                    shouldPatch = TRUE;
                                    break;
                                }
                            }
                        }

                        if (shouldPatch && w->bytes_len > 0) {
                            WriteBytes(hProc, addr + w->offset, w->bytes, w->bytes_len);
                        }
                    }
                }

                FreeAOBResults(&results);
            }
        }
        LocalFree(buffer);
    }

    ResumeProcess(hProc);
}

static const Patch patches_v30_0[] = {
    { 0x11F008DULL, {0x0F,0x84}, 2, {0x48,0xE9}, 2 },
    { 0x11EFF5BULL, {0x0F,0x84}, 2, {0x48,0xE9}, 2 },
    { 0x19DF22DULL, {0x74}, 1, {0xEB}, 1 }
};

static const Patch patches_v30_1[] = {
    { 0x120979BULL, {0x0F,0x84}, 2, {0x48,0xE9}, 2 },
    { 0x120967AULL, {0x0F,0x84}, 2, {0x48,0xE9}, 2 },
    { 0x63E93DULL,  {0x74}, 1, {0xEB}, 1 },
    { 0x134AE79ULL, {0xE8,0x22,0x0F,0xE0,0x01}, 5, {0xE9,0x25,0x00,0x00,0x00}, 5 },
    { 0x134AB07ULL, {0xE8,0x94,0x12,0xE0,0x01}, 5, {0xE9,0x1E,0x03,0x00,0x00}, 5 }
};

static const Patch patches_v30_2[] = {
    { 0x13D34A0ULL, {0x0F,0x84}, 2, {0x48,0xE9}, 2 },
    { 0x13D337AULL, {0x0F,0x84}, 2, {0x48,0xE9}, 2 },
    { 0x6931F4ULL,  {0x74}, 1, {0xEB}, 1 },
    { 0x14B15BEULL, {0xE8,0xED,0xB1,0xCD,0x01}, 5, {0xE9,0x25,0x00,0x00,0x00}, 5 },
    { 0x14B124DULL, {0xE8,0x5E,0xB5,0xCD,0x01}, 5, {0xE9,0x1E,0x03,0x00,0x00}, 5 }
};

static const Patch patches_v31_0[] = {
    { 0x15591F0ULL, {0x0F,0x84}, 2, {0x48,0xE9}, 2 },
    { 0x15590CAULL, {0x0F,0x84}, 2, {0x48,0xE9}, 2 },
    { 0x796164ULL,  {0x74}, 1, {0xEB}, 1 },
    { 0x1617EFEULL, {0xE8,0x5D,0x18,0xC5,0x01}, 5, {0xE9,0x25,0x00,0x00,0x00}, 5 },
    { 0x1617B8DULL, {0xE8,0xCE,0x1B,0xC5,0x01}, 5, {0xE9,0x1E,0x03,0x00,0x00}, 5 }
};

static const Patch patches_v31_1[] = {
    { 0x1462D90ULL, {0x0F,0x84}, 2, {0x48,0xE9}, 2 },
    { 0x1462C6AULL, {0x0F,0x84}, 2, {0x48,0xE9}, 2 },
    { 0x6F9BE4ULL,  {0x74}, 1, {0xEB}, 1 },
    { 0x153D86EULL, {0xE8,0x1D,0x7A,0xD6,0x01}, 5, {0xE9,0x25,0x00,0x00,0x00}, 5 },
    { 0x153D4FDULL, {0xE8,0x8E,0x7D,0xD6,0x01}, 5, {0xE9,0x1E,0x03,0x00,0x00}, 5 }
};

static const Patch patches_v32_0[] = {
    { 0x1590280ULL, {0x0F,0x84}, 2, {0x48,0xE9}, 2 },
    { 0x159015AULL, {0x0F,0x84}, 2, {0x48,0xE9}, 2 },
    { 0x6E3E74ULL,  {0x74}, 1, {0xEB}, 1 },
    { 0x160C9CEULL, {0xE8,0x8D,0x3D,0xD8,0x01}, 5, {0xE9,0x25,0x00,0x00,0x00}, 5 },
    { 0x160C65DULL, {0xE8,0xFE,0x40,0xD8,0x01}, 5, {0xE9,0x1E,0x03,0x00,0x00}, 5 }
};

static const Patch patches_v32_1[] = {
    { 0x15AC0C0ULL, {0x0F,0x84}, 2, {0x48,0xE9}, 2 },
    { 0x15ABF9AULL, {0x0F,0x84}, 2, {0x48,0xE9}, 2 },
    { 0x7B7AF4ULL,  {0x74}, 1, {0xEB}, 1 },
    { 0x16BF21EULL, {0xE8,0xCD,0x17,0xCE,0x01}, 5, {0xE9,0x25,0x00,0x00,0x00}, 5 },
    { 0x16BEEADULL, {0xE8,0x3E,0x1B,0xCE,0x01}, 5, {0xE9,0x1E,0x03,0x00,0x00}, 5 }
};

static const Patch patches_v33_0[] = {
    { 0x1772F10ULL, {0x0F,0x84}, 2, {0x48,0xE9}, 2 },
    { 0x1772DEAULL, {0x0F,0x84}, 2, {0x48,0xE9}, 2 },
    { 0x8AD0D4ULL,  {0x74}, 1, {0xEB}, 1 },
    { 0x17935DEULL, {0xE8,0x4D,0xA7,0xC5,0x01}, 5, {0xE9,0x25,0x00,0x00,0x00}, 5 },
    { 0x179326DULL, {0xE8,0xBE,0xAA,0xC5,0x01}, 5, {0xE9,0x1E,0x03,0x00,0x00}, 5 }
};

static const Patch patches_v33_1[] = {
    { 0x175F480ULL, {0x0F,0x84}, 2, {0x48,0xE9}, 2 },
    { 0x175F35AULL, {0x0F,0x84}, 2, {0x48,0xE9}, 2 },
    { 0x831D64ULL,  {0x74}, 1, {0xEB}, 1 },
    { 0x1822DEEULL, {0xE8,0xDD,0xC3,0xC6,0x01}, 5, {0xE9,0x25,0x00,0x00,0x00}, 5 },
    { 0x1822A7DULL, {0xE8,0x4E,0xC7,0xC6,0x01}, 5, {0xE9,0x1E,0x03,0x00,0x00}, 5 }
};

static const Patch patches_v34_0[] = {
    { 0x1712E10ULL, {0x0F,0x84}, 2, {0x48,0xE9}, 2 },
    { 0x1712CEAULL, {0x0F,0x84}, 2, {0x48,0xE9}, 2 },
    { 0x83A424ULL,  {0x74}, 1, {0xEB}, 1 },
    { 0x17999AEULL, {0xE8,0xED,0x28,0xCA,0x01}, 5, {0xE9,0x25,0x00,0x00,0x00}, 5 },
    { 0x179963DULL, {0xE8,0x5E,0x2C,0xCA,0x01}, 5, {0xE9,0x1E,0x03,0x00,0x00}, 5 }
};

static const Patch patches_v34_1[] = {
    { 0x185A190ULL, {0x0F,0x84}, 2, {0x48,0xE9}, 2 },
    { 0x185A06AULL, {0x0F,0x84}, 2, {0x48,0xE9}, 2 },
    { 0x824CF4ULL,  {0x74}, 1, {0xEB}, 1 },
    { 0x181CE7EULL, {0xE8,0xCD,0xDB,0xCE,0x01}, 5, {0xE9,0x25,0x00,0x00,0x00}, 5 },
    { 0x181CB0DULL, {0xE8,0x3E,0xDF,0xCE,0x01}, 5, {0xE9,0x1E,0x03,0x00,0x00}, 5 }
};

static const Patch patches_v35_0[] = {
    { 0x1867B70ULL, {0x0F,0x84}, 2, {0x48,0xE9}, 2 },
    { 0x1867A4AULL, {0x0F,0x84}, 2, {0x48,0xE9}, 2 },
    { 0x92BC44ULL,  {0x74}, 1, {0xEB}, 1 },
    { 0x198336EULL, {0xE8,0x2D,0x81,0xC2,0x01}, 5, {0xE9,0x25,0x00,0x00,0x00}, 5 },
    { 0x1982FFDULL, {0xE8,0x9E,0x84,0xC2,0x01}, 5, {0xE9,0x1E,0x03,0x00,0x00}, 5 }
};

static const Patch patches_v35_1[] = {
    { 0x181DA90ULL, {0x0F,0x84}, 2, {0x48,0xE9}, 2 },
    { 0x181D96AULL, {0x0F,0x84}, 2, {0x48,0xE9}, 2 },
    { 0x9DDB94ULL,  {0x74}, 1, {0xEB}, 1 },
    { 0x192AC8EULL, {0xE8,0x1D,0x55,0xC6,0x01}, 5, {0xE9,0x25,0x00,0x00,0x00}, 5 },
    { 0x192A91DULL, {0xE8,0x8E,0x58,0xC6,0x01}, 5, {0xE9,0x1E,0x03,0x00,0x00}, 5 }
};

static const Patch patches_v36_0[] = {
    { 0x16D1A50ULL, {0x0F,0x84}, 2, {0x48,0xE9}, 2 },
    { 0x16D192AULL, {0x0F,0x84}, 2, {0x48,0xE9}, 2 },
    { 0x8AC9F4ULL,  {0x74}, 1, {0xEB}, 1 },
    { 0x17BC65EULL, {0xE8,0x8D,0xE2,0xB8,0x01}, 5, {0xE9,0x25,0x00,0x00,0x00}, 5 },
    { 0x17BC2EDULL, {0xE8,0xFE,0xE5,0xB8,0x01}, 5, {0xE9,0x1E,0x03,0x00,0x00}, 5 }
};

static const Patch patches_v36_1[] = {
    { 0x1784A60ULL, {0x0F,0x84}, 2, {0x48,0xE9}, 2 },
    { 0x178493AULL, {0x0F,0x84}, 2, {0x48,0xE9}, 2 },
    { 0x957AB4ULL,  {0x74}, 1, {0xEB}, 1 },
    { 0x18475FEULL, {0xE8,0x2D,0x5E,0xBF,0x01}, 5, {0xE9,0x25,0x00,0x00,0x00}, 5 },
    { 0x184728DULL, {0xE8,0x9E,0x61,0xBF,0x01}, 5, {0xE9,0x1E,0x03,0x00,0x00}, 5 }
};

static const Patch patches_v37_0[] = {
    { 0x1802800ULL, {0x0F,0x84}, 2, {0x48,0xE9}, 2 },
    { 0x18026DAULL, {0x0F,0x84}, 2, {0x48,0xE9}, 2 },
    { 0x988924ULL,  {0x74}, 1, {0xEB}, 1 },
    { 0x18CEB3EULL, {0xE8,0x4D,0xA3,0xC8,0x01}, 5, {0xE9,0x25,0x00,0x00,0x00}, 5 },
    { 0x18CE7CDULL, {0xE8,0xBE,0xA6,0xC8,0x01}, 5, {0xE9,0x1E,0x03,0x00,0x00}, 5 }
};

static const Patch patches_v37_1[] = {
    { 0x17C07A0ULL, {0x0F,0x84}, 2, {0x48,0xE9}, 2 },
    { 0x17C067AULL, {0x0F,0x84}, 2, {0x48,0xE9}, 2 },
    { 0x8CFDA4ULL,  {0x74}, 1, {0xEB}, 1 },
    { 0x184AD7EULL, {0xE8,0xED,0xF8,0xB9,0x01}, 5, {0xE9,0x25,0x00,0x00,0x00}, 5 },
    { 0x184AA0DULL, {0xE8,0x5E,0xFC,0xB9,0x01}, 5, {0xE9,0x1E,0x03,0x00,0x00}, 5 }
};

static const Patch patches_v38_0[] = {
    { 0x182A880ULL, {0x0F,0x84}, 2, {0x48,0xE9}, 2 },
    { 0x182A75AULL, {0x0F,0x84}, 2, {0x48,0xE9}, 2 },
    { 0x947B74ULL,  {0x74}, 1, {0xEB}, 1 },
    { 0x184319EULL, {0xE8,0x1D,0xF8,0xCB,0x01}, 5, {0xE9,0x25,0x00,0x00,0x00}, 5 },
    { 0x1842E2DULL, {0xE8,0x8E,0xFB,0xCB,0x01}, 5, {0xE9,0x1E,0x03,0x00,0x00}, 5 }
};

static const Patch patches_v38_1[] = {
    { 0x185BD30ULL, {0x0F,0x84}, 2, {0x48,0xE9}, 2 },
    { 0x185BC0AULL, {0x0F,0x84}, 2, {0x48,0xE9}, 2 },
    { 0x9B99D4ULL,  {0x74}, 1, {0xEB}, 1 },
    { 0x194E78EULL, {0xE8,0x4D,0xF1,0xAE,0x01}, 5, {0xE9,0x25,0x00,0x00,0x00}, 5 },
    { 0x194E41DULL, {0xE8,0xBE,0xF4,0xAE,0x01}, 5, {0xE9,0x1E,0x03,0x00,0x00}, 5 }
};

static const Patch patches_v39_0[] = {
    { 0x1800B60ULL, {0x0F,0x84}, 2, {0x48,0xE9}, 2 },
    { 0x1800A3AULL, {0x0F,0x84}, 2, {0x48,0xE9}, 2 },
    { 0x8D0F24ULL,  {0x74}, 1, {0xEB}, 1 },
    { 0x18D9FCEULL, {0xE8,0x1D,0x6E,0xC5,0x01}, 5, {0xE9,0x25,0x00,0x00,0x00}, 5 },
    { 0x18D9C5DULL, {0xE8,0x8E,0x71,0xC5,0x01}, 5, {0xE9,0x1E,0x03,0x00,0x00}, 5 }
};

static const Version versions[] = {
    { patches_v30_0, sizeof(patches_v30_0) / sizeof(patches_v30_0[0]) },
    { patches_v30_1, sizeof(patches_v30_1) / sizeof(patches_v30_1[0]) },
    { patches_v30_2, sizeof(patches_v30_2) / sizeof(patches_v30_2[0]) },
    { patches_v31_0, sizeof(patches_v31_0) / sizeof(patches_v31_0[0]) },
    { patches_v31_1, sizeof(patches_v31_1) / sizeof(patches_v31_1[0]) },
    { patches_v32_0, sizeof(patches_v32_0) / sizeof(patches_v32_0[0]) },
    { patches_v32_1, sizeof(patches_v32_1) / sizeof(patches_v32_1[0]) },
    { patches_v33_0, sizeof(patches_v33_0) / sizeof(patches_v33_0[0]) },
    { patches_v33_1, sizeof(patches_v33_1) / sizeof(patches_v33_1[0]) },
    { patches_v34_0, sizeof(patches_v34_0) / sizeof(patches_v34_0[0]) },
    { patches_v34_1, sizeof(patches_v34_1) / sizeof(patches_v34_1[0]) },
    { patches_v35_0, sizeof(patches_v35_0) / sizeof(patches_v35_0[0]) },
    { patches_v35_1, sizeof(patches_v35_1) / sizeof(patches_v35_1[0]) },
    { patches_v36_0, sizeof(patches_v36_0) / sizeof(patches_v36_0[0]) },
    { patches_v36_1, sizeof(patches_v36_1) / sizeof(patches_v36_1[0]) },
    { patches_v37_0, sizeof(patches_v37_0) / sizeof(patches_v37_0[0]) },
    { patches_v37_1, sizeof(patches_v37_1) / sizeof(patches_v37_1[0]) },
    { patches_v38_0, sizeof(patches_v38_0) / sizeof(patches_v38_0[0]) },
    { patches_v38_1, sizeof(patches_v38_1) / sizeof(patches_v38_1[0]) },
    { patches_v39_0, sizeof(patches_v39_0) / sizeof(patches_v39_0[0]) }
};

static const SIZE_T versions_count = sizeof(versions) / sizeof(versions[0]);

int WINAPI wWinMain(_In_ HINSTANCE hInstance, _In_opt_ HINSTANCE hPrevInstance, _In_ PWSTR lpCmdLine, _In_ int nShowCmd) {
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = {};
    if (!CreateProcessW(L"Seaside Mystery.exe", NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        MessageBoxA(NULL, "Failed to start Seaside Mystery.exe", "Launcher", MB_OK | MB_ICONERROR);
        return 1;
    }

    DWORD pid = GetProcessId(pi.hProcess);

    u64 base = 0;
    SIZE_T moduleSize = 0;
    int waited = 0;
    const int maxWait = 30000, step = 250;
    while (waited < maxWait) {
        if (WaitForSingleObject(pi.hProcess, 0) == WAIT_OBJECT_0) break;
        if (GetModuleInfo(pid, L"GameAssembly.dll", &base, &moduleSize)) break;
        Sleep(step); waited += step;
    }
    if (!base) { CloseHandle(pi.hProcess); CloseHandle(pi.hThread); return 0; }

    HANDLE hProc = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProc) {
        MessageBoxA(NULL, "Failed to open game process", "Launcher", MB_OK | MB_ICONERROR);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return 0;
    }

    BOOL applied = FALSE;
    for (SIZE_T i = 0; i < versions_count; ++i) {
        if (PatchDirectAddresses(hProc, base, &versions[i])) { applied = TRUE; break; }
    }

    if (!applied) {
        FallbackAOB(hProc, base, moduleSize);
    }

    CloseHandle(hProc);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return 0;
}
