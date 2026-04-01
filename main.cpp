#include <windows.h>

uintptr_t offset = 0x15E0;


using is_password_correct_ptr = bool(*)(const char* password);

bool hk_is_password_correct(const char* password)
{
    MessageBoxW(nullptr, L"HOOKED", L"HOOKED", MB_OK);
    return true;
}

void hook(is_password_correct_ptr target, is_password_correct_ptr hook)
{
    DWORD old_protect;

    VirtualProtect(reinterpret_cast<LPVOID>(target), 12, PAGE_EXECUTE_READWRITE, &old_protect);

    BYTE patch[12];
    patch[0] = 0x48;
    patch[1] = 0xB8;
    *reinterpret_cast<void **>(patch + 2) = reinterpret_cast<LPVOID>(hook);
    patch[10] = 0xFF;
    patch[11] = 0xE0;

    memcpy(reinterpret_cast<LPVOID>(target), patch, 12);
    VirtualProtect(reinterpret_cast<LPVOID>(target), 12, old_protect, &old_protect);
}

DWORD WINAPI init_thread(LPVOID)
{
    auto base =
        reinterpret_cast<uintptr_t>(
            GetModuleHandleW(nullptr)
        );

    auto target =
        reinterpret_cast<is_password_correct_ptr>(
            base + offset
        );

    hook(target, hk_is_password_correct);

    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule,
                      DWORD ul_reason_for_call,
                      LPVOID lpReserved)
{
    switch (ul_reason_for_call) {
        case DLL_PROCESS_ATTACH:
            CreateThread(nullptr, 0, init_thread,
                nullptr, 0, nullptr);
    }
    return TRUE;
}

