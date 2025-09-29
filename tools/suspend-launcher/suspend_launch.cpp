// Minimal suspended-process launcher to set DBVM breakpoints before TLS runs
// Build (x64, VS Developer Prompt):
//   cl /nologo /EHsc /W3 /DUNICODE /D_UNICODE tools\suspend-launcher\suspend_launch.cpp /link psapi.lib
// Usage:
//   suspend_launch.exe "C:\\Path\\RobloxPlayerBeta.exe" [args...]
// Notes:
// - Prints PID, TID, main module base, and candidate TLS VA = base + RVA.
// - Default TLS RVA here is 0x0000000000791290 (from your dump). Override via /rva:0xHEX.

#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <tchar.h>
#include <cstdio>
#include <string>

#pragma comment(lib, "psapi.lib")

static ULONGLONG parse_rva_arg(int argc, wchar_t** argv, ULONGLONG defRva)
{
    for (int i = 1; i < argc; ++i)
    {
        if (wcsncmp(argv[i], L"/rva:", 5) == 0 || wcsncmp(argv[i], L"-rva:", 5) == 0)
        {
            const wchar_t* p = argv[i] + 5;
            ULONGLONG v = 0;
            if (swscanf_s(p, L"%llx", &v) == 1)
                return v;
        }
    }
    return defRva;
}

int wmain(int argc, wchar_t** argv)
{
    if (argc < 2)
    {
        wprintf(L"Usage:\n  %s \"C:\\Path\\RobloxPlayerBeta.exe\" [args...] [/rva:0x791290]\n", argv[0]);
        return 1;
    }

    // Default TLS RVA from analysis (adjustable via /rva)
    const ULONGLONG defaultTlsRva = 0x0000000000791290ULL;
    const ULONGLONG tlsRva = parse_rva_arg(argc, argv, defaultTlsRva);

    // Build command line (CreateProcessW can modify buffer; use writable string)
    std::wstring cmd;
    for (int i = 1; i < argc; ++i)
    {
        if (wcsncmp(argv[i], L"/rva:", 5) == 0 || wcsncmp(argv[i], L"-rva:", 5) == 0)
            continue; // skip our flag
        if (!cmd.empty()) cmd.append(L" ");
        // Quote each arg to be safe
        cmd.push_back(L'"');
        cmd.append(argv[i]);
        cmd.push_back(L'"');
    }

    STARTUPINFOW si{};
    PROCESS_INFORMATION pi{};
    si.cb = sizeof(si);

    DWORD flags = CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT;
    BOOL ok = CreateProcessW(
        /*lpApplicationName*/ nullptr,
        /*lpCommandLine   */ cmd.empty() ? nullptr : &cmd[0],
        /*lpProcessAttrs  */ nullptr,
        /*lpThreadAttrs   */ nullptr,
        /*bInheritHandles */ FALSE,
        /*dwCreationFlags */ flags,
        /*lpEnvironment   */ nullptr,
        /*lpCurrentDir    */ nullptr,
        /*lpStartupInfo   */ &si,
        /*lpProcessInfo   */ &pi);

    if (!ok)
    {
        wprintf(L"CreateProcessW failed: %lu\n", GetLastError());
        return 2;
    }

    wprintf(L"[+] Launched suspended. PID=%lu, TID=%lu\n", pi.dwProcessId, pi.dwThreadId);

    // Resume the thread briefly to let modules load, then suspend again
    wprintf(L"[*] Resuming briefly to load modules...\n");
    ResumeThread(pi.hThread);
    Sleep(1000); // Give it time to load DLLs but hopefully not run TLS callbacks
    SuspendThread(pi.hThread);
    wprintf(L"[*] Re-suspended after module load\n");

    // Now enumerate all modules using Toolhelp32Snapshot (more reliable)
    ULONGLONG exeBase = 0;
    ULONGLONG dllBase = 0;

    // Retry a few times if needed
    for (int retry = 0; retry < 5; retry++)
    {
        DWORD exitCode = 0;
        if (GetExitCodeProcess(pi.hProcess, &exitCode) && exitCode != STILL_ACTIVE)
        {
            wprintf(L"[!] Process died! Exit code: %lu\n", exitCode);
            break;
        }
        
        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pi.dwProcessId);
        if (hSnap != INVALID_HANDLE_VALUE)
        {
            MODULEENTRY32W me{};
            me.dwSize = sizeof(me);
            
            if (Module32FirstW(hSnap, &me))
            {
                wprintf(L"[+] Found modules:\n");
                do
                {
                    ULONGLONG base = reinterpret_cast<ULONGLONG>(me.modBaseAddr);
                    wprintf(L"    %s - Base: 0x%016llx (Size: 0x%08lx)\n", me.szModule, base, me.modBaseSize);
                    
                    // Check if this is RobloxPlayerBeta.exe or .dll
                    if (_wcsicmp(me.szModule, L"RobloxPlayerBeta.exe") == 0)
                    {
                        exeBase = base;
                    }
                    else if (_wcsicmp(me.szModule, L"RobloxPlayerBeta.dll") == 0)
                    {
                        dllBase = base;
                    }
                    
                } while (Module32NextW(hSnap, &me));
            }
            
            CloseHandle(hSnap);
            
            if (exeBase || dllBase)
                break;
        }
        else
        {
            wprintf(L"[!] CreateToolhelp32Snapshot failed: error %lu\n", GetLastError());
        }
        
        if (retry < 4)
        {
            wprintf(L"[*] Waiting for modules to load... (retry %d/5)\n", retry + 1);
            Sleep(200);
        }
    }

    wprintf(L"\n");
    
    if (exeBase)
    {
        wprintf(L"[+] RobloxPlayerBeta.exe base: 0x%016llx\n", exeBase);
        wprintf(L"    TLS callback (if in .exe): 0x%016llx\n", exeBase + tlsRva);
    }
    
    if (dllBase)
    {
        ULONGLONG dllTlsVA = dllBase + tlsRva;
        wprintf(L"[+] RobloxPlayerBeta.dll base: 0x%016llx\n", dllBase);
        wprintf(L"[!] HYPERION TLS CALLBACK: 0x%016llx\n", dllTlsVA);
        wprintf(L"    ^ SET YOUR DBVM EXECUTE BREAKPOINT AT THIS ADDRESS ^\n");
    }
    
    if (!exeBase && !dllBase)
    {
        wprintf(L"[!] Could not find RobloxPlayerBeta modules. Check CE manually.\n");
        wprintf(L"    Find RobloxPlayerBeta.dll base and add RVA 0x%llx\n", tlsRva);
    }

    wprintf(L"\nPress ENTER to ResumeThread...\n");
    (void)getchar();

    DWORD rc = ResumeThread(pi.hThread);
    if (rc == (DWORD)-1)
        wprintf(L"[!] ResumeThread failed: %lu\n", GetLastError());
    else
        wprintf(L"[>] Resumed (prev suspend count=%lu).\n", rc);

    // Optional: wait, so console stays open
    wprintf(L"Waiting for process to exit...\n");
    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD exitCode = 0;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    wprintf(L"[=] Process exit code: %lu\n", exitCode);

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return 0;
}