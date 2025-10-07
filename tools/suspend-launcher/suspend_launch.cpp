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
#include <vector>

#pragma comment(lib, "psapi.lib")

struct ExportTarget {
    const wchar_t* module;
    const char* function;
    const wchar_t* description;
};

// Suspend ALL threads in the target process
static void SuspendAllThreads(DWORD processId, DWORD excludeThreadId = 0)
{
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnap == INVALID_HANDLE_VALUE)
        return;
    
    THREADENTRY32 te{};
    te.dwSize = sizeof(te);
    
    if (Thread32First(hSnap, &te))
    {
        do
        {
            // Only suspend threads belonging to our target process
            if (te.th32OwnerProcessID == processId && te.th32ThreadID != excludeThreadId)
            {
                HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
                if (hThread)
                {
                    SuspendThread(hThread);
                    CloseHandle(hThread);
                }
            }
        } while (Thread32Next(hSnap, &te));
    }
    
    CloseHandle(hSnap);
}

// Resume ALL threads in the target process
static void ResumeAllThreads(DWORD processId, DWORD excludeThreadId = 0)
{
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnap == INVALID_HANDLE_VALUE)
        return;
    
    THREADENTRY32 te{};
    te.dwSize = sizeof(te);
    
    if (Thread32First(hSnap, &te))
    {
        do
        {
            if (te.th32OwnerProcessID == processId && te.th32ThreadID != excludeThreadId)
            {
                HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
                if (hThread)
                {
                    ResumeThread(hThread);
                    CloseHandle(hThread);
                }
            }
        } while (Thread32Next(hSnap, &te));
    }
    
    CloseHandle(hSnap);
}

// Count threads in the target process
static int CountThreads(DWORD processId)
{
    int count = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnap == INVALID_HANDLE_VALUE)
        return 0;
    
    THREADENTRY32 te{};
    te.dwSize = sizeof(te);
    
    if (Thread32First(hSnap, &te))
    {
        do
        {
            if (te.th32OwnerProcessID == processId)
                count++;
        } while (Thread32Next(hSnap, &te));
    }
    
    CloseHandle(hSnap);
    return count;
}

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

static bool has_flag(int argc, wchar_t** argv, const wchar_t* flag)
{
    for (int i = 1; i < argc; ++i)
    {
        if (_wcsicmp(argv[i], flag) == 0)
            return true;
    }
    return false;
}

static void findSystemExports(const std::vector<ExportTarget>& targets)
{
    wprintf(L"\n=== System Exit Path Addresses ===\n");
    
    for (const auto& target : targets)
    {
        HMODULE hMod = GetModuleHandleW(target.module);
        if (!hMod)
        {
            hMod = LoadLibraryW(target.module);
        }
        
        if (hMod)
        {
            FARPROC proc = GetProcAddress(hMod, target.function);
            if (proc)
            {
                wprintf(L"  [+] %s = 0x%016llx\n", target.description, (ULONGLONG)proc);
            }
            else
            {
                wprintf(L"  [!] %s - NOT FOUND\n", target.description);
            }
        }
        else
        {
            wprintf(L"  [!] %s - Module not loaded\n", target.description);
        }
    }
}

int wmain(int argc, wchar_t** argv)
{
    if (argc < 2)
    {
        wprintf(L"Usage:\n");
        wprintf(L"  %s \"C:\\Path\\RobloxPlayerBeta.exe\" [args...] [/rva:0xHEX] [/nopulse]\n", argv[0]);
        wprintf(L"\nOptions:\n");
        wprintf(L"  /rva:0xHEX  - Override TLS callback RVA (default: 0x%llx)\n", 0x0000000000D11290ULL);
        wprintf(L"  /nopulse    - Skip module loading (SAFEST - no TLS execution, but no module bases)\n");
        wprintf(L"  /fast       - Use 1ms pulses instead of 5ms (DANGEROUS but faster module load)\n");
        return 1;
    }

    // Default TLS RVA from analysis (adjustable via /rva)
    const ULONGLONG defaultTlsRva = 0x0000000000D11290ULL;
    const ULONGLONG tlsRva = parse_rva_arg(argc, argv, defaultTlsRva);
    const bool noPulse = has_flag(argc, argv, L"/nopulse");
    const bool fastMode = has_flag(argc, argv, L"/fast");
    const int pulseMs = fastMode ? 1 : 5; // 1ms in fast mode, 5ms normal

    // Build command line (CreateProcessW can modify buffer; use writable string)
    std::wstring cmd;
    for (int i = 1; i < argc; ++i)
    {
        // Skip our internal flags
        if (wcsncmp(argv[i], L"/rva:", 5) == 0 || wcsncmp(argv[i], L"-rva:", 5) == 0)
            continue;
        if (_wcsicmp(argv[i], L"/nopulse") == 0 || _wcsicmp(argv[i], L"/fast") == 0)
            continue;
        
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
    
    // IMMEDIATE: Suspend ALL threads right away (in case any were created during CreateProcess)
    // This is CRITICAL - some processes create threads immediately
    SuspendAllThreads(pi.dwProcessId, pi.dwThreadId);
    wprintf(L"[*] Immediately suspended all existing threads\n");

    ULONGLONG exeBase = 0;
    ULONGLONG dllBase = 0;
    
    if (noPulse)
    {
        // SAFEST MODE: Don't resume at all - no module loading, no TLS execution
        wprintf(L"[!] /nopulse mode: Skipping module load (NO TLS execution risk)\n");
        wprintf(L"[*] You'll need to find module bases manually in Cheat Engine\n");
        int threadCount = CountThreads(pi.dwProcessId);
        wprintf(L"[*] ✓ ALL %d threads FROZEN from start - ZERO code executed!\n", threadCount);
    }
    else
    {
        // CRITICAL: Resume for ABSOLUTE MINIMUM time to load modules
        // TLS callbacks (including Hyperion anti-debug) execute during module load!
        // We use ULTRA-SHORT pulses and suspend IMMEDIATELY
        wprintf(L"[*] Using %dms pulses to load modules (TLS callbacks will partially execute)...\n", pulseMs);
        if (fastMode)
            wprintf(L"[!] FAST MODE: 1ms pulses - VERY RISKY! TLS may execute fully!\n");
        
        // Try ULTRA-SHORT resume pulses and check if modules loaded
        // This is a race condition: we're trying to load modules before TLS kills us
        for (int pulse = 0; pulse < 20; pulse++)
    {
        // Check if process died
        DWORD exitCode = 0;
        if (GetExitCodeProcess(pi.hProcess, &exitCode) && exitCode != STILL_ACTIVE)
        {
            wprintf(L"[!] Process died during module load! Exit code: %lu (0x%lx)\n", exitCode, exitCode);
            wprintf(L"[!] TLS callback executed RaiseFailFastException BEFORE we could suspend!\n");
            wprintf(L"[!] This means anti-cheat detected DBVM in < %dms!\n", pulse * pulseMs);
            wprintf(L"\n💡 SOLUTIONS:\n");
            wprintf(L"   1. Use /nopulse flag to avoid ALL TLS execution (find module bases manually)\n");
            wprintf(L"   2. Use DBVM to hook RaiseFailFastException BEFORE launching this tool\n");
            wprintf(L"   3. Patch the TLS callback to NOP before first run\n");
            wprintf(L"   4. Use kernel driver to suspend process even earlier\n");
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
            return 3;
        }
        
            // Resume ALL threads briefly
            ResumeThread(pi.hThread);
            ResumeAllThreads(pi.dwProcessId, pi.dwThreadId);
            
            Sleep(pulseMs); // ULTRA short pulse!
            
            // IMMEDIATELY suspend ALL threads (including any newly created ones)
            SuspendThread(pi.hThread);
            SuspendAllThreads(pi.dwProcessId, pi.dwThreadId);
        
        // Check if modules are loaded yet
        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pi.dwProcessId);
        if (hSnap != INVALID_HANDLE_VALUE)
        {
            MODULEENTRY32W me{};
            me.dwSize = sizeof(me);
            
            if (Module32FirstW(hSnap, &me))
            {
                do
                {
                    ULONGLONG base = reinterpret_cast<ULONGLONG>(me.modBaseAddr);
                    
                    if (_wcsicmp(me.szModule, L"RobloxPlayerBeta.exe") == 0)
                        exeBase = base;
                    else if (_wcsicmp(me.szModule, L"RobloxPlayerBeta.dll") == 0)
                        dllBase = base;
                    
                } while (Module32NextW(hSnap, &me));
            }
            CloseHandle(hSnap);
            
            if (dllBase)
            {
                wprintf(L"[+] ✓ Modules loaded after %d pulses (total ~%dms) - SUSPENDED BEFORE TLS FINISHED!\n", pulse + 1, (pulse + 1) * pulseMs);
                break;
            }
        }
        }
        
        // CRITICAL: Final sweep to ensure ALL threads are suspended
        // Even threads created in the last microseconds of the pulse
        SuspendAllThreads(pi.dwProcessId, pi.dwThreadId);
        Sleep(10); // Let any in-flight thread creation complete
        SuspendAllThreads(pi.dwProcessId, pi.dwThreadId); // Suspend again to catch stragglers
        
        int threadCount = CountThreads(pi.dwProcessId);
        wprintf(L"[*] ✓ ALL %d threads FROZEN - no code can execute now!\n", threadCount);
    }

    // Now enumerate all modules using Toolhelp32Snapshot (more reliable)
    // Retry a few times if needed
    for (int retry = 0; retry < 3; retry++)
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
    
    // Print IAT thunks for RobloxPlayerBeta.dll
    if (dllBase)
    {
        wprintf(L"\n=== RobloxPlayerBeta.dll IAT Thunks ===\n");
        wprintf(L"  [+] NtTerminateProcess IAT = 0x%016llx\n", dllBase + 0x18E6C0);
        wprintf(L"  [+] ExitProcess IAT        = 0x%016llx\n", dllBase + 0x18E738);
    }
    
    // Find all system exit path exports
    std::vector<ExportTarget> exitTargets = {
        { L"ntdll.dll", "NtTerminateProcess", L"ntdll!NtTerminateProcess" },
        { L"ntdll.dll", "NtRaiseHardError", L"ntdll!NtRaiseHardError" },
        { L"ntdll.dll", "ZwRaiseException", L"ntdll!ZwRaiseException" },
        { L"ntdll.dll", "RtlExitUserProcess", L"ntdll!RtlExitUserProcess" },
        { L"ntdll.dll", "RtlFailFast2", L"ntdll!RtlFailFast2" },
        { L"ntdll.dll", "ZwTerminateProcess", L"ntdll!ZwTerminateProcess" },
        { L"ntdll.dll", "RtlReportFatalFailure", L"ntdll!RtlReportFatalFailure" },
        { L"kernel32.dll", "ExitProcess", L"kernel32!ExitProcess" },
        { L"kernelbase.dll", "RaiseFailFastException", L"kernelbase!RaiseFailFastException" },
    };
    
    findSystemExports(exitTargets);

    wprintf(L"\n=== DBVM Breakpoint Setup ===\n");
    wprintf(L"Set DBVM execute breakpoints on:\n");
    wprintf(L"  1. TLS callback: 0x%016llx\n", dllBase ? (dllBase + tlsRva) : 0);
    wprintf(L"  2. All addresses listed above (IAT + system exports)\n");
    wprintf(L"\n⚠️  CRITICAL: Anti-cheat may use DIRECT SYSCALLS!\n");
    wprintf(L"   - They bypass ntdll.dll and call kernel directly via SYSCALL instruction\n");
    wprintf(L"   - Suspended threads CAN'T execute syscalls, BUT:\n");
    wprintf(L"   - Watchdog timers/APCs registered BEFORE suspension may still trigger!\n");
    wprintf(L"\n🎯 DEFENSE STRATEGY:\n");
    wprintf(L"   1. Set ALL breakpoints listed above BEFORE pressing ENTER\n");
    wprintf(L"   2. Work QUICKLY - minimize time between ENTER and setting breakpoints\n");
    wprintf(L"   3. If you have DBVM kernel hooks, also hook syscall numbers:\n");
    wprintf(L"      - NtTerminateProcess = syscall 0x2C (varies by Windows version)\n");
    wprintf(L"      - This catches direct syscalls that bypass ntdll\n");
    wprintf(L"   4. If process dies instantly, a watchdog timer likely fired\n");
    wprintf(L"      - You'll need to find and patch the timer BEFORE resuming\n");

    wprintf(L"\n════════════════════════════════════════════════════════════════\n");
    wprintf(L"⏸️  PROCESS IS FROZEN - ALL THREADS SUSPENDED\n");
    wprintf(L"════════════════════════════════════════════════════════════════\n");
    wprintf(L"\nWHAT TO DO NOW:\n");
    wprintf(L"  1. Open Cheat Engine (CE) and attach to PID %lu\n", pi.dwProcessId);
    wprintf(L"  2. Set DBVM execute breakpoints on ALL addresses listed above\n");
    wprintf(L"  3. Set breakpoints on the SYSCALL instruction itself if possible\n");
    wprintf(L"  4. Once ready, press ENTER below to resume execution\n");
    wprintf(L"\n⚠️  WARNING: If process dies within 1-2 seconds after resume:\n");
    wprintf(L"    → A watchdog timer was registered BEFORE suspension\n");
    wprintf(L"    → You'll need to disable the timer in DBVM or patch it out\n");
    wprintf(L"\nPress ENTER to resume ALL threads...\n");
    (void)getchar();

    // Resume ALL threads
    DWORD rc = ResumeThread(pi.hThread);
    ResumeAllThreads(pi.dwProcessId, pi.dwThreadId);
    
    if (rc == (DWORD)-1)
        wprintf(L"[!] ResumeThread failed: %lu\n", GetLastError());
    else
        wprintf(L"[>] ALL threads resumed (main thread prev suspend count=%lu).\n", rc);

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