rule magala
{
    meta:
        author = "YourName"
        description = "Detects malware with Magala-related APIs and URLs (grouped with conditions)"
        date = "2025-11-27"
        tags = "magala, malware, apis, urls"

    strings:
        // Threadpool APIs
        $t1 = "CreateThreadpoolTimer" ascii wide
        $t2 = "WaitForThreadpoolTimerCallbacks" ascii wide
        $t3 = "CloseThreadpoolTimer" ascii wide
        $t4 = "CreateThreadpoolWait" ascii wide
        $t5 = "CreateThreadpoolWork" ascii wide

        // Process and File APIs
        $p1 = "GetCurrentProcessorNumber" ascii wide
        $p2 = "CreateSymbolicLink" ascii wide
        $p3 = "GetFileInformationByHandleEx" ascii wide
        $p4 = "RaiseException" ascii wide
        $p5 = "GetCurrentThreadId" ascii wide
        $p6 = "OpenProcess" ascii wide
        $p7 = "CreateToolhelp32Snapshot" ascii wide
        $p8 = "Process32First" ascii wide
        $p9 = "Process32Next" ascii wide
        $p10 = "CreateProcess" ascii wide
        $p11 = "GetCurrentProcess" ascii wide
        $p12 = "GetCurrentProcessId" ascii wide
        $p13 = "GetModuleHandleEx" ascii wide
        $p14 = "WriteFile" ascii wide
        $p15 = "FindFirstFileEx" ascii wide
        $p16 = "FindNextFile" ascii wide
        $p17 = "GetEnvironmentStrings" ascii wide
        $p18 = "SetEnvironmentVariable" ascii wide

        // Desktop and Window APIs
        $d1 = "EnumDesktopWindows" ascii wide
        $d2 = "OpenDesktop" ascii wide
        $d3 = "GetThreadDesktop" ascii wide
        $d4 = "CreateDesktop" ascii wide

        // Registry and Crypt APIs
        $r1 = "RegCreateKeyEx" ascii wide
        $r2 = "RegSetValueEx" ascii wide
        $r3 = "SHSetValue" ascii wide
        $r4 = "SHDeleteValue" ascii wide
        $r5 = "RefreshPolicy" ascii wide

        $c1 = "CryptGetHashParam" ascii wide
        $c2 = "CryptDestroyHash" ascii wide
        $c3 = "CryptReleaseContext" ascii wide
        $c4 = "CryptHashData" ascii wide
        $c5 = "CryptAcquireContext" ascii wide
        $c6 = "CryptCreateHash" ascii wide

        // HTTP APIs
        $h1 = "WinHttpCheckPlatform" ascii wide
        $h2 = "WinHttpCrackUrl" ascii wide
        $h3 = "WinHttpConnect" ascii wide
        $h4 = "WinHttpSendRequest" ascii wide
        $h5 = "WinHttpAddRequestHeaders" ascii wide
        $h6 = "WinHttpSetTimeouts" ascii wide
        $h7 = "WinHttpReceiveResponse" ascii wide
        $h8 = "WinHttpQueryHeaders" ascii wide

        // Debug API
        $dbg = "OutputDebugString" ascii wide

        // URLs
        $u1 = "http://dfgyw.com/?a=539431&c=1552872&m=32&s1=" ascii wide
        $u2 = "http://www.api-cdn.com/123.txt" ascii wide
        $u3 = "http://www.baidu.com" ascii wide

condition:
(
    (#t1 + #t2 + #t3 + #t4 + #t5) >= 2 and
    (#p1 + #p2 + #p3 + #p4 + #p5 + #p6 + #p7 + #p8 + #p9 + #p10 + #p11 + #p12 + #p13 + #p14 + #p15 + #p16 + #p17 + #p18) >= 5 and
    (#d1 + #d2 + #d3 + #d4) >= 1 and
    ((#r1 + #r2 + #r3 + #r4 + #r5) >= 2 or (#c1 + #c2 + #c3 + #c4 + #c5 + #c6) >= 2) and
    (#h1 + #h2 + #h3 + #h4 + #h5 + #h6 + #h7 + #h8) >= 1 and
    (#u1 + #u2 + #u3) >= 1 and
    (#dbg) >= 1
)

}
