import "pe"

rule rekaf_malware
{
    meta:
        author = "YourName"
        date = "2025-11-27"
        reference = "https://example.com/reference"
        tags = "rekaf, malware, token, service, winhttp"

    strings:
        // Previous Rekaf APIs
        $s1  = "GetProcessWindowStation" ascii
        $s2  = "GetUserObjectInformation" ascii
        $s3  = "Process32First" ascii
        $s4  = "Process32Next" ascii
        $s5  = "CreateToolhelp32Snapshot" ascii
        $s6  = "GlobalMemoryStatusEx" ascii
        $s7  = "DeleteFile" ascii
        $s8  = "SetPriorityClass" ascii
        $s9  = "GetCurrentProcess" ascii
        $s10 = "GetCurrentThread" ascii
        $s11 = "OpenProcess" ascii
        $s12 = "CreateProcess" ascii
        $s13 = "GetCurrentProcessId" ascii
        $s14 = "MoveFile" ascii
        $s15 = "MapViewOfFile" ascii
        $s16 = "UnmapViewOfFile" ascii
        $s17 = "MoveFileEx" ascii
        $s18 = "WriteFile" ascii
        $s19 = "CopyFile" ascii
        $s20 = "CreatePipe" ascii
        $s21 = "OpenProcessToken" ascii
        $s22 = "GetTokenInformation" ascii
        $s23 = "LookupAccountSid" ascii
        $s24 = "LookupPrivilegeValue" ascii
        $s25 = "AdjustTokenPrivileges" ascii
        $s26 = "OpenSCManager" ascii
        $s27 = "ChangeServiceConfig2" ascii
        $s28 = "RegSetValueEx" ascii
        $s29 = "CreateService" ascii
        $s30 = "RegCreateKey" ascii
        $s31 = "StartService" ascii
        $s32 = "RegisterServiceCtrlHandler" ascii
        $s33 = "ControlService" ascii
        $s34 = "CreateProcessAsUser" ascii
        $s35 = "DuplicateTokenEx" ascii
        $s36 = "SHChangeNotify" ascii
        $s37 = "ShellExecute" ascii
        $s38 = "PathIsDirectory" ascii
        $s39 = "WinHttpReceiveResponse" ascii
        $s40 = "WinHttpSetTimeouts" ascii
        $s41 = "WinHttpSetOption" ascii
        $s42 = "WinHttpSendRequest" ascii
        $s43 = "WinHttpWriteData" ascii
        $s44 = "WinHttpConnect" ascii
        $s45 = "WinHttpQueryHeaders" ascii
        $s46 = "WinHttpCrackUrl" ascii
        $s47 = "WinHttpSetCredentials" ascii
        $s48 = "WinHttpQueryAuthSchemes" ascii
        $s49 = "DnsFree" ascii
        $s50 = "DnsQuery_" ascii
        $s51 = "LoadUserProfile" ascii
        $s52 = "UnloadUserProfile" ascii
        $s53 = "EnumDeviceDrivers" ascii
        $s54 = "GetCurrentThreadId" ascii
        $s55 = "RaiseException" ascii
        $s56 = "GetEnvironmentStrings" ascii
        $s57 = "SetEnvironmentVariable" ascii
        $s58 = "CreateDirectory" ascii
        $s59 = "RegCreateKeyEx" ascii
        $s60 = "ImpersonateLoggedOnUser" ascii


    condition:
        uint16(0) == 0x5a4d and
        all of ($s*)
}
