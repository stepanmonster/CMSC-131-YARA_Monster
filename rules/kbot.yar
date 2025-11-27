import "pe"

rule kbot
{
    meta:
        author = "YourName"
        date = "2025-11-27"
        reference = "https://example.com/reference"
        tags = "cryptoshuffler, infostealer, clipboard, token, network"

    strings:
        // Clipboard / registry / process / crypto from first screenshot
        $api1  = "GlobalMemoryStatus" ascii
        $api2  = "SetEnvironmentVariable" ascii
        $api3  = "GetEnvironmentVariable" ascii
        $api4  = "FindFirstFile" ascii
        $api5  = "FindNextFile" ascii
        $api6  = "CopyFile" ascii
        $api7  = "GlobalMemoryStatusEx" ascii
        $api8  = "CreateToolhelp32Snapshot" ascii
        $api9  = "Process32First" ascii
        $api10 = "Process32Next" ascii
        $api11 = "SetDllDirectory" ascii
        $api12 = "RemoveDirectory" ascii
        $api13 = "DeleteFile" ascii
        $api14 = "GetLogicalDriveStrings" ascii
        $api15 = "CreateProcess" ascii
        $api16 = "RegCreateKeyEx" ascii
        $api17 = "AllocateAndInitializeSid" ascii
        $api18 = "LookupAccountSid" ascii
        $api19 = "CreateProcessAsUser" ascii
        $api20 = "CheckTokenMembership" ascii
        $api21 = "RegEnumKey" ascii
        $api22 = "CryptAcquireContext" ascii
        $api23 = "CryptCreateHash" ascii
        $api24 = "CryptHashData" ascii
        $api25 = "CryptGetHashParam" ascii
        $api26 = "CryptDestroyHash" ascii
        $api27 = "CryptReleaseContext" ascii
        $api28 = "EnumDisplayDevices" ascii
        $api29 = "ShellExecuteEx" ascii
        $api30 = "RtlComputeCrc32" ascii
        $api31 = "WTSGetActiveConsoleSessionId" ascii
        $api32 = "WTSQueryUserToken" ascii
        $api33 = "CreateEnvironmentBlock" ascii
        $api34 = "CryptUnprotectData" ascii
        $api35 = "gethostbyname" ascii
        $api36 = "socket" ascii
        $api37 = "send" ascii
        $api38 = "recv" ascii
        $api39 = "htons" ascii
        $api40 = "connect" ascii
        $api41 = "closesocket" ascii
        $api42 = "InternetOpen" ascii
        $api43 = "InternetConnect" ascii
        $api44 = "HttpOpenRequest" ascii
        $api45 = "HttpAddRequestHeaders" ascii
        $api46 = "HttpSendRequest" ascii
        $api47 = "InternetReadFile" ascii
        $api48 = "InternetCrackUrl" ascii
        $api49 = "InternetSetOption" ascii
        $api50 = "VirtualAlloc" ascii
        $api51 = "GetCurrentThreadId" ascii
        $api52 = "WriteFile" ascii
        $api53 = "RaiseException" ascii
        $api54 = "GetKeyboardType" ascii
        $api55 = "FreeSid" ascii
        $api56 = "GetCurrentProcessId" ascii
        $api57 = "GetCurrentProcess" ascii
        $api58 = "SHGetSpecialFolderLocation" ascii
        $api59 = "SHGetPathFromIDList" ascii

        // URLs
        $url1  = "https://dotbit.me/a/" ascii
        $url2  = "http://ip-api.com/json" ascii

    condition:
        uint16(0) == 0x5a4d and
        26 of ($api*) and
        any of ($url*)
}
