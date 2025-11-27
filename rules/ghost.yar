import "pe"

rule gh0st
{
    meta:
        author = "YourName"
        description = "Gh0st/Locky-class rule using environment, network, token, and process APIs"
        date = "2025-11-27"
        reference = "https://example.com/reference"
        tags = "gh0st, locky, ransomware, rat"

    strings:
        // Original core set
        $s1  = "VirtualProtect" ascii
        $s2  = "VirtualAlloc" ascii
        $s3  = "SHChangeNotify" ascii
        $s4  = "SHDeleteKey" ascii
        $s5  = "InternetOpen" ascii
        $s6  = "EnumProcessModules" ascii

        // Extended ghost-related group (previous + new screenshot)
        $g1  = "GetCurrentProcess" ascii
        $g2  = "GetEnvironmentStrings" ascii
        $g3  = "GetEnvironmentVariable" ascii
        $g4  = "WriteFile" ascii
        $g5  = "WinExec" ascii
        $g6  = "DeleteFile" ascii
        $g7  = "CreateDirectory" ascii
        $g8  = "Process32Next" ascii
        $g9  = "Process32First" ascii
        $g10 = "CreateToolhelp32Snapshot" ascii
        $g11 = "CreateProcessAsUser" ascii
        $g12 = "AdjustTokenPrivileges" ascii
        $g13 = "GetTokenInformation" ascii
        $g14 = "DuplicateTokenEx" ascii
        $g15 = "LookupPrivilegeValue" ascii
        $g16 = "OpenProcessToken" ascii
        $g17 = "SetSecurityDescriptorDacl" ascii
        $g18 = "RegisterServiceCtrlHandler" ascii
        $g19 = "StartServiceCtrlDispatcher" ascii
        $g20 = "ShellExecute" ascii
        $g21 = "WTSQueryUserToken" ascii
        $g22 = "CreateEnvironmentBlock" ascii
        $g23 = "ImageUnload" ascii
        $g24 = "ImageLoad" ascii
        $g25 = "OpenProcess" ascii
        $g26 = "WriteProcessMemory" ascii
        $g27 = "VirtualProtectEx" ascii
        $g28 = "CreateProcess" ascii
        $g29 = "GetCurrentThread" ascii
        $g30 = "FreeSid" ascii
        $g31 = "AccessCheck" ascii
        $g32 = "IsValidSecurityDescriptor" ascii
        $g33 = "SetSecurityDescriptorOwner" ascii
        $g34 = "SetSecurityDescriptorGroup" ascii
        $g35 = "AddAccessAllowedAce" ascii
        $g36 = "GetLengthSid" ascii
        $g37 = "AllocateAndInitializeSid" ascii
        $g38 = "OpenThreadToken" ascii
        $g39 = "WTSGetActiveConsoleSessionId" ascii
        $g40 = "GetNativeSystemInfo" ascii
        $g41 = "ShellExecuteEx" ascii
        $g42 = "ZwQueryVirtualMemory" ascii

    condition:
        uint16(0) == 0x5a4d and
        (all of ($s1,$s2,$s3,$s4,$s5,$s6) or
         all of ($g1,$g2,$g3,$g4,$g5,$g6,$g7,$g8,$g9,$g10,
               $g11,$g12,$g13,$g14,$g15,$g16,$g17,$g18,$g19,$g20,
               $g21,$g22,$g23,$g24,$g25,$g26,$g27,$g28,$g29,$g30,
               $g31,$g32,$g33,$g34,$g35,$g36,$g37,$g38,$g39,$g40,$g41,$g42))
}
