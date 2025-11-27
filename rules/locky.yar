import "pe"

rule locky
{
    meta:
        author = "YourName"
        description = "Locky-class ransomware style rule using environment, clipboard, and thread APIs"
        date = "2025-11-27"
        reference = "https://example.com/reference"
        tags = "locky, ransomware, clipboard"

    strings:
        $s1 = "SCardDisconnect" ascii
        $s2 = "SystemFunction036" ascii
        $s3 = "GetProcessWindowStation" ascii
        $s4 = "GetUserObjectInformation" ascii
        $s5 = "GetCurrentThread" ascii
        $s6 = "VirtualAlloc" ascii
        $s7 = "GetEnvironmentStrings" ascii
        $s8 = "OleGetClipboard" ascii
        $s9 = "GetCurrentThreadId" ascii
        $s10 = "WriteFile" ascii
        $s11 = "GetCurrentProcessId" ascii
        $s12 = "GetCurrentProcess" ascii
        $s13 = "RaiseException" ascii
        $s14 = "SetConsoleCtrlHandler" ascii
        $s15 = "SetEnvironmentVariable" ascii

    condition:
        uint16(0) == 0x5a4d and
        all of ($s*)
}
