import "pe"

rule fallchill_malware
{
    meta:
        author = "YourName"
        description = "Fallchill sample: tuned strict rule"
        date = "2025-11-27"
        tags = "fallchill, malware"

    strings:
        $s1  = "GetProcessWindowStation" ascii
        $s2  = "GetUserObjectInformation" ascii

        $s3  = "VirtualAlloc" ascii
        $s4  = "VirtualProtect" ascii

        $s5  = "MapViewOfFile" ascii
        $s6  = "UnmapViewOfFile" ascii

        $s7  = "FindFirstFile" ascii
        $s8  = "FindNextFile" ascii
        $s9  = "WriteFile" ascii

        $s10 = "GetCurrentProcess" ascii
        $s11 = "GetCurrentProcessId" ascii
        $s12 = "GetCurrentThreadId" ascii
        $s13 = "GetModuleHandleEx" ascii

        $s14 = "GetEnvironmentStrings" ascii
        $s15 = "SetEnvironmentVariable" ascii

        $s16 = "RaiseException" ascii
        $s17 = "RtlPcToFileHeader" ascii
        $s18 = "GetFileInformationByHandleEx" ascii

        $stub = "This program cannot be run in DOS mode" ascii

    condition:
        uint16(0) == 0x5a4d and
        filesize > 100KB and filesize < 200KB and
        $stub and
        2 of ($s1, $s2, $s3, $s4) and
        1 of ($s5, $s6) and
        2 of ($s7, $s8, $s9) and
        2 of ($s10, $s11, $s12, $s13) and
        1 of ($s14, $s15) and
        1 of ($s16, $s17, $s18)
}

