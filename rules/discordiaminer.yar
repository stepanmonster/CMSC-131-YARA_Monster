import "pe"

rule discordia
{
    meta:
        author = "YourName"
        description = "Example YARA rule demonstrating all flags and components"
        date = "YYYY-MM-DD"
        reference = "https://example.com/reference"
        tags = "tag1, tag2, example"

    strings:
        $text1 = "CreateSymbolicLink" ascii 
        $text2 = "CloseThreadpoolTimer" ascii
        $text3 = "CreateSymbolicLink" ascii
        $text4 = "CreateThreadpoolTimer" ascii
        $text5 = "CreateThreadpoolWait" ascii
        $text6 = "CreateThreadpoolWork" ascii
        $text7 = "CreateDirectory" ascii
        $text8 = "FindFirstFileEx" ascii
        $text9 = "FindNextFile" ascii
        $text10 = "GetClipboardData" ascii
        $text11 = "GetCurrentProcess" ascii
        $text12 = "GetCurrentProcessId" ascii
        $text13 = "GetCurrentProcessorNumber" ascii
        $text14 = "GetCurrentThreadId" ascii
        $text15 = "GetFileInformationByHandleEx" ascii
        $text16 = "GetModuleHandleEx" ascii
        $text17 = "OpenProcess" ascii
        $text18 = "CreateToolhelp32Snapshot" ascii
        $text19 = "Process32First" ascii
        $text20 = "Process32Next" ascii
        $text21 = "K32EnumProcessModules" ascii
        $text22 = "K32GetModuleBaseName" ascii
        $text23 = "WaitForThreadpoolTimerCallbacks" ascii
        $text24 = "WriteFile" ascii
        $text25 = "K32GetModuleFileNameEx" ascii
        $text26 = "ConvertStringSecurityDescriptorToSecurityDescriptor" ascii
        $text27 = "SetKernelObjectSecurity" ascii
        $text28 = "URLDownloadToFile" ascii 
        $text29 = "GetEnvironmentStrings" ascii 
        $text30 = "SetEnvironmentVariable" ascii 
        $text31 = "CreateProcess" ascii 
        $text32 = "SetFileAttributes" ascii 
        $text33 = "CreateToolhelp32Snapshot" ascii 
        $text34 = "URLDownloadToFile" ascii 
        $text35 = "ShellExecute" ascii 
        $text36 = "WinHttpConnect" ascii 
        $text37 = "WinHttpSendRequest" ascii 
        $text38 = "WinHttpReceiveResponse" ascii 



        $url1 = "https://github.com/" ascii

    condition:
    uint16(0) == 0x5a4d and
    30 of ($text*) and
    all of ($url*)
}
