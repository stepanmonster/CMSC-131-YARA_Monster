rule clipboardHijacker
{
    meta:
        author = "YourName"
        description = "Example YARA rule demonstrating all flags and components"
        date = "YYYY-MM-DD"
        reference = "https://example.com/reference"
        tags = "tag1, tag2, example"

    strings:
        $text1 = "CloseClipboard" ascii
        $text2 = "CloseThreadpoolTimer" ascii
        $text3 = "CreateSymbolicLink" ascii
        $text4 = "CreateThreadpoolTimer" ascii
        $text5 = "CreateThreadpoolWait" ascii
        $text6 = "CreateThreadpoolWork" ascii
        $text7 = "EmptyClipboard" ascii
        $text8 = "FindFirstFileEx" ascii
        $text9 = "FindNextFile" ascii
        $text10 = "GetClipboardData" ascii
        $text11 = "GetCurrentProcess" ascii
        $text12 = "GetCurrentProcessId" ascii
        $text13 = "GetCurrentProcessorNumber" ascii
        $text14 = "GetCurrentThreadId" ascii
        $text15 = "GetFileInformationByHandleEx" ascii
        $text16 = "GetModuleHandleEx" ascii
        $text17 = "OpenClipboard" ascii
        $text18 = "PathFindFileName" ascii
        $text19 = "RaiseException" ascii
        $text20 = "RegCreateKeyEx" ascii
        $text21 = "RegSetValueEx" ascii
        $text22 = "SetClipboardData" ascii
        $text23 = "WaitForThreadpoolTimerCallbacks" ascii
        $text24 = "WriteFile" ascii
        
        condition:
    uint16(0) == 0x5a4d and
    all of ($text*)
}