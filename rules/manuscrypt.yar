import "pe"

rule manuscrypt
{
    meta:
        author = "YourName"
        description = "Example YARA rule demonstrating all flags and components"
        date = "YYYY-MM-DD"
        reference = "https://example.com/reference"
        tags = "tag1, tag2, example"

    strings:
        $text1 = "WinHttpSendRequest" ascii
        $text2 = "WinHttpAddRequestHeaders" ascii
        $text3 = "WinHttpWriteData" ascii
        $text4 = "WinHttpReceiveResponse" ascii
        $text5 = "ObtainUserAgentString" ascii
        $text6 = "WinHttpGetIEProxyConfigForCurrentUser" ascii
        $text7 = "WinHttpSetTimeouts" ascii
        $text8 = "WinHttpConnect" ascii
        $text9 = "WinHttpSetOption" ascii
        $text10 = "GetCurrentProcess" ascii
        $text11 = "GetCurrentProcessId" ascii
        $text12 = "GetCurrentThreadId" ascii
        $text13 = "RaiseException" ascii
        $text14 = "GetModuleHandleEx" ascii
        $text15 = "FindFirstFileEx" ascii
        $text16 = "FindNextFile" ascii
        $text17 = "GetEnvironmentStrings" ascii
        $text18 = "WriteFile" ascii
        $text19 = "RtlPcToFileHeader" ascii


        $url1 = "https://theinspectionconsultant.com/wp-content/plugins/akismet/index1.php" ascii
        $url2 = "http://danagloverinteriors.com/wp-content/plugins/jetpack/common.php" ascii
        $url3 = "https://as-brant.ru/wp-content/themes/shapely/common.php" ascii
        $url4 = "http://aurumgroup.co.id/wp-includes/rest.php" ascii
        $url5 = "http://www.51shousheng.com/include/partview.php" ascii
        $url6 = "http://new.titanik.fr/wp-includes/common.php" ascii

    condition:
    uint16(0) == 0x5a4d and
    18 of ($text*) and
    3 of ($url*)
}
