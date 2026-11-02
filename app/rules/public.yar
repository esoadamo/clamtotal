// ClamTotal bundled public rules (original, written for this project).
// Mount your own public rules at /rules (YARA_RULES_DIR=/rules) — private rules are not supported.

rule EICAR_Test_File {
    meta:
        description = "EICAR standard antivirus test file"
    strings:
        $eicar = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
    condition:
        $eicar
}

rule Suspicious_PowerShell_Downloader {
    meta:
        description = "PowerShell download cradle / encoded command pattern"
    strings:
        $ps1 = "powershell" nocase
        $dl  = "DownloadString" nocase
        $dl2 = "DownloadFile" nocase
        $enc = /EncodedCommand|FromBase64String/ nocase
    condition:
        $ps1 and ($dl or $dl2 or $enc)
}

rule PE_With_Remote_Thread_Imports {
    meta:
        description = "PE importing process-injection primitives"
    strings:
        $a = "VirtualAllocEx"
        $b = "WriteProcessMemory"
        $c = "CreateRemoteThread"
    condition:
        uint16(0) == 0x5A4D and all of them
}
