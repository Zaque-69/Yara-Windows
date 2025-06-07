rule Windows_PowerPoint_ransomware {
    meta : 
		creation_date = "07/03/2024"
        update_date = "07/06/2025"
        github = "https://github.com/Zaque-69"
	    fingerprint = "CFC5E11781E05A1DE5AEEE5F42A79CC92BB58609E2505AD60B133F05F062E28C"
	    sample = "https://github.com/Endermanch/MalwareDatabase/blob/master/ransomwares/PowerPoint.zip"
        os = "Windows"
        
    strings : 
        $header = { 4D 5A }

            // fucked-up-shit
        	$a1 = { 66 75 63 6B 65 64 2D 75 70 2D 73 68 69 74 }

            // sqlhost.dllw
        	$a2 = { 73 71 6C 68 6F 73 74 2E 64 6C 6C }

            // SeShutdownPrivilege
        	$a3 = { 53 65 53 68 75 74 64 6F 77 6E 50 72 69 76 69 6C 65 67 65 }
        
            // \sys3.exe
        	$a4 = { 5C 73 79 73 33 2E 65 78 65 }

            // \systm.txt
            $a5 = { 5C 73 79 73 74 6D 2E 74 78 74 }

    condition : 
        3 of ( $a* ) 
        and filesize < 200KB
}