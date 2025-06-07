rule Windows_ColorBug_trojan {
    meta : 
		creation_date = "14/12/2024"
        update_date = "07/06/2025"
        github = "https://github.com/Zaque-69"
	    fingerprint = "CB3319DA5944692F5509B67DE9026A672C729B85D6393CEBED1935EDB98E441A"
	    sample = "https://github.com/Endermanch/MalwareDatabase/blob/master/trojans/ColorBug.zip"
        os = "Windows"

    strings : 

        // SOFTWARE\Borland\Delphi\RTL.FPUMaskValue
        $a1 = { 53 4F 46 54 57 41 52 45 5C 42 6F 72 6C 61 6E 64 5C 44 65 6C 70 68 69 5C 52 54 4C 00 46 50 55 4D 61 73 6B 56 61 6C 75 65 } 

        // Portions Copyright (c) 1983,97 Borland
        $a2 = { 50 6F 72 74 69 6F 6E 73 20 43 6F 70 79 72 69 67 68 74 20 28 63 29 20 31 39 38 33 2C 39 37 20 42 6F 72 6C 61 6E 64 }

        // Software\Borland\Delphi\Locales
        $a3 = { 53 6F 66 74 77 61 72 65 5C 42 6F 72 6C 61 6E 64 5C 44 65 6C 70 68 69 5C 4C 6F 63 61 6C 65 73 }
        
        // Control Panel\Colors
        $a4 = { 43 6F 6E 74 72 6F 6C 20 50 61 6E 65 6C 5C 43 6F 6C 6F 72 73 }

    condition : 
        all of them
        and filesize < 70KB
}