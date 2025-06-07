rule Windows_Evascape_enderware {
    meta : 
		creation_date = "13/12/2024"
        update_date = "07/06/2025"
        github = "https://github.com/Zaque-69"
	    fingerprint = "158905909346EC005F7CE34D56B285F3A6464A47A860283F01AB318E726ECC2C"
	    sample = "https://github.com/Endermanch/MalwareDatabase/blob/master/enderware/Evascape.zip"
        os = "Windows"

    strings : 
        
        // OnDblClickШB
        $a1 = { 4F 6E 44 62 6C 43 6C 69 63 6B D0 A8 42 }
        
        // OnDragOverx�B
        $a2 = { 4F 6E 44 72 61 67 4F 76 65 72 78 A9 42 }

        // OnMouseMove�B
        $a3 = { 4F 6E 4D 6F 75 73 65 4D 6F 76 65 E4 A6 42 }

        // Delphi Picture
        $a4 = { 44 65 6C 70 68 69 20 50 69 63 74 75 72 65 }

        // ERegistryException
        $a5 = { 45 52 65 67 69 73 74 72 79 45 78 63 65 70 74 69 6F 6E }

        // e.d.i.t.....e.x.p.l.o.r.e.r.b.a.r
        $a6 = { 65 00 64 00 69 00 74 00 00 00 00 00 65 00 78 00 70 00 6C 00 6F 00 72 00 65 00 72 00 62 00 61 00 72 }

        // t.a.s.k.b.a.r...t.o.o.l.b.a.r
        $a7 = { 74 00 61 00 73 00 6B 00 62 00 61 00 72 00 00 00 74 00 6F 00 6F 00 6C 00 62 00 61 00 72 }

        // imm32.dll
        $a8 = { 69 6D 6D 33 32 2E 64 6C 6C }

    condition : 
        5 of ( $a* ) 
        and filesize < 1MB
}