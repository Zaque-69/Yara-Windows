rule Windows_TaskILL_trojan {
    meta : 
		creation_date = "14/12/2024"
        update_date = "07/06/2025"
        github = "https://github.com/Zaque-69"
	    fingerprint = "1342649600202996256740C226588026A143209EF082B4B3D2474ACAB0120F97"
	    sample = "https://github.com/Endermanch/MalwareDatabase/blob/master/trojans/TaskILL.zip"
        os = "Windows"

    strings : 

        // T.a.s.k.I.L.L...e.x.e
        $a1 = { 54 00 61 00 73 00 6B 00 49 00 4C 00 4C 00 2E 00 65 00 78 00 65 }

        // Y.o.u.'.r.e. .l.u.c.k.y. .t.h.i.s. .t.i.m.e
        $a2 = { 59 00 6F 00 75 00 27 00 72 00 65 00 20 00 6C 00 75 00 63 00 6B 00 79 00 20 00 74 00 68 00 69 00 73 00 20 00 74 00 69 00 6D 00 65 }

        // M.U.T.S.E
        $a3 = { 4D 03 55 03 54 03 53 03 45 }

        // t.a.s.k.m.g.r
        $a4 = { 74 00 61 00 73 00 6B 00 6D 00 67 00 72 }

    condition : 
        all of them
        and filesize < 100KB
}