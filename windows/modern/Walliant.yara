rule Windows_Walliant_modern {
    meta : 
		creation_date = "13/12/2024"
        update_date = "07/06/2025"
        github = "https://github.com/Zaque-69"
	    fingerprint = "A23A98506925099E6835EBF625A4D457C4FC2314D03FED2A3A72CD2C374CC41F"
	    sample = "https://github.com/Endermanch/MalwareDatabase/blob/master/modern/Walliant.zip"
        os = "Windows"

    strings : 
        $header = { 4D 5A }

        // i.n.s.t.a.l.l. .i.n. .a.d.m.i.n.i.s.t.r.a.t.i.v.e
        $a1 = { 69 00 6E 00 73 00 74 00 61 00 6C 00 6C 00 20 00 69 00 6E 00 20 00 61 00 64 00 6D 00 69 00 6E 00 69 00 73 00 74 00 72 00 61 00 74 00 69 00 76 00 65 }

        // H.E.L.P.,. ./.?
        $a2 = { 48 00 45 00 4C 00 50 00 2C 00 20 00 2F 00 3F }

        // S.h.o.w.s. .t.h.i.s. .i.n.f.o.r.m.a.t.i.o.n
        $a3 = { 53 00 68 00 6F 00 77 00 73 00 20 00 74 00 68 00 69 00 73 00 20 00 69 00 6E 00 66 00 6F 00 72 00 6D 00 61 00 74 00 69 00 6F 00 6E }

        // V.E.R.Y.S.I.L.E.N.T
        $a4 = { 56 00 45 00 52 00 59 00 53 00 49 00 4C 00 45 00 4E 00 54 }

        // I.n.s.t.a.l.l. .f.a.i.l.u.r.e. .t.h.a.t. .r.e.q.u.e.s.t.s. .a. .r.e.s.t.a.r.t
        $a5 = { 49 00 6E 00 73 00 74 00 61 00 6C 00 6C 00 20 00 66 00 61 00 69 00 6C 00 75 00 72 00 65 00 20 00 74 00 68 00 61 00 74 00 20 00 72 00 65 00 71 00 75 00 65 00 73 00 74 00 73 00 20 00 61 00 20 00 72 00 65 00 73 00 74 00 61 00 72 00 74 }

        // c.l.o.s.e. .a.p.p.l.i.c.a.t.i.o.n.s
        $a6 = { 63 00 6C 00 6F 00 73 00 65 00 20 00 61 00 70 00 70 00 6C 00 69 00 63 00 61 00 74 00 69 00 6F 00 6E 00 73 }

        // u.s.i.n.g. .f.i.l.e.s. .t.h.a.t. .n.e.e.d. .t.o. .b.e. .u.p.d.a.t.e.d
        $a7 = { 75 00 73 00 69 00 6E 00 67 00 20 00 66 00 69 00 6C 00 65 00 73 00 20 00 74 00 68 00 61 00 74 00 20 00 6E 00 65 00 65 00 64 00 20 00 74 00 6F 00 20 00 62 00 65 00 20 00 75 00 70 00 64 00 61 00 74 00 65 00 64 }

        // c.r.y.p.t.b.a.s.e...d.l.l
        $a8 = { 63 00 72 00 79 00 70 00 74 00 62 00 61 00 73 00 65 00 2E 00 64 00 6C 00 6C }

        // http://ocsp.digicert.com
        $a9 = { 68 74 74 70 3A 2F 2F 6F 63 73 70 2E 64 69 67 69 63 65 72 74 2E 63 6F 6D }

    condition : 
        7 of ( $a* )
        and filesize < 6MB
}