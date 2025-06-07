rule Windows_lokiLocker_ransomware {
    meta : 
		creation_date = "27/01/2024"
        update_date = "07/06/2025"
        github = "https://github.com/Zaque-69"
	    fingerprint = "C31A7A441EB7EECFECE23320460126031A9B0D568448ECE8D202E345B9D7D6E2"
	    sample = "https://github.com/Endermanch/MalwareDatabase/blob/master/ransomwares/DeriaLock.zip"
        os = "Windows"
	strings:
		$header = { 4D 5A }

		// Y.o.u.r. .f.i.l.e.s. .h.a.v.e. .b.e.e.n. .e.n.c.r.y.p.t.e.d
		$a1 = { 59 00 6F 00 75 00 72 00 20 00 66 00 69 00 6C 00 65 00 73 00 20 00 68 00 61 00 76 00 65 00 20 00 62 00 65 00 65 00 6E 00 20 00 65 00 6E 00 63 00 72 00 79 00 70 00 74 00 65 00 64}
		
		// Y.o.u.r. .c.o.m.p.u.t.e.r. .i.s. .l.o.c.k.e.d.
		$a2 = { 59 00 6F 00 75 00 72 00 20 00 63 00 6F 00 6D 00 70 00 75 00 74 00 65 00 72 00 20 00 69 00 73 00 20 00 6C 00 6F 00 63 00 6B 00 65 00 64 }

		// P.l.e.a.s.e. .d.o. .n.o.t. .c.l.o.s.e. .t.h.i.s. .w.i.n.d.o.w
		$a3 = { 50 00 6C 00 65 00 61 00 73 00 65 00 20 00 64 00 6F 00 20 00 6E 00 6F 00 74 00 20 00 63 00 6C 00 6F 00 73 00 65 00 20 00 74 00 68 00 69 00 73 00 20 00 77 00 69 00 6E 00 64 00 6F 00 77 }

		// a.s. .t.h.a.t. .w.i.l.l. .r.e.s.u.l.t. .i.n. .s.e.r.i.o.u.s. .c.o.m.p.u.t.e.r. .d.a.m.a.g.e
		$c4 = { 61 00 73 00 20 00 74 00 68 00 61 00 74 00 20 00 77 00 69 00 6C 00 6C 00 20 00 72 00 65 00 73 00 75 00 6C 00 74 00 20 00 69 00 6E 00 20 00 73 00 65 00 72 00 69 00 6F 00 75 00 73 00 20 00 63 00 6F 00 6D 00 70 00 75 00 74 00 65 00 72 00 20 00 64 00 61 00 6D 00 61 00 67 00 65 }

        //"locked"
        $a5 = { 6C 00 6F 00 63 00 6B 00 65 00 64 }

		// C:\Users\Tyler\Desktop\hidden-tear-master\hidden-tear\hidden-tear\obj\Debug\VapeHacksLoader.pdb
        $a6 = { 43 3A 5C 55 73 65 72 73 5C 54 79 6C 65 72 5C 44 65 73 6B 74 6F 70 5C 68 69 64 64 65 6E 2D 74 65 61 72 2D 6D 61 73 74 65 72 5C 68 69 64 64 65 6E 2D 74 65 61 72 5C 68 69 64 64 65 6E 2D 74 65 61 72 5C 6F 62 6A 5C 44 65 62 75 67 5C 56 61 70 65 48 61 63 6B 73 4C 6F 61 64 65 72 2E 70 64 62 }

	condition : 
		( $header at 0 ) 
		and 5 of ( $a* )
}