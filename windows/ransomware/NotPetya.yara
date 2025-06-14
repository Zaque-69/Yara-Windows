rule Windows_notpetya_ransomware {
    meta : 
		creation_date = "14/12/2024"
        update_date = "07/06/2025"
        github = "https://github.com/Zaque-69"
	    fingerprint = "D00A590F33952BA3D9DD3997DBC3DA7253F2ECDE2D33ACF53A42FAEEDAAEB2F1"
	    sample = "https://github.com/Endermanch/MalwareDatabase/blob/master/ransomwares/Petya.A.zip"
        os = "Windows"

	strings:

		// S.e.n.d. .y.o.u.r. .B.i.t.c.o.i.n. .w.a.l.l.e.t. .I.D
		$a1 = { 53 00 65 00 6E 00 64 00 20 00 79 00 6F 00 75 00 72 00 20 00 42 00 69 00 74 00 63 00 6F 00 69 00 6E 00 20 00 77 00 61 00 6C 00 6C 00 65 00 74 00 20 00 49 00 44 }

		// a.n.d. .p.e.r.s.o.n.a.l. .i.n.s.t.a.l.l.a.t.i.o.n.
		$a2 = { 61 00 6E 00 64 00 20 00 70 00 65 00 72 00 73 00 6F 00 6E 00 61 00 6C 00 20 00 69 00 6E 00 73 00 74 00 61 00 6C 00 6C 00 61 00 74 00 69 00 6F 00 6E 00 } 

		// 1.M.z.7.1.5.3.H.M.u.x.X.T.u.R.2.R.1.t.7.8.m.G.S.d.z.a.A.t.N.b.B.W.X
		$a3 = { 31 00 4D 00 7A 00 37 00 31 00 35 00 33 00 48 00 4D 00 75 00 78 00 58 00 54 00 75 00 52 00 32 00 52 00 31 00 74 00 37 00 38 00  6D 00 47 00 53 00 64 00 7A 00 61 00 41 00 74 00 4E 00 62 00 42 00 57 00 58 } 

		// $.3.0.0. .w.o.r.t.h. .o.f. .B.i.t.c.o.i.n
		$a4 = { 24 00 33 00 30 00 30 00 20 00 77 00 6F 00 72 00 74 00 68 00 20 00 6F 00 66 00 20 00 42 00 69 00 74 00 63 00 6F 00 69 00 6E }

		//"encrypt"
		$a5 = { 65 00 6E 00 63 00 72 00 79 00 70 00 74 } 

		// WARNING: DO NOT TURN OFF YOUR PC! IF YOU ABORT THIS PROCESS, YOU COULD DESTROY ALL OF YOUR DATA!
		$a6 = { 57 41 52 4E 49 4E 47 3A 20 44 4F 20 4E 4F 54 20 54 55 52 4E 20 4F 46 46 20 59 4F 55 52 20 50 43 21 20 49 46 20 59 4F 55 20 41 42 4F 52 54 20 54 48 49 53 20 50 52 4F 43 45 53 53 2C 20 59 4F 55 20 43 4F 55 4C 44 20 44 45 53 54 52 4F 59 20 41 4C 4C 20 4F 46 20 59 4F 55 52 20 44 41 54 41 21 }
		
		// Ooops, your important files are encrypted
		$a7 = { 4F 6F 6F 70 73 2C 20 79 6F 75 72 20 69 6D 70 6F 72 74 61 6E 74 20 66 69 6C 65 73 20 61 72 65 20 65 6E 63 72 79 70 74 65 64 }

	condition : 
		5 of ( $a* )
		and filesize < 500KB
}