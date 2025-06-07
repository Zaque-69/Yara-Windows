rule Windows_DeriaLock_ransomware {
    meta : 
		creation_date = "13/12/2024"
        update_date = "07/06/2025"
        github = "https://github.com/Zaque-69"
	    fingerprint = "402060C10CEBBC48FD9C1BB35DB8434F091DB89F45AC25E775AD0308892B0B3E"
	    sample = "https://github.com/Endermanch/MalwareDatabase/blob/master/ransomwares/DeriaLock.zip"
        os = "Windows"

	strings:
		
		// http://wallup.net
		$a1 = { 68 74 74 70 3A 2F 2F 77 61 6C 6C 75 70 2E 6E 65 74 }

		// C.R.E.A.T.O.R.:. .g.d.-.j.p.e.g
		$a2 = { 43 00 52 00 45 00 41 00 54 00 4F 00 52 00 3A 00 20 00 67 00 64 00 2D 00 6A 00 70 00 65 00 67 }

		// N.a.m.e
		$a3 = { 4E 00 61 00 6D 00 65 }

		// LOGON.exe
		$a4 = { 4C 4F 47 4F 4E 2E 65 78 65 }

		// Y.O.U. .A.R.E. .I.N.F.E.C.T.E.D. .W.I.T.H. .D.E.R.I.A.L.O.C.K.!
		$a5 = { 59 00 4F 00 55 00 20 00 41 00 52 00 45 00 20 00 49 00 4E 00 46 00 45 00 43 00 54 00 45 00 44 00 20 00 57 00 49 00 54 00 48 00 20 00 44 00 45 00 52 00 49 00 41 00 4C 00 4F 00 43 00 4B 00 21 }

		// A.L.L. .Y.O.U.R. .F.I.L.E.S. .H.A.V.E. .B.E.E.N. .E.N.C.R.Y.P.T.E.D.!
		$a6 = { 41 00 4C 00 4C 00 20 00 59 00 4F 00 55 00 52 00 20 00 46 00 49 00 4C 00 45 00 53 00 20 00 48 00 41 00 56 00 45 00 20 00 42 00 45 00 45 00 4E 00 20 00 45 00 4E 00 43 00 52 00 59 00 50 00 54 00 45 00 44 00 21 }

		// D.O.N.T. .T.R.Y. .T.O. .D.E.L.E.T.E. .D.E.R.I.A.L.O.C.K.!
		$a7 = { 44 00 4F 00 4E 00 54 00 20 00 54 00 52 00 59 00 20 00 54 00 4F 00 20 00 44 00 45 00 4C 00 45 00 54 00 45 00 20 00 44 00 45 00 52 00 49 00 41 00 4C 00 4F 00 43 00 4B 00 21 }

		// ".A.R.I.Z.O.N.A.C.O.D.E.".!
		$a8 = { 22 00 41 00 52 00 49 00 5A 00 4F 00 4E 00 41 00 43 00 4F 00 44 00 45 00 22 00 21 }

		// I. .W.I.L.L. .D.E.L.E.T.E. .A.L.L. .F.I.L.E.S.!
		$a9 = { 49 00 20 00 57 00 49 00 4C 00 4C 00 20 00 44 00 45 00 4C 00 45 00 54 00 45 00 20 00 41 00 4C 00 4C 00 20 00 46 00 49 00 4C 00 45 00 53 00 21 }

		// N.a.m.e..=I. .M.A.D.E. .A. .P.A.Y.M.E.N.T.!
		$a10 = { 4E 00 61 00 6D 00 65 00 00 3D 49 00 20 00 4D 00 41 00 44 00 45 00 20 00 41 00 20 00 50 00 41 00 59 00 4D 00 45 00 4E 00 54 00 21 }

		// h.t.t.p.:././.a.r.i.z.o.n.a.c.o.d.e
		$a11 = { 68 00 74 00 74 00 70 00 3A 00 2F 00 2F 00 61 00 72 00 69 00 7A 00 6F 00 6E 00 61 00 63 00 6F 00 64 00 65 }

		// C:\Windows.old\Users\ArizonaCode\Documents\Visual Studio 2013
		$a12 = { 43 3A 5C 57 69 6E 64 6F 77 73 2E 6F 6C 64 5C 55 73 65 72 73 5C 41 72 69 7A 6F 6E 61 43 6F 64 65 5C 44 6F 63 75 6D 65 6E 74 73 5C 56 69 73 75 61 6C 20 53 74 75 64 69 6F 20 32 30 31 33 }

		// \Projects\LOGON\LOGON\obj\Debug\LOGON.pdb
		$a13 = { 5C 50 72 6F 6A 65 63 74 73 5C 4C 4F 47 4F 4E 5C 4C 4F 47 4F 4E 5C 6F 62 6A 5C 44 65 62 75 67 5C 4C 4F 47 4F 4E 2E 70 64 62 }

	condition : 

		8 of ($a*) 
		and filesize < 5MB
}
