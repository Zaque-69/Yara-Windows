rule pythonCryptography{
	meta : 
		author = "Z4que - All rights reserved"
		date = "22/01/2024"

	strings:
		// import
		$import = { 69 6D 70 6F 72 74 }
		
		// xcryptography
		$c1 =  { 78 63 72 79 70 74 6F 67 72 61 70 68 79 }

		// cryptography.hazmat.primitives
		$c2 = { 63 72 79 70 74 6F 67 72 61 70 68 79 2E 68 61 7A 6D 61 74 2E 70 72 69 6D 69 74 69 76 65 73 }
		
		// cryptography.fernet
		$c3 = { 63 72 79 70 74 6F 67 72 61 70 68 79 2E 66 65 72 6E 65 74 }

		// import cryptography
		$c4 = { 69 6D 70 6F 72 74 20 63 72 79 70 74 6F 67 72 61 70 68 79 }

	condition : 
		($import at 0) 
		and any of ($c*)
}