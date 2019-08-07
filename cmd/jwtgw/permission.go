package main

// par de certificate fingerprint + path
type Permission struct {
	Fingerprint, Scope string
}

//Audiences a serem adicionadas
type Claims struct {
	Audience []string
}

type PermissionClaims map[Permission]Claims
