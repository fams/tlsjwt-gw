package credential

// par de certificate fingerprint + path
type Permission struct {
	Fingerprint, Scope string
}

//Audiences a serem adicionadas
type AudienceList struct {
	Audience []string
}

type PermissionClaims map[Permission]AudienceList
