package credential

// par de certificate fingerprint + path
type Principal struct {
	Fingerprint, Scope string
}

//Permissions a serem adicionadas
type Permissions struct {
	Permission []string
}

type Acl map[Principal]Permissions
