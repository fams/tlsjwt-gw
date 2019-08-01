package main

import (
	"log"
)

//LoadAuth carrega as permissoes, e um adapter
type StaticLoader struct {
}

func (s StaticLoader) LoadCredentials() (PermissionClaims, bool) {
	pc := PermissionClaims{}
	pc[Permission{"b49d1cdd5a34b98290cd21deb1fc630e101b85f278d9632b60e82ee52263f59a", "/httpbin/headers"}] = Claims{"httpbin"}
	pc[Permission{"b49d1cdd5a34b98290cd21deb1fc630e101b85f278d9632b60e82ee52263f59a", "/service/1"}] = Claims{"service-a"}

	log.Print("filtros iniciais carregados")

	return pc, true
}
