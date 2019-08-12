package credential

import (
	log "github.com/sirupsen/logrus"
	"math/rand"
	"reflect"
	"sync"
	"time"
)

type CredentialMap struct {
	mymap     map[int]PermissionClaims
	lastepoch int
	m         *sync.RWMutex
	wg        *sync.WaitGroup
}

type CredentialLoader interface {
	LoadCredentials() (PermissionClaims, bool)
}

//Sched recarrega as credencials de tempos em tempos
func (tc *CredentialMap) Sched(interval time.Duration, loader CredentialLoader) {
	rand.Seed(time.Now().Unix())

	sleep := func() {
		//time.Sleep((time.Duration(rand.Intn(1000)) * time.Millisecond) + (interval * time.Second))
		time.Sleep(interval * time.Second)
	}
	tc.wg.Add(1)
	for {
		sleep()
		pc, ok := loader.LoadCredentials()
		if ok {
			if !reflect.DeepEqual(tc.mymap[tc.lastepoch], pc) {
				log.Info("Recbidos novos claims, reconciliando")
				newepoch := tc.lastepoch + 1
				tc.mymap[newepoch] = pc
				//area critica
				tc.m.Lock()
				tc.lastepoch = newepoch
				tc.m.Unlock()
				if newepoch > 5 {
					delete(tc.mymap, newepoch-5)
				}
			}
		} else {
			tc.wg.Done()
			log.Fatal("Erro reconciliando")
		}
	}

}

//init carrega o mapa de permissoes inicial recebendo a funcao de carga inicial
func (tc *CredentialMap) Init(loader CredentialLoader) {
	//
	trustee, ok := loader.LoadCredentials()
	tc.mymap = make(map[int]PermissionClaims)
	tc.m = &sync.RWMutex{}
	tc.wg = &sync.WaitGroup{}
	if ok {
		tc.lastepoch = 0
		tc.mymap[0] = trustee
	} else {
		log.Fatal("Erro carregando permissoes iniciais")
	}
}

//init carrega o mapa de permissoes inicial recebendo a funcao de carga inicial
func New(loader CredentialLoader) *CredentialMap {
	//
	tc := new(CredentialMap)
	trustee, ok := loader.LoadCredentials()
	tc.mymap = make(map[int]PermissionClaims)
	tc.m = &sync.RWMutex{}
	tc.wg = &sync.WaitGroup{}
	if ok {
		tc.lastepoch = 0
		tc.mymap[0] = trustee
	} else {
		log.Fatal("Erro carregando permissoes iniciais")
		return nil
	}
	return tc
}

//Validate verifica se o certificado enviado tem permissão no caminho solicitado, retorna os claims
func (tc *CredentialMap) Validate(perm Permission) (Claims, bool) {
	//Area Critica
	log.Debugf("Validando fingerprint %s, path: %s,", perm.Fingerprint, perm.Scope)
	tc.wg.Add(1)
	tc.m.RLock()
	epoch := tc.lastepoch
	tc.m.RUnlock()
	tc.wg.Done()

	claims, okClaims := tc.mymap[epoch][perm]
	if okClaims {
		return claims, true
	} else {
		return claims, false
	}
}
