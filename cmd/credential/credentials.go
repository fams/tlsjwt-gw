// Gerencia a base de credenciais que valida o fingerprint do mTLS e define os audiences validos
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

// CredentialLoader e a interface para multiplos provedores de base de permissionamento
type CredentialLoader interface {
	LoadCredentials() (PermissionClaims, bool)
}

//Sched recebe um intervalo de acao e uma funcao de recarga das credenciais,
// Agenda a funcao baseado no intervalo em segundos
func (tc *CredentialMap) Sched(interval time.Duration, loader CredentialLoader) {
	rand.Seed(time.Now().Unix())

	// funcao de intervalo de disparo
	sleep := func() {
		time.Sleep(interval * time.Second)
	}
	// obtem um mutex para acesso
	tc.wg.Add(1)
	for {
		sleep()
		// carrega as credenciais em pc
		pc, ok := loader.LoadCredentials()
		// Verifica se as credenciais recebidas nao sao as mesmas em atividade
		if ok {
			if !reflect.DeepEqual(tc.mymap[tc.lastepoch], pc) {
				log.Info("recebidos novos claims do provedor de claims, reconciliando")
				// Define novo conjunto de credenciais
				newepoch := tc.lastepoch + 1
				tc.mymap[newepoch] = pc

				// Area critica, muda o apontamento das credenciais para o novo conjunto e apaga o 6 mais antigo
				tc.m.Lock()
				tc.lastepoch = newepoch
				tc.m.Unlock()
				if newepoch > 5 {
					delete(tc.mymap, newepoch-5)
				}
			} else {
				log.Debug("nao e necessario reconciliar")
			}
		} else {
			tc.wg.Done()
			// Fixme deve ser implementado um exponential backoff para a carga de credenciais
			// Derrubar o validador não é uma opcao
			log.Error("Erro reconciliando credenciais")
		}
	}

}

// Recarga doo mapa de permissoes recebendo a funcao de carga inicial
// Deprecated
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

// Construtor da base de credenciais, gera o mapa na memoria, carrega base inicial e retorna o mapa em si
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

// Validate recebe uma tupla Permission(fingerprint, scope), verifica se essa permissao existe na base,
// retorna as claims (audiences) permitidas para esse PermissionClaim
func (tc *CredentialMap) Validate(permissionClaim Permission) (Claims, bool) {
	//Area Critica
	log.Debugf("Validando fingerprint %s, path: %s,", permissionClaim.Fingerprint, permissionClaim.Scope)
	//Area Critica detecta qual epoch está valido
	tc.wg.Add(1)
	tc.m.RLock()
	epoch := tc.lastepoch
	tc.m.RUnlock()
	tc.wg.Done()
	// Fixme, nao sei se preciso implementar area critica para leitura do mapa, uma vez
	//  que ele é sempre gravado para frente
	claims, okClaims := tc.mymap[epoch][permissionClaim]
	if okClaims {
		return claims, true
	} else {
		return claims, false
	}
}
