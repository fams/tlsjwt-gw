// Gerencia a base de credenciais que valida o fingerprint do mTLS e define os claims validos
package authzman

import (
	log "github.com/sirupsen/logrus"
	"math/rand"
	"reflect"
	"sync"
	"time"
)

type Store struct {
	permMapStorage map[int]PermissionMap
	lastepoch      int
	m              *sync.RWMutex
	wg             *sync.WaitGroup
}


// Loader e a interface para multiplos provedores de base de permissionamento
type Loader interface {
	LoadPermissions() (PermissionMap, bool)
}

//Sched recebe um intervalo de acao e uma funcao de recarga das credenciais,
// Agenda a funcao baseado no intervalo em segundos
func (tc *Store) Sched(interval time.Duration, loader Loader) {
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
		pc, ok := loader.LoadPermissions()
		// Verifica se as credenciais recebidas nao sao as mesmas em atividade
		if ok {
			if !reflect.DeepEqual(tc.permMapStorage[tc.lastepoch], pc) {
				log.Info("recebidos novos claims do provedor de claims, reconciliando")
				// Define novo conjunto de credenciais
				newepoch := tc.lastepoch + 1
				tc.permMapStorage[newepoch] = pc

				// Area critica, muda o apontamento das credenciais para o novo conjunto e apaga o 6 mais antigo
				log.Debug("iniciando area critica para atualizacao do mapa")
				tc.m.Lock()
				tc.lastepoch = newepoch
				if newepoch > 5 {
					delete(tc.permMapStorage, newepoch-5)
				}
				log.Debug("saindo da area critica")
				tc.m.Unlock()
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
func (tc *Store) Init(loader Loader) {
	//
	permMap, ok := loader.LoadPermissions()
	tc.permMapStorage = make(map[int]PermissionMap)
	tc.m = &sync.RWMutex{}
	tc.wg = &sync.WaitGroup{}
	if ok {
		tc.lastepoch = 0
		tc.permMapStorage[0] = permMap
	} else {
		log.Fatal("Erro carregando permissoes iniciais")
	}
}

// Construtor da base de credenciais, gera o mapa na memoria, carrega base inicial e retorna o mapa em si
func NewAsyncStorage(loader Loader) *Store {
	//
	tc := new(Store)
	currentAcl, ok := loader.LoadPermissions()
	tc.permMapStorage = make(map[int]PermissionMap)
	tc.m = &sync.RWMutex{}
	tc.wg = &sync.WaitGroup{}
	if ok {
		tc.lastepoch = 0
		tc.permMapStorage[0] = currentAcl
	} else {
		log.Fatal("Erro carregando permissoes iniciais")
		return nil
	}
	return tc
}

// Validate recebe uma tupla PermissionClaim(fingerprint, scope), verifica se existe permissoes para elas na base,
// retorna as claims (permissions) para esse PermissionClaim
func (tc *Store) Validate(pc PermissionClaim) (PermissionsContainer, bool) {
	//Area Critica
	log.Debugf("Validando fingerprint %s, path: %s,", pc.Fingerprint, pc.Scope)
	//Area Critica detecta qual epoch está valido
	tc.wg.Add(1)
	tc.m.RLock()
	epoch := tc.lastepoch
	tc.m.RUnlock()
	tc.wg.Done()
	// Fixme, nao sei se preciso implementar area critica para leitura do mapa, uma vez
	//  que ele é sempre gravado para frente
	claims, okClaims := tc.permMapStorage[epoch][pc]
	if okClaims {
		return claims, true
	} else {
		return claims, false
	}
}
func (tc *Store) Async () bool{
	return true
}