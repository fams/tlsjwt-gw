// Gerencia a base de credenciais que valida o fingerprint do mTLS e define os claims validos
package authzman

import (
	"reflect"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

// Store - Estrutura que armazena as permissoes,
type Store struct {
	permMapStorage map[int]PermissionMap
	// contagem crescente correspondendo as ultimas buscas ao provedor de
	// credenciais
	lastepoch int
	m         *sync.RWMutex
	wg        *sync.WaitGroup
	// Utiliza-se do conceito Embedded do Golang
	// (https://golang.org/doc/effective_go.html#embedding)
	// A interface tambem eh uma variavel na qual voce armazena o dado para
	// acessar os metodos a ela atrelada
	loader Loader
}

// Loader e a interface para multiplos provedores de base de permissionamento
type Loader interface {
	LoadPermissions() (PermissionMap, bool)
}

// sync -
//Init recebe um intervalo de acao e uma funcao de recarga das credenciais,
// Agenda a funcao baseado no intervalo em segundos
func (tc *Store) sync(loader Loader) {

	// Le as credenciais do provedor fonte e salva em pc
	pc, ok := loader.LoadPermissions()

	// se nao ha erro, verifica se as credenciais recebidas nao sao as mesmas
	// em atividade
	if ok {
		// Verifica em nivel de campos, exportados ou nao, se a ultima
		// (tc.lastepoch) estrutura ja existente do tipo PermissionMap eh
		// diferente a pc, solicitada agora
		if !reflect.DeepEqual(tc.permMapStorage[tc.lastepoch], pc) {
			// Define novo conjunto de credenciais
			log.Info("recebidos novos claims do provedor de claims, reconciliando")
			// Atualiza o last epoch
			newepoch := tc.lastepoch + 1

			// Adiciona as novas permissoes
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

			// Se igual, nao faz nada
		} else {
			log.Debug("nao e necessario reconciliar")
		}
	} else {
		// Informa ao Go que a funcao desta thread ja finalizou seus
		// procedimentos
		// Fixme deve ser implementado um exponential backoff para a carga de credenciais
		// Derrubar o validador não é uma opcao
		log.Error("Erro reconciliando credenciais")
	}

}

// Init - GoRoutine que fica buscando e verificando se os dados atuais estao
// atualizados com o provedor de credenciais
// INFO Isso eh uma thread que fica executando enquanto a aplicacao estiver
// executando?
func (tc *Store) Init(tick *time.Ticker) {

	// Diz para o Go que ha um grupo sendo executado e que ele nao pode
	// finalizar a aplicacao enquanto a quantidade de grupos for Zero.
	// Os numeros vao decrescendo ao utilizar a funcao tc.wg.Done()
	tc.wg.Add(1)

	// Invoca a funcao sync
	tc.sync(tc.loader)
	// INFO Pelo que eu entendi, ele repete a invocacao do sync ate que o ticker
	// realize a interrupcao
	// INFO mas se o sync faz um wg.done, nao deveria adiciar um add a cada
	// chamada nao?
	for range tick.C {
		// Invoca a funcao sync
		tc.sync(tc.loader)
	}

	tc.wg.Done()

}

//// Recarga doo mapa de permissoes recebendo a funcao de carga inicial
//// Deprecated
//func (tc *Store) Init(loader Loader) {
//	//
//	permMap, ok := loader.LoadPermissions()
//	tc.permMapStorage = make(map[int]PermissionMap)
//	tc.m = &sync.RWMutex{}
//	tc.wg = &sync.WaitGroup{}
//	if ok {
//		tc.lastepoch = 0
//		tc.permMapStorage[0] = permMap
//	} else {
//		log.Fatal("Erro carregando permissoes iniciais")
//	}
//}

// NewAsyncStorage -
// Construtor da base de credenciais, gera o mapa na memoria, carrega base inicial e retorna o mapa em si
func NewAsyncStorage(loader Loader) *Store {

	// INFO eu nao entendo o porque do nome tc
	// Instancia uma nova estrutura Store
	tc := new(Store)
	// Atribui as informacoes para acesso ao provedor de credenciais
	tc.loader = loader

	// Invoca a funcao LoadPermissions da respectiva estrutura para a leitura no
	// no provedor escolhido e retorna para permissions
	permissions, ok := tc.loader.LoadPermissions()

	// Cria um mapa de permissoes
	tc.permMapStorage = make(map[int]PermissionMap)

	// Instancia os metodos de semaforo e waitgroup
	tc.m = &sync.RWMutex{}
	tc.wg = &sync.WaitGroup{}

	// Verifica o retorno da funcao LoadPermissions, se valido, zera o lastepoch
	// e adiciona as permissoes
	// INFO esse teste nao deveria ser abaixo do LoadPermissions() nao?
	if ok {
		// zera o ultimo epoch
		tc.lastepoch = 0
		// adiciona as permissoes lidas no provedor anteriormente
		tc.permMapStorage[0] = permissions
	} else {
		log.Fatal("Erro carregando permissoes iniciais")
		return nil
	}

	// Retorna a estrutura tc
	return tc
}

// Validate recebe uma tupla PermissionClaim(fingerprint, scope), verifica se existe permissoes para elas na base,
// retorna as claims (permissions) para esse PermissionClaim
func (tc *Store) Validate(pc PermissionClaim, appID string) (Credential, bool) {
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

	return claims, okClaims
}

// Async -
// INFO ?
func (tc *Store) Async() bool {
	return true
}
