// GW de controle mTLS jwt
//
package main

// TODO FAMS, verificar os // INFO que eu coloquei nos codigos

import (
	"extauth/cmd/authzman"
	c "extauth/cmd/config"
	"extauth/cmd/jwthandler"
	"flag"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v2"
	"github.com/patrickmn/go-cache"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	// Prometheus packages
)

var (
	// Contador para total de todas as requisicoes
	metricAmIAlive = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "gtw_am_i_alive",
		Help: "Incrementa um  atual afirmando sua presenca",
	},
		[]string{"id"},
	)
)

func amIAlive(AppID string, delay time.Duration) chan bool {
	stop := make(chan bool)

	go func() {
		for {
			metricAmIAlive.WithLabelValues(AppID).Inc()
			select {
			case <-time.After(delay):
			case <-stop:
				return
			}
		}
	}()

	return stop
}

var addr = flag.String("listen-address", ":2112", "The address to listen on for HTTP requests.")

func main() {
	// Instancia variaveis com informacoes de configuracao
	var (
		err     error
		options c.Options
	)

	// Preenche a a estrutura opens com as configuracoes padroes de conexao com
	// o provedor de credenciais, jwt, issuers, etc...
	options, err = c.BuildOptions()

	scheduleAlive := amIAlive(options.AppID, 1*time.Millisecond*1000)

	// Inicializando algumas metricas
	metricsJwtTotal.WithLabelValues(options.AppID).Add(0)
	metricsJwtAceitoTotal.WithLabelValues(options.AppID).Add(0)
	metricsJwtNegadoTotal.WithLabelValues(options.AppID).Add(0)

	metricsMtlsTotal.WithLabelValues(options.AppID).Add(0)
	metricsMtlsAceitoTotal.WithLabelValues(options.AppID).Add(0)
	metricsMtlsNegadoTotal.WithLabelValues(options.AppID).Add(0)
	metricsMtlsCacheHit.WithLabelValues(options.AppID).Add(0)

	metricsRequisicaoTotal.WithLabelValues(options.AppID).Add(0)

	// inicia o servico do http prometheus na porta addr
	http.Handle("/metrics", promhttp.Handler())
	go http.ListenAndServe(*addr, nil)

	if err != nil {
		log.Fatalf("main: Error when reading config: %v", err)
	}

	// Define-se o tipo de log que sera utilizado na aplicacao a partir da
	// configuracao
	switch options.Loglevel {
	case "info":
		log.SetLevel(log.InfoLevel)
	case "debug":
		log.SetLevel(log.DebugLevel)
	default:
		log.SetLevel(log.InfoLevel)
	}

	log.Infof("ID: %s", options.AppID)

	// Le as permissoes situadas no provedor de credenciais e salva numa
	// estrutura/interface que possui o semaforo, o waitgroup e elas.
	// Iniciando o reconciliador de credenciais com o loader
	//var PermissionManager authzman.AuthzDB
	PermissionManager := authzman.NewPermDb(options.PermissionDB.Config)

	// Verifica se nao ocorreu algum erro na criacao da estrutura
	if PermissionManager == nil {
		log.Fatalf("main: Error when creating a new Permission DB\n")
	}

	var ticker *time.Ticker

	if PermissionManager.Async() {
		// captura o intervalo de tempo de requisicao
		duration, err := time.ParseDuration(options.PermissionDB.Config.Options["interval"])
		// se nao existe erro
		if err == nil {
			// Cria um novo ticker com duracao duration com Channel
			// Ao utilizar um channel, ele enviara uma interrupcao ao final do
			ticker = time.NewTicker(duration)
			// Inicia-se uma GoRoutine (que eh uma thread)
			go PermissionManager.Init(ticker)
		} else {
			log.Fatal("main: Nao foi possivel converter %s para time.duration ", options.PermissionDB.Config.Options["interval"], ": ", err)
		}
	} else {
		log.Info("main: iniciando banco syncrono")
		ticker = time.NewTicker(time.Second)
		PermissionManager.Init(ticker)
	}

	//
	// Configurando o JWT Handler
	//

	// Chave de assinatura dos tokens emitidos pelo GW
	privKeyPath := options.JwtConf.RsaPrivateFile

	// Le a chave privada do algoritmo RSA
	signKeyBytes, err := ioutil.ReadFile(privKeyPath)

	// verifica se ha algum problema na leitura
	if err != nil {
		log.Fatalf("main: Error when reading private key: %v", err)
	}

	// Issuer usado pelo GW
	localIssuer := options.JwtConf.LocalIssuer
	log.Debugf("main: local Issuer: %s", localIssuer)
	log.Debugf("main: authzHeader: %s", options.AuthHeader)
	log.Debugf("main: claimString: %s", options.ClaimString)

	// Iniciando o gerenciador JWT
	// Instancia um JWTHandler invocando a funcao New do pacote jwthandler
	myJwtHandler := jwthandler.New(signKeyBytes, localIssuer, options.JwtConf.TokenLifetime, options.JwtConf.Kid)

	// Adiciona Issuers ao JWT gerado de acordo com a estrutura options
	for i := 0; i < len(options.JwtConf.Issuers); i++ {
		// Invoca a funcao que busca os issuers e aplica no JWT
		err := myJwtHandler.AddJWK(options.JwtConf.Issuers[i].Issuer, options.JwtConf.Issuers[i].Url)
		if err != nil {
			log.Fatalf("main: Erro carregando JWTconf: %s iss: %s src: %s", err, options.JwtConf.Issuers[i].Issuer, options.JwtConf.Issuers[i].Url)
		}
	}

	// Inicializando Servidor de Autorizacao
	// Injetando Cache de tokens, base de credenciais e gerenciador de JWT
	authServer := &AuthorizationServer{
		credentialCache:   cache.New(options.PermissionDB.CacheInterval, options.PermissionDB.CacheClean),
		PermissionManager: PermissionManager,
		jwtinstance:       myJwtHandler,
		Options:           &options,
	}

	// create a TCP listener on port 4000
	lis, err := net.Listen("tcp", ":4000")

	if err != nil {
		log.Fatalf("main: failed to listen: %v", err)
	}
	log.Infof("main: listening on %s ", lis.Addr()) //,authServer.jwtinstance.GetConf())

	// Inicia o Servidor GRPC
	grpcServer := grpc.NewServer()

	// Registrando o servidor de autenticacao no servidor GRPC
	auth.RegisterAuthorizationServer(grpcServer, authServer)

	// Verifica se o servidor esta escutando
	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("main: Failed to start server: %v", err)
	}

	// Graceful end
	// Finaliza a funcao de metrica amIAlive
	scheduleAlive <- true
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	<-sigs
	ticker.Stop()
	grpcServer.Stop()

}
