package config

import (
	//"extauth/cmd/jwthandler"
	"fmt"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

// DBConf Estrutura para informacoes de tipo e acesso ao provedor das credencias
type DBConf struct {
	// Informacoes necessarias para acesso ao banco que armazena as credenciais
	Options map[string]string
	// Tipo de Banco que esta sendo acessado: csv, s3, dynamo, etc...
	DBType string
}

// PermissionDBConf Estrutura para informacoes de Permissao do provedor das credencias
// INFO O nome PermissionDBConf nao ficou legal, ja que as permissoes estao na estrutura DBConf
type PermissionDBConf struct {
	// Estrutura com informacoes de Type e Options
	Config DBConf
	// Informacoes de quanto tempo as informacoes serao consideradas validas e intervalo de busca
	CacheInterval time.Duration
	CacheClean    time.Duration
}

//type issuerConf interface {
//	iss() string
//	jwks() jwthandler.Jwks
//}

// jwtConf - Estrutura que armazena informacoes de configuracao do JWT
type jwtConf struct {
	RsaPrivateFile string
	LocalIssuer    string
	TokenLifetime  time.Duration
	Issuers        []IssuerConf
	Kid            string
}

// Options - Estrutura com todas as configuracoes necessarias para a execucao
// da aplicacao.
type Options struct {
	Loglevel      string
	Port          int
	Hostname      string
	Oidc          OidcConf
	IgnorePaths   []string
	PermissionDB  *PermissionDBConf
	JwtConf       *jwtConf
	EnableOptions bool
	AuthHeader    string
	ClaimString   string
}

// OidcConf - Estrutura que armazena dados do OIDC
type OidcConf struct {
	Hostname string
	Path     string
}

//// fatal -  kill program
//func fatal(err error) {
//	if err != nil {
//		log.Fatal(err)
//	}
//}
// IssuerConf - Estrutura que armazena dados do Issuer e a URL de acesso a este
type IssuerConf struct {
	Issuer string
	// INFO O padrao na comunicade eh sempre usar a variavel URL toda em caixa
	// alta
	Url string
}

// DefaultConf Retorna uma estrutura em Viper com as configuracoes padroes
func DefaultConf() (v1 *viper.Viper, err error) {
	// Definindo Padroes e lendo arquivo de configuracao
	v1, err = ReadConfig("extauth", map[string]interface{}{
		"port":     8080,
		"hostname": "localhost",
		"loglevel": "debug",

		"oidc": map[string]interface{}{
			"hostname": "localhost",
			"path":     "/auth",
		},
		"IgnorePaths": map[string]interface{}{
			"none": "none",
		},

		"credentialCache": map[string]interface{}{
			"expiration": 31,
			"cleanup":    60,
		},
		"credentials": map[string]string{
			"type":   "csv",
			"path":   "/auth/authzman",
			"reload": "60",
		},
		"jwt": map[string]interface{}{
			"rsaPrivateFile": "/auth/extauth.rsa",
			"localIssuer":    "tlsgw.local",
			"kid":            "",
			"tokenLifetime":  60,
			"authHeader":     "authorization",
			"claimString":    "aud",
			"issuers": map[string]interface{}{
				"name1": map[string]interface{}{
					"iss": "tlsgw.local",
					"url": "file:///auth/extauth.rsa.pub",
				},
			},
		},
	})
	return
}

// ReadConfig - Associa os dados de tipo Mapa para a estrutura Viper e retorna-o
func ReadConfig(filename string, defaults map[string]interface{}) (*viper.Viper, error) {

	// Cria a estrutura Viper
	v := viper.New()

	// Copia os dados do mapa defaults para a estrutura Viper
	for key, value := range defaults {
		v.SetDefault(key, value)
	}

	// Incrementa outra informacoes
	v.SetConfigName(filename)
	v.AddConfigPath(".")
	v.AutomaticEnv()

	// Retorna a estrutura construida
	err := v.ReadInConfig()
	return v, err
}

// BuildOptions - Metodo principal para preenchimento da estrutura options
// Carrega as configuracoes padroes
// Instancia um tipo PermissionDBConf e define as configuracoes de leitura de
// provedor de credenciais
// Instancia um tipo jwtConf e define configuracoes inicias do JWT
// INFO Questao: Voce define somente 1 vez a variavel err. Se por acaso der um
// erro na definicao de dados csv ele vai alterar a variavel err. existe o err
// mas nao o retorno saindo da funcao
func BuildOptions() (Options, error) {
	// Retorna uma estrutura Viper com os dados de configuracoes default
	v1, err := DefaultConf()
	if err != nil {
		log.Fatalf("config: Error when reading config: %v\n", err)
	}

	// Cria-se uma estrutura do tipo Options e inicia-se o seu preenchimento de
	// informacoes
	var opt Options
	opt.Hostname = v1.GetString("hostname")
	opt.Port = v1.GetInt("port")

	opt.Loglevel = v1.GetString("loglevel")
	//
	// Config PermissionDB
	//var cc PermissionDBConf

	// Cria uma nova instancia e associa as configuracoes de permissao do
	// provedor
	// A instancia eh instanciada vazia
	// Este sera preenchido ao ler as credenciais
	opt.PermissionDB = new(PermissionDBConf)

	// Preenche o ramo PermissionDB da estrutura opt com o tipo e as informacoes
	// de acesso ao
	// provedor que armazena as credenciais
	switch v1.GetString("credentials.type") {
	case "dynamodb":
		param := make(map[string]string)

		param["tableName"] = v1.GetString("credentials.tableName")
		param["region"] = v1.GetString("credentials.region")
		param["timeout"] = v1.GetString("credentials.timeout")
		opt.PermissionDB.Config = DBConf{param, "dynamodb"}

		log.Debugf("config: using dynamodb with table %s", v1.GetString("credentials.tableName"))

	case "csv":
		//path := v1.GetString("credentials.path")
		//var param map[string]interface{}
		if path := v1.GetString("credentials.path"); len(path) < 2 {
			log.Fatalf("config: Erro analisando config do provedor de credenciais %v", err)
		} else {
			param := make(map[string]string)
			param["CsvPath"] = path
			param["interval"] = v1.GetString("credentials.reload")
			opt.PermissionDB.Config = DBConf{param, "csv"}
		}
	case "s3":
		param := make(map[string]string)
		param["bucket"] = v1.GetString("credentials.bucket")
		param["key"] = v1.GetString("credentials.key")
		param["region"] = v1.GetString("credentials.region")
		//interval := v1.GetInt("credentials.reload")
		//if interval < 10 {
		//	log.Fatal("Intervalo de recarga de credenciais não pode ser < 10")
		//}
		param["interval"] = v1.GetString("credentials.reload")
		opt.PermissionDB.Config = DBConf{param, "s3"}
	case "mongo":
		param := make(map[string]string)
		param["uri"] = v1.GetString("credentials.uri")
		param["database"] = v1.GetString("credentials.database")
		opt.PermissionDB.Config = DBConf{param, "mongo"}
		log.Debug("config: using mongo with %s, %s", v1.GetString("credentials.uri"), v1.GetString("credentials.database"))
	default:
		log.Fatal("config: Nenhum provedor de credenciais configurado")
	}

	//Configuracoes de AsyncDb

	// Preenche as informacoes de quanto tempo as informacoes obtidas serao
	// consideradas validas
	opt.PermissionDB.CacheClean = time.Duration(v1.GetInt64("credentialCache.cleanup")) * time.Minute
	opt.PermissionDB.CacheInterval = time.Duration(v1.GetInt64("credentialCache.expiration")) * time.Minute

	// Verifica se as configuracoes lidas sao validas para o funcionamento desta
	// aplicacao
	if opt.PermissionDB.CacheInterval > opt.PermissionDB.CacheClean || opt.PermissionDB.CacheInterval < 30 {
		log.Fatal("config: Tempo de vida do cache minimo 30s, tempo de limpeza deve ser superior ao tempo de vida")
	}

	// JWT Config
	//var jwtConf jwtConf
	// inicia-se a definicao de informacoes de configuracao do JWT que sera
	// emitido
	opt.JwtConf = new(jwtConf)
	// Chave de assinatura dos tokens emitidos pelo GW
	opt.JwtConf.RsaPrivateFile = v1.GetString("jwt.rsaprivatefile")
	opt.JwtConf.LocalIssuer = v1.GetString("jwt.localIssuer")
	opt.JwtConf.Kid = v1.GetString("jwt.kid")
	opt.JwtConf.TokenLifetime = time.Duration(v1.GetInt64("jwt.tokenLifetime"))

	// Adiciona a estrutura opt os caminhos que serao ignorados, descritos pela
	// configuracao lida anteriormente
	ignorePaths := v1.GetStringMap("ignorePaths")
	for e := range ignorePaths {
		// captura um path
		path := v1.GetString(fmt.Sprintf("ignorePaths.%s", e))
		// Adiciona ao final do vetor IgnorePaths
		opt.IgnorePaths = append(opt.IgnorePaths, path)
		log.Debugf("config: ignore path: %s", path)
	}
	//var issAllow  []IssuerConf

	// Cria um vetor termporario de lista de issuers
	issuers := v1.GetStringMap("jwt.issuers")

	// Cria um vetor do tipo IssuerConf
	var ic []IssuerConf

	// preenche o vetor IssuerConfig com informacoes de Issuer e URL e adiciona
	for k := range issuers {
		iss := v1.GetString(fmt.Sprintf("jwt.issuers.%s.iss", k))
		url := v1.GetString(fmt.Sprintf("jwt.issuers.%s.url", k))
		// INFO Voce esta definindo opt.JwtConf.Issuers aqui e logo que termina
		// o For. Remova a linha depois do for pra evitar processamento
		// desnecessario
		opt.JwtConf.Issuers = append(ic, IssuerConf{iss, url})
	}

	// INFO instrucao desnecessaria
	opt.JwtConf.Issuers = ic

	// Define informacoes de OIDC
	opt.Oidc = OidcConf{v1.GetString("oidc.hostname"), v1.GetString("oidc.path")}

	// Define informacoes de Auth e Claim
	opt.AuthHeader = v1.GetString("jwt.authHeader")
	log.Debugf("config: authHeader: %s", opt.AuthHeader)
	opt.ClaimString = v1.GetString("jwt.claimString")
	log.Debugf("config: claimString: %s", opt.ClaimString)
	//opt.IgnoreList

	//fatal(err)

	// Issuer usado pelo GW
	//localIssuer := v1.GetString("jwt.localissuer")
	//log.Debugf("local Issuer: %s", localIssuer)

	// Retorna o arquivo de configuracao construido
	// Possui informacoes de acesso ao provedor de credencial, JWT, etc.
	return opt, err
}
