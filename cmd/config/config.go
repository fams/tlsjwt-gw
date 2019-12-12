package config

import (
	"strconv"

	//"extauth/cmd/jwthandler"
	"fmt"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"time"
)

type DBConf struct {
	Options map[string]string
	DBType  string
}

type PermissionDBConf struct {
	Config        DBConf
	CacheInterval time.Duration
	CacheClean    time.Duration
}

//type issuerConf interface {
//	iss() string
//	jwks() jwthandler.Jwks
//}

type jwtConf struct {
	RsaPrivateFile string
	LocalIssuer    string
	TokenLifetime  time.Duration
	Issuers        []IssuerConf
	Kid            string
}

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

type OidcConf struct {
	Hostname string
	Path     string
}

//// kill program
//func fatal(err error) {
//	if err != nil {
//		log.Fatal(err)
//	}
//}

type IssuerConf struct {
	Issuer string
	Url    string
}

// Default conf
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

func ReadConfig(filename string, defaults map[string]interface{}) (*viper.Viper, error) {

	v := viper.New()
	for key, value := range defaults {
		v.SetDefault(key, value)
	}
	v.SetConfigName(filename)
	v.AddConfigPath(".")
	v.AutomaticEnv()
	err := v.ReadInConfig()
	return v, err
}

func BuildOptions() (Options, error) {
	v1, err := DefaultConf()
	if err != nil {
		panic(fmt.Errorf("Error when reading config: %v\n", err))
	}
	var opt Options
	opt.Hostname = v1.GetString("hostname")
	opt.Port = v1.GetInt("port")

	opt.Loglevel = v1.GetString("loglevel")
	//
	// Config PermissionDB
	//var cc PermissionDBConf

	opt.PermissionDB = new(PermissionDBConf)

	switch v1.GetString("credentials.type") {
	case "csv":
		//path := v1.GetString("credentials.path")
		//var param map[string]interface{}
		if path := v1.GetString("credentials.path"); len(path) < 2 {
			log.Fatalf("Erro analisando config do provedor de credenciais %v", err)
		} else {
			param := make(map[string]string)
			param["CsvPath"] = path
			interval := v1.GetInt("credentials.reload")
			if interval < 10 {
				log.Fatal("Intervalo de recarga de credenciais não pode ser < 10")
			}
			param["interval"] = strconv.Itoa(interval)
			opt.PermissionDB.Config = DBConf{param, "csv"}
		}
	case "s3":
		param := make(map[string]string)
		param["bucket"] = v1.GetString("credentials.bucket")
		param["key"] = v1.GetString("credentials.key")
		param["region"] = v1.GetString("credentials.region")
		interval := v1.GetInt("credentials.reload")
		if interval < 10 {
			log.Fatal("Intervalo de recarga de credenciais não pode ser < 10")
		}
		param["interval"] = strconv.Itoa(interval)
		opt.PermissionDB.Config = DBConf{param, "s3"}
	case "mongo":
		param := make(map[string]string)
		param["hostname"] = v1.GetString("credentials.hostname")
		param["table"] = v1.GetString("credentials.table")
		opt.PermissionDB.Config = DBConf{param, "mongo"}


		log.Debug("using mongo with %s, %s", v1.GetString("credentials.hostname"), v1.GetString("credentials.table"))
	default:
		log.Fatal("Nenhum provedor de credenciais configurado")
	}

	//Configuracoes de AsyncDb

	opt.PermissionDB.CacheClean = time.Duration(v1.GetInt64("credentialCache.cleanup")) * time.Minute
	opt.PermissionDB.CacheInterval = time.Duration(v1.GetInt64("credentialCache.expiration")) * time.Minute

	if opt.PermissionDB.CacheInterval > opt.PermissionDB.CacheClean || opt.PermissionDB.CacheInterval < 30 {
		log.Fatal("Tempo de vida do cache minimo 30s, tempo de limpeza deve ser superior ao tempo de vida")
	}

	// JWT Config
	//var jwtConf jwtConf
	opt.JwtConf = new(jwtConf)
	// Chave de assinatura dos tokens emitidos pelo GW
	opt.JwtConf.RsaPrivateFile = v1.GetString("jwt.rsaprivatefile")
	opt.JwtConf.LocalIssuer = v1.GetString("jwt.localIssuer")
	opt.JwtConf.Kid = v1.GetString("jwt.kid")
	opt.JwtConf.TokenLifetime = time.Duration(v1.GetInt64("jwt.tokenLifetime"))

	ignorePaths := v1.GetStringMap("ignorePaths")
	for e := range ignorePaths {
		path := v1.GetString(fmt.Sprintf("ignorePaths.%s", e))
		opt.IgnorePaths = append(opt.IgnorePaths, path)
		log.Debugf("ignore path: %s", path)
	}
	//var issAllow  []IssuerConf

	issuers := v1.GetStringMap("jwt.issuers")

	var ic []IssuerConf
	for k := range issuers {
		iss := v1.GetString(fmt.Sprintf("jwt.issuers.%s.iss", k))
		url := v1.GetString(fmt.Sprintf("jwt.issuers.%s.url", k))
		opt.JwtConf.Issuers = append(ic, IssuerConf{iss, url})
	}
	opt.JwtConf.Issuers = ic

	opt.Oidc = OidcConf{v1.GetString("oidc.hostname"), v1.GetString("oidc.path")}

	opt.AuthHeader = v1.GetString("jwt.authHeader")
	log.Debugf("authHeader: %s", opt.AuthHeader)
	opt.ClaimString = v1.GetString("jwt.claimString")
	log.Debugf("claimString: %s", opt.ClaimString)
	//opt.IgnoreList

	//fatal(err)

	// Issuer usado pelo GW
	//localIssuer := v1.GetString("jwt.localissuer")
	//log.Debugf("local Issuer: %s", localIssuer)

	return opt, err
}
