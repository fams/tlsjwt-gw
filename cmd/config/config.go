package config

import (
	"extauth/cmd/credential"
	"extauth/cmd/jwthandler"
	"fmt"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"time"
)


type credentialConf struct {
	Loader         credential.CredentialLoader
	LoaderInterval time.Duration
	CacheInterval  time.Duration
	CacheClean     time.Duration
}
type issuerConf ***REMOVED***face {
	iss() string
	jwks() jwthandler.Jwks
}

type jwtConf struct {
	RsaPrivateFile string
	LocalIssuer    string
	Issuers        *[]issuerConf
}

type Options struct {
	Loglevel     string
	Port         int
	Hostname     string
	Oidc         OidcConf
	Credentialdb *credentialConf
	JwtConf      *jwtConf
}

type OidcConf struct {
	Hostname string
	Path	string
}

// kill program
func fatal(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
// Default conf
func DefaultConf() (v1 *viper.Viper, err error) {
	// Definindo Padroes e lendo arquivo de configuracao
	v1, err = ReadConfig("extauth", map[string]***REMOVED***face{}{
		"port":     8080,
		"hostname": "localhost",
		"loglevel": "debug",
		"oidc": map[string]***REMOVED***face{}{
			"hostname": "localhost",
			"path":     "/auth",
		},

		"credentialCache": map[string]***REMOVED***face{}{
			"expiration": 31,
			"cleanup":    60,
		},
		"credentials": map[string]string{
			"type":   "csv",
			"config": "{\"path\": \"/auth/credential\"}",
			"path":   "/auth/credential",
			"reload": "60",
		},
		"jwt": map[string]***REMOVED***face{}{
			"rsaPrivateFile": "/auth/extauth.rsa",
			"localIssuer":    "tlsgw.local",
			"issuers": map[string]***REMOVED***face{}{
				"name1": map[string]***REMOVED***face{}{
					"iss": "tlsgw.local",
					"local": map[string]string{
						"rsaPublicFile": "/auth/extauth.rsa.pub",
					},
				},
				"name2": map[string]***REMOVED***face{}{
					"iss": "oauth.tlsgw.local",
					"remote": map[string]string{
						"url": "oauth.backend.local/uat/.well-known/jwks.json",
					},
				},
			},
		},
	})
	return
}

func ReadConfig(filename string, defaults map[string]***REMOVED***face{}) (*viper.Viper, error) {

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
	// Credentials
	//var cc credentialConf
	credentialdb := &credentialConf{}
	opt.Credentialdb = credentialdb

	***REMOVED***val := v1.GetInt("credentials.reload")
	if ***REMOVED***val < 10 {
		log.Fatal("Intervalo de recarga de credenciais não pode ser < 10")
	}

	opt.Credentialdb.LoaderInterval = time.Duration(***REMOVED***val)

	switch v1.GetString("credentials.type") {
	case "csv":
		//path := v1.GetString("credentials.path")
		//var param map[string]***REMOVED***face{}
		if path := v1.GetString("credentials.path"); len(path) < 2 {
			log.Fatalf("Erro analisando config do provedor de credenciais %v", err)
		} else {
			opt.Credentialdb.Loader = &credential.CsvLoader{CsvPath: path}
		}
	case "s3":
		bucket := v1.GetString("credentials.bucket")
		key := v1.GetString("credentials.key")
		region := v1.GetString("credentials.region")
		opt.Credentialdb.Loader = &credential.S3loader{BucketName: bucket, KeyName: key, Region: region}
	default:
		log.Fatal("Nenhum provedor de credenciais configurado")
	}

	opt.Credentialdb.CacheClean = time.Duration(v1.GetInt64("credentialCache.cleanup")) * time.Minute
	opt.Credentialdb.CacheInterval = time.Duration(v1.GetInt64("credentialCache.expiration")) * time.Minute
	if opt.Credentialdb.CacheInterval > opt.Credentialdb.CacheClean || opt.Credentialdb.CacheInterval < 30 {
		log.Fatal("Tempo de vida do cache minimo 30s, tempo de limpeza deve ser superior ao tempo de vida")
	}
	var jwtConf jwtConf
	opt.JwtConf = &jwtConf
	// Chave de assinatura dos tokens emitidos pelo GW
	opt.JwtConf.RsaPrivateFile = v1.GetString("jwt.rsaprivatefile")
	opt.JwtConf.LocalIssuer = v1.GetString("jwt.localIssuer")

	issuers := v1.GetStringMap("jwt.issuers")
	for k := range issuers {
		iss := v1.GetString(fmt.Sprintf("jwt.issuers.%s.iss", k))

		if local := v1.GetStringMapString(fmt.Sprintf("jwt.issuers.%s.local", k)); len(local) > 0 {
			jwksFile := local["rsaPublicFile"]
			log.Debugf("Issuer: %s\njwksFile: %s\n", iss, jwksFile)
		}
		if remote := v1.GetStringMapString(fmt.Sprintf("jwt.issuers.%s.remote", k)); len(remote) > 0 {
			url := remote["url"]
			log.Debugf("Issuer: %s\nurl: %s\n", iss, url)
		}
	}

	opt.Oidc = OidcConf{v1.GetString("oidc.hostname"), v1.GetString("oidc.path")}

	fatal(err)

	// Issuer usado pelo GW
	localIssuer := v1.GetString("jwt.localissuer")
	log.Debugf("Local Issuer: %s", localIssuer)

	return opt, err
}
