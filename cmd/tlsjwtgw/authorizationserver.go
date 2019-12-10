package main

import (
	"context"
	"errors"
	c "extauth/cmd/config"
	"extauth/cmd/credential"
	"extauth/cmd/jwthandler"
	"fmt"
	"github.com/envoyproxy/go-control-plane/envoy/api/v2/core"
	auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v2"
	envoytype "github.com/envoyproxy/go-control-plane/envoy/type"
	"github.com/gogo/googleapis/google/rpc"
	"github.com/patrickmn/go-cache"
	log "github.com/sirupsen/logrus"
	//"crypto/x509"
	"strconv"
	"strings"
)

// empty struct because this isn't a fancy example
type AuthorizationServer struct {
	credentialCache *cache.Cache
	credentialMap   *credential.Store
	jwtinstance     *jwthandler.JwtHandler
	Options *c.Options
}


//CacheToken

func (a *AuthorizationServer) BuildToken(principal credential.Principal, clientId string) (string, bool) {

	var hash strings.Builder
	hash.WriteString(principal.Fingerprint)
	hash.WriteString(":")
	hash.WriteString(principal.Scope)

	cachedToken, found := a.credentialCache.Get(hash.String())

	if found {
		log.Debug("Cache encontrado ", cachedToken.(string))
		return cachedToken.(string), true
	} else {
		log.Debug("Nao encontrei credentialCache para", hash.String())

		log.Debugf("Validando fingerprint: %s, scope: %s", principal.Fingerprint, principal.Scope)

		claims, okClaim := a.credentialMap.Validate(principal)
		// Se retornou ok, carrega as claims no jwt
		if len(principal.Fingerprint) == 64 && okClaim {
			log.Debugf("Fingerprint %s valida para scope: %s ", principal.Fingerprint, principal.Scope)

			// Build token
			var myClaims map[string][]string
			myClaims = make(map[string][]string)
			myClaims["aud"]=claims.Permission
			tokenString, err := a.jwtinstance.SignToken(myClaims, clientId)

			if err != nil {
				log.Errorf("error sign Token: %v", err)
				return "", false
			}
			a.credentialCache.Set(hash.String(), tokenString, cache.DefaultExpiration)
			return tokenString, true
		}
		return "", false

	}
}

// FromAuthHeader is a "TokenExtractor" that takes a given Authorization Header and extracts
// the JWT token
func FromAuthHeader(authHeader string) (string, error) {
	if authHeader == "" {
		return "", nil // No error, just no token
	}

	authHeaderParts := strings.Fields(authHeader)
	if len(authHeaderParts) != 2 || strings.ToLower(authHeaderParts[0]) != "bearer" {
		return "", errors.New("authorization header format must be Bearer {token}")
	}

	return authHeaderParts[1], nil
}

type ClientcertHeaderParts struct {
	hash    string
	subject string
}

func (chp *ClientcertHeaderParts) GetCn() (string, error) {
	var s, _ = strconv.Unquote(chp.subject)

	parts := strings.Split(s, ",")
	if len(parts) < 1 {
		return "", fmt.Errorf("nao recebi informacao suficiente do certificado")
	}
	if strings.ToLower(parts[0][0:2]) == "cn" {
		return parts[0][3:], nil
	} else {
		return "", fmt.Errorf("string do certificado invalida:%s", s)
	}
}

// FromFingerprint extrai os dados do certificao header x-forwarded-client-cert exportado pelo mTLS

func FromClientCertHeader(ClientcertHeader string) (*ClientcertHeaderParts, error) {

	//var CertParts *ClientcertHeaderParts
	CertParts := new(ClientcertHeaderParts)

	if ClientcertHeader == "" {
		return CertParts, nil // No error, just no token
	}

	HeadersParts := strings.Split(ClientcertHeader, ";")
	if len(HeadersParts) != 2 {
		return CertParts, fmt.Errorf("certificate Information Header invalid")
	}
	log.Debugf("Certificate Header: %s, subjetct: %s", HeadersParts[0], HeadersParts[1])

	for i := 0; i < len(HeadersParts); i++ {
		if strings.ToLower(HeadersParts[i][0:4]) == "hash" {
			parts := strings.Split(HeadersParts[i], "=")
			if len(parts) < 2 {
				return CertParts, errors.New("fingerprint header format must be Hash={fingerprint}")
			} else {
				CertParts.hash = parts[1]
			}
		}
		if strings.ToLower(HeadersParts[i])[0:7] == "subject" {
			subjectString := HeadersParts[i][8:]
			CertParts.subject = subjectString
		}

	}
	if len(CertParts.hash) > 1 && len(CertParts.subject) > 1 {
		return CertParts, nil
	}else{
		return CertParts, fmt.Errorf("certificate Information Header invalid")
	}
}

// Check implementa a logica de permissionamento do gw
// Caso a conexao tenha uma autenticacao mTLS valida e o fingerprint dela for valido no validador,
// retornara ok com um jws contendo as permissoes ligadas ao fingerprint
// Se um Bearer token valido for enviado retorna tambem um Ok
// Se o acesso for para o servidor de autenticacao /auth configurado, o acesso e validado
// em tods os outros casos a conexao e barrada
func (a *AuthorizationServer) Check(ctx context.Context, req *auth.CheckRequest) (*auth.CheckResponse, error) {

	// Return fail for Options
	//FIXME Preciso construir um bloco unico de respostas com case para result
	// Caso UNAUTHENTICATED com Body customizado
	if !a.Options.EnableOptions {
		if req.Attributes.Request.Http.Method == "OPTIONS" {
			return &auth.CheckResponse{
				Status: &rpc.Status{
					Code: int32(rpc.UNAUTHENTICATED),
				},
				HttpResponse: &auth.CheckResponse_DeniedResponse{
					DeniedResponse: &auth.DeniedHttpResponse{
						Status: &envoytype.HttpStatus{
							Code: envoytype.StatusCode_Unauthorized,
						},
						Body: "<em>Options Invalid<em>",
					},
				},
			}, nil
		}
	}

	//Header com fingerprint dos dados do certificado
	clientCertHeader, _ := req.Attributes.Request.Http.Headers["x-forwarded-client-cert"]
	log.Debugf(clientCertHeader)

	//Header de scopo de claims
	scopeString, _ := req.Attributes.Request.Http.Headers["x-scope-audience"]
	//Fixme controle de entrada do scope tem de ser melhor que isso
	if len(scopeString) > 20 {
		scopeString = ""
	}

	authHeader := a.Options.AuthHeader

	//Header JWT de autorizacao
	authorizationHeader, _ := req.Attributes.Request.Http.Headers[authHeader]

	//Recupera o JWT
	authz, authzErr := FromAuthHeader(authorizationHeader)

	// Obtem o HOSTNAME e o PATH da request
	hostname := req.Attributes.Request.Http.Host
	path := req.Attributes.Request.Http.Path

	log.Debugf("OIDC, hostname: %s, path: %s",hostname,path)

	//Healthz

	// Verificando se o request e destinado ao endpoint de autenticacao interno
	//FIXME necessario um bloco de retorno unico com case
	// Caso Allowed sem modificacao
	if hostname == a.Options.Oidc.Hostname && len(path) > len(a.Options.Oidc.Path) && a.Options.Oidc.Path == path[:len(a.Options.Oidc.Path)] {
		log.Debugf("Auth request")
		return &auth.CheckResponse{
			Status: &rpc.Status{
				Code: int32(rpc.OK),
			},
			HttpResponse: &auth.CheckResponse_OkResponse{
				OkResponse: &auth.OkHttpResponse{},
			},
		}, nil
	}

	// Se receber um Bearer token Valido, verifica a autorizadao
	if authzErr == nil && len(authz) > 0 {
		ok, err := a.jwtinstance.ValidateJwt(authz)
		log.Debugf("Received Authorization for: %s, result %v", authz, ok)
		// Response ok par token valido e false para token invalido
		if ok {
			//FIXME necessario um bloco de retorno unico com case
			// Caso Allowed sem modificacao
			return &auth.CheckResponse{
				Status: &rpc.Status{
					Code: int32(rpc.OK),
				},
				HttpResponse: &auth.CheckResponse_OkResponse{
					OkResponse: &auth.OkHttpResponse{},
				},
			}, nil
		} else {
			log.Debugf("Received Error %s", err)
			//FIXME necessario um bloco de retorno unico com case
			// Caso UNAUTHENTICATED com Body custom
			return &auth.CheckResponse{
				Status: &rpc.Status{
					Code: int32(rpc.UNAUTHENTICATED),
				},
				HttpResponse: &auth.CheckResponse_DeniedResponse{
					DeniedResponse: &auth.DeniedHttpResponse{
						Status: &envoytype.HttpStatus{
							Code: envoytype.StatusCode_Unauthorized,
						},
						Body: "<em>Invalid JWT<em>",
					},
				},
			}, nil
		}
	}

	// Obtem o fingerprint do mTLS
	certParts, certPartsErr := FromClientCertHeader(clientCertHeader)

	//Se tiver um fingerprint permitido Gera o JWT com as permissoes e aceita a requisicao
	if certPartsErr == nil && len(certParts.hash) > 0 {
		log.Debugf("Fingerprint: %s recebido", certParts.hash)
		var cn string
		var err error

		// Se o certificado nao tem CN, nao tem subject
		if cn, err = certParts.GetCn(); err != nil {
			cn = ""
		}

		token, okToken := a.BuildToken(credential.Principal{Fingerprint: certParts.hash, Scope: scopeString}, cn)

		if okToken {

			tokenSha := fmt.Sprintf("Bearer %s", token)

			log.Debugf("Build token: %s", tokenSha)
			//FIXME necessario um bloco de retorno unico com case
			// Caso UNAUTHENTICATED com Header Custom
			return &auth.CheckResponse{
				Status: &rpc.Status{
					Code: int32(rpc.OK),
				},
				HttpResponse: &auth.CheckResponse_OkResponse{
					OkResponse: &auth.OkHttpResponse{
						Headers: []*core.HeaderValueOption{
							{
								Header: &core.HeaderValue{
									Key:   authHeader,
									Value: tokenSha,
								},
							},
						},
					},
				},
			}, nil
		}
	}else{
		log.Debugf("Error certificate parts incomplete %v",certPartsErr)
	}

	// Sem Autorizacao, mTLS, ou caminho permitido, retorna falha de autenticacao
	log.Debugf("Retornando unauth\n")
	//FIXME necessario um bloco de retorno unico com case
	// Caso UNAUTHENTICATED com Body Custom
	return &auth.CheckResponse{
		Status: &rpc.Status{
			Code: int32(rpc.UNAUTHENTICATED),
		},
		HttpResponse: &auth.CheckResponse_DeniedResponse{
			DeniedResponse: &auth.DeniedHttpResponse{
				Status: &envoytype.HttpStatus{
					Code: envoytype.StatusCode_Unauthorized,
				},
				Body: "<em>No auth access to protected resource<em>",
			},
		},
	}, nil

}
