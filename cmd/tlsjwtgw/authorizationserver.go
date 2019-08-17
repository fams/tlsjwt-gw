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
	"strings"
)

// empty struct because this isn't a fancy example
type AuthorizationServer struct {
	credentialCache *cache.Cache
	credentialMap   *credential.CredentialMap
	jwtinstance     *jwthandler.JwtHandler
//	Oidc 			*c.OidcConf
	Options			*c.Options
}

//type oidcConf struct{
//	hostname string
//	path string
//}
//CacheToken

func (a *AuthorizationServer) BuildToken(permission credential.Permission) (string, bool) {

	var hash strings.Builder
	hash.WriteString(permission.Fingerprint)
	hash.WriteString(":")
	hash.WriteString(permission.Scope)

	cachedToken, found := a.credentialCache.Get(hash.String())

	if found {
		log.Debug("Cache encontrado ", cachedToken.(string))
		return cachedToken.(string), true
	} else {
		log.Debug("Nao encontrei credentialCache para", hash.String())

		log.Debugf("Validando fingerprint: %s, scope: %s", permission.Fingerprint, permission.Scope)

		claims, okClaim := a.credentialMap.Validate(permission)
		// Se retornou ok, carrega as claims no jwt
		if len(permission.Fingerprint) == 64 && okClaim {
			log.Debugf("Fingerprint %s valida para scope: %s ", permission.Fingerprint, permission.Scope)

			// Build token
			tokenString, err := a.jwtinstance.SignToken(claims.Audience, 60)

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

// FromAuthHeader is a "TokenExtractor" that takes a give request and extracts
// the JWT token from the Authorization header.
func FromAuthHeader(authHeader string) (string, error) {
	if authHeader == "" {
		return "", nil // No error, just no token
	}

	authHeaderParts := strings.Fields(authHeader)
	if len(authHeaderParts) != 2 || strings.ToLower(authHeaderParts[0]) != "bearer" {
		return "", errors.New("Authorization header format must be Bearer {token}")
	}

	return authHeaderParts[1], nil
}

// FromFingerprint extrai o fingerprint do cabecalho exportado pelo mTLS

func FromFingerprintHeader(FingerprintHeader string) (string, error) {
	if FingerprintHeader == "" {
		return "", nil // No error, just no token
	}

	FingerprintHeaderParts := strings.Split(FingerprintHeader, "=")
	//log.Debugf("Fingerprint: %s",FingerprintHeader)
	if len(FingerprintHeaderParts) != 2 || strings.ToLower(FingerprintHeaderParts[0]) != "hash" {
		return "", errors.New("Fingerprint header format must be Hash={fingerprint}")
	}

	return FingerprintHeaderParts[1], nil
}

// Check implementa a logica de permissionamento do gw
// Caso a conexao tenha uma autenticacao mTLS valida e o fingerprint dela for valido no validador,
// retornara ok com um jws contendo as permissoes ligadas ao fingerprint
// Se um Bearer token valido for enviado retorna tambem um Ok
// Se o acesso for para o servidor de autenticacao /auth configurado, o acesso e validado
// em tods os outros casos a conexao e barrada
func (a *AuthorizationServer) Check(ctx context.Context, req *auth.CheckRequest) (*auth.CheckResponse, error) {

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
						Body: "<em>Optons Invalid<em>",
					},
				},
			}, nil
		}
	}
	//Header  com fingerprint de certificado
	clientCertHeader, _ := req.Attributes.Request.Http.Headers["x-forwarded-client-cert"]

	//Header de scopo de claims
	scopeHeader, _ := req.Attributes.Request.Http.Headers["x-scope-audience"]

	//Header JWT de authorizacao
	authorizationHeader, _ := req.Attributes.Request.Http.Headers["authorization"]

	//Authorization JWT
	authz, authzErr := FromAuthHeader(authorizationHeader)

	// Hostname and path to Auth
	hostname := req.Attributes.Request.Http.Host
	path := req.Attributes.Request.Http.Path

	// Verificando se o acesso e para o endpoint de autenticacao interno
	if hostname == a.Options.Oidc.Hostname && a.Options.Oidc.Path == path[:len( a.Options.Oidc.Hostname )]{
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

	// Se receber um Bearer token Valido e ele é autorizado, aceita a requisicao nao sendo autorizado retorna unauth
	if authzErr == nil && len(authz) > 0 {
		ok, err := a.jwtinstance.ValidateJwt(authz)
		log.Debugf("Received Authorization for: %s, result %s", authz, ok)
		if ok {
			return &auth.CheckResponse{
				Status: &rpc.Status{
					Code: int32(rpc.OK),
				},
				HttpResponse: &auth.CheckResponse_OkResponse{
					OkResponse: &auth.OkHttpResponse{},
				},
			}, nil
		}else{
			log.Debugf("Received Error %s",err)
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
	fingerprint, fingerprintErr := FromFingerprintHeader(clientCertHeader)
	log.Debugf("Fingerprint: %s recebido\n Error: %v",fingerprint,fingerprintErr)

	//Se tiver um fingerprint permitido Gera o JWT com as permissoes e aceita a requisicao
	if fingerprintErr == nil || len(fingerprint) > 0 {

		log.Debugf("received fingerprint %s", fingerprint)

		token, okToken := a.BuildToken(credential.Permission{fingerprint, scopeHeader})

		if okToken {

			tokenSha := fmt.Sprintf("Bearer %s", token)

			log.Debugf("Build token: %s", tokenSha)
			return &auth.CheckResponse{
				Status: &rpc.Status{
					Code: int32(rpc.OK),
				},
				HttpResponse: &auth.CheckResponse_OkResponse{
					OkResponse: &auth.OkHttpResponse{
						Headers: []*core.HeaderValueOption{
							{
								Header: &core.HeaderValue{
									Key:   "Authorization",
									Value: tokenSha,
								},
							},
						},
					},
				},
			}, nil
		}
	}

	// Sem Autorizacao, mTLS, ou caminho permitido, retorna falha de autenticacao
	log.Debugf("Retornando unauth\n")
	return &auth.CheckResponse{
		Status: &rpc.Status{
			Code: int32(rpc.UNAUTHENTICATED),
		},
		HttpResponse: &auth.CheckResponse_DeniedResponse{
			DeniedResponse: &auth.DeniedHttpResponse{
				Status: &envoytype.HttpStatus{
					Code: envoytype.StatusCode_Unauthorized,
				},
				Body: "<em>Unauth access to protected resource<em>",
			},
		},
	}, nil
}