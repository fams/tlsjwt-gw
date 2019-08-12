package main

import (
	"context"
	"errors"
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
	cache         *cache.Cache
	credentialMap *credential.CredentialMap
	jwtinstance   *jwthandler.JwtHandler
}

//CacheToken

func (a *AuthorizationServer) BuildToken(permission credential.Permission) (string, bool) {

	var hash strings.Builder
	hash.WriteString(permission.Fingerprint)
	hash.WriteString(":")
	hash.WriteString(permission.Scope)

	cachedToken, found := a.cache.Get(hash.String())

	if found {
		log.Debug("Cache encontrado ", cachedToken.(string))
		return cachedToken.(string), true
	} else {
		log.Debug("Nao encontrei cache para", hash.String())

		log.Debugf("Validando fingerprint: %s, scope: %s", permission.Fingerprint, permission.Scope)

		claims, okClaim := a.credentialMap.Validate(permission)
		// Se retornou ok, carrega as claims no jwt
		if len(permission.Fingerprint) == 64 && okClaim {
			log.Debugf("Valid fingerprint %s for path: %s ", permission.Fingerprint, permission.Scope)

			// Build token
			tokenString, err := a.jwtinstance.SignToken(claims.Audience, 60)

			if err != nil {
				log.Errorf("error sign Token: %v", err)
				return "", false
			}
			a.cache.Set(hash.String(), tokenString, cache.DefaultExpiration)
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
	if len(FingerprintHeaderParts) != 2 || strings.ToLower(FingerprintHeaderParts[0]) != "Hash" {
		return "", errors.New("Fingerprint header format must be Hash={fingerprint}")
	}

	return FingerprintHeaderParts[1], nil
}

// Check verifica o tls fingerprint contra a base corrente e gera o tls fingerprint
func (a *AuthorizationServer) Check(ctx context.Context, req *auth.CheckRequest) (*auth.CheckResponse, error) {

	//Header  com fingerprint de certificado
	clientCertHeader, _ := req.Attributes.Request.Http.Headers["x-forwarded-client-cert"]

	//Header de scopo de claims
	scopeHeader, _ := req.Attributes.Request.Http.Headers["x-scope-audience"]

	//Header JWT de authorizacao
	authorizationHeader, _ := req.Attributes.Request.Http.Headers["authorization"]

	//Authorization JWT
	bearer, bearerErr := FromAuthHeader(authorizationHeader)

	// Se receber um Authorization Valido retorna ok
	if bearerErr == nil && len(bearer) > 0 {
		log.Debugf("Received Authorization")
		return &auth.CheckResponse{
			Status: &rpc.Status{
				Code: int32(rpc.OK),
			},
			HttpResponse: &auth.CheckResponse_OkResponse{
				OkResponse: &auth.OkHttpResponse{},
			},
		}, nil
	}

	fingerprint, fingerprintErr := FromFingerprintHeader(clientCertHeader)

	//Se tiver um fingerprint permitido Gera os JWT e repassa
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
	// Sem Authorization ou mTLS retorna falha de autenticacao
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
				Body: "Not valid fingerprint",
			},
		},
	}, nil
}
