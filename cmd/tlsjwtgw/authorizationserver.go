package main

import (
	"context"
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
	cache *cache.Cache
}

//CacheToken

func (a *AuthorizationServer) GetToken(permission credential.Permission) (string, bool) {

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

		claims, okClaim := configMap.Validate(permission)
		// Se retornou ok, carrega as claims no jwt
		if len(permission.Fingerprint) == 64 && okClaim {
			log.Debugf("Valid fingerprint %s for path: %s ", permission.Fingerprint, permission.Scope)

			// Build token
			tokenString, err := jwthandler.SignToken(claims.Audience, signKey, 60)

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

// Check verifica o tls fingerprint contra a base corrente e gera o tls fingerprint
func (a *AuthorizationServer) Check(ctx context.Context, req *auth.CheckRequest) (*auth.CheckResponse, error) {

	//Header  com fingerprint de certificado
	clientCert, ok := req.Attributes.Request.Http.Headers["x-forwarded-client-cert"]
	var splitHash []string
	if ok {
		splitHash = strings.Split(clientCert, "Hash=")
	}

	log.Debugf("header: %s\ncode:%d", clientCert, len(splitHash))

	//Header de scopo de claims
	scope, ok := req.Attributes.Request.Http.Headers["x-scope-audience"]

	//Verifica se possui um fingerprint a verificar
	if len(splitHash) == 2 {

		//extraindo fingerprint
		fingerprint := splitHash[1]
		log.Debugf("received fingerprint %s", fingerprint)

		token, okToken := a.GetToken(credential.Permission{fingerprint, scope})

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
