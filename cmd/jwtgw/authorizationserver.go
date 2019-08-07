package main

import (
	"context"

	"fmt"
	"github.com/envoyproxy/go-control-plane/envoy/api/v2/core"
	auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v2"
	envoytype "github.com/envoyproxy/go-control-plane/envoy/type"

	"github.com/gogo/googleapis/google/rpc"

	log "github.com/sirupsen/logrus"
	"net/url"
	"strings"
)

// empty struct because this isn't a fancy example
type AuthorizationServer struct{}

// Check verifica o tls fingerprint contra a base corrente e gera o tls fingerprint
func (a *AuthorizationServer) Check(ctx context.Context, req *auth.CheckRequest) (*auth.CheckResponse, error) {
	clientCert, ok := req.Attributes.Request.Http.Headers["x-forwarded-client-cert"]
	var splitHash []string
	if ok {
		splitHash = strings.Split(clientCert, "Hash=")
	}
	log.Debugf("header: %s\ncode:%d", clientCert, len(splitHash))

	u, _ := url.Parse(req.Attributes.Request.Http.Path)
	splitPath := strings.Split(u.Path, "/")

	if len(splitHash) == 2 && len(splitPath) > 2 {
		fingerprint := splitHash[1]
		log.Debugf("received fingerprint %s", fingerprint)

		var serviceTag strings.Builder
		serviceTag.WriteString("/")
		serviceTag.WriteString(splitPath[1])
		serviceTag.WriteString("/")
		serviceTag.WriteString(splitPath[2])

		//Valida o Fingerprint
		claims, okClaim := configMap.Validate(Permission{fingerprint, serviceTag.String()})

		// Se retornou ok, carrega as claims no jwt
		if len(fingerprint) == 64 && okClaim {
			log.Debugf("Valid fingerprint %s for path: %s ", fingerprint, serviceTag.String())

			// Build token
			token, err := GetToken(fingerprint, serviceTag.String(), claims.Audience, signKey, 60)

			if err != nil {
				log.Fatalf("failed to listen: %v", err)
			}
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
