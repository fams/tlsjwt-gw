package main

import (
	"context"

	"extauth/cmd/authzman"
	c "extauth/cmd/config"
	"extauth/cmd/jwthandler"
	"fmt"

	auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v2"
	"github.com/patrickmn/go-cache"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	log "github.com/sirupsen/logrus"

	//"crypto/x509"
	"strings"
)

var (
	// Contador de quantas credencias de sucesso foram realizadas
	metricsJwtTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "gtw_jwt_total",
		Help: "O numero total de credenciais, tanto insucesso como sucesso",
	},
		[]string{"id"},
	)
	// Contador de quantas credencias foram concedidas
	metricsJwtAceitoTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "gtw_jwt_aceito_total",
		Help: "O numero total de jwt validados",
	},
		[]string{"id"},
	)
	// Contador de quantas credencias que nao foram cometidas
	metricsJwtNegadoTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "gtw_jwt_negado_total",
		Help: "O numero total de jwt rejeitados",
	},
		[]string{"id"},
	)
)

var (
	// Contador para requisicoes mtls
	metricsMtlsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "gtw_mtls_total",
		Help: "O numero total de pedidos de autenticacao por mTLS",
	},
		[]string{"id"},
	)

	metricsMtlsAceitoTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "gtw_mtls_aceito_total",
		Help: "O numero total de pedidos de autenticacao por mTLS concedidos",
	},
		[]string{"id"},
	)

	metricsMtlsNegadoTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "gtw_mtls_negado_total",
		Help: "O numero total de pedidos de autenticacao por mTLS rejeitados",
	},
		[]string{"id"},
	)

	// Contador de cachehit
	metricsMtlsCacheHit = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "gtw_mtls_cache_hit_total",
		Help: "O numero total de cache HIT de requisicoes mTLS",
	},
		[]string{"id"},
	)
)

var (
	// Contador para total de todas as requisicoes
	metricsRequisicaoTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "gtw_req_total",
		Help: "O numero total de pedidos de autenticacao, tanto JWT quanto mTLS",
	},
		[]string{"id"},
	)
)

// AuthorizationServer - Estrutura de controle do servidor
type AuthorizationServer struct {
	credentialCache   *cache.Cache
	PermissionManager authzman.AuthzDB
	jwtinstance       *jwthandler.JwtHandler
	Options           *c.Options
}

// CacheGet -
func (a *AuthorizationServer) CacheGet(principal authzman.PermissionClaim) (string, bool) {
	var hash strings.Builder
	hash.WriteString(principal.Fingerprint)
	hash.WriteString(":")
	hash.WriteString(principal.Scope)

	log.Debugf("authserver: checando hit de: %s", hash.String())

	cachedToken, found := a.credentialCache.Get(hash.String())
	if found {
		log.Debug("authserver: Cache encontrado ", cachedToken.(string))
		return cachedToken.(string), true
	} else {
		log.Debugf("authserver: nenhum hit encontrado")
		return "", false
	}
}

// CacheSet -
func (a *AuthorizationServer) CacheSet(principal authzman.PermissionClaim, tokenString string) {
	var hash strings.Builder
	hash.WriteString(principal.Fingerprint)
	hash.WriteString(":")
	hash.WriteString(principal.Scope)
	log.Debugf("authserver: adicionando cache: %s, %s", hash.String(), tokenString)
	a.credentialCache.Set(hash.String(), tokenString, cache.DefaultExpiration)
}

// GetAuthorizationToken - Verifica se existe token em cache, se não tenta obter credenciais da base configurada
func (a *AuthorizationServer) GetAuthorizationToken(permissionClaim authzman.PermissionClaim, clientId string) (string, bool) {

	if len(permissionClaim.Fingerprint) != 64 {
		log.Debugf("authserver: o certificate fingerprint %s, esta em formato invalido", permissionClaim.Fingerprint)
		return "", false
	}

	//Busca em cache
	cachedToken, found := a.CacheGet(permissionClaim)
	if found {
		log.Debug("authserver: ------- CACHE ENCONTRADO ", cachedToken)
		metricsMtlsCacheHit.WithLabelValues(a.Options.AppID).Inc()

	} else {
		log.Debugf("authserver: nao encontrei credentialCache para %s, scope: %s, buscando no provedor", permissionClaim.Fingerprint, permissionClaim.Scope)

		//Verifica se existem credenciais para esse claim
		claims, okClaim := a.PermissionManager.Validate(permissionClaim, a.Options.AppID)
		// Se retornou ok, carrega as claims no jwt
		if okClaim {
			log.Debugf("authserver: encontrei fingerprint %s valida para scope: %s ", permissionClaim.Fingerprint, permissionClaim.Scope)

			// Claims map
			myClaims := make(map[string][]string)
			claimString := a.Options.ClaimString
			myClaims[claimString] = claims.Permissions

			tokenString, err := a.jwtinstance.GetSignedToken(myClaims, clientId)

			if err != nil {
				log.Errorf("authserver: error sign Token: %v", err)
				return "", false
			}
			//Armazena em cache e retorna
			a.CacheSet(permissionClaim, tokenString)
			return tokenString, true
		}
		return "", false
	}

	return cachedToken, true
}

// Check implementa a logica de permissionamento do gw
// Caso a conexao tenha uma autenticacao mTLS valida e o fingerprint dela for valido no validador,
// retornara ok com um jws contendo as permissoes ligadas ao fingerprint
// Se um Bearer token valido for enviado retorna tambem um Ok
// Se o acesso for para o servidor de autenticacao /auth configurado, o acesso e validado
// em tods os outros casos a conexao e barrada
func (a *AuthorizationServer) Check(ctx context.Context, req *auth.CheckRequest) (*auth.CheckResponse, error) {

	metricsRequisicaoTotal.WithLabelValues(a.Options.AppID).Inc()

	// Return fail for Options
	// Caso UNAUTHENTICATED com Body customizado
	if !a.Options.EnableOptions {
		if req.Attributes.Request.Http.Method == "OPTIONS" {
			response, _ := BuildResponse(1, "<em>Options Invalid<em>", nil)
			return response, nil
		}
	}
	//
	// Se receber um Header JWT de autorizacao, tenta validar por ele
	//
	authHeader := a.Options.AuthHeader
	authorizationHeader, _ := req.Attributes.Request.Http.Headers[authHeader]

	//Recupera o JWS se existir
	authz, authzErr := FromAuthHeader(authorizationHeader)
	// Se receber um Bearer token Valido, verifica a autorizadao
	if authzErr == nil && len(authz) > 0 {
		ok, err := a.jwtinstance.ValidateJwt(authz)
		metricsJwtTotal.WithLabelValues(a.Options.AppID).Inc()
		log.Debugf("authserver: Received Authorization for: %s, result %v", authz, ok)
		// Response ok par token valido e false para token invalido
		if ok {
			metricsJwtAceitoTotal.WithLabelValues(a.Options.AppID).Inc()
			// Caso Allowed sem modificacao
			response, _ := BuildResponse(0, "", nil)
			return response, nil
		} else {
			metricsJwtNegadoTotal.WithLabelValues(a.Options.AppID).Inc()
			log.Debugf("authserver: Received Error %s", err)
			// Caso UNAUTHENTICATED com Body custom
			response, _ := BuildResponse(1, "<em>Invalid JWT<em>", nil)
			return response, nil
		}
	}

	//
	// Verificando se o request e destinado ao endpoint de autenticacao interno

	log.Debugf("authserver: verificando se o request eh destinado ao endpoint de autenticacao interno")
	// Obtem o HOSTNAME e o PATH da request
	hostname := req.Attributes.Request.Http.Host
	path := req.Attributes.Request.Http.Path

	log.Debugf("authserver: OIDC, hostname: %s, path: %s", hostname, path)

	// Caso Allowed sem modificacao
	for i := 0; i < len(a.Options.Oidc); i++ {
		log.Debugf("%d - Hostname: %s; Path: %s", i, a.Options.Oidc[i].Hostname, a.Options.Oidc[i].Path)
		if hostname == a.Options.Oidc[i].Hostname &&
			len(path) > len(a.Options.Oidc[i].Path) &&
			a.Options.Oidc[i].Path == path[:len(a.Options.Oidc[i].Path)] {

			log.Debugf("authserver: Auth request")
			response, _ := BuildResponse(0, "", nil)
			return response, nil
		}
	}
	log.Debugf("authserver: autenticacao OIDC nao aplicada")

	log.Debugf("authserver: iniciando verificando JWT")
	//
	// Autorizacao por mTLS
	//
	//Header com fingerprint dos dados do certificado
	clientCertHeader, _ := req.Attributes.Request.Http.Headers["x-forwarded-client-cert"]
	log.Debugf("authserver: %s", clientCertHeader)

	//Header de scopo de claims
	scopeString, _ := req.Attributes.Request.Http.Headers["x-scope-audience"]

	// Se scope for > 20 ja retorna deny
	if len(scopeString) > 20 {
		response, _ := BuildResponse(1, "<em>No allowed auth method to access protected resource<em>", nil)
		return response, nil
	}

	// Obtem dados do certificado
	certParts, certPartsErr := FromClientCertHeader(clientCertHeader)

	//Se tiver um fingerprint permitido Gera o JWT com as permissoes e aceita a requisicao
	if certPartsErr == nil && len(certParts.hash) > 0 {
		log.Debugf("authserver: Fingerprint: %s recebido", certParts.hash)

		//Se possivel, obtem o cn para construir o subject do token
		cn, _ := certParts.GetCn()

		// requisicao de autorizacao
		permissionClaim := authzman.PermissionClaim{Fingerprint: certParts.hash, Scope: scopeString}

		// Verificar o cache, se exitir, retorna o cache, se não existir valida o token, se estiver válido constroi o
		// token, salva em cache e retorna o header, se não for válido, passa para o caso não autorizado
		token, okToken := a.GetAuthorizationToken(permissionClaim, cn)
		metricsMtlsTotal.WithLabelValues(a.Options.AppID).Inc()
		if okToken {
			tokenSha := fmt.Sprintf("Bearer %s", token)
			log.Debugf("authserver: Build token: %s size:%d", tokenSha, len(tokenSha))
			metricsMtlsAceitoTotal.WithLabelValues(a.Options.AppID).Inc()
			// Caso UNAUTHENTICATED com Header Custom
			response, _ := BuildResponse(0, "", map[string]string{authHeader: tokenSha})
			return response, nil
		} else {
			metricsMtlsNegadoTotal.WithLabelValues(a.Options.AppID).Inc()
		}
	} else {
		log.Debugf("authserver: Error certificate parts incomplete %v", certPartsErr)
	}

	// Sem Autorizacao, mTLS, ou caminho permitido, retorna falha de autenticacao
	log.Debugf("authserver: Retornando unauth\n")
	// INFO Nao esta retornando a resposta
	// Caso UNAUTHENTICATED com Body Custom
	response, _ := BuildResponse(1, "<em>No allowed auth method to access protected resource<em>", nil)
	return response, nil
}
