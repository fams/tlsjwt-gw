package main

import (
	"context"

	"extauth/cmd/authzman"
	c "extauth/cmd/config"
	"extauth/cmd/jwthandler"
	"fmt"

	auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v2"
	"github.com/patrickmn/go-cache"
	log "github.com/sirupsen/logrus"

	//"crypto/x509"
	"strings"
)

// AuthorizationServer - Estrutura de controle do servidor
type AuthorizationServer struct {
	credentialCache   *cache.Cache
	PermissionManager authzman.AuthzDB
	jwtinstance       *jwthandler.JwtHandler
	Options           *c.Options
}

func (a *AuthorizationServer) CacheGet(principal authzman.PermissionClaim) (string, bool) {
	var hash strings.Builder
	hash.WriteString(principal.Fingerprint)
	hash.WriteString(":")
	hash.WriteString(principal.Scope)

	cachedToken, found := a.credentialCache.Get(hash.String())
	if found {
		log.Debug("Cache encontrado ", cachedToken.(string))
		return cachedToken.(string), true
	} else {
		return "", false
	}
}
func (a *AuthorizationServer) CacheSet(principal authzman.PermissionClaim, tokenString string) {
	var hash strings.Builder
	hash.WriteString(principal.Fingerprint)
	hash.WriteString(":")
	hash.WriteString(principal.Scope)
	a.credentialCache.Set(hash.String(), tokenString, cache.DefaultExpiration)
}

// GetAuthorizationToken Verifica se existe token em cache, se não tenta obter credenciais da base configurada
func (a *AuthorizationServer) GetAuthorizationToken(permissionClaim authzman.PermissionClaim, clientId string) (string, bool) {

	if len(permissionClaim.Fingerprint) != 64 {
		log.Debugf("o certificate fingerprint %s, esta em formato invalido", permissionClaim.Fingerprint)
		return "", false
	}

	//Busca em cache
	cachedToken, found := a.CacheGet(permissionClaim)
	if found {
		log.Debug("Cache encontrado ", cachedToken)
		return cachedToken, true
	} else {
		log.Debugf("nao encontrei credentialCache para %s, scope: %s, buscando no storage", permissionClaim.Fingerprint, permissionClaim.Scope)

		//Verifica se existem credenciais para esse claim
		claims, okClaim := a.PermissionManager.Validate(permissionClaim)

		// Se retornou ok, carrega as claims no jwt
		if okClaim {
			log.Debugf("encontrei fingerprint %s valida para scope: %s ", permissionClaim.Fingerprint, permissionClaim.Scope)

			// Claims map
			myClaims := make(map[string][]string)
			claimString := a.Options.ClaimString
			myClaims[claimString] = claims.Permissions

			tokenString, err := a.jwtinstance.GetSignedToken(myClaims, clientId)

			if err != nil {
				log.Errorf("error sign Token: %v", err)
				return "", false
			}
			//Armazena em cache e retorna
			a.CacheSet(permissionClaim, tokenString)
			return tokenString, true
		}

		return "", false
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
		log.Debugf("Received Authorization for: %s, result %v", authz, ok)
		// Response ok par token valido e false para token invalido
		if ok {
			// Caso Allowed sem modificacao
			response, _ := BuildResponse(0, "", nil)
			return response, nil
		} else {
			log.Debugf("Received Error %s", err)
			// Caso UNAUTHENTICATED com Body custom
			response, _ := BuildResponse(1, "<em>Invalid JWT<em>", nil)
			return response, nil
		}
	}

	// Verificando se o request e destinado ao endpoint de autenticacao interno

	// Obtem o HOSTNAME e o PATH da request
	hostname := req.Attributes.Request.Http.Host
	path := req.Attributes.Request.Http.Path

	log.Debugf("OIDC, hostname: %s, path: %s", hostname, path)

	// Caso Allowed sem modificacao
	if hostname == a.Options.Oidc.Hostname && len(path) > len(a.Options.Oidc.Path) && a.Options.Oidc.Path == path[:len(a.Options.Oidc.Path)] {
		log.Debugf("Auth request")
		response, _ := BuildResponse(0, "", nil)
		return response, nil
	}

	//
	// Autorizacao por mTLS
	//
	//Header com fingerprint dos dados do certificado
	clientCertHeader, _ := req.Attributes.Request.Http.Headers["x-forwarded-client-cert"]
	log.Debugf(clientCertHeader)

	//Header de scopo de claims
	scopeString, _ := req.Attributes.Request.Http.Headers["x-scope-audience"]

	//Fixme controle de entrada do scope tem de ser melhor que isso
	if len(scopeString) > 20 {
		scopeString = ""
	}

	// Obtem dados do certificado
	certParts, certPartsErr := FromClientCertHeader(clientCertHeader)

	//Se tiver um fingerprint permitido Gera o JWT com as permissoes e aceita a requisicao
	if certPartsErr == nil && len(certParts.hash) > 0 {
		log.Debugf("Fingerprint: %s recebido", certParts.hash)

		//Se possivel, obtem o cn para construir o subject do token
		cn, _ := certParts.GetCn()

		// requisicao de autorizacao
		permissionClaim := authzman.PermissionClaim{Fingerprint: certParts.hash, Scope: scopeString}

		// Verificar o cache, se exitir, retorna o cache, se não existir valida o token, se estiver válido constroi o
		// token, salva em cache e retorna o header, se não for válido, passa para o caso não autorizado
		token, okToken := a.GetAuthorizationToken(permissionClaim, cn)
		if okToken {
			tokenSha := fmt.Sprintf("Bearer %s", token)
			log.Debugf("Build token: %s", tokenSha)
			// Caso UNAUTHENTICATED com Header Custom
			response, _ := BuildResponse(0, "", map[string]string{authHeader: tokenSha})
			return response, nil
		}
	} else {
		log.Debugf("Error certificate parts incomplete %v", certPartsErr)
	}

	// Sem Autorizacao, mTLS, ou caminho permitido, retorna falha de autenticacao
	log.Debugf("Retornando unauth\n")
	// INFO Nao esta retornando a resposta
	// Caso UNAUTHENTICATED com Body Custom
	response, _ := BuildResponse(1, "<em>No allowed auth method to access protected resource<em>", nil)
	return response, nil
}
