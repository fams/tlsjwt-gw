# Configuração
A configuração pode ser feita com o yaml exemplo abaixo:

```yaml
port:     8080,
hostname: localhost
loglevel: info
oidc:
    hostname: localhost
    path:     /auth
credentialCache:
    expiration: 31
    cleanup:    60
credentials:
    type:   csv
    path:   authzman
    reload: 60
jwt:
    rsaPrivateFile: /auth/extauth.rsa,
    localIssuer:    tlsgw.local
    kid:
    tokenLifetime:  60
    issuers:
        name1:
            iss: tlsgw.local
            url: file:///auth/extauth.rsa.pub
```

## port
Porta TCP onde o autenticador vai esctar

## hostname
Hostname a ser utilizado ao abrir a porta

## loglevel
info: informações de boot e tokens assinados/rejeitados

error: Erros de operação

debug: todos os passos da autenticação

## oidc
Parametros para o OIDC atrás do GW
### hostname
endpoint do emissord de tokens
### path
Caminho do endpoint de emissão de tokens

## credentialCache
Atenção! o tempo de expiração deve ser menor que o de limpeza e ambos devem ser menores que o tempo de expiraçãod do token
### expiration
Tempo em segundos para uma jwt assinado expirar no GW

### cleanup
Tempo em segundos para limpeza do cache de tokens

## credentials
Base de credenciais podendo ser CSV ou json

### type
csv ou s3

### reload
intervalo de reconciliação da base de credenciais
## configuração com S3
### bucket
Nome do bucket com as credenciais
### key
caminho no bucket do json de credenciais
### region
Região S3

## Configuracão com CSV
### path
Caminho do csv com as credenciais

## jwt:
Configuração do emissor de tokens
### rsaPrivateFile
Chave privada para emissão

### localIssuer
Hostname a ser utilizado como issuer

### kid
key identitiy, hint para o GW encontrar a chave pública de validação no JWKS
### tokenLifetime
Tempo de expiração do token
### issuers
Configuração dos issuers permitidos de passar pelo GW sem mTLS

Formato de cada entrada segue o padrão
```yaml
Nome:
    iss: issuer configurado no token
    url: caminho do jwks, pode ser file:// ou https://
```

# Credentials
A base de credenciais pode ter dois formatos csv local ou json S3

## CSV
O primeiro campo é o fingerprint do certificado, o segundo é o escopo das audiences e o ultimo as audiences separadas por |

Exemplo:
```csv
"b49d1cdd5a34b98290cd21deb1fc630e101b85f278d9632b60e82ee52263f59a","scope-a","httpbin-get|helloworld"
"b49d1cdd5a34b98290cd21deb1fc630e101b85f278d9632b60e82ee52263f59a","scope-b","httpbin-post|goodbyworld"
"91ac3e2fcbef50072be0d98d8bc242876a850286eb4484103402ed35cec63847","scope-a","httpbin-get|helloworld"
"91ac3e2fcbef50072be0d98d8bc242876a850286eb4484103402ed35cec63847","scope-b","httpbin-post|goodbyworld"
```



## JSON
O Json é uma estrutrua contendo fingerprint|scopes. scopes contem name|audiences, audiences é uma lista

Exemplo:
```json
{
    "fingerprint": "b49d1cdd5a34b98290cd21deb1fc630e101b85f278d9632b60e82ee52263f59a",
    "scopes": [
{
        "name": "scope-a",
        "audiences": [
            "httpbin-get",
            "helloworld"
        ]
    }
,{
        "name": "scope-b",
        "audiences": [
            "httpbin-post",
            "goodbyworld"
        ]
    }
]
}
{
    "fingerprint": "91ac3e2fcbef50072be0d98d8bc242876a850286eb4484103402ed35cec63847",
    "scopes": [
{
        "name": "scope-a",
        "audiences": [
            "httpbin-get",
            "helloworld"
        ]
    }
,{
        "name": "scope-b",
        "audiences": [
            "httpbin-post",
            "goodbyworld"
        ]
    }
]
}
```

# Configuração do Envoy

Para o correto funcionamento do Gw, o envoy deve ser configurado para enviar as solicitacoes de autenticacao para ele

abaixo segue um exemplo de configuracao do envoy:
```yaml
...
    filter_chains:
    - filters:
      - name: envoy.http_connection_manager
      - name: envoy.http_connection_manager
        config:
          stat_prefix: egress_http
          rds:
            route_config_name: local_route
            config_source:
              path: /conf/routes.yaml
          forward_client_cert_details: "sanitize_set"
          set_current_client_cert_details:
            subject: True
          access_log:
            name: envoy.file_access_log
            config:
              path: /dev/stdout
          http_filters:
          - name: envoy.ext_authz
            config:
              grpc_service:
                envoy_grpc:
                  cluster_name: extauth
          - name: envoy.router
      tls_context:
        require_client_certificate: false
        common_tls_context:
          validation_context:
            trusted_ca:
              filename: "/ssl/ca.pem"
          tls_certificates:
            - certificate_chain:
                filename: "/ssl/tlsjwt.pem"
              private_key:
                filename: "/ssl/tlsjwt-key.pem"
...

  clusters:
    - name: extauth
      type: STRICT_DNS
      connect_timeout: 0.25s
      http2_protocol_options: {}
      load_assignment:
        cluster_name: extauth
        endpoints:
        - lb_endpoints:
          - endpoint:
              address:
                socket_address:
                  address: extauth
                  port_value: 4000
``` 
