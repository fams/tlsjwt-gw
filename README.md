tlsjwt-gw [![Build Status](https://travis-ci.org/fams/tlsjwt-gw.svg?branch=master)](https://travis-ci.org/fams/tlsjwt-gw) [![Docker Repository](https://img.shields.io/docker/build/fams/tlsjwt-gw "Docker Repository")](https://hub.docker.com/r/fams/tlsjwt-gw) 
==========


External Auth para o envoy que transforma uma chamada mTLS em um JWT assinado com audiences baseados em uma fonte externa

# Caracteristicas

- Recebe os audiences de um arquivo CSV ou Json no aws S3
- Adiciona o CN do certificado como claim no JWT assinado
- Assinatura com RS256
- Valida Tokens emitidos por outros OIDC

Layout

<img src="https://github.com/fams/tlsjwt-gw/raw/master/docs/tlsgw.png" width="100">

# Compilação e Configuração

O TLSJWT-GW foi preparado para ser executado em container.

Para compilar:
```bash
docker build https://github.com/fams/tlsjwt-gw.git
```

#Configuração
A configuração é feita em arquivo yaml ou json com nome extauth.json ou extauth.yaml residente no mesmo diretorio do autenticador
Detalhes em [configuração](https://github.com/fams/tlsjwt-gw/docs/config.md)


