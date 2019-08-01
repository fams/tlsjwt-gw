#!/bin/bash
#===============================================================================
#
#          FILE: build.sh
# 
#         USAGE: ./build.sh 
# 
#   DESCRIPTION: 
# 
#       OPTIONS: ---
#  REQUIREMENTS: ---
#          BUGS: ---
#         NOTES: ---
#        AUTHOR: Fernando Augusto Medeiros Silva (), fams@linuxplace.com.br
#  ORGANIZATION: Linuxplace
#       CREATED: 01/08/2019 17:58
#      REVISION:  ---
#===============================================================================

set -o nounset                              # Treat unset variables as an error
go build -o ext-auth-poc cmd/jwtgw/*.go

