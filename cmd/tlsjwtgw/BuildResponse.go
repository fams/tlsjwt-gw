package main

import (
	"github.com/envoyproxy/go-control-plane/envoy/api/v2/core"
	auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v2"
	envoytype "github.com/envoyproxy/go-control-plane/envoy/type"
	"github.com/gogo/googleapis/google/rpc"
)

const (
	UNAUTH = 1
	OK     = 0
	ERROr  = 3
)

func BuildResponse(status int, body string, headers map[string]string) (*auth.CheckResponse, error) {
	var response auth.CheckResponse

	switch status {
	case UNAUTH:
		response = auth.CheckResponse{
			Status: &rpc.Status{
				Code: int32(rpc.UNAUTHENTICATED),
			},
			HttpResponse: &auth.CheckResponse_DeniedResponse{
				DeniedResponse: &auth.DeniedHttpResponse{
					Status: &envoytype.HttpStatus{
						Code: envoytype.StatusCode_Unauthorized,
					},
					Body: body,
				},
			},
		}
	case OK:

		if headers != nil {
			var headerValues = make([]*core.HeaderValueOption, len(headers))
			var i int = 0
			for key, value := range headers {
				headerValues[i] = &core.HeaderValueOption{
					Header: &core.HeaderValue{
						Key:   key,
						Value: value,
					},
				}
			}
			response = auth.CheckResponse{
				Status: &rpc.Status{
					Code: int32(rpc.OK),
				},
				HttpResponse: &auth.CheckResponse_OkResponse{
					OkResponse: &auth.OkHttpResponse{
						Headers: headerValues,
					},
				},
			}
		} else {
			response = auth.CheckResponse{
				Status: &rpc.Status{
					Code: int32(rpc.OK),
				},
				HttpResponse: &auth.CheckResponse_OkResponse{
					OkResponse: &auth.OkHttpResponse{},
				},
			}
		}

	}
	return &response, nil
}
