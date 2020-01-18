package internalapi

import (
	"net/http"

	"github.com/julienschmidt/httprouter"
	"golang.org/x/xerrors"
	"google.golang.org/grpc"

	"github.com/f110/lagrangian-proxy/pkg/rpc/rpcclient"
	"github.com/f110/lagrangian-proxy/pkg/server"
)

type ResourceServer struct {
	client *rpcclient.Client
}

var _ server.ChildServer = &ResourceServer{}

func NewResourceServer(conn *grpc.ClientConn, token string) (*ResourceServer, error) {
	c, err := rpcclient.NewClientForInternal(conn, token)
	if err != nil {
		return nil, xerrors.Errorf(": %v", err)
	}
	return &ResourceServer{client: c}, nil
}

func (r *ResourceServer) Route(mux *httprouter.Router) {
	mux.GET("/internal/publickey", func(w http.ResponseWriter, req *http.Request, _ httprouter.Params) {
		b, err := r.client.GetPublicKey()
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/x-pem-file")
		w.Write(b)
	})
}
