package heimdev

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"os"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/gorilla/websocket"
	"golang.org/x/xerrors"

	"go.f110.dev/heimdallr/pkg/auth/authn"
	"go.f110.dev/heimdallr/pkg/authproxy"
	"go.f110.dev/heimdallr/pkg/cmd"
)

func testServer(port int, publicKeyFile string) error {
	fBuf, err := os.ReadFile(publicKeyFile)
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}
	block, rest := pem.Decode(fBuf)
	if len(rest) != 0 {
		return xerrors.New("heimdev: invalid pem file")
	}
	if block.Type != "PUBLIC KEY" {
		return xerrors.Errorf("heimdev: PEM file type is not PUBLIC KEY: %s", block.Type)
	}

	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}

	http.Handle("/favicon.ico", http.NotFoundHandler())
	http.HandleFunc("/env", func(w http.ResponseWriter, req *http.Request) {
		b, _ := httputil.DumpRequest(req, true)
		fmt.Println(string(b))

		w.Write(b)
	})
	http.HandleFunc("/jwt", func(w http.ResponseWriter, req *http.Request) {
		if publicKey == nil {
			fmt.Println("Public key not provided")
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		token := req.Header.Get(authproxy.TokenHeaderName)
		if token == "" {
			fmt.Printf("%s is empty\n", authproxy.TokenHeaderName)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		claim := &authn.TokenClaims{}
		_, err := jwt.ParseWithClaims(token, claim, func(t *jwt.Token) (interface{}, error) {
			if t.Method != jwt.SigningMethodES256 {
				return nil, xerrors.New("heimdev: invalid signing method")
			}
			return publicKey, nil
		})
		if err != nil {
			fmt.Println(err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if err := claim.Valid(); err != nil {
			fmt.Println(err)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		if err := json.NewEncoder(w).Encode(claim); err != nil {
			fmt.Println(err)
		}
	})
	http.HandleFunc("/ws", func(w http.ResponseWriter, req *http.Request) {
		upgrader := &websocket.Upgrader{ReadBufferSize: 1024, WriteBufferSize: 1024}
		conn, err := upgrader.Upgrade(w, req, nil)
		if err != nil {
			return
		}

		go func() {
			for {
				typ, buf, err := conn.ReadMessage()
				if err != nil {
					log.Print(err)
					return
				}
				log.Print(string(buf))

				if err := conn.WriteMessage(typ, buf); err != nil {
					log.Print(err)
					return
				}
			}
		}()
	})
	http.HandleFunc("/ws_client", func(w http.ResponseWriter, req *http.Request) {
		io.WriteString(w, `<!DOCTYPE html>
<html>
<head>
<script type="text/javascript">
window.onload = function () {
	conn = new WebSocket("wss://" + document.location.host + "/ws");
	conn.onmessage = function (evt) {
		console.log(evt);
	};
	setInterval(function() {conn.send("test")}, 1000);
};
</script>
</head>
<body>
</body>
</html>`)
	})
	http.HandleFunc("/multipart", func(w http.ResponseWriter, req *http.Request) {
		io.WriteString(w, `<!DOCTYPE html>
<html>
<body>
<form action="/multipart_upload" method="post" enctype="multipart/form-data">
	<input type="file" name="file" id="file">
	<input type="submit" name="submit">
</form>
</body>
</html>`)
	})
	http.HandleFunc("/multipart_upload", func(w http.ResponseWriter, req *http.Request) {
		if err := req.ParseMultipartForm(16 * 1024 * 1024); err != nil {
			log.Print(err)
			return
		}
		for k := range req.MultipartForm.File {
			log.Print(k)
		}
		io.WriteString(w, "DONE")
	})
	http.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		time.Sleep(5 * time.Millisecond)
		fmt.Fprint(w, "It's working!")
	})
	fmt.Printf("Listen :%d\n", port)
	return http.ListenAndServe(fmt.Sprintf(":%d", port), nil)
}

func TestServer(rootCmd *cmd.Command) {
	port := 4501
	publicKeyFile := ""

	testServerCmd := &cmd.Command{
		Use:   "testserver",
		Short: "Start a http server for testing",
		Run: func(_ context.Context, _ *cmd.Command, _ []string) error {
			return testServer(port, publicKeyFile)
		},
	}
	testServerCmd.Flags().Int("port", "Listen port").Var(&port).Default(4501)
	testServerCmd.Flags().String("public-key", "public key file").Var(&publicKeyFile).Default(publicKeyFile)

	rootCmd.AddCommand(testServerCmd)
}
