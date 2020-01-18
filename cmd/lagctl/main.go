package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	mrand "math/rand"
	"net/http"
	"net/http/httputil"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/f110/lagrangian-proxy/pkg/cert"
	"github.com/f110/lagrangian-proxy/pkg/config"
	"github.com/f110/lagrangian-proxy/pkg/config/configreader"
	"github.com/f110/lagrangian-proxy/pkg/rpc"
	"github.com/f110/lagrangian-proxy/pkg/rpc/rpcclient"
	"github.com/f110/lagrangian-proxy/pkg/version"
	"github.com/gorilla/securecookie"
	"github.com/gorilla/websocket"
	"github.com/spf13/pflag"
	"golang.org/x/xerrors"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
	"sigs.k8s.io/yaml"
)

const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

func commandBootstrap(args []string) error {
	confFile := ""
	fs := pflag.NewFlagSet("lagctl", pflag.ContinueOnError)
	fs.StringVarP(&confFile, "config", "c", confFile, "Config file")
	if err := fs.Parse(args); err != nil {
		return err
	}

	p, err := filepath.Abs(confFile)
	if err != nil {
		return xerrors.Errorf(": %v", err)
	}
	dir := filepath.Dir(p)
	confBuf, err := ioutil.ReadFile(p)
	if err != nil {
		return xerrors.Errorf(": %v", err)
	}
	conf := &config.Config{}
	if err := yaml.Unmarshal(confBuf, conf); err != nil {
		return xerrors.Errorf(": %v", err)
	}
	if conf.General == nil || conf.General.CertificateAuthority == nil {
		return xerrors.New("not enough configuration")
	}

	_, err = os.Stat(absPath(conf.General.CertificateAuthority.CertFile, dir))
	certFileExist := !os.IsNotExist(err)
	_, err = os.Stat(absPath(conf.General.CertificateAuthority.KeyFile, dir))
	keyFileExist := !os.IsNotExist(err)
	if !certFileExist && !keyFileExist {
		if err := generateNewCertificateAuthority(conf, dir); err != nil {
			return xerrors.Errorf(": %v", err)
		}
	}

	b, err := ioutil.ReadFile(absPath(conf.General.CertificateAuthority.CertFile, dir))
	if err != nil {
		return xerrors.Errorf(": %v", err)
	}
	block, _ := pem.Decode(b)
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return xerrors.Errorf(": %v", err)
	}
	b, err = ioutil.ReadFile(absPath(conf.General.CertificateAuthority.KeyFile, dir))
	if err != nil {
		return xerrors.Errorf(": %v", err)
	}
	block, _ = pem.Decode(b)
	privateKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return xerrors.Errorf(": %v", err)
	}

	_, err = os.Stat(absPath(conf.General.CertFile, dir))
	certFileExist = !os.IsNotExist(err)
	_, err = os.Stat(absPath(conf.General.KeyFile, dir))
	keyFileExist = !os.IsNotExist(err)
	if !certFileExist && !keyFileExist {
		if err := createNewServerCertificate(conf, dir, c, privateKey); err != nil {
			return xerrors.Errorf(": %v", err)
		}
	}

	_, err = os.Stat(absPath(conf.General.SigningPrivateKeyFile, dir))
	if os.IsNotExist(err) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return xerrors.Errorf(": %v", err)
		}
		b, err := x509.MarshalECPrivateKey(privateKey)
		if err != nil {
			return xerrors.Errorf(": %v", err)
		}
		if err := cert.PemEncode(absPath(conf.General.SigningPrivateKeyFile, dir), "EC PRIVATE KEY", b, nil); err != nil {
			return xerrors.Errorf(": %v", err)
		}
	}

	_, err = os.Stat(absPath(conf.General.InternalTokenFile, dir))
	if os.IsNotExist(err) {
		b := make([]byte, 32)
		for i := range b {
			b[i] = letters[mrand.Intn(len(letters))]
		}
		f, err := os.Create(absPath(conf.General.InternalTokenFile, dir))
		if err != nil {
			return xerrors.Errorf(": %v", err)
		}
		f.Write(b)
		f.Close()
	}

	_, err = os.Stat(absPath(conf.FrontendProxy.GithubWebHookSecretFile, dir))
	if os.IsNotExist(err) {
		b := make([]byte, 32)
		if _, err := io.ReadFull(rand.Reader, b); err != nil {
			return xerrors.Errorf(": %v", err)
		}
		f, err := os.Create(absPath(conf.FrontendProxy.GithubWebHookSecretFile, dir))
		if err != nil {
			return xerrors.Errorf(": %v", err)
		}
		f.Write(b)
		f.Close()
	}

	_, err = os.Stat(absPath(conf.FrontendProxy.Session.KeyFile, dir))
	if os.IsNotExist(err) {
		switch conf.FrontendProxy.Session.Type {
		case config.SessionTypeSecureCookie:
			hashKey := securecookie.GenerateRandomKey(32)
			blockKey := securecookie.GenerateRandomKey(16)
			f, err := os.Create(absPath(conf.FrontendProxy.Session.KeyFile, dir))
			if err != nil {
				return xerrors.Errorf(": %v", err)
			}
			f.WriteString(hex.EncodeToString(hashKey))
			f.WriteString("\n")
			f.WriteString(hex.EncodeToString(blockKey))
			f.Close()
		}
	}

	return nil
}

func generateNewCertificateAuthority(conf *config.Config, dir string) error {
	c, privateKey, err := cert.CreateCertificateAuthorityForConfig(conf)
	if err != nil {
		return xerrors.Errorf(": %v", err)
	}

	b, err := x509.MarshalECPrivateKey(privateKey.(*ecdsa.PrivateKey))
	if err != nil {
		return xerrors.Errorf(": %v", err)
	}
	if err := cert.PemEncode(absPath(conf.General.CertificateAuthority.KeyFile, dir), "EC PRIVATE KEY", b, nil); err != nil {
		return xerrors.Errorf(": %v", err)
	}

	if err := cert.PemEncode(absPath(conf.General.CertificateAuthority.CertFile, dir), "CERTIFICATE", c, nil); err != nil {
		return xerrors.Errorf(": %v", err)
	}
	return nil
}

func createNewServerCertificate(conf *config.Config, dir string, ca *x509.Certificate, caPrivateKey crypto.PrivateKey) error {
	c, privateKey, err := cert.GenerateServerCertificate(ca, caPrivateKey, []string{"local-proxy.f110.dev", "*.local-proxy.f110.dev", "short.f110.dev"})

	b, err := x509.MarshalECPrivateKey(privateKey.(*ecdsa.PrivateKey))
	if err != nil {
		return xerrors.Errorf(": %v", err)
	}
	if err := cert.PemEncode(absPath(conf.General.KeyFile, dir), "EC PRIVATE KEY", b, nil); err != nil {
		return xerrors.Errorf(": %v", err)
	}
	if err := cert.PemEncode(absPath(conf.General.CertFile, dir), "CERTIFICATE", c, nil); err != nil {
		return xerrors.Errorf(": %v", err)
	}
	return nil
}

func commandTestServer() error {
	http.Handle("/favicon.ico", http.NotFoundHandler())
	http.HandleFunc("/env", func(w http.ResponseWriter, req *http.Request) {
		b, _ := httputil.DumpRequest(req, true)
		fmt.Println(string(b))

		w.Write(b)
	})
	http.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		time.Sleep(5 * time.Millisecond)
		io.WriteString(w, "It's working!")
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
	fmt.Println("Listen :4501")
	return http.ListenAndServe(":4501", nil)
}

func commandCluster(args []string) error {
	confFile := ""
	fs := pflag.NewFlagSet("lagctl", pflag.ContinueOnError)
	fs.StringVarP(&confFile, "config", "c", confFile, "Config file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	conf, err := configreader.ReadConfig(confFile)
	if err != nil {
		return xerrors.Errorf(": %v", err)
	}

	var cp *x509.CertPool
	if conf.General.Debug {
		cp = conf.General.CertificateAuthority.CertPool
	}
	cred := credentials.NewTLS(&tls.Config{ServerName: conf.General.ServerNameHost, RootCAs: cp})
	conn, err := grpc.Dial(
		conf.General.ServerName,
		grpc.WithTransportCredentials(cred),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{Time: 20 * time.Second, Timeout: time.Second, PermitWithoutStream: true}),
	)
	if err != nil {
		return xerrors.Errorf(": %v", err)
	}

	c, err := rpcclient.NewClientWithStaticToken(conn)
	if err != nil {
		return xerrors.Errorf(": %v", err)
	}

	switch args[0] {
	case "member-list":
		memberList, err := c.ClusterMemberList()
		if err != nil {
			return xerrors.Errorf(": %v", err)
		}
		for i, v := range memberList {
			fmt.Printf("[%d] %s\n", i+1, v)
		}
		return nil
	}
	return nil
}

func commandInternal(args []string) error {
	confFile := ""
	fs := pflag.NewFlagSet("lagctl", pflag.ContinueOnError)
	fs.StringVarP(&confFile, "config", "c", confFile, "Config file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	conf, err := configreader.ReadConfig(confFile)
	if err != nil {
		return xerrors.Errorf(": %v", err)
	}

	cred := credentials.NewTLS(&tls.Config{ServerName: conf.General.ServerNameHost, RootCAs: conf.General.CertificateAuthority.CertPool})
	conn, err := grpc.Dial(
		conf.General.RpcTarget,
		grpc.WithTransportCredentials(cred),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{Time: 20 * time.Second, Timeout: time.Second, PermitWithoutStream: true}),
	)
	if err != nil {
		return xerrors.Errorf(": %v", err)
	}

	c, err := rpcclient.NewClientForInternal(conn, conf.General.InternalToken)
	if err != nil {
		return xerrors.Errorf(": %v", err)
	}

	switch args[0] {
	case "defragment":
		result, err := c.Defragment()
		if err != nil {
			return xerrors.Errorf(": %v", err)
		}

		for k, v := range result {
			if v {
				fmt.Printf("%s: Success\n", k)
			} else {
				fmt.Printf("%s: Failure\n", k)
			}
		}
	}

	return nil
}

func commandAdmin(args []string) error {
	confFile := ""
	role := ""
	fs := pflag.NewFlagSet("lagctl", pflag.ContinueOnError)
	fs.StringVarP(&confFile, "config", "c", confFile, "Config file")
	fs.StringVar(&role, "role", role, "Role")
	if err := fs.Parse(args); err != nil {
		return err
	}
	conf, err := configreader.ReadConfig(confFile)
	if err != nil {
		return xerrors.Errorf(": %v", err)
	}

	var cp *x509.CertPool
	if conf.General.Debug {
		cp = conf.General.CertificateAuthority.CertPool
	}
	cred := credentials.NewTLS(&tls.Config{ServerName: conf.General.ServerNameHost, RootCAs: cp})
	conn, err := grpc.Dial(
		conf.General.ServerName,
		grpc.WithTransportCredentials(cred),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{Time: 20 * time.Second, Timeout: time.Second, PermitWithoutStream: true}),
	)
	if err != nil {
		return xerrors.Errorf(": %v", err)
	}

	c, err := rpcclient.NewClientWithStaticToken(conn)
	if err != nil {
		return xerrors.Errorf(": %v", err)
	}

	switch args[0] {
	case "user-list":
		var userList []*rpc.UserItem
		if role != "" {
			userList, err = c.ListUser(role)
		} else {
			userList, err = c.ListAllUser()
		}
		if err != nil {
			return xerrors.Errorf(": %v", err)
		}
		for _, v := range userList {
			fmt.Printf("%s\n", v.Id)
		}
		return nil
	}
	return nil
}

func cli(args []string) error {
	version := false
	fs := pflag.NewFlagSet("lagctl", pflag.ContinueOnError)
	fs.BoolVarP(&version, "version", "v", version, "Show version")
	fs.Parse(args)

	if version {
		printVersion()
		return nil
	}

	switch args[1] {
	case "bootstrap":
		return commandBootstrap(args[2:])
	case "testserver":
		return commandTestServer()
	case "cluster":
		return commandCluster(args[2:])
	case "admin":
		return commandAdmin(args[2:])
	case "internal":
		return commandInternal(args[2:])
	}

	return nil
}

func absPath(path, dir string) string {
	if strings.HasPrefix(path, "./") {
		a, err := filepath.Abs(filepath.Join(dir, path))
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return ""
		}
		return a
	}
	return path
}

func printVersion() {
	fmt.Printf("Version: %s\n", version.Version)
	fmt.Printf("Go version: %s\n", runtime.Version())
}

func main() {
	if err := cli(os.Args); err != nil {
		fmt.Fprintf(os.Stderr, "%+v\n", err)
		os.Exit(1)
	}
}
