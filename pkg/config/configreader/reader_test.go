package configreader

import (
	"crypto/ecdsa"
	"crypto/x509"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/f110/lagrangian-proxy/pkg/cert"

	"github.com/f110/lagrangian-proxy/pkg/config"
)

func TestReadConfig(t *testing.T) {
	roleBuf := `- name: admin
  title: administrator
  description: for administrator
  bindings:
    - backend: test.local-proxy.f110.dev
      permission: all
`
	proxyBuf := `
- name: test.local-proxy.f110.dev
  upstream: http://localhost:4501
  permissions:
    - name: all
      locations:
        - get: /get
          post: /post
          put: /put
          delete: /delete
          head: /head
          connect: /connect
          options: /options
          trace: /trace
          patch: /patch
- name: content.local-proxy.f110.dev
  upstream: http://localhost:4502
  permissions:
    - name: all
      locations:
        - get: /
`
	b := `
general:
  role_file: ./roles.yaml
  proxy_file: ./proxies.yaml
  certificate_authority:
    cert_file: ./ca.crt
    key_file: ./ca.key
datastore:
  url: etcd://embed
  data_dir: ./data
frontend_proxy:
  bind: :4000
  cert_file: ./tls.crt
  key_file: ./tls.key
logger:
  level: debug
  encoding: console
`

	tmpDir, err := ioutil.TempDir("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	f, err := ioutil.TempFile(tmpDir, "")
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString(b)
	f.Sync()
	if err := ioutil.WriteFile(filepath.Join(tmpDir, "roles.yaml"), []byte(roleBuf), 0644); err != nil {
		t.Fatal(err)
	}
	if err := ioutil.WriteFile(filepath.Join(tmpDir, "proxies.yaml"), []byte(proxyBuf), 0644); err != nil {
		t.Fatal(err)
	}
	caCert, privateKey, err := cert.CreateCertificateAuthorityForConfig(
		&config.Config{General: &config.General{
			CertificateAuthority: &config.CertificateAuthority{
				Organization:     "Test",
				OrganizationUnit: "Test Unit",
				Country:          "JP",
			},
		}},
	)
	if err != nil {
		t.Fatal(err)
	}
	privKey, err := x509.MarshalECPrivateKey(privateKey.(*ecdsa.PrivateKey))
	if err != nil {
		t.Fatal(err)
	}
	if err := cert.PemEncode(filepath.Join(tmpDir, "ca.key"), "EC PRIVATE KEY", privKey, nil); err != nil {
		t.Fatal(err)
	}
	if err := cert.PemEncode(filepath.Join(tmpDir, "ca.crt"), "CERTIFICATE", caCert.Raw, nil); err != nil {
		t.Fatal(err)
	}

	c, privateKey, err := cert.GenerateServerCertificate(caCert, privateKey, []string{"test.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	privKey, err = x509.MarshalECPrivateKey(privateKey.(*ecdsa.PrivateKey))
	if err != nil {
		t.Fatal(err)
	}
	if err := cert.PemEncode(filepath.Join(tmpDir, "tls.key"), "EC PRIVATE KEY", privKey, nil); err != nil {
		t.Fatal(err)
	}
	if err := cert.PemEncode(filepath.Join(tmpDir, "tls.crt"), "CERTIFICATE", c.Raw, nil); err != nil {
		t.Fatal(err)
	}

	conf, err := ReadConfig(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	if conf.Datastore == nil {
		t.Fatal("yaml parse error or something")
	}
	if conf.Datastore.Url.Scheme != "etcd" {
		t.Errorf("datastore url is expected etcd: %s", conf.Datastore.Url.Scheme)
	}
	if conf.Datastore.Url.Hostname() != "embed" {
		t.Errorf("datastore host is expect embed: %s", conf.Datastore.Url.Hostname())
	}
	if conf.Logger == nil {
		t.Fatal("yaml parse error or something")
	}
	if conf.Logger.Level != "debug" {
		t.Errorf("expect logger level is debug: %s", conf.Logger.Level)
	}
	if conf.Logger.Encoding != "console" {
		t.Errorf("expect logger encoding is console: %s", conf.Logger.Encoding)
	}
	if conf.Datastore.DataDir != filepath.Join(tmpDir, "data") {
		t.Errorf("datastore.data expect %s: %s", filepath.Join(tmpDir, "data"), conf.Datastore.DataDir)
	}

	err = ioutil.WriteFile(filepath.Join(tmpDir, "data", config.EmbedEtcdUrlFilename), []byte("etcd://localhost:60000"), 0600)
	if err != nil {
		t.Fatal(err)
	}
	conf, err = ReadConfig(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	if conf.Datastore.EtcdUrl.Host != "localhost:60000" {
		t.Errorf("failed read previous etcd url: %s", conf.Datastore.EtcdUrl.String())
	}
}

func TestReadConfigFromFile(t *testing.T) {
	_, err := ReadConfig("./testdata/config_debug.yaml")
	if err != nil {
		t.Fatalf("%+v", err)
	}
}
