package main

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"flag"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"time"

	"yurt-tunnel-x/pkg/util/certmanager"
)

func main() {
	rootCACertPath := flag.String("root-ca-cert", "", "the path to root CA certificate")
	rootCAKeyPath := flag.String("root-ca-key", "", "the path to root CA key")
	flag.Parse()

	rootCACert, rootCertPool, err := certmanager.GenCertAndPoolUseCA(*rootCACertPath)
	if err != nil {
		fmt.Printf("cannot load CA certificate, err: %s\n", err.Error())
		os.Exit(1)
	}
	rootCAKey, err := certmanager.LoadRSAKey(*rootCAKeyPath)
	if err != nil {
		fmt.Printf("cannot load CA key, err: %s\n", err.Error())
		os.Exit(1)
	}
	serverCertTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1660),
		Subject: pkix.Name{
			CommonName:   "simple-https-server",
			Organization: []string{"simple-https-server"},
		},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().AddDate(1, 0, 0),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature,
	}
	tlsCfg, err := certmanager.GenLocalTLSConfigUseCertAndKey(serverCertTemplate, rootCertPool, rootCACert, rootCAKey, true)
	if err != nil {
		fmt.Printf("cannot load tls config, err: %s\n", err.Error())
		os.Exit(1)
	}
	server := http.Server{
		Addr:         "127.0.0.1:9000",
		Handler:      &handler{},
		ReadTimeout:  10 * time.Second,
		TLSConfig:    tlsCfg,
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
	}
	fmt.Printf("simple https server listening at %s\n", server.Addr)
	if err := server.ListenAndServeTLS("", ""); err != nil {
		fmt.Printf("cannot serve tls config, err: %s\n", err.Error())
		os.Exit(1)
	}
}

type handler struct{}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte("This is an example server.\n"))
}
