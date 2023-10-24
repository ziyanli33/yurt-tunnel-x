/*
Copyright 2020 The OpenYurt Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package certmanager

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"

	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/certificate"
)

func GenLocalTLSConfigUseCertAndKey(serverCertTemplate *x509.Certificate, root *x509.CertPool, caCert *x509.Certificate, caKey *rsa.PrivateKey, isServer bool) (*tls.Config, error) {
	serverCertPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, err
	}
	serverCertBytes, err := x509.CreateCertificate(rand.Reader, serverCertTemplate, caCert, &serverCertPrivKey.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	certPEM := new(bytes.Buffer)
	err = pem.Encode(certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: serverCertBytes,
	})
	if err != nil {
		return nil, err
	}
	certPrivKeyPEM := new(bytes.Buffer)
	err = pem.Encode(certPrivKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(serverCertPrivKey),
	})
	if err != nil {
		return nil, err
	}
	serverCert, err := tls.X509KeyPair(certPEM.Bytes(), certPrivKeyPEM.Bytes())
	if err != nil {
		return nil, err
	}
	tlsConfig := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    root,
		RootCAs:      root,
	}
	if isServer {
		tlsConfig.ClientAuth = tls.VerifyClientCertIfGiven
	}
	return tlsConfig, nil
}

// GenTLSConfigUseCurrentCertAndCertPool generates a TLS configuration
// using the given current certificate and x509 CertPool
func GenTLSConfigUseCurrentCertAndCertPool(
	current func() *tls.Certificate,
	root *x509.CertPool,
	mode string) (*tls.Config, error) {
	tlsConfig := &tls.Config{
		// Can't use SSLv3 because of POODLE and BEAST
		// Can't use TLSv1.0 because of POODLE and BEAST using CBC cipher
		// Can't use TLSv1.1 because of RC4 cipher usage
		MinVersion: tls.VersionTLS12,
	}

	switch mode {
	case "server":
		tlsConfig.ClientCAs = root
		tlsConfig.ClientAuth = tls.VerifyClientCertIfGiven
		if current != nil {
			tlsConfig.GetCertificate = func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
				cert := current()
				if cert == nil {
					return &tls.Certificate{Certificate: nil}, nil
				}
				return cert, nil
			}
		}
	case "client":
		tlsConfig.RootCAs = root
		if current != nil {
			tlsConfig.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
				cert := current()
				if cert == nil {
					return &tls.Certificate{Certificate: nil}, nil
				}
				return cert, nil
			}
		}
	default:
		return nil, fmt.Errorf("unsupported cert manager mode(only server or client), %s", mode)
	}

	return tlsConfig, nil
}

// GenRootCertPool generates a x509 CertPool based on the given kubeconfig,
// if the kubeConfig is empty, it will creates the CertPool using the CA file
func GenRootCertPool(kubeConfig, caFile string) (*x509.CertPool, error) {
	if kubeConfig != "" {
		// kubeconfig is given, generate the clientset based on it
		if _, err := os.Stat(kubeConfig); os.IsNotExist(err) {
			return nil, err
		}

		// load the root ca from the given kubeconfig file
		config, err := clientcmd.LoadFromFile(kubeConfig)
		if err != nil || config == nil {
			return nil, fmt.Errorf("failed to load the kubeconfig file(%s), %w",
				kubeConfig, err)
		}

		if len(config.CurrentContext) == 0 {
			return nil, fmt.Errorf("'current context' is not set in %s",
				kubeConfig)
		}

		ctx, ok := config.Contexts[config.CurrentContext]
		if !ok || ctx == nil {
			return nil, fmt.Errorf("'current context(%s)' is not found in %s",
				config.CurrentContext, kubeConfig)
		}

		cluster, ok := config.Clusters[ctx.Cluster]
		if !ok || cluster == nil {
			return nil, fmt.Errorf("'cluster(%s)' is not found in %s",
				ctx.Cluster, kubeConfig)
		}

		if len(cluster.CertificateAuthorityData) == 0 {
			// Some kubeconfigs hold CertificateAuthority instead of CertificateAuthorityData
			b, err := os.ReadFile(cluster.CertificateAuthority)
			if err != nil {
				return nil, fmt.Errorf("certificate authority data of the cluster(%s) is not set in %s, read certificate authority error %v",
					ctx.Cluster, kubeConfig, err)
			}
			dst := make([]byte, base64.StdEncoding.EncodedLen(len(b)))
			base64.StdEncoding.Encode(dst, b)
			if len(dst) == 0 {
				return nil, fmt.Errorf("certificate authority file of the cluster(%s) set in %s is empty",
					ctx.Cluster, kubeConfig)
			}
			cluster.CertificateAuthorityData = dst
		}

		rootCertPool := x509.NewCertPool()
		rootCertPool.AppendCertsFromPEM(cluster.CertificateAuthorityData)
		return rootCertPool, nil
	}

	// kubeConfig is missing, generate the cluster root ca based on the given ca file
	return GenCertPoolUseCA(caFile)
}

// GenTLSConfigUseCertMgrAndCA generates a TLS configuration based on the
// given certificate manager and the CA file
func GenTLSConfigUseCertMgrAndCA(
	m certificate.Manager,
	serverAddr, caFile string) (*tls.Config, error) {
	root, err := GenCertPoolUseCA(caFile)
	if err != nil {
		return nil, err
	}

	host, _, err := net.SplitHostPort(serverAddr)
	if err != nil {
		return nil, err
	}

	tlsConfig := &tls.Config{
		// Can't use SSLv3 because of POODLE and BEAST
		// Can't use TLSv1.0 because of POODLE and BEAST using CBC cipher
		// Can't use TLSv1.1 because of RC4 cipher usage
		MinVersion: tls.VersionTLS12,
		ServerName: host,
		RootCAs:    root,
	}

	tlsConfig.GetClientCertificate =
		func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			cert := m.Current()
			if cert == nil {
				return &tls.Certificate{Certificate: nil}, nil
			}
			return cert, nil
		}
	tlsConfig.GetCertificate =
		func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			cert := m.Current()
			if cert == nil {
				return &tls.Certificate{Certificate: nil}, nil
			}
			return cert, nil
		}

	return tlsConfig, nil
}

// GenCertPoolUseCA generates a x509 CertPool based on the given CA file
func GenCertPoolUseCA(caFile string) (*x509.CertPool, error) {
	if caFile == "" {
		return nil, errors.New("CA file is not set")
	}

	if _, err := os.Stat(caFile); err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("CA file(%s) doesn't exist", caFile)
		}
		return nil, fmt.Errorf("fail to stat the CA file(%s): %w", caFile, err)
	}

	caData, err := os.ReadFile(caFile)
	if err != nil {
		return nil, err
	}

	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(caData)
	return certPool, nil
}

// GenCertAndPoolUseCA generates a x509 Cert and CertPool based on the given CA file
func GenCertAndPoolUseCA(caFile string) (*x509.Certificate, *x509.CertPool, error) {
	if caFile == "" {
		return nil, nil, errors.New("CA file is not set")
	}

	if _, err := os.Stat(caFile); err != nil {
		if os.IsNotExist(err) {
			return nil, nil, fmt.Errorf("CA file(%s) doesn't exist", caFile)
		}
		return nil, nil, fmt.Errorf("fail to stat the CA file(%s): %w", caFile, err)
	}

	caData, err := os.ReadFile(caFile)
	if err != nil {
		return nil, nil, err
	}

	block, _ := pem.Decode(caData)
	if block == nil {
		return nil, nil, fmt.Errorf("failed to parse empty or malformed certificate PEM from file(%s)", caFile)
	}
	if block.Type != "CERTIFICATE" {
		return nil, nil, fmt.Errorf("failed to parse certificate PEM from file(%s), type is not CERTIFICATE", caFile)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse certificate(%s): %w", caFile, err)
	}

	certPool := x509.NewCertPool()
	certPool.AddCert(cert)
	return cert, certPool, nil
}

func LoadRSAKey(keyFile string) (*rsa.PrivateKey, error) {
	if keyFile == "" {
		return nil, errors.New("key file is not set")
	}

	if _, err := os.Stat(keyFile); err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("key file(%s) doesn't exist", keyFile)
		}
		return nil, fmt.Errorf("fail to stat the key file(%s): %w", keyFile, err)
	}

	keyData, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(keyData)
	if block == nil {
		return nil, fmt.Errorf("failed to parse empty or malformed key PEM from file(%s)", keyFile)
	}
	var key *rsa.PrivateKey
	switch block.Type {
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse PKCS1 key(%s): %w", keyFile, err)
		}
	case "PRIVATE KEY":
		keyAny, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse PKCS8 key(%s): %w", keyFile, err)
		}
		key = keyAny.(*rsa.PrivateKey)
	default:
		return nil, fmt.Errorf("failed to parse key PEM from file(%s), type is neither PKCS#1 RSA PRIVATE KEY nor PKCS#8 PRIVATE KEY", keyFile)
	}

	return key, nil
}
