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

package app

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"os"
	"time"

	"github.com/spf13/cobra"
	certificatesv1 "k8s.io/api/certificates/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/util/certificate"
	"k8s.io/klog/v2"

	"yurt-tunnel-x/cmd/yurt-tunnel-agent/app/config"
	"yurt-tunnel-x/cmd/yurt-tunnel-agent/app/options"
	"yurt-tunnel-x/pkg/projectinfo"
	"yurt-tunnel-x/pkg/util/certmanager"
	certfactory "yurt-tunnel-x/pkg/util/certmanager/factory"
	"yurt-tunnel-x/pkg/yurttunnel/agent"
	"yurt-tunnel-x/pkg/yurttunnel/constants"
	"yurt-tunnel-x/pkg/yurttunnel/server/serveraddr"
	"yurt-tunnel-x/pkg/yurttunnel/util"
)

// NewYurttunnelAgentCommand creates a new yurttunnel-agent command
func NewYurttunnelAgentCommand(stopCh <-chan struct{}) *cobra.Command {
	agentOptions := options.NewAgentOptions()

	cmd := &cobra.Command{
		Short: fmt.Sprintf("Launch %s", projectinfo.GetAgentName()),
		RunE: func(c *cobra.Command, args []string) error {
			if agentOptions.Version {
				fmt.Printf("%s: %#v\n", projectinfo.GetAgentName(), projectinfo.Get())
				return nil
			}
			klog.Infof("%s version: %#v", projectinfo.GetAgentName(), projectinfo.Get())

			if err := agentOptions.Validate(); err != nil {
				return err
			}

			cfg, err := agentOptions.Config()
			if err != nil {
				return err
			}
			if cfg.NoCloudRootCACert != nil {
				if err := RunNoCloud(cfg.Complete(), stopCh); err != nil {
					return err
				}
			} else {
				if err := Run(cfg.Complete(), stopCh); err != nil {
					return err
				}
			}
			return nil
		},
		Args: cobra.NoArgs,
	}

	agentOptions.AddFlags(cmd.Flags())
	return cmd
}

func RunNoCloud(cfg *config.CompletedConfig, stopCh <-chan struct{}) error {
	var (
		err error
	)

	// 1. get the address of the yurttunnel-server
	klog.Infof("%s address: %s", projectinfo.GetServerName(), cfg.TunnelServerAddr)

	serverCertTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1659),
		Subject: pkix.Name{
			CommonName:   constants.YurtTunnelAgentCSRCN,
			Organization: []string{constants.YurtTunnelCSROrg},
		},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		DNSNames:    []string{cfg.NodeName},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().AddDate(1, 0, 0),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature,
	}
	// 3. generate a TLS configuration for securing the connection to server
	tlsCfg, err := certmanager.GenLocalTLSConfigUseCertAndKey(serverCertTemplate, cfg.RootCertPool, cfg.NoCloudRootCACert, cfg.NoCloudRootCAKey, false)
	if err != nil {
		return err
	}

	// 4. start the yurttunnel-agent
	ta := agent.NewTunnelAgent(tlsCfg, cfg.TunnelServerAddr, cfg.NodeName, cfg.AgentIdentifiers)
	ta.Run(stopCh)

	// 5. start meta server
	util.RunMetaServer(cfg.AgentMetaAddr)

	<-stopCh
	return nil
}

// Run starts the yurttunel-agent
func Run(cfg *config.CompletedConfig, stopCh <-chan struct{}) error {
	var (
		tunnelServerAddr string
		err              error
		agentCertMgr     certificate.Manager
	)

	// 1. get the address of the yurttunnel-server
	tunnelServerAddr = cfg.TunnelServerAddr
	if tunnelServerAddr == "" {
		if tunnelServerAddr, err = serveraddr.GetTunnelServerAddr(cfg.Client); err != nil {
			return err
		}
	}
	klog.Infof("%s address: %s", projectinfo.GetServerName(), tunnelServerAddr)

	// 2. create a certificate manager
	// As yurttunnel-agent will run on the edge node with Host network mode,
	// we can use the status.podIP as the node IP
	nodeIP := os.Getenv(constants.YurttunnelAgentPodIPEnv)
	if nodeIP == "" {
		return fmt.Errorf("env %s is not set", constants.YurttunnelAgentPodIPEnv)
	}
	agentCertMgr, err = certfactory.NewCertManagerFactory(cfg.Client).New(&certfactory.CertManagerConfig{
		ComponentName: projectinfo.GetAgentName(),
		CertDir:       cfg.CertDir,
		SignerName:    certificatesv1.KubeAPIServerClientSignerName,
		CommonName:    constants.YurtTunnelAgentCSRCN,
		Organizations: []string{constants.YurtTunnelCSROrg},
		DNSNames:      []string{os.Getenv("NODE_NAME")},
		IPs:           []net.IP{net.ParseIP(nodeIP)},
	})
	if err != nil {
		return err
	}
	agentCertMgr.Start()

	// 2.1. waiting for the certificate is generated
	_ = wait.PollUntil(5*time.Second, func() (bool, error) {
		if agentCertMgr.Current() != nil {
			return true, nil
		}
		klog.Infof("certificate %s not signed, waiting...",
			projectinfo.GetAgentName())
		return false, nil
	}, stopCh)
	klog.Infof("certificate %s ok", projectinfo.GetAgentName())

	// 3. generate a TLS configuration for securing the connection to server
	tlsCfg, err := certmanager.GenTLSConfigUseCertMgrAndCA(agentCertMgr,
		tunnelServerAddr, constants.YurttunnelCAFile)
	if err != nil {
		return err
	}

	// 4. start the yurttunnel-agent
	ta := agent.NewTunnelAgent(tlsCfg, tunnelServerAddr, cfg.NodeName, cfg.AgentIdentifiers)
	ta.Run(stopCh)

	// 5. start meta server
	util.RunMetaServer(cfg.AgentMetaAddr)

	<-stopCh
	return nil
}
