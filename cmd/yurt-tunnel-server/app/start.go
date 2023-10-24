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
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"sync"
	"time"

	"github.com/spf13/cobra"
	certificatesv1 "k8s.io/api/certificates/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"
	"yurt-tunnel-x/cmd/yurt-tunnel-server/app/config"
	"yurt-tunnel-x/cmd/yurt-tunnel-server/app/options"
	"yurt-tunnel-x/pkg/projectinfo"
	"yurt-tunnel-x/pkg/util/certmanager"
	certfactory "yurt-tunnel-x/pkg/util/certmanager/factory"
	"yurt-tunnel-x/pkg/yurttunnel/constants"
	"yurt-tunnel-x/pkg/yurttunnel/handlerwrapper/initializer"
	"yurt-tunnel-x/pkg/yurttunnel/handlerwrapper/wraphandler"
	"yurt-tunnel-x/pkg/yurttunnel/informers"
	"yurt-tunnel-x/pkg/yurttunnel/server"
	"yurt-tunnel-x/pkg/yurttunnel/server/serveraddr"
	"yurt-tunnel-x/pkg/yurttunnel/trafficforward/dns"
	"yurt-tunnel-x/pkg/yurttunnel/trafficforward/iptables"
	"yurt-tunnel-x/pkg/yurttunnel/util"
)

// NewYurttunnelServerCommand creates a new yurttunnel-server command
func NewYurttunnelServerCommand(stopCh <-chan struct{}) *cobra.Command {
	serverOptions := options.NewServerOptions()

	cmd := &cobra.Command{
		Use:   "Launch " + projectinfo.GetServerName(),
		Short: projectinfo.GetServerName() + " sends requests to " + projectinfo.GetAgentName(),
		RunE: func(c *cobra.Command, args []string) error {
			if serverOptions.Version {
				fmt.Printf("%s: %#v\n", projectinfo.GetServerName(), projectinfo.Get())
				return nil
			}
			klog.Infof("%s version: %#v", projectinfo.GetServerName(), projectinfo.Get())

			if err := serverOptions.Validate(); err != nil {
				return err
			}

			cfg, err := serverOptions.Config()
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

	serverOptions.AddFlags(cmd.Flags())

	return cmd
}

func RunNoCloud(cfg *config.CompletedConfig, stopCh <-chan struct{}) error {
	serverCertTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1658),
		Subject: pkix.Name{
			CommonName:   "tunnel-server",
			Organization: []string{constants.YurtTunnelCSROrg},
		},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().AddDate(1, 0, 0),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature,
	}
	tlsCfg, err := certmanager.GenLocalTLSConfigUseCertAndKey(serverCertTemplate, cfg.RootCertPool, cfg.NoCloudRootCACert, cfg.NoCloudRootCAKey, true)
	if err != nil {
		return err
	}

	proxyClientTlsCfg, err := certmanager.GenLocalTLSConfigUseCertAndKey(serverCertTemplate, cfg.RootCertPool, cfg.NoCloudRootCACert, cfg.NoCloudRootCAKey, false)
	if err != nil {
		return err
	}

	// start the server
	ts := server.NewTunnelServer(
		cfg.EgressSelectorEnabled,
		cfg.InterceptorServerUDSFile,
		cfg.ListenAddrForMaster,
		cfg.ListenInsecureAddrForMaster,
		cfg.ListenAddrForAgent,
		cfg.ServerCount,
		tlsCfg,
		proxyClientTlsCfg,
		nil,
		cfg.ProxyStrategy)
	if err := ts.Run(); err != nil {
		return err
	}

	// start meta server
	util.RunMetaServer(cfg.ListenMetaAddr)

	<-stopCh
	return nil
}

// run starts the yurttunel-server
func Run(cfg *config.CompletedConfig, stopCh <-chan struct{}) error {
	var wg sync.WaitGroup
	// register informers that tunnel server need
	informers.RegisterInformersForTunnelServer(cfg.SharedInformerFactory)

	// 0. start the DNS controller
	if cfg.EnableDNSController {
		dnsController, err := dns.NewCoreDNSRecordController(cfg.Client,
			cfg.SharedInformerFactory,
			cfg.ListenInsecureAddrForMaster,
			cfg.ListenAddrForMaster,
			cfg.DNSSyncPeriod)
		if err != nil {
			return fmt.Errorf("fail to create a new dnsController, %w", err)
		}
		go dnsController.Run(stopCh)
	}
	// 1. start the IP table manager
	if cfg.EnableIptables {
		iptablesMgr, err := iptables.NewIptablesManagerWithIPFamily(cfg.Client,
			cfg.SharedInformerFactory.Core().V1().Nodes(),
			cfg.ListenAddrForMaster,
			cfg.ListenInsecureAddrForMaster,
			cfg.IptablesSyncPeriod,
			cfg.IPFamily)
		if err != nil {
			return fmt.Errorf("fail to create a new IptableManager, %w", err)
		}
		wg.Add(1)
		go iptablesMgr.Run(stopCh, &wg)
	}

	// 2. create a certificate manager for the tunnel server
	certManagerFactory := certfactory.NewCertManagerFactory(cfg.Client)
	ips, dnsNames, err := getTunnelServerIPsAndDNSNamesBeforeInformerSynced(cfg.Client, stopCh)
	if err != nil {
		return err
	}
	serverCertMgr, err := certManagerFactory.New(&certfactory.CertManagerConfig{
		IPs:      append(ips, cfg.CertIPs...),
		DNSNames: append(dnsNames, cfg.CertDNSNames...),
		IPGetter: func() ([]net.IP, error) {
			_, dynamicIPs, err := serveraddr.YurttunnelServerAddrManager(cfg.SharedInformerFactory)
			dynamicIPs = append(dynamicIPs, cfg.CertIPs...)
			return dynamicIPs, err
		},
		ComponentName:  projectinfo.GetServerName(),
		CertDir:        cfg.CertDir,
		SignerName:     certificatesv1.KubeletServingSignerName,
		CommonName:     fmt.Sprintf("system:node:%s", constants.YurtTunnelServerNodeName),
		Organizations:  []string{user.NodesGroup},
		ForServerUsage: true,
	})
	if err != nil {
		return err
	}
	serverCertMgr.Start()

	// 3. create a certificate manager for the tunnel proxy client
	tunnelProxyCertMgr, err := certManagerFactory.New(&certfactory.CertManagerConfig{
		ComponentName: fmt.Sprintf("%s-proxy-client", projectinfo.GetServerName()),
		CertDir:       cfg.CertDir,
		SignerName:    certificatesv1.KubeAPIServerClientSignerName,
		CommonName:    constants.YurtTunnelProxyClientCSRCN,
		Organizations: []string{constants.YurtTunnelCSROrg},
	})
	if err != nil {
		return err
	}
	tunnelProxyCertMgr.Start()

	// 4. create handler wrappers
	mInitializer := initializer.NewMiddlewareInitializer(cfg.SharedInformerFactory)
	wrappers, err := wraphandler.InitHandlerWrappers(mInitializer, cfg.IsIPv6())
	if err != nil {
		klog.Errorf("failed to init handler wrappers, %v", err)
		return err
	}

	// after all of informers are configured completed, start the shared index informer
	cfg.SharedInformerFactory.Start(stopCh)

	// 5. waiting for the certificate is generated
	_ = wait.PollUntil(5*time.Second, func() (bool, error) {
		// keep polling until the certificate is signed
		if serverCertMgr.Current() != nil && tunnelProxyCertMgr.Current() != nil {
			return true, nil
		}
		klog.Infof("waiting for the master to sign the %s certificate", projectinfo.GetServerName())
		return false, nil
	}, stopCh)

	// 6. generate the TLS configuration based on the latest certificate
	tlsCfg, err := certmanager.GenTLSConfigUseCurrentCertAndCertPool(serverCertMgr.Current, cfg.RootCertPool, "server")
	if err != nil {
		return err
	}

	proxyClientTlsCfg, err := certmanager.GenTLSConfigUseCurrentCertAndCertPool(tunnelProxyCertMgr.Current, cfg.RootCertPool, "client")
	if err != nil {
		return err
	}

	// 7. start the server
	ts := server.NewTunnelServer(
		cfg.EgressSelectorEnabled,
		cfg.InterceptorServerUDSFile,
		cfg.ListenAddrForMaster,
		cfg.ListenInsecureAddrForMaster,
		cfg.ListenAddrForAgent,
		cfg.ServerCount,
		tlsCfg,
		proxyClientTlsCfg,
		wrappers,
		cfg.ProxyStrategy)
	if err := ts.Run(); err != nil {
		return err
	}

	// 8. start meta server
	util.RunMetaServer(cfg.ListenMetaAddr)

	<-stopCh
	wg.Wait()
	return nil
}

func getTunnelServerIPsAndDNSNamesBeforeInformerSynced(clientset kubernetes.Interface, stopCh <-chan struct{}) ([]net.IP, []string, error) {
	var (
		ips      = []net.IP{}
		dnsNames = []string{}
		err      error
	)

	// the ips and dnsNames should be acquired through api-server at the first time, because the informer factory has not started yet.
	werr := wait.PollUntil(5*time.Second, func() (bool, error) {
		dnsNames, ips, err = serveraddr.GetYurttunelServerDNSandIP(clientset)
		if err != nil {
			klog.Errorf("failed to get yurt tunnel server dns and ip, %v", err)
			return false, err
		}

		// get clusterIP for tunnel server internal service
		svc, err := clientset.CoreV1().Services(constants.YurttunnelServerServiceNs).Get(context.Background(), constants.YurttunnelServerInternalServiceName, metav1.GetOptions{})
		if errors.IsNotFound(err) {
			// compatible with versions that not supported x-tunnel-server-internal-svc
			klog.Warningf("get service: %s not found", constants.YurttunnelServerInternalServiceName)
			return true, nil
		} else if err != nil {
			klog.Warningf("get service: %s err, %v", constants.YurttunnelServerInternalServiceName, err)
			return false, err
		}

		if svc.Spec.ClusterIP != "" && net.ParseIP(svc.Spec.ClusterIP) != nil {
			ips = append(ips, net.ParseIP(svc.Spec.ClusterIP))
			dnsNames = append(dnsNames, serveraddr.GetDefaultDomainsForSvc(svc.Namespace, svc.Name)...)
		}

		return true, nil
	}, stopCh)
	if werr != nil {
		return nil, nil, werr
	}
	return ips, dnsNames, nil
}
