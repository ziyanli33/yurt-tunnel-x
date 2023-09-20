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

package main

import (
	"flag"
	"os"
	"os/signal"
	"syscall"

	"k8s.io/klog/v2"

	"yurt-tunnel/cmd/yurt-tunnel-server/app"
	"yurt-tunnel/pkg/projectinfo"
)

func main() {
	klog.InitFlags(nil)
	defer klog.Flush()

	// Set up channel on which to send signal notifications.
	// We must use a buffered channel or risk missing the signal
	// if we're not ready to receive when the signal is sent.
	s := make(chan os.Signal, 1)
	signal.Notify(s, syscall.SIGINT, syscall.SIGHUP, syscall.SIGTERM,
		syscall.SIGQUIT, syscall.SIGILL, syscall.SIGTRAP, syscall.SIGABRT)
	stop := make(chan struct{})
	go func() {
		<-s
		close(stop)
	}()

	cmd := app.NewYurttunnelServerCommand(stop)
	cmd.Flags().AddGoFlagSet(flag.CommandLine)
	if err := cmd.Execute(); err != nil {
		klog.Fatalf("%s failed: %s", projectinfo.GetServerName(), err)
	}
}
