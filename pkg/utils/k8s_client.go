package utils

import (
	"os"
	"path/filepath"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
)

func InCluster() bool {
	ic := false
	if os.Getenv("KUBERNETES_SERVICE_HOST") != "" {
		ic = true
	}
	return ic
}

func NewK8sClient(inCluster bool) (*kubernetes.Clientset, error) {
	var config *rest.Config
	var err error
	switch inCluster {
	case false:
		kubeconfig := filepath.Join(homedir.HomeDir(), ".kube", "config")
		config, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
	case true:
		config, err = rest.InClusterConfig()
	}
	if err != nil {
		return nil, err
	}
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}
	return clientset, nil

}
