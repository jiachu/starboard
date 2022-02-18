// Code generated by client-gen. DO NOT EDIT.

package fake

import (
	v1alpha1 "../pkg/generated/clientset/versioned/typed/unisecurity/v1alpha1"
	rest "k8s.io/client-go/rest"
	testing "k8s.io/client-go/testing"
)

type FakeUnisecurityV1alpha1 struct {
	*testing.Fake
}

func (c *FakeUnisecurityV1alpha1) ContainerServices(namespace string) v1alpha1.ContainerServiceInterface {
	return &FakeContainerServices{c, namespace}
}

// RESTClient returns a RESTClient that is used to communicate
// with API server by this client implementation.
func (c *FakeUnisecurityV1alpha1) RESTClient() rest.Interface {
	var ret *rest.RESTClient
	return ret
}
