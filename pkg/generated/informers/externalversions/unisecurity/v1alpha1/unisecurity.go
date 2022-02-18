// Code generated by informer-gen. DO NOT EDIT.

package v1alpha1

import (
	"context"
	time "time"

	internalinterfaces "../pkg/generated/informers/externalversions/internalinterfaces"
	unisecurityv1alpha1 "./../pkg/apis/unisecurity/v1alpha1"
	versioned "./../pkg/generated/clientset/versioned"
	v1alpha1 "./../pkg/generated/listers/unisecurity/v1alpha1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"
	watch "k8s.io/apimachinery/pkg/watch"
	cache "k8s.io/client-go/tools/cache"
)

// UniSecurityInformer provides access to a shared informer and lister for
// UniSecurities.
type UniSecurityInformer interface {
	Informer() cache.SharedIndexInformer
	Lister() v1alpha1.UniSecurityLister
}

type uniSecurityInformer struct {
	factory          internalinterfaces.SharedInformerFactory
	tweakListOptions internalinterfaces.TweakListOptionsFunc
	namespace        string
}

// NewUniSecurityInformer constructs a new informer for UniSecurity type.
// Always prefer using an informer factory to get a shared informer instead of getting an independent
// one. This reduces memory footprint and number of connections to the server.
func NewUniSecurityInformer(client versioned.Interface, namespace string, resyncPeriod time.Duration, indexers cache.Indexers) cache.SharedIndexInformer {
	return NewFilteredUniSecurityInformer(client, namespace, resyncPeriod, indexers, nil)
}

// NewFilteredUniSecurityInformer constructs a new informer for UniSecurity type.
// Always prefer using an informer factory to get a shared informer instead of getting an independent
// one. This reduces memory footprint and number of connections to the server.
func NewFilteredUniSecurityInformer(client versioned.Interface, namespace string, resyncPeriod time.Duration, indexers cache.Indexers, tweakListOptions internalinterfaces.TweakListOptionsFunc) cache.SharedIndexInformer {
	return cache.NewSharedIndexInformer(
		&cache.ListWatch{
			ListFunc: func(options v1.ListOptions) (runtime.Object, error) {
				if tweakListOptions != nil {
					tweakListOptions(&options)
				}
				return client.UnisecurityV1alpha1().UniSecurities(namespace).List(context.TODO(), options)
			},
			WatchFunc: func(options v1.ListOptions) (watch.Interface, error) {
				if tweakListOptions != nil {
					tweakListOptions(&options)
				}
				return client.UnisecurityV1alpha1().UniSecurities(namespace).Watch(context.TODO(), options)
			},
		},
		&unisecurityv1alpha1.UniSecurity{},
		resyncPeriod,
		indexers,
	)
}

func (f *uniSecurityInformer) defaultInformer(client versioned.Interface, resyncPeriod time.Duration) cache.SharedIndexInformer {
	return NewFilteredUniSecurityInformer(client, f.namespace, resyncPeriod, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc}, f.tweakListOptions)
}

func (f *uniSecurityInformer) Informer() cache.SharedIndexInformer {
	return f.factory.InformerFor(&unisecurityv1alpha1.UniSecurity{}, f.defaultInformer)
}

func (f *uniSecurityInformer) Lister() v1alpha1.UniSecurityLister {
	return v1alpha1.NewUniSecurityLister(f.Informer().GetIndexer())
}
