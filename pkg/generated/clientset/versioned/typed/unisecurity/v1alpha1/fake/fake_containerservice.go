// Code generated by client-gen. DO NOT EDIT.

package fake

import (
	"context"

	v1alpha1 "../pkg/apis/unisecurity/v1alpha1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	labels "k8s.io/apimachinery/pkg/labels"
	schema "k8s.io/apimachinery/pkg/runtime/schema"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	testing "k8s.io/client-go/testing"
)

// FakeContainerServices implements ContainerServiceInterface
type FakeContainerServices struct {
	Fake *FakeUnisecurityV1alpha1
	ns   string
}

var containerservicesResource = schema.GroupVersionResource{Group: "unisecurity.unicloud.com", Version: "v1alpha1", Resource: "containerservices"}

var containerservicesKind = schema.GroupVersionKind{Group: "unisecurity.unicloud.com", Version: "v1alpha1", Kind: "ContainerService"}

// Get takes name of the containerService, and returns the corresponding containerService object, and an error if there is any.
func (c *FakeContainerServices) Get(ctx context.Context, name string, options v1.GetOptions) (result *v1alpha1.ContainerService, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewGetAction(containerservicesResource, c.ns, name), &v1alpha1.ContainerService{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.ContainerService), err
}

// List takes label and field selectors, and returns the list of ContainerServices that match those selectors.
func (c *FakeContainerServices) List(ctx context.Context, opts v1.ListOptions) (result *v1alpha1.ContainerServiceList, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewListAction(containerservicesResource, containerservicesKind, c.ns, opts), &v1alpha1.ContainerServiceList{})

	if obj == nil {
		return nil, err
	}

	label, _, _ := testing.ExtractFromListOptions(opts)
	if label == nil {
		label = labels.Everything()
	}
	list := &v1alpha1.ContainerServiceList{ListMeta: obj.(*v1alpha1.ContainerServiceList).ListMeta}
	for _, item := range obj.(*v1alpha1.ContainerServiceList).Items {
		if label.Matches(labels.Set(item.Labels)) {
			list.Items = append(list.Items, item)
		}
	}
	return list, err
}

// Watch returns a watch.Interface that watches the requested containerServices.
func (c *FakeContainerServices) Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error) {
	return c.Fake.
		InvokesWatch(testing.NewWatchAction(containerservicesResource, c.ns, opts))

}

// Create takes the representation of a containerService and creates it.  Returns the server's representation of the containerService, and an error, if there is any.
func (c *FakeContainerServices) Create(ctx context.Context, containerService *v1alpha1.ContainerService, opts v1.CreateOptions) (result *v1alpha1.ContainerService, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewCreateAction(containerservicesResource, c.ns, containerService), &v1alpha1.ContainerService{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.ContainerService), err
}

// Update takes the representation of a containerService and updates it. Returns the server's representation of the containerService, and an error, if there is any.
func (c *FakeContainerServices) Update(ctx context.Context, containerService *v1alpha1.ContainerService, opts v1.UpdateOptions) (result *v1alpha1.ContainerService, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewUpdateAction(containerservicesResource, c.ns, containerService), &v1alpha1.ContainerService{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.ContainerService), err
}

// Delete takes name of the containerService and deletes it. Returns an error if one occurs.
func (c *FakeContainerServices) Delete(ctx context.Context, name string, opts v1.DeleteOptions) error {
	_, err := c.Fake.
		Invokes(testing.NewDeleteActionWithOptions(containerservicesResource, c.ns, name, opts), &v1alpha1.ContainerService{})

	return err
}

// DeleteCollection deletes a collection of objects.
func (c *FakeContainerServices) DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error {
	action := testing.NewDeleteCollectionAction(containerservicesResource, c.ns, listOpts)

	_, err := c.Fake.Invokes(action, &v1alpha1.ContainerServiceList{})
	return err
}

// Patch applies the patch and returns the patched containerService.
func (c *FakeContainerServices) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v1alpha1.ContainerService, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewPatchSubresourceAction(containerservicesResource, c.ns, name, pt, data, subresources...), &v1alpha1.ContainerService{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.ContainerService), err
}
