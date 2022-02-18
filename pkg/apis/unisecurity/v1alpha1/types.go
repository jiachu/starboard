package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	ActionForImageScanner = "P_ImageScanner"
	ActionForConfigAudit  = "P_ConfigAudit"
	ActionForCISBench     = "P_CISBench"
)

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type ContainerService struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Data ContainerServiceSpec `json:"data"`
}

type ContainerServiceSpec struct {
	Action       string `json:"action"`
	Kind         string `json:"kind"`
	ResourceName string `json:"resource_name"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type ContainerServiceList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	Items []ContainerService `json:"items"`
}
