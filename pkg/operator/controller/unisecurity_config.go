package controller

import (
	"context"
	"fmt"
	"github.com/aquasecurity/starboard/pkg/apis/unisecurity/v1alpha1"
	"github.com/aquasecurity/starboard/pkg/kube"
	"github.com/aquasecurity/starboard/pkg/operator/etc"
	"github.com/aquasecurity/starboard/pkg/operator/predicate"
	"github.com/aquasecurity/starboard/pkg/starboard"
	"github.com/go-logr/logr"
	k8sapierror "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

type UnisecurityReconciler struct {
	logr.Logger
	etc.Config
	client.Client
	kube.ObjectResolver
	LimitChecker
	starboard.ConfigData
	vul       *VulnerabilityReportReconciler
	confAudit *ConfigAuditReportReconciler
	cis       *CISKubeBenchReportReconciler
}

func (r *UnisecurityReconciler) SetupWithManager(mgr ctrl.Manager) error {
	opts := builder.WithPredicates(
		predicate.Not(predicate.IsBeingTerminated))

	r.Logger.V(1).Info("create unicloud security reconciler")

	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.ContainerService{}, opts).
		Complete(r.reconcileUnisConfig(kube.KindUniContainerService))
}

func (r *UnisecurityReconciler) RegisterVulReconciler(vul *VulnerabilityReportReconciler) {
	r.vul = vul
}

func (r *UnisecurityReconciler) RegisterConfAuditReconciler(configAudit *ConfigAuditReportReconciler) {
	r.confAudit = configAudit
}

func (r *UnisecurityReconciler) RegisterCISBenchReconciler(cisBench *CISKubeBenchReportReconciler) {
	r.cis = cisBench
}

func (r *UnisecurityReconciler) reconcileUnisConfig(workloadKind kube.Kind) reconcile.Func {
	return func(ctx context.Context, req reconcile.Request) (res reconcile.Result, e error) {
		log := r.Logger.WithValues("kind", workloadKind, "name", req.NamespacedName)
		workloadPartial := kube.ObjectRefFromKindAndNamespacedName(workloadKind, req.NamespacedName)

		log.V(1).Info("Getting workload from cache")
		cs, err := r.GetContainerSrvByObj(ctx, workloadPartial)
		if err != nil {
			if k8sapierror.IsNotFound(err) {
				log.V(1).Info("Ignoring cached workload that must have been deleted")
				return ctrl.Result{}, nil
			}
			return ctrl.Result{}, fmt.Errorf("getting %s from cache: %w", workloadKind, err)
		}

		// crd to scan resource
		_, gvk, err := kube.GVRForResource(r.RESTMapper(), cs.Data.Kind)
		if err != nil {
			return ctrl.Result{}, err
		}
		if "" == cs.Data.ResourceName {
			return ctrl.Result{}, fmt.Errorf("required workload name is blank")
		}

		workload := kube.ObjectRef{
			Namespace: cs.Namespace,
			Kind:      kube.Kind(gvk.Kind),
			Name:      cs.Data.ResourceName,
		}
		switch cs.Data.Action {
		case v1alpha1.ActionForImageScanner:
			if r.vul == nil {
				log.Info("vulnerability is not enabled")
				return ctrl.Result{}, fmt.Errorf("vulnerability is not enabled")
			}
			return r.vul.reconcileWorkload(workload.Kind).Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{
				Namespace: workload.Namespace,
				Name:      workload.Name,
			}})
		case v1alpha1.ActionForConfigAudit:
			if r.confAudit == nil {
				log.Info("config audit is not enabled")
				return ctrl.Result{}, fmt.Errorf("config audit is not enabled")
			}
			return r.confAudit.reconcileResource(workload.Kind).Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{
				Namespace: workload.Namespace,
				Name:      workload.Name,
			}})
		case v1alpha1.ActionForCISBench:
			if r.cis == nil {
				log.Info("cis bench is not enabled")
				return ctrl.Result{}, fmt.Errorf("cis bench  is not enabled")
			}
			return r.cis.reconcileNodes().Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{
				Namespace: workload.Namespace,
				Name:      workload.Name,
			}})
		}
		return ctrl.Result{}, fmt.Errorf("unknown action [%s]", cs.Data.Action)
	}
}
