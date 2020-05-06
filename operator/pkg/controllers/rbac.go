package controllers

// +kubebuilder:rbac:groups=proxy.f110.dev,resources=proxies,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=proxy.f110.dev,resources=proxies/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=proxy.f110.dev,resources=backends,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=proxy.f110.dev,resources=backends/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=proxy.f110.dev,resources=roles,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=proxy.f110.dev,resources=roles/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=proxy.f110.dev,resources=rpcpermissions,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=proxy.f110.dev,resources=rpcpermissions/status,verbs=get;update;patch

// +kubebuilder:rbac:groups=etcd.f110.dev,resources=etcdclusters,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=etcd.f110.dev,resources=etcdclusters/status,verbs=get;update;patch

// +kubebuilder:rbac:groups=cert-manager.io,resources=certificates;clusterissuers,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=monitoring.coreos.com,resources=podmonitors;servicemonitors,verbs=get;list;watch;create;update;patch;delete

// +kubebuilder:rbac:groups=*,resources=pods;secrets;configmaps;services;cronjobs;deployments;poddisruptionbudgets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=*,resources=pods/portforward,verbs=get;list;create
// +kubebuilder:rbac:groups=batch,resources=cronjobs,verbs=get;list;watch;create;update;patch;delete
