package etcd

const (
	LabelNameClusterName = "etcdcluster.f110.dev/name"
	LabelNameEtcdVersion = "etcdcluster.f110.dev/version"
	LabelNameRole        = "etcdcluster.f110.dev/role"

	AnnotationKeyTemporaryMember   = "etcdcluster.f110.dev/tempmember"
	AnnotationKeyServerCertificate = "etcdcluster.f110.dev/servercert"
	AnnotationKeyRestartedAt       = "etcdcluster.f110.dev/restartedAt"

	PodAnnotationKeyRunningAt = "etcdcluster.f110.dev/runningAt"
)
