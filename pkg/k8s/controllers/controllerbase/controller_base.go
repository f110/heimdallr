package controllerbase

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"time"

	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	typedcorev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/record"
	"k8s.io/client-go/util/workqueue"

	"go.f110.dev/heimdallr/pkg/k8s/client/versioned/scheme"
	"go.f110.dev/heimdallr/pkg/logger"
)

type TimeKey struct{}
type ReconciliationId struct{}

type ObjectToKeyConverter func(obj interface{}) (keys []string, err error)

type ControllerBase interface {
	Name() string
	Finalizers() []string
	ListerSynced() []cache.InformerSynced
	EventSources() []cache.SharedIndexInformer
	ConvertToKeys() ObjectToKeyConverter
	GetObject(key string) (interface{}, error)
	UpdateObject(ctx context.Context, obj interface{}) error
	Reconcile(ctx context.Context, obj interface{}) error
	Finalize(ctx context.Context, obj interface{}) error
}

type Controller struct {
	Base ControllerBase

	log     *zap.Logger
	recoder record.EventRecorder
	queue   workqueue.RateLimitingInterface

	useFinalizer bool
}

func NewController(base ControllerBase, coreClient kubernetes.Interface) *Controller {
	c := &Controller{
		Base: base,
		queue: workqueue.NewNamedRateLimitingQueue(
			workqueue.DefaultControllerRateLimiter(),
			base.Name(),
		),
		log:          logger.Log.Named(base.Name()),
		useFinalizer: len(base.Finalizers()) > 0,
	}
	for _, v := range base.EventSources() {
		v.AddEventHandler(c)
	}

	eventBroadcaster := record.NewBroadcaster()
	eventBroadcaster.StartLogging(func(format string, args ...interface{}) {
		c.Log(nil).Info(fmt.Sprintf(format, args...))
	})
	eventBroadcaster.StartRecordingToSink(&typedcorev1.EventSinkImpl{Interface: coreClient.CoreV1().Events(metav1.NamespaceAll)})
	recorder := eventBroadcaster.NewRecorder(scheme.Scheme, corev1.EventSource{Component: base.Name()})
	c.recoder = recorder

	return c
}

func (c *Controller) Run(ctx context.Context, workers int) {
	defer c.queue.ShutDown()

	synced := make([]cache.InformerSynced, 0)
	for _, v := range c.Base.ListerSynced() {
		if v != nil {
			synced = append(synced, v)
		}
	}

	if !cache.WaitForCacheSync(ctx.Done(), synced...) {
		return
	}

	for i := 0; i < workers; i++ {
		go c.worker()
	}

	<-ctx.Done()
}

func (c *Controller) Log(ctx context.Context) *zap.Logger {
	return c.log.With(WithReconciliationId(ctx))
}

func (c *Controller) EventRecorder() record.EventRecorder {
	return c.recoder
}

func (c *Controller) processNextItem() bool {
	defer c.Log(nil).Debug("Finish processNextItem")

	key, shutdown := c.queue.Get()
	if shutdown {
		return false
	}
	c.Log(nil).Debug("Get next queue", zap.Any("key", key))

	err := c.ProcessKey(key.(string))
	if err != nil {
		c.Log(nil).Info("Failed sync", zap.Error(err))
	}

	return true
}

func (c *Controller) ProcessKey(key string) error {
	defer c.queue.Done(key)

	ctx, cancelFunc := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancelFunc()
	ctx = context.WithValue(ctx, ReconciliationId{}, randomString(8))

	obj, err := c.Base.GetObject(key)
	if err != nil {
		return err
	}
	if obj == nil {
		return nil
	}
	ctx = context.WithValue(ctx, TimeKey{}, time.Now())

	objMeta, err := meta.Accessor(obj)
	if err != nil {
		return err
	}
	if c.useFinalizer {
		if objMeta.GetDeletionTimestamp().IsZero() {
			for _, finalizer := range c.Base.Finalizers() {
				if !containsString(objMeta.GetFinalizers(), finalizer) {
					objMeta.SetFinalizers(append(objMeta.GetFinalizers(), finalizer))
					if err := c.Base.UpdateObject(ctx, obj); err != nil {
						return err
					}
				}
			}
		}
	}

	if objMeta.GetDeletionTimestamp().IsZero() {
		err = c.Base.Reconcile(ctx, obj)
	} else {
		err = c.Base.Finalize(ctx, obj)
	}
	if err != nil {
		if errors.Is(err, &RetryError{}) {
			c.Log(ctx).Debug("Retrying", zap.Error(err))
			c.queue.AddRateLimited(key)
			return nil
		}

		return err
	}

	c.queue.Forget(key)
	return nil
}

func (c *Controller) worker() {
	c.Log(nil).Debug("Start worker")
	for c.processNextItem() {
	}
}

func (c *Controller) OnAdd(obj interface{}) {
	c.enqueue(obj)
}

func (c *Controller) OnUpdate(old, new interface{}) {
	oldObj, err := meta.Accessor(old)
	if err != nil {
		return
	}
	newObj, err := meta.Accessor(new)
	if err != nil {
		return
	}

	if oldObj.GetUID() != newObj.GetUID() {
		if key, err := cache.MetaNamespaceKeyFunc(oldObj); err != nil {
			return
		} else {
			c.OnDelete(cache.DeletedFinalStateUnknown{Key: key, Obj: oldObj})
		}
	}

	c.enqueue(newObj)
}

func (c *Controller) OnDelete(obj interface{}) {
	dfsu, ok := obj.(cache.DeletedFinalStateUnknown)
	if ok {
		c.enqueue(dfsu.Key)
		return
	}

	c.enqueue(obj)
}

func (c *Controller) enqueue(obj interface{}) {
	if keys, err := c.Base.ConvertToKeys()(obj); err != nil {
		return
	} else {
		for _, key := range keys {
			c.queue.Add(key)
		}
	}
}

func RemoveFinalizer(metaObj *metav1.ObjectMeta, finalizer string) {
	metaObj.Finalizers = removeString(metaObj.Finalizers, finalizer)
}

func containsString(v []string, s string) bool {
	for _, item := range v {
		if item == s {
			return true
		}
	}

	return false
}

func removeString(v []string, s string) []string {
	result := make([]string, 0, len(v))
	for _, item := range v {
		if item == s {
			continue
		}

		result = append(result, item)
	}

	return result
}

var charset = []byte("abcdefghijklmnopqrstuvwxyz0123456789")

func randomString(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}

	return string(b)
}
