package registry

import (
	"context"
	"errors"
	"fmt"
	"log"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"go.f110.dev/xerrors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"go.f110.dev/heimdallr/pkg/k8s"
)

// ErrImageNotFound indicates that the OCI layout doesn't contain an image for the requested platform.
var ErrImageNotFound = xerrors.New("registry: the image for the platform is not found")

type ContainerImage struct {
	// Layout is a path of the OCI layout directory.
	Layout string
	// Repository is an image reference without the tag. (e,g, ghcr.io/f110/heimdallr/proxy)
	Repository string
	Tag        string
}

// Push uploads the images to the registry in the cluster through the port forwarding.
// The registry part of Repository is dropped because the node resolves MirrorHost to the registry.
func Push(ctx context.Context, cfg *rest.Config, platform v1.Platform, images ...*ContainerImage) error {
	repositories := make([]name.Repository, len(images))
	for i, v := range images {
		repo, err := name.NewRepository(v.Repository)
		if err != nil {
			return xerrors.WithStack(err)
		}
		if repo.RegistryStr() != MirrorHost {
			return xerrors.NewfWithStack("%s is not hosted on %s. The pushed image will never be pulled", v.Repository, MirrorHost)
		}
		repositories[i] = repo
	}

	client, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return xerrors.WithStack(err)
	}
	svc, err := client.CoreV1().Services(Namespace).Get(ctx, ServiceName, metav1.GetOptions{})
	if err != nil {
		return xerrors.WithStack(err)
	}
	forwarder, err := k8s.PortForward(ctx, cfg, client, svc, Port)
	if err != nil {
		return err
	}
	defer forwarder.Close()
	ports, err := forwarder.GetPorts()
	if err != nil {
		return xerrors.WithStack(err)
	}
	endpoint := fmt.Sprintf("127.0.0.1:%d", ports[0].Local)

	for i, v := range images {
		img, err := ImageFromLayout(v.Layout, platform)
		if err != nil {
			return err
		}
		tag, err := name.NewTag(fmt.Sprintf("%s/%s:%s", endpoint, repositories[i].RepositoryStr(), v.Tag), name.Insecure)
		if err != nil {
			return xerrors.WithStack(err)
		}

		log.Printf("Push %s:%s", v.Repository, v.Tag)
		if err := remote.Write(tag, img, remote.WithContext(ctx)); err != nil {
			return xerrors.WithStack(err)
		}
		if _, err := remote.Head(tag, remote.WithContext(ctx)); err != nil {
			return xerrors.WithStack(err)
		}
	}

	return nil
}

// ImageFromLayout picks the image that runs on platform from the OCI layout directory.
func ImageFromLayout(path string, platform v1.Platform) (v1.Image, error) {
	idx, err := layout.ImageIndexFromPath(path)
	if err != nil {
		return nil, xerrors.WithStack(err)
	}

	img, err := findImage(idx, platform)
	if err != nil {
		return nil, err
	}
	return img, nil
}

// findImage walks down the descriptors of idx. A descriptor that has no platform is adopted only
// when the index has no platform aware descriptor at all. (e,g, the layout of a single image)
func findImage(idx v1.ImageIndex, platform v1.Platform) (v1.Image, error) {
	m, err := idx.IndexManifest()
	if err != nil {
		return nil, xerrors.WithStack(err)
	}

	var unknown []v1.Descriptor
	for _, desc := range m.Manifests {
		switch {
		case desc.MediaType.IsIndex():
			child, err := idx.ImageIndex(desc.Digest)
			if err != nil {
				return nil, xerrors.WithStack(err)
			}
			img, err := findImage(child, platform)
			if err != nil {
				if errors.Is(err, ErrImageNotFound) {
					continue
				}
				return nil, err
			}
			return img, nil
		case desc.MediaType.IsImage():
			if desc.Platform == nil {
				unknown = append(unknown, desc)
				continue
			}
			if desc.Platform.Satisfies(platform) {
				img, err := idx.Image(desc.Digest)
				if err != nil {
					return nil, xerrors.WithStack(err)
				}
				return img, nil
			}
		}
	}

	if len(unknown) == 1 {
		img, err := idx.Image(unknown[0].Digest)
		if err != nil {
			return nil, xerrors.WithStack(err)
		}
		return img, nil
	}

	return nil, ErrImageNotFound
}
