/*
Copyright 2016 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package images

import (
	"context"
	"fmt"
	"strings"
	"time"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"k8s.io/client-go/util/flowcontrol"
	"k8s.io/klog/v2"

	runtimeapi "k8s.io/cri-api/pkg/apis/runtime/v1"
	crierrors "k8s.io/cri-api/pkg/errors"
	kubecontainer "k8s.io/kubernetes/pkg/kubelet/container"
	"k8s.io/kubernetes/pkg/kubelet/events"
	"k8s.io/kubernetes/pkg/kubelet/metrics"
	"k8s.io/kubernetes/pkg/util/parsers"
)

type ImagePodPullingTimeRecorder interface {
	RecordImageStartedPulling(podUID types.UID)
	RecordImageFinishedPulling(podUID types.UID)
}

// imageManager provides the functionalities for image pulling.
type imageManager struct {
	recorder     record.EventRecorder
	imageService kubecontainer.ImageService
	backOff      *flowcontrol.Backoff
	// It will check the presence of the image, and report the 'image pulling', image pulled' events correspondingly.
	puller imagePuller

	podPullingTimeRecorder ImagePodPullingTimeRecorder
}

var _ ImageManager = &imageManager{}

// NewImageManager instantiates a new ImageManager object.
func NewImageManager(recorder record.EventRecorder, imageService kubecontainer.ImageService, imageBackOff *flowcontrol.Backoff, serialized bool, maxParallelImagePulls *int32, qps float32, burst int, podPullingTimeRecorder ImagePodPullingTimeRecorder) ImageManager {
	imageService = throttleImagePulling(imageService, qps, burst)

	var puller imagePuller
	if serialized {
		puller = newSerialImagePuller(imageService)
	} else {
		puller = newParallelImagePuller(imageService, maxParallelImagePulls)
	}
	return &imageManager{
		recorder:               recorder,
		imageService:           imageService,
		backOff:                imageBackOff,
		puller:                 puller,
		podPullingTimeRecorder: podPullingTimeRecorder,
	}
}

// shouldPullImage returns whether we should pull an image according to
// the presence and pull policy of the image.
func shouldPullImage(pullPolicy v1.PullPolicy, imagePresent bool) bool {
	if pullPolicy == v1.PullNever {
		return false
	}

	if pullPolicy == v1.PullAlways ||
		(pullPolicy == v1.PullIfNotPresent && (!imagePresent)) {
		return true
	}

	return false
}

// records an event using ref, event msg.  log to glog using prefix, msg, logFn
func (m *imageManager) logIt(ref *v1.ObjectReference, eventtype, event, prefix, msg string, logFn func(args ...interface{})) {
	if ref != nil {
		m.recorder.Event(ref, eventtype, event, msg)
	} else {
		logFn(fmt.Sprint(prefix, " ", msg))
	}
}

// EnsureImageExists pulls the image for the specified pod and container, and returns
// (imageRef, error message, error).
func (m *imageManager) EnsureImageExists(ctx context.Context, pod *v1.Pod, container *v1.Container, pullSecrets []v1.Secret, podSandboxConfig *runtimeapi.PodSandboxConfig, podRuntimeHandler string, pullPolicy v1.PullPolicy) (string, string, error) {
	ref, err := kubecontainer.GenerateContainerRef(pod, container)
	if err != nil {
		klog.ErrorS(err, "Couldn't make a ref to pod", "pod", klog.KObj(pod), "containerName", container.Name)
	}

	imageRef, message, _, err := m.EnsureOCIObject(ctx, "image", ref, pod, container.Image, false, "", pullSecrets, podSandboxConfig, podRuntimeHandler, pullPolicy)
	if err != nil {
		return "", "", err
	}
	return imageRef, message, nil
}

func (m *imageManager) EnsureOCIObject(
	ctx context.Context,
	pullType string,
	ref *v1.ObjectReference,
	pod *v1.Pod,
	ociReference string,
	mount bool,
	mountLabel string,
	pullSecrets []v1.Secret,
	podSandboxConfig *runtimeapi.PodSandboxConfig,
	podRuntimeHandler string,
	pullPolicy v1.PullPolicy,
) (imageRef, message, mountPoint string, err error) {
	logPrefix := fmt.Sprintf("%s/%s/%s", pod.Namespace, pod.Name, ociReference)

	// If the image contains no tag or digest, a default tag should be applied.
	image, err := applyDefaultImageTag(ociReference)
	if err != nil {
		msg := fmt.Sprintf("Failed to apply default %s tag %q: %v", pullType, ociReference, err)
		m.logIt(ref, v1.EventTypeWarning, events.FailedToInspectImage, logPrefix, msg, klog.Warning)
		return "", msg, "", ErrInvalidImageName
	}

	var podAnnotations []kubecontainer.Annotation
	for k, v := range pod.GetAnnotations() {
		podAnnotations = append(podAnnotations, kubecontainer.Annotation{
			Name:  k,
			Value: v,
		})
	}

	spec := kubecontainer.ImageSpec{
		Image:          image,
		Annotations:    podAnnotations,
		RuntimeHandler: podRuntimeHandler,
		Mount:          mount,
		MountLabel:     mountLabel,
	}

	imageRef, err = m.imageService.GetImageRef(ctx, spec)
	if err != nil {
		msg := fmt.Sprintf("Failed to inspect %s %q: %v", pullType, ociReference, err)
		m.logIt(ref, v1.EventTypeWarning, events.FailedToInspectImage, logPrefix, msg, klog.Warning)
		return "", msg, "", ErrImageInspect
	}

	present := imageRef != ""
	if !shouldPullImage(pullPolicy, present) {
		if present {
			msg := fmt.Sprintf("Container %s %q already present on machine", pullType, ociReference)
			m.logIt(ref, v1.EventTypeNormal, events.PulledImage, logPrefix, msg, klog.Info)

			if mount {
				mountPoint, err = m.imageService.GetImageMountPoint(ctx, spec)
				if err != nil {
					msg := fmt.Sprintf("Failed to get %s mountpoint %q: %v", pullType, ociReference, err)
					m.logIt(ref, v1.EventTypeWarning, events.FailedToInspectImage, logPrefix, msg, klog.Warning)
					return "", msg, "", ErrImageInspect
				}

				// Object not mounted any more (for example due to a reboot),
				// we need to re-pull to enforce another mount
				if mountPoint == "" {
					if pullPolicy != v1.PullNever {
						msg := fmt.Sprintf("OCI object %q exists but it not mounted any more, pulling again", ociReference)
						m.logIt(ref, v1.EventTypeNormal, events.PullingImage, logPrefix, msg, klog.Info)
						goto pull
					} else {
						msg := fmt.Sprintf("OCI object %q exists but it not mounted any more, can't repull with pull policy of Never", ociReference)
						m.logIt(ref, v1.EventTypeWarning, events.ErrImageNeverPullPolicy, logPrefix, msg, klog.Warning)
						return imageRef, "", "", ErrImageNeverPull
					}
				}

				return imageRef, "", mountPoint, nil
			}

			return imageRef, "", "", nil
		}
		msg := fmt.Sprintf("Container %s %q is not present with pull policy of Never", pullType, ociReference)
		m.logIt(ref, v1.EventTypeWarning, events.ErrImageNeverPullPolicy, logPrefix, msg, klog.Warning)
		return "", msg, "", ErrImageNeverPull
	}

pull:
	backOffKey := fmt.Sprintf("%s_%s", pod.UID, ociReference)
	if m.backOff.IsInBackOffSinceUpdate(backOffKey, m.backOff.Clock.Now()) {
		msg := fmt.Sprintf("Back-off pulling %s %q", pullType, ociReference)
		m.logIt(ref, v1.EventTypeNormal, events.BackOffPullImage, logPrefix, msg, klog.Info)
		return "", msg, "", ErrImagePullBackOff
	}
	m.podPullingTimeRecorder.RecordImageStartedPulling(pod.UID)
	m.logIt(ref, v1.EventTypeNormal, events.PullingImage, logPrefix, fmt.Sprintf("Pulling %s %q", pullType, ociReference), klog.Info)
	startTime := time.Now()
	pullChan := make(chan pullResult)
	m.puller.pullImage(ctx, spec, pullSecrets, pullChan, podSandboxConfig)
	imagePullResult := <-pullChan
	if imagePullResult.err != nil {
		m.logIt(ref, v1.EventTypeWarning, events.FailedToPullImage, logPrefix, fmt.Sprintf("Failed to pull %s %q: %v", pullType, ociReference, imagePullResult.err), klog.Warning)
		m.backOff.Next(backOffKey, m.backOff.Clock.Now())

		msg, err := evalCRIPullErr(pullType, ociReference, imagePullResult.err)
		return "", msg, "", err
	}
	m.podPullingTimeRecorder.RecordImageFinishedPulling(pod.UID)
	imagePullDuration := time.Since(startTime).Truncate(time.Millisecond)
	m.logIt(ref, v1.EventTypeNormal, events.PulledImage, logPrefix, fmt.Sprintf("Successfully pulled %s %q in %v (%v including waiting). Size: %v bytes.",
		pullType, ociReference, imagePullResult.pullDuration.Truncate(time.Millisecond), imagePullDuration, imagePullResult.imageSize), klog.Info)
	metrics.ImagePullDuration.WithLabelValues(metrics.GetImageSizeBucket(imagePullResult.imageSize)).Observe(imagePullDuration.Seconds())
	m.backOff.GC()
	return imagePullResult.imageRef, "", imagePullResult.mountPoint, nil
}

func evalCRIPullErr(pullType, ociReference string, err error) (errMsg string, errRes error) {
	// Error assertions via errors.Is is not supported by gRPC (remote runtime) errors right now.
	// See https://github.com/grpc/grpc-go/issues/3616
	if strings.HasPrefix(err.Error(), crierrors.ErrRegistryUnavailable.Error()) {
		errMsg = fmt.Sprintf(
			"%s pull failed for %s because the registry is unavailable%s",
			pullType,
			ociReference,
			// Trim the error name from the message to convert errors like:
			// "RegistryUnavailable: a more detailed explanation" to:
			// "...because the registry is unavailable: a more detailed explanation"
			strings.TrimPrefix(err.Error(), crierrors.ErrRegistryUnavailable.Error()),
		)
		return errMsg, crierrors.ErrRegistryUnavailable
	}

	if strings.HasPrefix(err.Error(), crierrors.ErrSignatureValidationFailed.Error()) {
		errMsg = fmt.Sprintf(
			"%s pull failed for %s because the signature validation failed%s",
			pullType,
			ociReference,
			// Trim the error name from the message to convert errors like:
			// "SignatureValidationFailed: a more detailed explanation" to:
			// "...because the signature validation failed: a more detailed explanation"
			strings.TrimPrefix(err.Error(), crierrors.ErrSignatureValidationFailed.Error()),
		)
		return errMsg, crierrors.ErrSignatureValidationFailed
	}

	// Fallback for no specific error
	return err.Error(), ErrImagePull
}

// applyDefaultImageTag parses a docker image string, if it doesn't contain any tag or digest,
// a default tag will be applied.
func applyDefaultImageTag(image string) (string, error) {
	_, tag, digest, err := parsers.ParseImageName(image)
	if err != nil {
		return "", err
	}
	// we just concatenate the image name with the default tag here instead
	if len(digest) == 0 && len(tag) > 0 && !strings.HasSuffix(image, ":"+tag) {
		// we just concatenate the image name with the default tag here instead
		// of using dockerref.WithTag(named, ...) because that would cause the
		// image to be fully qualified as docker.io/$name if it's a short name
		// (e.g. just busybox). We don't want that to happen to keep the CRI
		// agnostic wrt image names and default hostnames.
		image = image + ":" + tag
	}
	return image, nil
}
