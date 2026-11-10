package k8swebhook

import "encoding/json"

// The following types are a dependency-free, JSON-compatible subset of
// k8s.io/api/admission/v1 and the core Pod schema. The project deliberately
// avoids the heavyweight k8s client-go/api module dependency; the admission
// protocol is a stable, versioned JSON contract, so a faithful struct subset is
// sufficient and keeps the webhook's build surface tiny. Only the fields the
// decision engine reads (or must echo back) are modeled; unknown fields are
// ignored on decode.

// admissionReviewGVK is the apiVersion/kind the API server sends and expects
// back in the response envelope.
const (
	admissionAPIVersion = "admission.k8s.io/v1"
	admissionKind       = "AdmissionReview"
)

// AdmissionReview is the top-level request/response envelope exchanged with the
// API server. The API server populates Request; the webhook fills Response and
// echoes APIVersion/Kind.
type AdmissionReview struct {
	APIVersion string             `json:"apiVersion"`
	Kind       string             `json:"kind"`
	Request    *AdmissionRequest  `json:"request,omitempty"`
	Response   *AdmissionResponse `json:"response,omitempty"`
}

// GroupVersionKind / GroupVersionResource identify the reviewed object's type.
type GroupVersionKind struct {
	Group   string `json:"group"`
	Version string `json:"version"`
	Kind    string `json:"kind"`
}

type GroupVersionResource struct {
	Group    string `json:"group"`
	Version  string `json:"version"`
	Resource string `json:"resource"`
}

// UserInfo describes the authenticated user that submitted the request.
type UserInfo struct {
	Username string   `json:"username,omitempty"`
	UID      string   `json:"uid,omitempty"`
	Groups   []string `json:"groups,omitempty"`
}

// AdmissionRequest is the API server's review request for a single object.
type AdmissionRequest struct {
	UID         string               `json:"uid"`
	Kind        GroupVersionKind     `json:"kind"`
	Resource    GroupVersionResource `json:"resource"`
	SubResource string               `json:"subResource,omitempty"`
	Name        string               `json:"name,omitempty"`
	Namespace   string               `json:"namespace,omitempty"`
	Operation   string               `json:"operation,omitempty"`
	UserInfo    UserInfo             `json:"userInfo,omitempty"`
	Object      json.RawMessage      `json:"object,omitempty"`
	OldObject   json.RawMessage      `json:"oldObject,omitempty"`
	DryRun      *bool                `json:"dryRun,omitempty"`
}

// AdmissionResponse is the webhook's verdict for a request.
type AdmissionResponse struct {
	UID              string            `json:"uid"`
	Allowed          bool              `json:"allowed"`
	Status           *Status           `json:"status,omitempty"`
	Warnings         []string          `json:"warnings,omitempty"`
	AuditAnnotations map[string]string `json:"auditAnnotations,omitempty"`
}

// Status carries a human-readable rejection reason and an HTTP-style code,
// surfaced by kubectl when a Pod is denied.
type Status struct {
	Message string `json:"message,omitempty"`
	Reason  string `json:"reason,omitempty"`
	Code    int32  `json:"code,omitempty"`
}

// --- core object subset -----------------------------------------------------

// objectMeta is the subset of ObjectMeta the webhook reads.
type objectMeta struct {
	Name        string            `json:"name,omitempty"`
	Namespace   string            `json:"namespace,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
}

// container is the subset of a PodSpec container the webhook reads.
type container struct {
	Name  string `json:"name,omitempty"`
	Image string `json:"image,omitempty"`
}

// podSpec covers all three container collections an image can hide in.
type podSpec struct {
	Containers          []container `json:"containers,omitempty"`
	InitContainers      []container `json:"initContainers,omitempty"`
	EphemeralContainers []container `json:"ephemeralContainers,omitempty"`
}

// podObject is the decoded AdmissionRequest.Object when the reviewed resource is
// a Pod.
type podObject struct {
	Metadata objectMeta `json:"metadata"`
	Spec     podSpec    `json:"spec"`
}

// imageSource pairs a container's image with where it was declared, for precise
// rejection messages.
type imageSource struct {
	Container string // container name
	Kind      string // "container" | "initContainer" | "ephemeralContainer"
	Image     string // raw image reference
}

// extractImages collects every container image from a decoded Pod object,
// preserving declaration order (regular, then init, then ephemeral).
func extractImages(pod *podObject) []imageSource {
	if pod == nil {
		return nil
	}
	out := make([]imageSource, 0, len(pod.Spec.Containers)+len(pod.Spec.InitContainers)+len(pod.Spec.EphemeralContainers))
	collect := func(cs []container, kind string) {
		for _, c := range cs {
			if c.Image == "" {
				continue
			}
			out = append(out, imageSource{Container: c.Name, Kind: kind, Image: c.Image})
		}
	}
	collect(pod.Spec.Containers, "container")
	collect(pod.Spec.InitContainers, "initContainer")
	collect(pod.Spec.EphemeralContainers, "ephemeralContainer")
	return out
}

// isPodRequest reports whether the review targets a core/v1 Pod create/connect.
// The webhook is registered for Pods specifically, but a belt-and-suspenders
// check keeps a misconfigured rule from being treated as fail-open on non-pods.
func isPodRequest(req *AdmissionRequest) bool {
	if req == nil {
		return false
	}
	r := req.Resource
	return r.Resource == "pods" && (r.Group == "" || r.Group == "core")
}
