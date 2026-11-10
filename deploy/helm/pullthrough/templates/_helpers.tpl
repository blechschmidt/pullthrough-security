{{/*
Expand the name of the chart.
*/}}
{{- define "pullthrough.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Fully qualified app name. Truncated at 63 chars for DNS-label limits.
*/}}
{{- define "pullthrough.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{- define "pullthrough.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels.
*/}}
{{- define "pullthrough.labels" -}}
helm.sh/chart: {{ include "pullthrough.chart" . }}
{{ include "pullthrough.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels — stable across upgrades, used by Deployment/Service/PDB.
*/}}
{{- define "pullthrough.selectorLabels" -}}
app.kubernetes.io/name: {{ include "pullthrough.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
ServiceAccount name.
*/}}
{{- define "pullthrough.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "pullthrough.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Image reference. Falls back to chart appVersion when image.tag is empty.
*/}}
{{- define "pullthrough.image" -}}
{{- $tag := .Values.image.tag | default .Chart.AppVersion -}}
{{- printf "%s:%s" .Values.image.repository $tag -}}
{{- end }}

{{/*
Name of the Secret holding env-injected secrets (existing or chart-managed).
*/}}
{{- define "pullthrough.secretName" -}}
{{- if .Values.secrets.existingSecret }}
{{- .Values.secrets.existingSecret }}
{{- else }}
{{- printf "%s-secrets" (include "pullthrough.fullname" .) }}
{{- end }}
{{- end }}

{{/*
Admission-webhook object name.
*/}}
{{- define "pullthrough.webhookName" -}}
{{- printf "%s-webhook" (include "pullthrough.fullname" .) | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Admission-webhook serving-cert Secret name (existing, cert-manager-managed, or default).
*/}}
{{- define "pullthrough.webhookTLSSecretName" -}}
{{- if .Values.webhook.tls.existingSecret }}
{{- .Values.webhook.tls.existingSecret }}
{{- else }}
{{- printf "%s-tls" (include "pullthrough.webhookName" .) }}
{{- end }}
{{- end }}

{{/*
Admission-webhook image reference (falls back to the main image).
*/}}
{{- define "pullthrough.webhookImage" -}}
{{- $repo := .Values.webhook.image.repository | default .Values.image.repository -}}
{{- $tag := .Values.webhook.image.tag | default .Values.image.tag | default .Chart.AppVersion -}}
{{- printf "%s:%s" $repo $tag -}}
{{- end }}

{{/*
Name of the PVC for the cache volume (existing or chart-managed).
*/}}
{{- define "pullthrough.pvcName" -}}
{{- if .Values.persistence.existingClaim }}
{{- .Values.persistence.existingClaim }}
{{- else }}
{{- printf "%s-data" (include "pullthrough.fullname" .) }}
{{- end }}
{{- end }}
