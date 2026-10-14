{{/* SPDX-License-Identifier: Apache-2.0 */}}
{{- define "apf.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "apf.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name (include "apf.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "apf.labels" -}}
app.kubernetes.io/name: {{ include "apf.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
{{- end -}}

{{- define "apf.selectorLabels" -}}
app.kubernetes.io/name: {{ include "apf.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "apf.bundleConfigMap" -}}
{{- if .Values.bundle.existingConfigMap -}}
{{- .Values.bundle.existingConfigMap -}}
{{- else -}}
{{- printf "%s-bundle" (include "apf.fullname" .) -}}
{{- end -}}
{{- end -}}

{{- define "apf.bundleSource" -}}
{{- $source := required "bundle.source must be http or local" .Values.bundle.source -}}
{{- if not (or (eq $source "http") (eq $source "local")) -}}
{{- fail "bundle.source must be http or local" -}}
{{- end -}}
{{- $source -}}
{{- end -}}

{{- define "apf.trustConfigMap" -}}
{{- if .Values.trustRoot.existingConfigMap -}}
{{- .Values.trustRoot.existingConfigMap -}}
{{- else -}}
{{- printf "%s-trust" (include "apf.fullname" .) -}}
{{- end -}}
{{- end -}}

{{- define "apf.signingSecret" -}}
{{- required "signing.existingSecret is required; provision it outside Helm" .Values.signing.existingSecret -}}
{{- end -}}
