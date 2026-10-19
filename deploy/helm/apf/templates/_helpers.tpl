{{- /*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */ -}}
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

{{/*
apf.image renders a component image reference from its image block and the
global defaults: [registry/]repository@digest, or [registry/]repository:tag
with the chart appVersion as the fallback tag. Call with (dict "image"
<component image> "global" .Values.global "chart" .Chart).
*/}}
{{- define "apf.image" -}}
{{- $registry := default .global.image.registry .image.registry -}}
{{- $repository := required "image.repository is required" .image.repository -}}
{{- $name := ternary (printf "%s/%s" $registry $repository) $repository (ne $registry "") -}}
{{- if .image.digest -}}
{{- printf "%s@%s" $name .image.digest -}}
{{- else -}}
{{- printf "%s:%s" $name (default .chart.AppVersion (default .global.image.tag .image.tag)) -}}
{{- end -}}
{{- end -}}

{{/*
apf.pullPolicy returns the component pull policy, or the global one when the
component leaves it null. Call with (dict "image" <component image> "global" .Values.global).
*/}}
{{- define "apf.pullPolicy" -}}
{{- default .global.image.pullPolicy .image.pullPolicy -}}
{{- end -}}

{{- define "apf.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "apf.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{- define "apf.bundleConfigMap" -}}
{{- if .Values.policyService.bundle.local.existingConfigMap -}}
{{- .Values.policyService.bundle.local.existingConfigMap -}}
{{- else -}}
{{- printf "%s-bundle" (include "apf.fullname" .) -}}
{{- end -}}
{{- end -}}

{{- define "apf.bundleSource" -}}
{{- $source := required "policyService.bundle.source must be http or local" .Values.policyService.bundle.source -}}
{{- if not (or (eq $source "http") (eq $source "local")) -}}
{{- fail "policyService.bundle.source must be http or local" -}}
{{- end -}}
{{- $source -}}
{{- end -}}

{{- define "apf.trustConfigMap" -}}
{{- if .Values.policyService.trustRoot.existingConfigMap -}}
{{- .Values.policyService.trustRoot.existingConfigMap -}}
{{- else -}}
{{- printf "%s-trust" (include "apf.fullname" .) -}}
{{- end -}}
{{- end -}}

{{- define "apf.signingSecret" -}}
{{- required "policyService.signing.existingSecret is required; provision it outside Helm" .Values.policyService.signing.existingSecret -}}
{{- end -}}
