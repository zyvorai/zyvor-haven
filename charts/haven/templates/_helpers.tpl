{{- define "haven.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "haven.labels" -}}
app.kubernetes.io/name: {{ include "haven.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/part-of: haven
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
{{- end -}}

{{/* haven-idp labels; the selector subset (name + instance) is immutable. See internal/render/IDP_CONTRACT.md. */}}
{{- define "haven.idpSelector" -}}
app.kubernetes.io/name: haven-idp
app.kubernetes.io/instance: {{ .Values.plane.name }}
{{- end -}}

{{- define "haven.idpLabels" -}}
{{ include "haven.idpSelector" . }}
app.kubernetes.io/part-of: haven
app.kubernetes.io/component: identity
haven.identity/managed: "true"
haven.identity/plane: {{ .Values.plane.name }}
{{- end -}}
