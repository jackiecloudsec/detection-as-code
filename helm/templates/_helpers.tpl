{{/*
Common labels
*/}}
{{- define "detection-engine.labels" -}}
app.kubernetes.io/name: detection-engine
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: engine
{{- end }}

{{/*
Selector labels
*/}}
{{- define "detection-engine.selectorLabels" -}}
app: detection-engine
{{- end }}
