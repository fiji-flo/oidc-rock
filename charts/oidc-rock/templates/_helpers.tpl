{{/*
Expand the name of the chart.
*/}}
{{- define "oidc-rock.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "oidc-rock.fullname" -}}
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

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "oidc-rock.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "oidc-rock.labels" -}}
helm.sh/chart: {{ include "oidc-rock.chart" . }}
{{ include "oidc-rock.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "oidc-rock.selectorLabels" -}}
app.kubernetes.io/name: {{ include "oidc-rock.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Extract hostname from baseUrl
Example: https://oidc.example.com/path -> oidc.example.com
*/}}
{{- define "oidc-rock.hostname" -}}
{{- if .Values.app.baseUrl -}}
{{- $url := .Values.app.baseUrl | trimPrefix "http://" | trimPrefix "https://" -}}
{{- $url | splitList "/" | first -}}
{{- end -}}
{{- end }}

{{/*
Extract scheme from baseUrl
Example: https://oidc.example.com -> https
*/}}
{{- define "oidc-rock.scheme" -}}
{{- if .Values.app.baseUrl -}}
{{- if hasPrefix "https://" .Values.app.baseUrl -}}
https
{{- else -}}
http
{{- end -}}
{{- end -}}
{{- end }}

{{/*
Extract path from baseUrl (defaults to /)
Example: https://oidc.example.com/auth -> /auth
*/}}
{{- define "oidc-rock.path" -}}
{{- if .Values.app.baseUrl -}}
{{- $url := .Values.app.baseUrl | trimPrefix "http://" | trimPrefix "https://" -}}
{{- $parts := $url | splitList "/" -}}
{{- if gt (len $parts) 1 -}}
/{{ rest $parts | join "/" }}
{{- else -}}
/
{{- end -}}
{{- else -}}
/
{{- end -}}
{{- end }}

{{/*
Check if baseUrl uses TLS/HTTPS
*/}}
{{- define "oidc-rock.isTLS" -}}
{{- if .Values.app.baseUrl -}}
{{- hasPrefix "https://" .Values.app.baseUrl -}}
{{- else -}}
false
{{- end -}}
{{- end }}
