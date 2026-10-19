{{- define "privatevault.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "privatevault.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name (include "privatevault.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "privatevault.selectorLabels" -}}
app.kubernetes.io/name: {{ include "privatevault.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "privatevault.labels" -}}
{{ include "privatevault.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | trunc 63 | trimSuffix "-" }}
{{- end -}}

{{- define "privatevault.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "privatevault.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{- define "privatevault.image" -}}
{{- if .Values.image.digest -}}
{{- printf "%s@%s" .Values.image.repository .Values.image.digest -}}
{{- else -}}
{{- printf "%s:%s" .Values.image.repository (default .Chart.AppVersion .Values.image.tag) -}}
{{- end -}}
{{- end -}}

{{/*
Refuse configurations that would start but not be safe, at render time, with
the same rules the API enforces at start-up.
*/}}
{{- define "privatevault.validate" -}}
{{- $multi := or (gt (int .Values.replicaCount) 1) .Values.autoscaling.enabled -}}
{{- if and $multi (not .Values.postgres.enabled) -}}
{{- fail "more than one replica needs postgres.enabled=true: SQLite cannot be shared between pods" -}}
{{- end -}}
{{- if and (not .Values.postgres.enabled) (not .Values.persistence.enabled) -}}
{{- fail "without PostgreSQL set persistence.enabled=true: a ledger in the pod's filesystem is lost on restart" -}}
{{- end -}}
{{- if not .Values.secrets.name -}}
{{- fail "secrets.name is required: an existing Secret with the API keys (and seeds or database URL)" -}}
{{- end -}}
{{- if not .Values.config.name -}}
{{- fail "config.name is required: an existing ConfigMap with grants and the trust bundle" -}}
{{- end -}}
{{- if and .Values.secureProfile (not .Values.signing.trustedPublicKeys) -}}
{{- fail "secureProfile needs signing.trustedPublicKeys (hex public key of the decision receipt signer)" -}}
{{- end -}}
{{- if and .Values.secureProfile (not .Values.config.presenterBundleKey) -}}
{{- fail "secureProfile needs config.presenterBundleKey: every permit binds its presenter (ADR 0028; init_secure_profile writes presenter-bundle.json)" -}}
{{- end -}}
{{- if and .Values.secureProfile (ne .Values.lineage "enforce") -}}
{{- fail "secureProfile needs lineage=enforce" -}}
{{- end -}}
{{- if and .Values.image.digest (not (hasPrefix "sha256:" .Values.image.digest)) -}}
{{- fail "image.digest must be sha256:<hex>" -}}
{{- end -}}
{{- end -}}
