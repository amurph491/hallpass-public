#!/bin/sh
set -eu

config_dir=/var/lib/hallpass-config
install -d -m 700 -o hallpass -g hallpass "$config_dir"

copy_secret() {
  variable_name=$1
  source_path=$2
  destination_path="$config_dir/$3"

  if [ ! -f "$source_path" ]; then
    echo "Configured secret for $variable_name is not a readable regular file." >&2
    exit 1
  fi

  install -m 600 -o hallpass -g hallpass "$source_path" "$destination_path"
  eval "export $variable_name=\$destination_path"
}

copy_secret HALLPASS_DB_PASSWORD_FILE "${HALLPASS_DB_PASSWORD_FILE:?}" db_password
copy_secret HALLPASS_SLACK_CLIENT_SECRET_FILE "${HALLPASS_SLACK_CLIENT_SECRET_FILE:?}" slack_client_secret
copy_secret HALLPASS_SECRET_MASTER_KEY_FILE "${HALLPASS_SECRET_MASTER_KEY_FILE:?}" secret_master_key
copy_secret HALLPASS_AGENT_CREDENTIAL_KEYS_FILE "${HALLPASS_AGENT_CREDENTIAL_KEYS_FILE:?}" agent_credential_keys
# Optional: an empty HALLPASS_ADMIN_BOOTSTRAP_FILE turns the shared bootstrap login off, so a host reachable from a
# network signs in with OIDC only. With neither login method configured the API refuses to start.
if [ -n "${HALLPASS_ADMIN_BOOTSTRAP_FILE:-}" ]; then
  copy_secret HALLPASS_ADMIN_BOOTSTRAP_FILE "$HALLPASS_ADMIN_BOOTSTRAP_FILE" admin_bootstrap
fi
# Optional: copied only when configured, so an older stack without these files still starts.
if [ -n "${HALLPASS_OIDC_CLIENT_SECRET_FILE:-}" ]; then
  copy_secret HALLPASS_OIDC_CLIENT_SECRET_FILE "$HALLPASS_OIDC_CLIENT_SECRET_FILE" oidc_client_secret
fi
# GitHub App secrets: only when GitHub is enabled, so the non-root API can read them.
if [ -n "${HALLPASS_GITHUB_APP_ID:-}" ]; then
  copy_secret HALLPASS_GITHUB_PRIVATE_KEY_FILE "${HALLPASS_GITHUB_PRIVATE_KEY_FILE:?}" github_app_private_key
  copy_secret HALLPASS_GITHUB_CLIENT_SECRET_FILE "${HALLPASS_GITHUB_CLIENT_SECRET_FILE:?}" github_client_secret
fi
# Notion OAuth client secret: only when Notion is enabled.
if [ -n "${HALLPASS_NOTION_CLIENT_ID:-}" ]; then
  copy_secret HALLPASS_NOTION_CLIENT_SECRET_FILE "${HALLPASS_NOTION_CLIENT_SECRET_FILE:?}" notion_client_secret
fi
# Linear's OAuth client secret: only when Linear is enabled.
if [ -n "${HALLPASS_LINEAR_CLIENT_ID:-}" ]; then
  copy_secret HALLPASS_LINEAR_CLIENT_SECRET_FILE "${HALLPASS_LINEAR_CLIENT_SECRET_FILE:?}" linear_client_secret
fi
# Google Drive OAuth client secret: only when Google Drive is enabled.
if [ -n "${HALLPASS_GOOGLE_DRIVE_CLIENT_ID:-}" ]; then
  copy_secret HALLPASS_GOOGLE_DRIVE_CLIENT_SECRET_FILE "${HALLPASS_GOOGLE_DRIVE_CLIENT_SECRET_FILE:?}" google_drive_client_secret
fi
# HubSpot OAuth client secret: only when HubSpot is enabled.
if [ -n "${HALLPASS_HUBSPOT_CLIENT_ID:-}" ]; then
  copy_secret HALLPASS_HUBSPOT_CLIENT_SECRET_FILE "${HALLPASS_HUBSPOT_CLIENT_SECRET_FILE:?}" hubspot_client_secret
fi
if [ -n "${HALLPASS_OTLP_HEADERS_FILE:-}" ]; then
  copy_secret HALLPASS_OTLP_HEADERS_FILE "$HALLPASS_OTLP_HEADERS_FILE" otlp_headers
fi

exec runuser -u hallpass -- "$@"
