#!/usr/bin/env bash
set -euo pipefail

REPO_URL="https://github.com/atillakurtulussimsek/netflow-logger.git"
INSTALL_DIR="/srv/netflow-logger"
SERVICE_NAME="netflow-logger"
SERVICE_USER="netflow-logger"
SERVICE_GROUP="netflow-logger"
LOG_DIR="${INSTALL_DIR}/logs"
ENV_FILE="${INSTALL_DIR}/.env"
BIN_PATH="${INSTALL_DIR}/netflow-logger"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
GO_APT_PACKAGE="golang-go"
GO_FALLBACK_API="https://go.dev/dl/?mode=json"

if [[ "${EUID}" -ne 0 ]]; then
  echo "Bu kurulum aracı root olarak çalıştırılmalıdır."
  exit 1
fi

require_command() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    return 1
  fi
  return 0
}

ensure_base_packages() {
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  apt-get install -y git curl tar ca-certificates python3
}

ensure_go() {
  if command -v go >/dev/null 2>&1; then
    return 0
  fi

  echo "Go bulunamadı, önce apt paketi deneniyor..."
  apt-get install -y "${GO_APT_PACKAGE}"
  if command -v go >/dev/null 2>&1; then
    return 0
  fi

  echo "Apt paketi ile Go kurulamadı, go.dev üzerinden güncel stable sürüm indiriliyor..."
  local tmp_dir go_tarball go_url
  tmp_dir="$(mktemp -d)"
  trap 'rm -rf "${tmp_dir}"' RETURN

  go_tarball="$(curl -fsSL "${GO_FALLBACK_API}" | python3 -c 'import json,sys; data=json.load(sys.stdin); print(next(f["filename"] for r in data if r.get("stable") for f in r.get("files", []) if f.get("os")=="linux" and f.get("arch")=="amd64" and f.get("kind")=="archive"))')"
  go_url="https://go.dev/dl/${go_tarball}"

  curl -fsSL "${go_url}" -o "${tmp_dir}/${go_tarball}"
  rm -rf /usr/local/go
  tar -C /usr/local -xzf "${tmp_dir}/${go_tarball}"
  ln -sf /usr/local/go/bin/go /usr/local/bin/go
  ln -sf /usr/local/go/bin/gofmt /usr/local/bin/gofmt
}

ensure_service_user() {
  if ! getent group "${SERVICE_GROUP}" >/dev/null 2>&1; then
    groupadd --system "${SERVICE_GROUP}"
  fi

  if ! id -u "${SERVICE_USER}" >/dev/null 2>&1; then
    useradd \
      --system \
      --gid "${SERVICE_GROUP}" \
      --home-dir "${INSTALL_DIR}" \
      --create-home \
      --shell /usr/sbin/nologin \
      "${SERVICE_USER}"
  fi
}

clone_or_update_repo() {
  if [[ -d "${INSTALL_DIR}/.git" ]]; then
    echo "Mevcut kurulum bulundu, GitHub'dan güncel kod çekiliyor..."
    git -C "${INSTALL_DIR}" fetch --all --tags
    git -C "${INSTALL_DIR}" reset --hard origin/HEAD
    return 0
  fi

  rm -rf "${INSTALL_DIR}"
  git clone "${REPO_URL}" "${INSTALL_DIR}"
}

prompt_value() {
  local prompt_text="$1"
  local default_value="$2"
  local result=""
  read -r -p "${prompt_text} [${default_value}]: " result
  if [[ -z "${result}" ]]; then
    result="${default_value}"
  fi
  printf '%s' "${result}"
}

prompt_secret() {
  local prompt_text="$1"
  local result=""
  while [[ -z "${result}" ]]; do
    read -r -s -p "${prompt_text}: " result
    echo
  done
  printf '%s' "${result}"
}

write_env_file() {
  if [[ -f "${ENV_FILE}" ]]; then
    local rewrite_env=""
    read -r -p ".env dosyası mevcut. Yeniden oluşturulsun mu? [y/N]: " rewrite_env
    case "${rewrite_env}" in
      y|Y|yes|YES)
        ;;
      *)
        echo "Mevcut .env korunuyor."
        chown "${SERVICE_USER}:${SERVICE_GROUP}" "${ENV_FILE}"
        chmod 640 "${ENV_FILE}"
        return 0
        ;;
    esac
  fi

  local dashboard_user dashboard_pass netflow_addr dashboard_addr timezone tsa_url

  dashboard_user="$(prompt_value "Dashboard kullanıcı adı" "admin")"
  dashboard_pass="$(prompt_secret "Dashboard parolası")"
  netflow_addr="$(prompt_value "NetFlow dinleme adresi" ":9995")"
  dashboard_addr="$(prompt_value "Dashboard dinleme adresi" ":8080")"
  timezone="$(prompt_value "Zaman dilimi" "Europe/Istanbul")"
  tsa_url="$(prompt_value "TSA URL" "https://freetsa.org/tsr")"

  cat > "${ENV_FILE}" <<EOF
NETFLOW_LISTEN_ADDRESS=${netflow_addr}
DASHBOARD_ADDRESS=${dashboard_addr}
DASHBOARD_USERNAME=${dashboard_user}
DASHBOARD_PASSWORD=${dashboard_pass}
LOG_ROOT=${LOG_DIR}
TSA_URL=${tsa_url}
TIMEZONE=${timezone}
EOF

  chown "${SERVICE_USER}:${SERVICE_GROUP}" "${ENV_FILE}"
  chmod 640 "${ENV_FILE}"
}

build_binary() {
  cd "${INSTALL_DIR}"
  /usr/local/bin/go mod tidy
  /usr/local/bin/go build -o "${BIN_PATH}" .
  chown "${SERVICE_USER}:${SERVICE_GROUP}" "${BIN_PATH}"
  chmod 750 "${BIN_PATH}"
}

write_service_file() {
  cat > "${SERVICE_FILE}" <<EOF
[Unit]
Description=NetFlow Logger Service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${SERVICE_USER}
Group=${SERVICE_GROUP}
WorkingDirectory=${INSTALL_DIR}
EnvironmentFile=${ENV_FILE}
ExecStart=${BIN_PATH}
Restart=always
RestartSec=5
NoNewPrivileges=true
ProtectSystem=full
ProtectHome=true
PrivateTmp=true
ReadWritePaths=${INSTALL_DIR}
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
EOF

  chmod 644 "${SERVICE_FILE}"
}

prepare_permissions() {
  mkdir -p "${LOG_DIR}"
  chown -R "${SERVICE_USER}:${SERVICE_GROUP}" "${INSTALL_DIR}"
  chmod 755 "${INSTALL_DIR}"
  chmod 755 "${LOG_DIR}"
}

enable_and_start_service() {
  systemctl daemon-reload
  systemctl enable "${SERVICE_NAME}"
  systemctl restart "${SERVICE_NAME}"
  systemctl --no-pager --full status "${SERVICE_NAME}" || true
}

main() {
  ensure_base_packages
  ensure_go
  ensure_service_user
  clone_or_update_repo
  prepare_permissions
  write_env_file
  build_binary
  write_service_file
  enable_and_start_service

  echo
  echo "Kurulum/güncelleme tamamlandı."
  echo "Servis adı: ${SERVICE_NAME}"
  echo "Kurulum dizini: ${INSTALL_DIR}"
  echo "Çevre dosyası: ${ENV_FILE}"
  echo "Log dizini: ${LOG_DIR}"
  echo "Güncelleme için aynı script tekrar çalıştırılabilir; mevcut kurulum varsa repo güncellenir ve servis yeniden başlatılır."
}

main "$@"
