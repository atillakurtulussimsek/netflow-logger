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
  git config --global --add safe.directory "${INSTALL_DIR}" >/dev/null 2>&1 || true

  if [[ -d "${INSTALL_DIR}/.git" ]]; then
    echo "Mevcut kurulum bulundu, GitHub'dan güncel kod çekiliyor..."
    git -C "${INSTALL_DIR}" fetch --all --tags
    git -C "${INSTALL_DIR}" reset --hard origin/HEAD
    return 0
  fi

  rm -rf "${INSTALL_DIR}"
  git clone "${REPO_URL}" "${INSTALL_DIR}"
  git config --global --add safe.directory "${INSTALL_DIR}" >/dev/null 2>&1 || true
}

prompt_value() {
  local prompt_text="$1"
  local default_value="$2"
  local result=""
  read -r -p "${prompt_text} [${default_value}]: " result </dev/tty
  if [[ -z "${result}" ]]; then
    result="${default_value}"
  fi
  printf '%s' "${result}"
}

prompt_secret() {
  local prompt_text="$1"
  local result=""
  while [[ -z "${result}" ]]; do
    read -r -s -p "${prompt_text}: " result </dev/tty
    printf '\n' >/dev/tty
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
        if ! grep -q '^FTP_ENABLED=' "${ENV_FILE}"; then
          configure_ftp
        fi
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

  configure_ftp

  if grep -qv '=' "${ENV_FILE}"; then
    echo ".env oluşturulurken geçersiz satır tespit edildi. Lütfen scripti tekrar çalıştırın."
    exit 1
  fi

  chown "${SERVICE_USER}:${SERVICE_GROUP}" "${ENV_FILE}"
  chmod 640 "${ENV_FILE}"
}

prompt_yes_no() {
  local prompt_text="$1"
  local default_value="$2"
  local result=""
  read -r -p "${prompt_text} [${default_value}]: " result </dev/tty
  result="${result:-${default_value}}"
  case "${result}" in
    e|E|evet|EVET|y|Y|yes|YES) return 0 ;;
    *) return 1 ;;
  esac
}

# configure_ftp, FTP arşivleme ayarlarını sorar ve .env sonuna ekler.
configure_ftp() {
  sed -i -E '/^(FTP_ENABLED|FTP_HOST|FTP_PORT|FTP_USER|FTP_PASSWORD|FTP_PREFIX|FTP_BACKFILL|LOCAL_RETENTION_DAYS)=/d' "${ENV_FILE}"

  if ! prompt_yes_no "Saatlik loglar FTP sunucusuna yüklensin mi? (e/h)" "h"; then
    printf 'FTP_ENABLED=false\n' >> "${ENV_FILE}"
    return 0
  fi

  local ftp_host="" ftp_port ftp_user="" ftp_pass ftp_prefix ftp_backfill retention_days
  while [[ -z "${ftp_host}" ]]; do
    read -r -p "FTP sunucusu: " ftp_host </dev/tty
  done
  ftp_port="$(prompt_value "FTP portu" "21")"
  while [[ -z "${ftp_user}" ]]; do
    read -r -p "FTP kullanıcı adı: " ftp_user </dev/tty
  done
  ftp_pass="$(prompt_secret "FTP parolası")"
  read -r -p "FTP klasör öneki (boş bırakılabilir, ör. firma1/netflow): " ftp_prefix </dev/tty
  ftp_backfill="false"
  if prompt_yes_no "Şimdiye kadar oluşmuş loglar da geriye dönük yüklensin mi? (e/h)" "h"; then
    ftp_backfill="true"
  fi
  retention_days="$(prompt_value "FTP'ye yüklenen loglar yerelde kaç gün tutulsun? (0 = silme)" "7")"

  {
    printf 'FTP_ENABLED=true\n'
    printf 'FTP_HOST=%s\n' "${ftp_host}"
    printf 'FTP_PORT=%s\n' "${ftp_port}"
    printf 'FTP_USER=%s\n' "${ftp_user}"
    printf 'FTP_PASSWORD=%s\n' "${ftp_pass}"
    printf 'FTP_PREFIX=%s\n' "${ftp_prefix}"
    printf 'FTP_BACKFILL=%s\n' "${ftp_backfill}"
    printf 'LOCAL_RETENTION_DAYS=%s\n' "${retention_days}"
  } >> "${ENV_FILE}"
}

# test_ftp_connection, FTP açıksa derlenen binary ile bağlantıyı uçtan uca dener.
test_ftp_connection() {
  if ! grep -q '^FTP_ENABLED=true' "${ENV_FILE}"; then
    return 0
  fi

  while true; do
    if (cd "${INSTALL_DIR}" && runuser -u "${SERVICE_USER}" -- "${BIN_PATH}" ftp-test); then
      return 0
    fi
    echo "FTP bağlantı testi başarısız."
    if prompt_yes_no "FTP ayarları yeniden girilsin mi? (e/h)" "e"; then
      configure_ftp
      chown "${SERVICE_USER}:${SERVICE_GROUP}" "${ENV_FILE}"
      chmod 640 "${ENV_FILE}"
      if ! grep -q '^FTP_ENABLED=true' "${ENV_FILE}"; then
        return 0
      fi
    else
      echo "Uyarı: FTP ayarları hatalı olabilir; servis yüklemeyi her 5 dakikada yeniden deneyecek."
      return 0
    fi
  done
}

build_binary() {
  local go_bin
  go_bin="$(command -v go)"
  if [[ -z "${go_bin}" ]]; then
    echo "Go binary bulunamadı, derleme yapılamıyor."
    exit 1
  fi

  cd "${INSTALL_DIR}"
  "${go_bin}" mod tidy
  "${go_bin}" build -buildvcs=false -o "${BIN_PATH}" .
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
  test_ftp_connection
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
