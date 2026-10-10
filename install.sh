#!/bin/sh
# Obliguard panel installer: server + web client with Docker Compose
# (the agents are installed separately, from the panel).
#
#   curl -fsSL https://raw.githubusercontent.com/obli-tools/Obliguard/main/install.sh | sh
#
# Non-interactive:   ... | sh -s -- -y
# Other options:     ... | sh -s -- --dir /opt/obliguard --port 8080 --url https://obliguard.example.com
# All options:       ... | sh -s -- --help
#
# Checks Docker and Docker Compose (offers to install them on Linux, only
# after confirmation), downloads docker-compose.yml and .env.example into the
# install directory, creates .env with unique random secrets on the first
# install (an existing .env is never modified), then pulls and starts the
# containers. Running it again upgrades the install.

# ---- Per-tool configuration -------------------------------------------------
TOOL_NAME="Obliguard"
TOOL_SLUG="obliguard"
# Raw base URL of the repository (override to install from a fork or mirror).
REPO_RAW="${OBLIGUARD_REPO_RAW:-https://raw.githubusercontent.com/obli-tools/Obliguard/main}"
INSTALL_DIR="${OBLIGUARD_DIR:-./obliguard}"
# Secrets generated into .env on the first install, as KEY:kind:size
# (alnum:N = N letters/digits, hex:N = N random bytes in hex, b64:N = N random
# bytes in base64). The compose file derives DATABASE_URL from DB_PASSWORD.
SECRETS="DB_PASSWORD:alnum:32 SESSION_SECRET:alnum:48 DEFAULT_ADMIN_PASSWORD:alnum:20"
ADMIN_USER_KEY="DEFAULT_ADMIN_USERNAME"
ADMIN_PASSWORD_KEY="DEFAULT_ADMIN_PASSWORD"
# .env key of the published web port (--port), its default, and the scheme
# the web client answers on.
PORT_KEY="LISTEN_PORT"
DEFAULT_PORT="3001"
URL_SCHEME="http"
# Ports checked for conflicts on the first install (KEY:default).
CHECK_PORTS="LISTEN_PORT:3001"
# .env keys set from the public URL (--url): ORIGIN_KEYS get scheme://host[:port],
# URL_KEYS the full URL.
ORIGIN_KEYS="CLIENT_ORIGIN"
URL_KEYS=""
# Repository files the compose file bind-mounts (downloaded next to it), and
# local directories to create before the first start.
EXTRA_FILES=""
CREATE_DIRS="custom"
# External Docker networks the compose file expects to exist.
EXTERNAL_NETWORKS=""
SERVER_SERVICE="server"
# Named volume of the database (a leftover one blocks a fresh .env).
DB_VOLUME="postgres_data"

tool_notes() {
  printf '\n  Notes:\n'
  printf '    - Production session cookies are HTTPS-only: sign-in over plain HTTP\n'
  printf '      does not stick. Put a TLS reverse proxy in front (sending\n'
  printf '      X-Forwarded-Proto: https), set CLIENT_ORIGIN in .env to its https://\n'
  printf '      address and TRUSTED_PROXY_HOPS=2, then run "up -d" again.\n'
}

set -eu

# ============================================================================
# Everything below is shared by every Obli* panel installer. Edit the
# template, not a generated copy.
# ============================================================================

DOCKER_DOCS_URL="https://docs.docker.com/engine/install/"
DOCKER_DESKTOP_URL="https://docs.docker.com/desktop/"
WAIT_TIMEOUT=120

ASSUME_YES=0
ENV_ONLY=0
OPT_PORT=""
OPT_URL=""
DOCKER_SUDO=0
COMPOSE_KIND=""
ADMIN_PASSWORD=""
FIRST_INSTALL=0
PUBLIC_URL=""

info() { printf '%s\n' "$*"; }
step() { printf '\n==> %s\n' "$*"; }
warn() { printf 'WARNING: %s\n' "$*" >&2; }
fail() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
has() { command -v "$1" > /dev/null 2>&1; }
is_root() { [ "$(id -u)" -eq 0 ]; }

usage() {
  cat <<EOF
$TOOL_NAME panel installer (server + web client, Docker Compose).

  curl -fsSL $REPO_RAW/install.sh | sh
  curl -fsSL $REPO_RAW/install.sh | sh -s -- [options]

Options:
  -y, --yes       Non-interactive: accept the defaults and install Docker
                  if it is missing (no questions asked).
  --dir PATH      Install directory (default: $INSTALL_DIR).
  --port PORT     Host port of the web interface, default $DEFAULT_PORT
                  (first install only; later, edit $PORT_KEY in .env).
  --url URL       Public URL of the panel, e.g. https://$TOOL_SLUG.example.com
                  (first install only; default: $URL_SCHEME://<this host's IP>:<port>).
  --env-only      Only create .env from the .env.example already present in
                  the install directory, then stop (no download, no Docker).
  -h, --help      Show this help.

Running it again on an existing install upgrades it: docker-compose.yml is
refreshed (previous copy kept as docker-compose.yml.bak), .env is never
modified.
EOF
}

# ---- Prompts (stdin is the script itself under "curl | sh": use the tty) ---

can_prompt() { ( : < /dev/tty ) 2> /dev/null; }

# confirm QUESTION: yes/no, default No. --yes answers yes.
confirm() {
  [ "$ASSUME_YES" -eq 1 ] && return 0
  can_prompt || return 1
  printf '%s [y/N] ' "$1" > /dev/tty
  confirm_answer=""
  read -r confirm_answer < /dev/tty || confirm_answer=""
  case "$confirm_answer" in
    [yY] | [yY][eE][sS]) return 0 ;;
    *) return 1 ;;
  esac
}

as_root() {
  if is_root; then
    "$@"
  elif has sudo; then
    sudo "$@"
  else
    return 1
  fi
}

# ---- Random secrets (no weak fallback: abort without a random source) -----

# gen_secret KIND SIZE
#   alnum N: N letters and digits
#   hex N:   N random bytes, hex encoded (2N characters)
#   b64 N:   N random bytes, base64 encoded
gen_secret() {
  gen_kind=$1
  gen_size=$2
  gen_value=""
  case "$gen_kind" in
    alnum)
      if [ -r /dev/urandom ]; then
        gen_value=$(LC_ALL=C tr -dc 'A-Za-z0-9' < /dev/urandom 2> /dev/null | head -c "$gen_size") || gen_value=""
      fi
      if [ "${#gen_value}" -ne "$gen_size" ] && has openssl; then
        gen_value=$(openssl rand -base64 $((gen_size * 3)) | LC_ALL=C tr -dc 'A-Za-z0-9' | head -c "$gen_size") || gen_value=""
      fi
      gen_expected=$gen_size
      ;;
    hex)
      if has openssl; then
        gen_value=$(openssl rand -hex "$gen_size" 2> /dev/null | tr -d ' \r\n') || gen_value=""
      fi
      if [ "${#gen_value}" -ne $((gen_size * 2)) ] && [ -r /dev/urandom ] && has od; then
        gen_value=$(od -An -tx1 -N "$gen_size" /dev/urandom | tr -d ' \r\n') || gen_value=""
      fi
      gen_expected=$((gen_size * 2))
      ;;
    b64)
      if has openssl; then
        gen_value=$(openssl rand -base64 "$gen_size" 2> /dev/null | tr -d ' \r\n') || gen_value=""
      fi
      gen_expected=$(((gen_size + 2) / 3 * 4))
      if [ "${#gen_value}" -ne "$gen_expected" ] && [ -r /dev/urandom ] && has base64; then
        gen_value=$(head -c "$gen_size" /dev/urandom | base64 | tr -d ' \r\n') || gen_value=""
      fi
      ;;
    *)
      return 1
      ;;
  esac
  [ "${#gen_value}" -eq "$gen_expected" ] || return 1
  printf '%s' "$gen_value"
}

# ---- .env helpers ----------------------------------------------------------

# set_env FILE KEY VALUE: replaces the active KEY= line; else uncomments the
# first "# KEY=" line; else appends KEY=VALUE.
set_env() {
  set_file=$1
  set_key=$2
  set_value=$3
  if grep -q "^${set_key}=" "$set_file"; then
    set_mode=active
  elif grep -q "^#[[:space:]]*${set_key}=" "$set_file"; then
    set_mode=commented
  else
    printf '%s=%s\n' "$set_key" "$set_value" >> "$set_file"
    return 0
  fi
  SET_K=$set_key SET_V=$set_value SET_M=$set_mode awk '
    BEGIN { k = ENVIRON["SET_K"]; v = ENVIRON["SET_V"]; m = ENVIRON["SET_M"]; done = 0 }
    {
      if (m == "active" && index($0, k "=") == 1) { print k "=" v; next }
      if (m == "commented" && !done) {
        s = $0
        if (sub(/^#[ \t]*/, "", s) && index(s, k "=") == 1) { print k "=" v; done = 1; next }
      }
      print
    }' "$set_file" > "$set_file.new"
  mv "$set_file.new" "$set_file"
}

# get_env FILE KEY: value of the last active KEY= line (inline comment and
# surrounding quotes removed), empty when absent.
get_env() {
  [ -f "$1" ] || return 0
  sed -n "s/^$2=//p" "$1" | tail -n 1 | tr -d '\r' \
    | sed -e 's/[[:space:]]#.*$//' -e 's/[[:space:]]*$//' \
      -e 's/^"\(.*\)"$/\1/' -e "s/^'\(.*\)'\$/\1/"
}

env_mentions() { grep -q "^#\{0,1\}[[:space:]]*$2=" "$1"; }

# ---- Networking ------------------------------------------------------------

host_ip() {
  hip=""
  if [ "$(uname -s)" = "Linux" ]; then
    hip=$(hostname -I 2> /dev/null | awk '{ print $1 }') || hip=""
    if [ -z "$hip" ] && has ip; then
      hip=$(ip -4 -o addr show scope global 2> /dev/null | awk '{ sub(/\/.*/, "", $4); print $4; exit }') || hip=""
    fi
  elif has ipconfig; then
    hip=$(ipconfig getifaddr en0 2> /dev/null || ipconfig getifaddr en1 2> /dev/null) || hip=""
  fi
  printf '%s' "${hip:-localhost}"
}

valid_port() {
  case "$1" in
    '' | *[!0-9]*) return 1 ;;
  esac
  [ "$1" -ge 1 ] && [ "$1" -le 65535 ]
}

# check_url URL: prints the URL without trailing slash, fails when invalid.
check_url() {
  case "$1" in
    http://?* | https://?*) ;;
    *) fail "The URL must start with http:// or https:// (got: $1)" ;;
  esac
  case "$1" in
    *[!][A-Za-z0-9.:/_~%+-]*) fail "The URL contains unsupported characters (got: $1)" ;;
  esac
  printf '%s' "${1%/}"
}

url_origin() { printf '%s\n' "$1" | sed 's#^\(https\{0,1\}://[^/]*\).*#\1#'; }

port_in_use() {
  if has ss; then
    ss -ltn 2> /dev/null | awk 'NR > 1 { print $4 }' | grep -q "[:.]$1\$"
  elif has netstat; then
    netstat -an 2> /dev/null | grep -i 'listen' | awk '{ print $4 }' | grep -q "[:.]$1\$"
  else
    return 1
  fi
}

# ---- Docker ----------------------------------------------------------------

docker_cmd() {
  if [ "$DOCKER_SUDO" -eq 1 ]; then sudo docker "$@"; else docker "$@"; fi
}

compose() {
  if [ "$COMPOSE_KIND" = "v2" ]; then
    docker_cmd compose "$@"
  elif [ "$DOCKER_SUDO" -eq 1 ]; then
    sudo docker-compose "$@"
  else
    docker-compose "$@"
  fi
}

compose_display() {
  cd_prefix=""
  [ "$DOCKER_SUDO" -eq 1 ] && cd_prefix="sudo "
  if [ "$COMPOSE_KIND" = "v1" ]; then
    printf '%sdocker-compose' "$cd_prefix"
  else
    printf '%sdocker compose' "$cd_prefix"
  fi
}

detect_compose() {
  COMPOSE_KIND=""
  if has docker && docker compose version > /dev/null 2>&1; then
    COMPOSE_KIND=v2
  elif has docker-compose && docker-compose version > /dev/null 2>&1; then
    COMPOSE_KIND=v1
  fi
}

install_docker() {
  step "Docker setup"
  if has docker; then
    info "Docker is installed but the Docker Compose v2 plugin is missing."
  else
    info "Docker is not installed."
  fi
  info "This installer can install Docker with Docker's official convenience"
  info "script (https://get.docker.com). It adds Docker's package repository and"
  info "installs Docker Engine, the docker CLI, containerd, Buildx and the Compose"
  info "plugin, then enables and starts the docker service. Root access (sudo)"
  info "is needed."
  if ! is_root && ! has sudo; then
    info ""
    info "Run this installer again as root to let it install Docker, or install"
    info "Docker yourself: $DOCKER_DOCS_URL"
    exit 1
  fi
  if ! confirm "Install Docker now?"; then
    if [ "$ASSUME_YES" -eq 0 ] && ! can_prompt; then
      info "No terminal to ask on: add -y (curl ... | sh -s -- -y) to accept."
    fi
    info "Docker was not installed. Install it by following $DOCKER_DOCS_URL"
    info "then run this installer again."
    exit 1
  fi
  has curl || fail "curl is required to download the Docker install script."
  docker_script=$(mktemp 2> /dev/null || printf '%s' "${TMPDIR:-/tmp}/get-docker.$$.sh")
  if ! curl -fsSL https://get.docker.com -o "$docker_script"; then
    rm -f "$docker_script"
    fail "Cannot download https://get.docker.com"
  fi
  if ! as_root sh "$docker_script" < /dev/null; then
    rm -f "$docker_script"
    fail "The Docker installation failed (see the messages above). Manual install: $DOCKER_DOCS_URL"
  fi
  rm -f "$docker_script"
  if has systemctl; then
    as_root systemctl enable --now docker < /dev/null || warn "Could not enable/start the docker service with systemctl."
  elif has service; then
    as_root service docker start < /dev/null || warn "Could not start the docker service."
  fi
  hash -r 2> /dev/null || true
  if ! is_root; then
    info "Tip: to run docker without sudo, add your user to the docker group:"
    info "  sudo usermod -aG docker \"\$USER\"   (then sign out and back in)"
  fi
}

ensure_docker() {
  step "Checking Docker"
  detect_compose
  if ! has docker || [ -z "$COMPOSE_KIND" ]; then
    if [ "$(uname -s)" = "Darwin" ]; then
      fail "Docker Desktop (with Docker Compose) is required on macOS: install and start it ($DOCKER_DESKTOP_URL), then run this installer again."
    fi
    install_docker
    detect_compose
    has docker || fail "docker is still not available. Manual install: $DOCKER_DOCS_URL"
  fi
  [ "$COMPOSE_KIND" = "v2" ] || [ "$COMPOSE_KIND" = "v1" ] \
    || fail "Docker Compose is missing. Install the Compose plugin: https://docs.docker.com/compose/install/linux/"

  if docker info > /dev/null 2>&1; then
    DOCKER_SUDO=0
  elif ! is_root && has sudo && sudo docker info < /dev/null > /dev/null 2>&1; then
    DOCKER_SUDO=1
    info "Your user cannot reach the Docker daemon: Docker commands run with sudo."
  else
    fail "Cannot reach the Docker daemon. Start it (e.g. sudo systemctl start docker) or add your user to the docker group, then run this installer again."
  fi

  if [ "$COMPOSE_KIND" = "v2" ]; then
    info "Docker $(docker_cmd version --format '{{.Server.Version}}' 2> /dev/null || printf '?'), $(docker_cmd compose version --short 2> /dev/null || printf 'Compose v2')"
  else
    warn "Using the legacy docker-compose (v1). Docker Compose v2 is recommended."
  fi
}

# ---- Files -----------------------------------------------------------------

# download REPO_PATH DEST [backup]: atomic download; with "backup", a changed
# previous DEST is kept as DEST.bak.
download() {
  dl_tmp="$2.download.$$"
  if ! curl -fsSL "$REPO_RAW/$1" -o "$dl_tmp"; then
    rm -f "$dl_tmp"
    fail "Cannot download $REPO_RAW/$1"
  fi
  if [ "${3:-}" = "backup" ] && [ -f "$2" ] && ! cmp -s "$dl_tmp" "$2"; then
    cp "$2" "$2.bak"
    info "    previous $2 saved as $2.bak"
  fi
  mv "$dl_tmp" "$2"
}

fetch_files() {
  step "Downloading files from $REPO_RAW"
  info "  docker-compose.yml"
  download docker-compose.yml docker-compose.yml backup
  info "  .env.example"
  download .env.example .env.example
  for extra_file in $EXTRA_FILES; do
    info "  $extra_file"
    mkdir -p "$(dirname "$extra_file")"
    download "$extra_file" "$extra_file" backup
  done
  for extra_dir in $CREATE_DIRS; do
    mkdir -p "$extra_dir"
  done
}

# ---- First install: public URL and .env ------------------------------------

choose_url() {
  [ -n "$ORIGIN_KEYS$URL_KEYS" ] || return 0
  cu_port=${OPT_PORT:-$DEFAULT_PORT}
  cu_default="$URL_SCHEME://$(host_ip):$cu_port"
  if [ -n "$OPT_URL" ]; then
    PUBLIC_URL=$OPT_URL
  elif [ "$ASSUME_YES" -eq 0 ] && can_prompt; then
    {
      printf '\nPublic URL of %s, as users (and agents) will reach it,\n' "$TOOL_NAME"
      printf 'e.g. https://%s.example.com behind a TLS reverse proxy.\n' "$TOOL_SLUG"
      printf 'URL [%s]: ' "$cu_default"
    } > /dev/tty
    cu_answer=""
    read -r cu_answer < /dev/tty || cu_answer=""
    PUBLIC_URL=${cu_answer:-$cu_default}
  else
    PUBLIC_URL=$cu_default
  fi
  PUBLIC_URL=$(check_url "$PUBLIC_URL")
}

# The volume of a previous install would keep its database password: new
# secrets would lock the server out. Stop before generating anything.
check_previous_volume() {
  [ -n "$DB_VOLUME" ] || return 0
  pv_project=$(compose config 2> /dev/null | sed -n 's/^name: *//p' | head -n 1 | tr -d "\"' \r") || pv_project=""
  if [ -z "$pv_project" ]; then
    pv_project=$(printf '%s' "${COMPOSE_PROJECT_NAME:-$(basename "$(pwd)")}" \
      | tr '[:upper:]' '[:lower:]' | tr -cd 'a-z0-9_-' | sed 's/^[-_]*//')
  fi
  [ -n "$pv_project" ] || return 0
  if docker_cmd volume inspect "${pv_project}_${DB_VOLUME}" > /dev/null 2>&1; then
    printf 'ERROR: %s has no .env, but the database volume %s already exists.\n' "$(pwd)" "${pv_project}_${DB_VOLUME}" >&2
    printf '  The database keeps the password it was created with: new secrets would\n' >&2
    printf '  lock the server out of it. Nothing was changed. Either:\n' >&2
    printf '    - restore the previous .env in this directory and run the installer again;\n' >&2
    printf '    - or delete ALL %s data and start over:\n' "$TOOL_NAME" >&2
    printf '      cd "%s" && %s down && %s volume rm %s\n' "$(pwd)" "$(compose_display)" \
      "$(if [ "$DOCKER_SUDO" -eq 1 ]; then printf 'sudo docker'; else printf 'docker'; fi)" "${pv_project}_${DB_VOLUME}" >&2
    exit 1
  fi
}

create_env() {
  [ -f .env.example ] || fail "No .env.example in $(pwd)."
  ce_umask=$(umask)
  umask 077
  ce_tmp=".env.tmp.$$"
  tr -d '\r' < .env.example > "$ce_tmp"

  for ce_spec in $SECRETS; do
    ce_key=${ce_spec%%:*}
    ce_rest=${ce_spec#*:}
    ce_kind=${ce_rest%%:*}
    ce_size=${ce_rest#*:}
    if ! ce_value=$(gen_secret "$ce_kind" "$ce_size"); then
      rm -f "$ce_tmp"
      fail "Cannot generate random secrets (no usable /dev/urandom or openssl). .env was not created."
    fi
    set_env "$ce_tmp" "$ce_key" "$ce_value"
    if [ "$ce_key" = "$ADMIN_PASSWORD_KEY" ]; then ADMIN_PASSWORD=$ce_value; fi
  done

  if [ -n "$OPT_PORT" ]; then set_env "$ce_tmp" "$PORT_KEY" "$OPT_PORT"; fi

  if [ -n "$PUBLIC_URL" ]; then
    ce_origin=$(url_origin "$PUBLIC_URL")
    for ce_key in $ORIGIN_KEYS; do set_env "$ce_tmp" "$ce_key" "$ce_origin"; done
    for ce_key in $URL_KEYS; do set_env "$ce_tmp" "$ce_key" "$PUBLIC_URL"; done
    case "$PUBLIC_URL" in
      https://*)
        # TLS in front: mark the session cookie Secure.
        if env_mentions "$ce_tmp" FORCE_HTTPS; then set_env "$ce_tmp" FORCE_HTTPS true; fi
        ;;
      *)
        # Plain HTTP usually means the port is published directly: believe one
        # X-Forwarded-For hop only, so clients cannot choose their address.
        if [ "$URL_SCHEME" = "http" ] && env_mentions "$ce_tmp" TRUSTED_PROXY_HOPS; then
          set_env "$ce_tmp" TRUSTED_PROXY_HOPS 1
        fi
        ;;
    esac
  fi

  # Every generated secret must be present exactly as an active line.
  for ce_spec in $SECRETS; do
    ce_key=${ce_spec%%:*}
    if [ -z "$(get_env "$ce_tmp" "$ce_key")" ]; then
      rm -f "$ce_tmp"
      fail "Could not write $ce_key to .env. .env was not created."
    fi
  done

  mv "$ce_tmp" .env
  chmod 600 .env
  umask "$ce_umask"
  info "  .env created with generated secrets (chmod 600): $(pwd)/.env"
}

warn_busy_ports() {
  command -v ss > /dev/null 2>&1 || command -v netstat > /dev/null 2>&1 || return 0
  for wp_spec in $CHECK_PORTS; do
    wp_key=${wp_spec%%:*}
    wp_port=$(get_env .env "$wp_key")
    wp_port=${wp_port:-${wp_spec#*:}}
    if valid_port "$wp_port" && port_in_use "$wp_port"; then
      warn "Port $wp_port ($wp_key) is already in use on this host: change $wp_key in .env if the start fails."
    fi
  done
}

# ---- Start -----------------------------------------------------------------

create_networks() {
  for net in $EXTERNAL_NETWORKS; do
    if ! docker_cmd network inspect "$net" > /dev/null 2>&1; then
      info "  creating the Docker network \"$net\""
      docker_cmd network create "$net" > /dev/null
    fi
  done
}

wait_for_server() {
  ws_id=$(compose ps -q "$SERVER_SERVICE" 2> /dev/null | head -n 1) || ws_id=""
  if [ -z "$ws_id" ]; then
    warn "The $SERVER_SERVICE container was not found."
    return 1
  fi
  printf 'Waiting for the server to be ready'
  ws_elapsed=0
  while [ "$ws_elapsed" -lt "$WAIT_TIMEOUT" ]; do
    ws_state=$(docker_cmd inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$ws_id" 2> /dev/null) || ws_state=unknown
    case "$ws_state" in
      healthy | running)
        printf ' ready.\n'
        return 0
        ;;
      unhealthy | exited | dead)
        printf '\n'
        warn "The server is $ws_state. See its logs: cd \"$(pwd)\" && $(compose_display) logs $SERVER_SERVICE"
        return 1
        ;;
    esac
    printf '.'
    sleep 3
    ws_elapsed=$((ws_elapsed + 3))
  done
  printf '\n'
  warn "The server is not ready after ${WAIT_TIMEOUT}s (the first start runs the database migrations and can take longer). Follow it: cd \"$(pwd)\" && $(compose_display) logs -f $SERVER_SERVICE"
  return 1
}

start_stack() {
  step "Starting $TOOL_NAME"
  create_networks
  compose pull < /dev/null || fail "Cannot pull the images (see above)."
  if ! compose up -d --no-build < /dev/null; then
    fail "docker compose up failed. Logs: cd \"$(pwd)\" && $(compose_display) logs $SERVER_SERVICE"
  fi
  wait_for_server || SERVER_NOT_READY=1
}

panel_url() {
  pu_url=""
  for pu_key in $URL_KEYS $ORIGIN_KEYS; do
    pu_url=$(get_env .env "$pu_key")
    [ -n "$pu_url" ] && break
  done
  case "$pu_url" in
    '' | *://localhost | *://localhost/* | *://localhost:* | *://127.0.0.1*)
      pu_port=$(get_env .env "$PORT_KEY")
      pu_url="$URL_SCHEME://$(host_ip):${pu_port:-$DEFAULT_PORT}"
      ;;
  esac
  printf '%s' "$pu_url"
}

summary() {
  sm_compose=$(compose_display)
  printf '\n'
  printf '============================================================\n'
  if [ "${SERVER_NOT_READY:-0}" -eq 1 ]; then
    printf '  %s was started, but the server is not ready yet.\n' "$TOOL_NAME"
  else
    printf '  %s is running.\n' "$TOOL_NAME"
  fi
  printf '============================================================\n\n'
  printf '  Open:       %s\n' "$(panel_url)"
  if [ -n "$ADMIN_PASSWORD" ]; then
    sm_user=$(get_env .env "$ADMIN_USER_KEY")
    printf '  Sign in:    %s / %s\n' "${sm_user:-admin}" "$ADMIN_PASSWORD"
    printf '              Shown only this once. It is also in .env (%s),\n' "$ADMIN_PASSWORD_KEY"
    printf '              used only to create this first account: change it after\n'
    printf '              the first sign-in and enable two-factor authentication.\n'
  fi
  printf '  Settings:   %s/.env  (secrets: keep it private, back it up)\n' "$(pwd)"
  printf '\n  Update:     cd "%s" && %s pull && %s up -d\n' "$(pwd)" "$sm_compose" "$sm_compose"
  printf '  Logs:       cd "%s" && %s logs -f %s\n' "$(pwd)" "$sm_compose" "$SERVER_SERVICE"
  printf '  Stop:       cd "%s" && %s down\n' "$(pwd)" "$sm_compose"
  tool_notes
  printf '\n'
}

# ---- Main ------------------------------------------------------------------

main() {
  while [ $# -gt 0 ]; do
    case "$1" in
      -y | --yes) ASSUME_YES=1 ;;
      --dir)
        [ $# -ge 2 ] || fail "--dir needs a value."
        INSTALL_DIR=$2
        shift
        ;;
      --dir=*) INSTALL_DIR=${1#--dir=} ;;
      --port)
        [ $# -ge 2 ] || fail "--port needs a value."
        OPT_PORT=$2
        shift
        ;;
      --port=*) OPT_PORT=${1#--port=} ;;
      --url)
        [ $# -ge 2 ] || fail "--url needs a value."
        OPT_URL=$2
        shift
        ;;
      --url=*) OPT_URL=${1#--url=} ;;
      --env-only) ENV_ONLY=1 ;;
      -h | --help)
        usage
        exit 0
        ;;
      *) fail "Unknown option: $1 (see --help)." ;;
    esac
    shift
  done
  [ -n "$INSTALL_DIR" ] || fail "--dir cannot be empty."
  if [ -n "$OPT_PORT" ]; then valid_port "$OPT_PORT" || fail "--port must be a port number (1-65535), got: $OPT_PORT"; fi
  if [ -n "$OPT_URL" ]; then OPT_URL=$(check_url "$OPT_URL"); fi

  printf '\n  ------------------------------------------\n'
  printf '   %s - panel installer\n' "$TOOL_NAME"
  printf '  ------------------------------------------\n'

  if [ "$ENV_ONLY" -eq 1 ]; then
    cd "$INSTALL_DIR" || fail "Cannot enter $INSTALL_DIR."
    [ ! -f .env ] || fail "$(pwd)/.env already exists: left untouched."
    choose_url
    create_env
    [ -z "$ADMIN_PASSWORD" ] || info "  Initial admin password: $ADMIN_PASSWORD"
    exit 0
  fi

  case "$(uname -s)" in
    Linux | Darwin) ;;
    *) fail "Unsupported system: $(uname -s). This installer supports Linux, and macOS with Docker Desktop." ;;
  esac
  has curl || fail "curl is required."

  ensure_docker

  mkdir -p "$INSTALL_DIR" || fail "Cannot create $INSTALL_DIR."
  cd "$INSTALL_DIR"
  step "Installing in $(pwd)"
  fetch_files

  if [ -f .env ]; then
    info "  .env already exists: kept untouched (upgrade). Compare it with"
    info "  .env.example for settings added since your install."
    if [ -n "$OPT_PORT$OPT_URL" ]; then
      warn "--port / --url only apply to a first install: edit .env instead."
    fi
  else
    FIRST_INSTALL=1
    check_previous_volume
    step "Creating .env"
    choose_url
    create_env
    warn_busy_ports
  fi

  start_stack
  summary
}

# Run only once the whole script is read (safe with "curl | sh").
main "$@"
