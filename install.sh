#!/usr/bin/env bash
# UwUSync Server, from an empty machine to a running sync server.
#
#   curl -fsSLO https://github.com/MinifyX/UwUSync-Server/releases/latest/download/install.sh
#   sudo bash install.sh
#
# It installs Docker when it is missing, asks how your devices reach this machine, sets up
# /opt/uwusync, starts the server and shows the setup code to paste into UwUSSH or UwURDP.
# Every answer is a flag as well, so it can run without questions:
#
#   sudo bash install.sh --public nas.lan --yes
#
#   --dir DIR              where UwUSync Server lives (default /opt/uwusync)
#   --public ADDRESS       how your devices reach this machine: a name or an address, like
#                          nas.lan, 192.168.1.20 or a Tailscale name. The port is added.
#   --bind X               where it listens here: a port, or address:port (default 8443)
#   --behind-proxy URL     a reverse proxy in front does TLS and answers on URL, like
#                          https://sync.example.com; the server then listens on 127.0.0.1 only
#   --registration MODE    invite (default), open or closed
#   --version TAG          latest (default), beta, edge, or an exact version like 0.1.0
#   --no-update-check      the server never asks GitHub whether there is a newer release
#   --no-docker-install    stop instead of installing Docker when it is missing
#   --from-checkout        take compose.yaml and the rest from the repository this script is in
#   --no-pull              start the image already on this machine (for trying a build)
#   --yes                  ask nothing; whatever is not passed keeps its default
#   --help
#
# The whole way, with a reverse proxy, backups and updates: docs/deployment.md.
set -uo pipefail

repo=MinifyX/UwUSync-Server
releases="https://github.com/$repo/releases"
service=uwusync
here="$(cd "$(dirname "$0")" && pwd)"

dir=/opt/uwusync
public=""
bind=""
proxy=""
registration=invite
version=latest
update_check=on
docker_install=true
from_checkout=false
pull=true
ask=true

die() {
  printf '\n  (>_<) %s\n' "$1" >&2
  exit 1
}
step() { printf '  %s\n' "$1"; }
warn() { printf '  (>_<) %s\n' "$1" >&2; }

while [ $# -gt 0 ]; do
  case "$1" in
    --dir) dir="${2:?--dir needs a directory}"; shift 2 ;;
    --public) public="${2:?--public needs an address}"; shift 2 ;;
    --bind) bind="${2:?--bind needs a port}"; shift 2 ;;
    --behind-proxy) proxy="${2:?--behind-proxy needs the address the proxy answers on}"; shift 2 ;;
    --registration) registration="${2:?--registration needs invite, open or closed}"; shift 2 ;;
    --version) version="${2:?--version needs a tag}"; shift 2 ;;
    --no-update-check) update_check=off; shift ;;
    --no-docker-install) docker_install=false; shift ;;
    --from-checkout) from_checkout=true; shift ;;
    --no-pull) pull=false; shift ;;
    --yes | -y) ask=false; shift ;;
    -h | --help)
      # Piped into bash, there is no file to read the help from.
      if [ -f "$0" ]; then sed -n '2,28p' "$0" | sed 's/^# \{0,1\}//'; else
        printf 'Download it first to read the help: %s/latest/download/install.sh\n' "$releases"
      fi
      exit 0
      ;;
    *) die "unknown option: $1" ;;
  esac
done

[ "$(id -u)" -eq 0 ] || die "please run this as root: sudo bash install.sh"

# ── small helpers ─────────────────────────────────────────────────────────────────────────────
# Whether there is a terminal to ask on. A device node that is there is not the same as one that
# answers, so this opens it rather than looking at it.
have_tty() { { : </dev/tty; } 2>/dev/null; }

askfor() {
  local prompt="$1" fallback="${2:-}" answer=""
  if ! $ask || ! have_tty; then
    printf '%s' "$fallback"
    return 0
  fi
  if [ -n "$fallback" ]; then
    read -r -p "  $prompt [$fallback]: " answer </dev/tty
  else
    read -r -p "  $prompt: " answer </dev/tty
  fi
  printf '%s' "${answer:-$fallback}"
}

yesno() {
  local prompt="$1" fallback="$2" answer=""
  if ! $ask || ! have_tty; then
    [ "$fallback" = y ] && return 0 || return 1
  fi
  read -r -p "  $prompt [$([ "$fallback" = y ] && echo 'Y/n' || echo 'y/N')]: " answer </dev/tty
  answer="${answer:-$fallback}"
  case "$answer" in [yYjJ]*) return 0 ;; *) return 1 ;; esac
}

fetch() {
  local url="$1" target="$2"
  if command -v curl >/dev/null 2>&1; then
    curl -fsL --proto '=https' --tlsv1.2 -o "$target" "$url"
  elif command -v wget >/dev/null 2>&1; then
    wget -q --https-only -O "$target" "$url"
  else
    die "neither curl nor wget is here, so nothing can be downloaded"
  fi
}

# The newest release of any kind, beta included: GitHub's "latest" only knows stable ones.
newest_tag() {
  local list tag
  list=$(mktemp) || return 1
  if fetch "https://api.github.com/repos/$repo/releases?per_page=10" "$list"; then
    tag=$(grep -oE '"tag_name": *"v[0-9][A-Za-z0-9.-]*"' "$list" | head -1 |
      sed -E 's/.*"(v[^"]+)"$/\1/')
  fi
  rm -f "$list"
  printf '%s' "${tag:-}"
}

# Where the files for a tag are: that version's own release, the newest one of any kind for beta,
# and the newest stable one for everything else.
release_base() {
  local tag
  case "$1" in
    [0-9]*) printf '%s/download/v%s' "$releases" "$1" ;;
    beta)
      tag=$(newest_tag)
      if [ -n "$tag" ]; then printf '%s/download/%s' "$releases" "$tag"; else
        printf '%s/latest/download' "$releases"
      fi
      ;;
    *) printf '%s/latest/download' "$releases" ;;
  esac
}

# A release file and the checksum next to it; nothing is used unless the two agree. That keeps a
# broken download out. It does not keep out a release somebody replaced: the checksum comes from
# the same place, and trusting it is trusting the release, as with the image itself.
fetch_checked() {
  local name="$1" target="$2" base="$3" sums want have
  fetch "$base/$name" "$target" || return 1
  sums=$(mktemp) || return 1
  if ! fetch "$base/$name.sha256" "$sums"; then
    rm -f "$sums"
    return 1
  fi
  want=$(cut -d' ' -f1 <"$sums")
  have=$(sha256sum "$target" | cut -d' ' -f1)
  rm -f "$sums"
  [ -n "$want" ] && [ "$want" = "$have" ]
}

# The files come from the release — or, when asked for with --from-checkout, from the repository
# this script sits in. Never by guessing from the directory: piped into bash, "here" is wherever
# root happened to be, and whatever somebody left there would be installed as root.
take() {
  local name="$1" target="$2" asset="${3:-$1}"
  if $from_checkout; then
    [ -f "$here/$name" ] || die "--from-checkout, but there is no $name next to this script"
    install -m 0644 "$here/$name" "$target"
    step "$name from this checkout"
  else
    fetch_checked "$asset" "$target" "$files_from" ||
      die "$asset could not be downloaded, or its checksum did not match; nothing was started"
    step "$name from the $version release"
  fi
}

hash_of() { sha256sum "$1" | cut -d' ' -f1; }

# A value on its way into the .env has to be one line of plain characters. The answers are checked
# for that below already; this is the same check update.sh makes, so the two cannot drift apart.
plain_value() { case "${1:-}" in "" | *[!a-zA-Z0-9.:_/+\[\]-]*) return 1 ;; *) return 0 ;; esac; }

# Writes one line of the .env, whether it is in there already, commented out, or missing.
set_env() {
  local key="$1" value="$2" file="$dir/.env" line found=false tmp="$dir/.env.tmp"
  plain_value "$value" || die "$key would become something odd, so nothing was written: $value"
  install -m 0600 /dev/null "$tmp"
  while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in
      "$key="* | "#$key="*)
        if $found; then continue; fi
        printf '%s=%s\n' "$key" "$value" >>"$tmp"
        found=true
        ;;
      *) printf '%s\n' "$line" >>"$tmp" ;;
    esac
  done <"$file"
  $found || printf '%s=%s\n' "$key" "$value" >>"$tmp"
  cat "$tmp" >"$file"
  rm -f "$tmp"
}
trap 'rm -f "$dir/.env.tmp"' EXIT INT TERM

# ── the answers, checked before anything happens ──────────────────────────────────────────────
# Every one of them goes into the .env or a download address, so each is one line of plain
# characters: a line break in one would become a second setting that Compose reads as its own.
case "$version" in
  "" | *[!a-zA-Z0-9._-]*) die "a version is letters, digits, dots, dashes and underscores: $version" ;;
esac
case "$registration" in
  invite | open | closed) ;;
  *) die "registration is invite, open or closed, not $registration" ;;
esac
if [ -n "$proxy" ]; then
  case "$proxy" in
    https://*) ;;
    *) die "--behind-proxy wants the https address the proxy answers on, like https://sync.example.com" ;;
  esac
  case "${proxy#https://}" in
    "" | *[!a-zA-Z0-9.:/_-]*) die "that address holds characters an address does not: $proxy" ;;
  esac
  proxy="${proxy%/}"
fi
if $from_checkout && [ -n "$(find "$here" -maxdepth 0 -perm -0002 2>/dev/null)" ]; then
  die "--from-checkout, but anybody may write to $here; nothing from there is installed as root"
fi

# A port, or an address:port, the way Compose wants it. The number has to be one a port can be.
valid_bind() {
  [[ "$1" =~ ^(\[[0-9a-fA-F:]+\]:|[0-9]{1,3}(\.[0-9]{1,3}){3}:)?[0-9]{1,5}$ ]] || return 1
  local port=$((10#${1##*:}))
  [ "$port" -ge 1 ] && [ "$port" -le 65535 ]
}
port_of() { printf '%s' "${1##*:}"; }
on_loopback() { case "$1" in 127.0.0.1:* | "[::1]:"*) return 0 ;; *) return 1 ;; esac; }

if [ -n "$bind" ]; then
  valid_bind "$bind" || die "--bind wants a port from 1 to 65535, or an address:port, not $bind"
fi
# Behind a proxy the server believes the address the proxy passes on. Reachable past the proxy,
# anybody could pass on whatever address they like; Docker's ports get past ufw, too.
if [ -n "$proxy" ] && [ -n "$bind" ] && ! on_loopback "$bind"; then
  die "behind a proxy the server listens on this machine only: --bind 127.0.0.1:$(port_of "$bind")"
fi

if $ask && ! have_tty; then
  die "there is no terminal to ask on. Pass --public ... --yes, or start this from a shell."
fi

printf '\n  UwUSync Server\n  ~~~~~~~~~~~~~\n\n'

if [ -f "$dir/.env" ]; then
  die "$dir is set up already. A newer version? cd $dir && sudo bash update.sh"
fi
# Set up while it was called UwUSSH Server: that one moves over with its own update.sh.
if [ "$dir" = /opt/uwusync ] && [ -f /opt/uwussh/.env ]; then
  die "UwUSSH Server is set up in /opt/uwussh, and it is UwUSync Server now. Bring it over, with its data and devices: cd /opt/uwussh && sudo bash update.sh"
fi

# ── Docker ────────────────────────────────────────────────────────────────────────────────────
# The one thing this needs that a fresh machine does not have. Docker's own script knows every
# common distribution and brings Compose along; the log stays behind when it goes wrong.
install_docker() {
  local script log
  script=$(mktemp)
  log=$(mktemp /tmp/uwusync-docker-XXXXXX.log)
  step "installing Docker with Docker's own script (a minute or two)"
  fetch https://get.docker.com "$script" || die "Docker's install script could not be downloaded"
  # Not from standard input: piped into bash, that is the rest of this script.
  if ! sh "$script" </dev/null >"$log" 2>&1; then
    tail -n 15 "$log" | sed 's/^/      /' >&2
    die "Docker did not install. All it said is in $log"
  fi
  rm -f "$script" "$log"
}

if ! command -v docker >/dev/null 2>&1; then
  $docker_install ||
    die "Docker is missing. How to get it: https://docs.docker.com/engine/install/"
  yesno "Docker is not installed. Install it now, from get.docker.com?" y ||
    die "stopped. Docker first, then this again: https://docs.docker.com/engine/install/"
  install_docker
fi

if ! docker compose version >/dev/null 2>&1; then
  # Docker from the distribution's own packages, without the compose plugin. The package has a
  # different name everywhere: Docker's own repository, Ubuntu, Debian.
  $docker_install || die "Docker Compose v2 is missing: https://docs.docker.com/compose/install/linux/"
  yesno "Docker Compose v2 is missing. Install it now?" y || die "stopped. Compose first, then this again."
  step "installing Docker Compose"
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update -qq </dev/null >/dev/null 2>&1
    for package in docker-compose-plugin docker-compose-v2 docker-compose; do
      apt-get install -y -qq "$package" </dev/null >/dev/null 2>&1 &&
        docker compose version >/dev/null 2>&1 && break
    done
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y -q docker-compose-plugin </dev/null >/dev/null 2>&1
  fi
  docker compose version >/dev/null 2>&1 ||
    die "Docker Compose v2 could not be installed: https://docs.docker.com/compose/install/linux/"
fi

if ! docker info >/dev/null 2>&1; then
  command -v systemctl >/dev/null 2>&1 && systemctl enable --now docker >/dev/null 2>&1
  docker info >/dev/null 2>&1 || die "Docker is installed but does not answer: systemctl start docker"
fi

# ── where the server listens ──────────────────────────────────────────────────────────────────
# Docker only finds out that it cannot have a port when everything else is done already, and
# then it is the start that fails, on a machine that looks installed. So we look first.
port_busy() {
  local port="$1"
  if command -v ss >/dev/null 2>&1; then
    ss -Hltn "sport = :$port" 2>/dev/null | grep -q .
  elif command -v netstat >/dev/null 2>&1; then
    netstat -ltn 2>/dev/null | awk '{ print $4 }' | grep -qE "[:.]$port$"
  else
    return 1
  fi
}

# The first free port from there on, so what we suggest is one that works.
free_from() {
  local port="$1"
  while [ "$port" -lt 65535 ] && port_busy "$port"; do port=$((port + 1)); done
  printf '%s' "$port"
}

if [ -z "$bind" ]; then
  # Behind a proxy nothing but the proxy needs to reach it.
  if [ -n "$proxy" ]; then bind=127.0.0.1:8443; else bind=8443; fi
  if port_busy 8443; then
    if ! $ask || ! have_tty; then
      die "port 8443 is taken on this machine. Say which one to use instead: --bind <port>"
    fi
    warn "port 8443 is taken on this machine"
    answer=$(askfor "Which port should UwUSync Server listen on instead?" "$(free_from 8444)")
    valid_bind "$answer" || die "that is not a port from 1 to 65535, or an address:port: $answer"
    if [ -n "$proxy" ]; then
      bind="127.0.0.1:$(port_of "$answer")"
    else
      bind="$answer"
    fi
  fi
elif port_busy "$(port_of "$bind")"; then
  warn "--bind points at $bind, and that one is taken as well"
fi
port=$(port_of "$bind")

# ── how the devices reach it ──────────────────────────────────────────────────────────────────
# A guess: the address this machine talks to the world from. Nothing is sent to find it out.
guess_address() {
  local address=""
  if command -v ip >/dev/null 2>&1; then
    address=$(ip -4 route get 1.1.1.1 2>/dev/null |
      awk '{ for (i = 1; i < NF; i++) if ($i == "src") { print $(i + 1); exit } }')
  fi
  [ -n "$address" ] || address=$(hostname -I 2>/dev/null | awk '{ print $1 }')
  [ -n "$address" ] || address=$(hostname 2>/dev/null)
  printf '%s' "$address"
}

if [ -n "$proxy" ]; then
  public="$proxy"
else
  if [ -z "$public" ]; then
    if command -v tailscale >/dev/null 2>&1; then
      tailnet=$(tailscale ip -4 </dev/null 2>/dev/null | head -1)
      [ -n "$tailnet" ] &&
        step "this machine is on a tailnet as $tailnet: that address works wherever your devices are on it too"
    fi
    public=$(askfor "How do your devices reach this machine? A name or an address" "$(guess_address)")
  fi
  public="${public#https://}"
  public="${public%/}"
  case "$public" in
    "" | *[!a-zA-Z0-9.:_\[\]-]*) die "that is not a name or an address: $public" ;;
  esac
  # The port goes with it, since that is what a device dials.
  case "$public" in
    \[*\]:*) ;;
    \[*\]) public="$public:$port" ;;
    *:*:*) public="[$public]:$port" ;;
    *:*) ;;
    *) public="$public:$port" ;;
  esac
fi

# ── the files ─────────────────────────────────────────────────────────────────────────────────
printf '\n'
files_from=""
$from_checkout || files_from=$(release_base "$version")
step "setting up $dir"
install -d -m 0755 "$dir"
take compose.yaml "$dir/compose.yaml"
take .env.example "$dir/.env.example" env.example
take update.sh "$dir/update.sh"
chmod 0755 "$dir/update.sh"

install -m 0600 "$dir/.env.example" "$dir/.env"
set_env UWUSYNC_PUBLIC "$public"
set_env UWUSYNC_VERSION "$version"
set_env UWUSYNC_BIND "$bind"
set_env UWUSYNC_REGISTRATION "$registration"
set_env UWUSYNC_UPDATE_CHECK "$update_check"
if [ -n "$proxy" ]; then
  set_env UWUSYNC_TLS off
  set_env UWUSYNC_TRUST_FORWARDED on
else
  set_env UWUSYNC_TLS auto
  set_env UWUSYNC_TRUST_FORWARDED off
fi
step "wrote $dir/.env"

# update.sh replaces a compose.yaml it knows it put here, and this is how it knows.
{
  printf '# Written by install.sh and update.sh: what they put here, so they know what they may replace.\n'
  printf 'compose %s\n' "$(hash_of "$dir/compose.yaml")"
} >"$dir/.uwusync-update"
chmod 0644 "$dir/.uwusync-update"

# ── the first start ───────────────────────────────────────────────────────────────────────────
cd "$dir" || die "cannot go into $dir"

# A first start that did not work leaves nothing that stops the next try: the container goes, and
# the answers move aside to .env.failed. The data volume stays, in case there is anything in it.
give_up() {
  docker compose logs --tail 20 "$service" </dev/null 2>/dev/null | sed 's/^/      /' >&2
  docker compose down </dev/null >/dev/null 2>&1
  mv -f "$dir/.env" "$dir/.env.failed"
  die "$1
      Your answers are in $dir/.env.failed. Once the cause is fixed, run install.sh again."
}

if $pull; then
  step "fetching the image"
  docker compose pull --quiet </dev/null || give_up "the image could not be fetched"
fi

step "starting UwUSync Server"
docker compose up -d </dev/null || give_up "UwUSync Server did not start"

printf '  waiting for the server'
healthy=false
for _ in $(seq 1 60); do
  printf '.'
  sleep 2
  case "$(docker inspect --format '{{.State.Health.Status}}' "$service" 2>/dev/null)" in
    healthy)
      healthy=true
      break
      ;;
    unhealthy) break ;;
  esac
  # A server that keeps falling over is not going to be healthy by waiting.
  [ "$(docker inspect --format '{{.RestartCount}}' "$service" 2>/dev/null)" = 0 ] || break
done
printf '\n\n'

$healthy || give_up "the server did not come up"

# The first start writes the code into its log, as a field of its own, before anybody can reach
# it — so the first one there is the server's. A volume from an earlier installation has its
# accounts already, so then there is none, and one is made.
code=$(docker compose logs --no-color "$service" </dev/null 2>/dev/null |
  grep -oE 'setup_code=uwu1_[A-Za-z0-9_-]+' | head -1 | cut -d= -f2)
if [ -z "$code" ]; then
  code=$(docker compose exec -T "$service" uwusync-server invite </dev/null 2>/dev/null |
    grep -oE 'uwu1_[A-Za-z0-9_-]+' | head -1)
fi
[ -n "$code" ] || die "the server runs, but gave no setup code. Ask for one: cd $dir && docker compose exec $service uwusync-server invite"

fingerprint=""
if [ -z "$proxy" ]; then
  fingerprint=$(docker compose exec -T "$service" uwusync-server fingerprint </dev/null 2>/dev/null |
    grep -oE 'SHA256:[A-Za-z0-9+/]+' | head -1)
fi

address="$public"
case "$address" in https://*) ;; *) address="https://$address" ;; esac

cat <<DONE
  UwUSync Server is running (=^･ω･^=)

  Setup code    $code
  Address       $address
DONE
[ -n "$fingerprint" ] && printf '  Fingerprint   %s\n' "$fingerprint"
cat <<DONE

  In UwUSSH or UwURDP, open Settings → Sync, paste the setup code and type your master password.
  The code makes one account and is good for a week; every other device joins from the
  first one, with three words it shows you.
DONE
[ -n "$fingerprint" ] && cat <<PIN

  The fingerprint is what your devices pin, the way an SSH client pins a host key. The
  setup code carries it, so there is nothing to type; it is here to compare, if you like.
PIN
cat <<DONE

  Another setup code:   cd $dir && sudo docker compose exec $service uwusync-server invite
  Next version:         cd $dir && sudo bash update.sh
  What is next:         https://github.com/$repo/blob/main/docs/deployment.md

DONE

if [ -n "$proxy" ]; then
  cat <<PROXY
  Your reverse proxy sends $proxy to http://$bind now, with its own certificate
  for that name. Until it does, no device can reach the server. Examples for Caddy and nginx:
  https://github.com/$repo/blob/main/docs/deployment.md#behind-a-reverse-proxy

PROXY
fi
