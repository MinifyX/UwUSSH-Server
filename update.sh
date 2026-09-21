#!/usr/bin/env bash
# Brings UwUSSH Server to the newest version, where it runs.
#
#   cd /opt/uwussh && sudo bash update.sh
#
# It updates itself first, then looks at compose.yaml, makes a backup, fetches the new image and
# watches the server come back. If it does not come back, the old version does.
#
#   --dir DIR          where UwUSSH Server lives (default: this directory, then /opt/uwussh)
#   --version TAG      switch to another tag: latest, beta, edge, or an exact version like 0.1.0
#   --no-backup        do not back up first
#   --force            take the new compose.yaml even when this one was changed by hand
#   --keep-compose     leave compose.yaml alone, now and from now on
#   --no-self-update   do not fetch a newer update.sh first
#   --no-pull          start the image already on this machine (for trying a build)
#   --yes              ask nothing; every answer takes its default
#   --help
#
# What it never touches: your data, and a compose.yaml you edited yourself unless you say --force.
# Of the .env it only ever changes what it says it changes. The whole story: docs/deployment.md.
set -uo pipefail

repo=MinifyX/UwUSSH-Server
releases="https://github.com/$repo/releases"
image=ghcr.io/minifyx/uwussh-server
service=uwussh
here="$(cd "$(dirname "$0")" && pwd)"

# What we were called with, for the copy that takes over after a self-update.
called_with=("$@")

dir=""
version=""
backup=true
force=false
keep_compose=false
self_update=true
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
    --version) version="${2:?--version needs a tag}"; shift 2 ;;
    --no-backup) backup=false; shift ;;
    --force) force=true; shift ;;
    --keep-compose) keep_compose=true; shift ;;
    --no-self-update) self_update=false; shift ;;
    --no-pull) pull=false; shift ;;
    --yes | -y) ask=false; shift ;;
    -h | --help)
      sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *) die "unknown option: $1" ;;
  esac
done

[ "$(id -u)" -eq 0 ] || die "please run this as root: sudo bash update.sh"
command -v docker >/dev/null 2>&1 || die "Docker is missing"
docker compose version >/dev/null 2>&1 || die "Docker Compose v2 is missing"

# ── small helpers ─────────────────────────────────────────────────────────────────────────────
# Whether there is a terminal to ask on: after an exec there may be none, whatever /dev/tty
# looks like in the file system.
have_tty() { { : </dev/tty; } 2>/dev/null; }

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
    return 1
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

hash_of() { sha256sum "$1" | cut -d' ' -f1; }
looks_like_version() { case "${1:-}" in [0-9]*) return 0 ;; *) return 1 ;; esac; }

# A value on its way into the .env has to be one line of plain characters, wherever it came from:
# a flag, or a compose.yaml somebody wrote by hand.
plain_value() { case "${1:-}" in "" | *[!a-zA-Z0-9.:_/+\[\]-]*) return 1 ;; *) return 0 ;; esac; }

# ── where UwUSSH Server lives ─────────────────────────────────────────────────────────────────
# Next to this script first: "sudo bash /opt/uwussh/update.sh" from somewhere else means that
# one. And only a directory whose compose.yaml runs this server — never another project's.
ours() { [ -f "$1/compose.yaml" ] && [ -f "$1/.env" ] && grep -q "uwussh-server" "$1/compose.yaml"; }
if [ -z "$dir" ]; then
  for candidate in "$here" "$PWD" /opt/uwussh; do
    if ours "$candidate"; then
      dir="$candidate"
      break
    fi
  done
  [ -n "$dir" ] || die "no UwUSSH Server here. Pass --dir with the directory it runs from."
fi
dir="$(cd "$dir" 2>/dev/null && pwd)" || die "there is no directory $dir"
ours "$dir" || die "$dir holds no compose.yaml for UwUSSH Server with an .env next to it"
cd "$dir" || die "cannot go into $dir"
state="$dir/.uwussh-update"

# Reads one value out of the .env, without sourcing a file we did not write.
env_value() {
  local line
  line=$(grep -m1 "^$1=" "$dir/.env" 2>/dev/null) || return 1
  printf '%s' "${line#*=}"
}

# Writes one line of the .env, whether it is in there already, commented out, or missing. The
# copy is made with the rights of the file it replaces, not whatever the umask happens to be.
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

# Waits for the server's own health check: up to two minutes, less when it keeps falling over.
wait_healthy() {
  printf '  waiting for the server'
  for _ in $(seq 1 60); do
    printf '.'
    sleep 2
    case "$(docker inspect --format '{{.State.Health.Status}}' "$service" 2>/dev/null)" in
      healthy)
        printf '\n'
        return 0
        ;;
      unhealthy) break ;;
    esac
    [ "$(docker inspect --format '{{.RestartCount}}' "$service" 2>/dev/null)" = 0 ] || break
  done
  printf '\n'
  return 1
}

if [ -n "$version" ]; then
  plain_value "$version" || die "a version is letters, digits, dots, dashes and underscores"
fi
# What this machine follows after this run, and so where its files come from.
target="${version:-$(env_value UWUSSH_VERSION || printf latest)}"
plain_value "$target" || target=latest

printf '\n  UwUSSH Server, update\n  ~~~~~~~~~~~~~~~~~~~~~\n\n'

# ── a newer updater first ─────────────────────────────────────────────────────────────────────
# From the newest release of the channel — for a pinned version too, since a newer update.sh
# knows how to handle an older server. Reading the script and replacing the file are two
# different things: bash holds the old file open, so swapping it out under us is safe, and the
# new one takes over with exec right after. The directory goes last, so a relative --dir the
# first run resolved is not resolved again from here.
if $self_update; then
  fresh=$(mktemp)
  scripts_from=$(release_base "$([ "$target" = beta ] && echo beta || echo latest)")
  if fetch_checked update.sh "$fresh" "$scripts_from" &&
    [ "$(hash_of "$fresh")" != "$(hash_of "$0")" ]; then
    step "there is a newer update.sh; taking that one"
    install -m 0755 "$fresh" "$dir/update.sh"
    rm -f "$fresh"
    exec bash "$dir/update.sh" "${called_with[@]}" --no-self-update --dir "$dir"
  fi
  rm -f "$fresh"
fi

# What the .env and compose.yaml were before this run, so a way back puts them back too. Made
# only now, after the self-update: an exec takes no trap along to clean up after it.
saved=$(mktemp -d) || die "no room for a temporary directory"
trap 'rm -f "$dir/.env.tmp"; rm -rf "$saved"' EXIT INT TERM
cp -p "$dir/.env" "$saved/env"
cp -p "$dir/compose.yaml" "$saved/compose.yaml"
put_back() {
  cp -p "$saved/env" "$dir/.env"
  cp -p "$saved/compose.yaml" "$dir/compose.yaml"
}

# ── what is running now ───────────────────────────────────────────────────────────────────────
running_version=$(docker inspect "$service" \
  --format '{{index .Config.Labels "org.opencontainers.image.version"}}' 2>/dev/null)
running_image=$(docker inspect "$service" --format '{{.Image}}' 2>/dev/null)
[ -n "$running_version" ] && step "running now: $running_version"

# ── the compose file ──────────────────────────────────────────────────────────────────────────
# The settings the stock file takes from .env. Written by hand into compose.yaml instead, they
# move into .env; anything else somebody changed stops the update.
lifted="UWUSSH_PUBLIC UWUSSH_REGISTRATION UWUSSH_TLS UWUSSH_TRUST_FORWARDED UWUSSH_UPDATE_CHECK"
lifted="$lifted UWUSSH_MAX_ACCOUNTS UWUSSH_ACCOUNT_MAX_RECORDS UWUSSH_ACCOUNT_MAX_MB"

# shellcheck disable=SC2016  # the ${...} here are strings to compare against, not expansions
lift_into_env() {
  local file="$1" value key
  value=$(grep -oE "image: $image:[^ ]+" "$file" | head -1 | cut -d: -f3)
  case "$value" in
    "" | '${UWUSSH_VERSION'*) ;;
    *)
      step "moving the image tag $value into .env"
      set_env UWUSSH_VERSION "$value"
      ;;
  esac
  value=$(grep -oE '^ *- "[^"]+:8443"' "$file" | head -1 | sed -E 's/.*"(.*):8443"/\1/')
  case "$value" in
    "" | '${UWUSSH_BIND'*) ;;
    *)
      step "moving the port, which is $value here, into .env"
      set_env UWUSSH_BIND "$value"
      ;;
  esac
  for key in $lifted; do
    value=$(grep -E "^ +$key: " "$file" | head -1 |
      sed -E "s/^ +$key: *//; s/[[:space:]]+#.*//; s/^[\"']//; s/[\"']\$//")
    case "$value" in
      "" | '${'*) ;;
      *)
        step "moving $key into .env"
        set_env "$key" "$value"
        ;;
    esac
  done
}

# The same file with every value we understand blanked out. What is left over after that is a
# change nobody can translate, and then we stop. The last line takes the width of the comment
# column out of it as well: a port written by hand shifts the comment behind it, and that is not
# a change worth stopping for.
normalized() {
  local expressions=(
    -e "s#(image: $image:).*#\1@#"
    -e 's#^( *- ")[^"]+(:8443".*)#\1@\2#'
    -e 's|[[:space:]]+#| #|'
  )
  local key
  for key in $lifted; do
    expressions+=(-e "s#^( +$key: ).*#\1@#")
  done
  sed -E "${expressions[@]}" "$1" | sha256sum | cut -d' ' -f1
}

# True when this compose.yaml is one we put here: either we wrote down its checksum, or it is
# exactly the file that came with the version running now.
compose_is_ours() {
  local mine theirs
  mine=$(hash_of "$dir/compose.yaml")
  [ -f "$state" ] && grep -qxF "compose $mine" "$state" && return 0
  looks_like_version "$running_version" || return 1
  theirs=$(mktemp)
  if fetch_checked compose.yaml "$theirs" "$releases/download/v$running_version" &&
    [ "$(hash_of "$theirs")" = "$mine" ]; then
    rm -f "$theirs"
    return 0
  fi
  rm -f "$theirs"
  return 1
}

if ! $keep_compose && [ -f "$state" ] && grep -qx "compose keep" "$state"; then
  keep_compose=true
  step "compose.yaml is yours; leaving it alone"
fi

stock=$(mktemp)
compose_known=false
if $keep_compose; then
  :
elif fetch_checked compose.yaml "$stock" "$(release_base "$target")"; then
  if [ "$(hash_of "$stock")" = "$(hash_of "$dir/compose.yaml")" ]; then
    step "compose.yaml is the current one"
    compose_known=true
  elif compose_is_ours; then
    install -m 0644 "$stock" "$dir/compose.yaml"
    step "compose.yaml brought up to date"
    compose_known=true
  elif [ "$(normalized "$dir/compose.yaml")" = "$(normalized "$stock")" ]; then
    lift_into_env "$dir/compose.yaml"
    install -m 0644 "$stock" "$dir/compose.yaml"
    step "compose.yaml brought up to date, your changes live in .env now"
    compose_known=true
  elif $force; then
    cp -p "$dir/compose.yaml" "$dir/compose.yaml.bak"
    lift_into_env "$dir/compose.yaml.bak"
    install -m 0644 "$stock" "$dir/compose.yaml"
    warn "compose.yaml replaced as asked; the old one is next to it as compose.yaml.bak"
    compose_known=true
  else
    printf '\n'
    warn "your compose.yaml is not the one this version ships, and not everything in it fits"
    warn "into .env. Nothing was changed. This is what differs:"
    printf '\n'
    diff -u "$dir/compose.yaml" "$stock" | sed -n '3,40p'
    cat <<-CHOICE

	  Your file on purpose, say so once and it stops asking:  sudo bash update.sh --keep-compose
	  Take the new one, yours stays as compose.yaml.bak:      sudo bash update.sh --force

	CHOICE
    rm -f "$stock"
    exit 1
  fi
else
  warn "could not fetch the current compose.yaml; going on with the one that is here"
fi
rm -f "$stock"
compose_hash=$(hash_of "$dir/compose.yaml")

if [ -n "$version" ]; then
  set_env UWUSSH_VERSION "$version"
  step "switching to the $version tag"
fi

# ── a backup first ────────────────────────────────────────────────────────────────────────────
# It stays in the volume next to the nightly ones, under backups/. The server writes it itself,
# consistently, while it runs — and it is the way back if the new version changes the database
# and then does not come up.
backup_name=""
if $backup; then
  if docker compose ps --status running --services 2>/dev/null | grep -qx "$service"; then
    step "backing up first"
    # exec does not go through the image entrypoint, so the binary is named here.
    if written=$(docker compose exec -T "$service" uwussh-server backup </dev/null); then
      backup_name=$(printf '%s' "$written" | grep -oE 'uwussh-[0-9-]+\.db' | tail -1)
      step "  ${backup_name:-written}"
    else
      warn "no backup was made"
      yesno "Update anyway?" n || {
        put_back
        die "stopped, nothing was changed"
      }
    fi
  else
    warn "UwUSSH Server is not running, so nothing was backed up"
  fi
fi

# ── the new version ───────────────────────────────────────────────────────────────────────────
if $pull; then
  step "fetching the image"
  docker compose pull --quiet </dev/null || {
    put_back
    die "the image could not be fetched; nothing was changed"
  }
fi

step "starting the new version"
if ! docker compose up -d </dev/null; then
  warn "the new version did not start"
  healthy=false
elif wait_healthy; then
  healthy=true
else
  healthy=false
fi

# ── back to the old one, when the new one does not come up ────────────────────────────────────
if ! $healthy; then
  warn "the new version did not come up healthy; putting the one from before back"
  put_back
  if looks_like_version "$running_version"; then
    set_env UWUSSH_VERSION "$running_version"
  elif [ -n "$running_image" ]; then
    docker tag "$running_image" "$image:rollback" >/dev/null 2>&1 && set_env UWUSSH_VERSION rollback
  fi
  docker compose up -d </dev/null >/dev/null 2>&1
  if wait_healthy; then
    warn "UwUSSH Server runs on the version from before, and .env says which one that is."
  elif [ -n "$backup_name" ]; then
    # The old version does not come up either: the new one changed the database, and the old
    # one will not run on a database newer than itself. The backup from a minute ago will do.
    warn "the version from before does not come up on the database the new one left behind;"
    warn "putting the backup from just before the update back ($backup_name)"
    docker compose stop </dev/null >/dev/null 2>&1
    if docker compose run --rm -T "$service" restore "$backup_name" </dev/null >/dev/null &&
      docker compose up -d </dev/null >/dev/null 2>&1 && wait_healthy; then
      warn "UwUSSH Server runs on the version from before, with the database from just before"
      warn "the update. What the new version had made of it is kept next to it in the volume."
    else
      warn "that did not bring it back either."
    fi
  else
    warn "the version from before does not come up either."
  fi
  warn "What went wrong: cd $dir && docker compose logs $service"
  exit 1
fi

{
  printf '# Written by install.sh and update.sh: what they put here, so they know what they may replace.\n'
  if $keep_compose; then
    printf 'compose keep\n'
  elif $compose_known; then
    printf 'compose %s\n' "$compose_hash"
  fi
} >"$state"
chmod 0644 "$state"

# The image from before has no name any more; only ours, and only those, go.
docker image prune -f --filter "label=org.opencontainers.image.source=https://github.com/$repo" \
  >/dev/null 2>&1 || true

new_version=$(docker inspect "$service" \
  --format '{{index .Config.Labels "org.opencontainers.image.version"}}' 2>/dev/null)
printf '\n'
if [ -n "$new_version" ] && [ "$new_version" != "$running_version" ]; then
  printf '  UwUSSH Server is on %s now (=^･ω･^=)\n\n' "$new_version"
else
  printf '  UwUSSH Server is up to date (=^･ω･^=)\n\n'
fi
printf '  What is new: %s/latest\n\n' "$releases"
