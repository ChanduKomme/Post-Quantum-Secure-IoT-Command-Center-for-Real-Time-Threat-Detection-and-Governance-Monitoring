
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="${PQC_ENV_FILE:-$ROOT/.env}"
ROLE=""
BUILD_ALL=0
CLEAN=0

usage(){
  cat <<'USAGE'
Usage:
  bash tools/build_firmware.sh --role sender|Receiver|sniffer [--clean]
  bash tools/build_firmware.sh --all [--clean]

Environment:
  BL60X_SDK_PATH=/path/to/bl602_iot_sdk      Required
  PQC_ENV_FILE=/path/to/.env                 Optional local env file
  SPLUNK_HEC_TOKEN=<token>                   Inject HEC token at build time
  SPLUNK_HEC_PORT=8088                       Optional; default 8088
  SPLUNK_STATIC_HOST=192.168.1.10            Optional bypass for discovery

Notes:
  - Real tokens are compiler defines only; they are not written to source.
  - For automatic Splunk IP discovery, leave SPLUNK_STATIC_HOST unset.
  - This script creates customer_app/<role> symlinks automatically because the
    BL602 SDK image packer expects that layout.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --role) ROLE="${2:-}"; shift 2;;
    --all) BUILD_ALL=1; shift;;
    --clean) CLEAN=1; shift;;
    -h|--help) usage; exit 0;;
    *) echo "Unknown argument: $1" >&2; usage; exit 2;;
  esac
done

if [[ -f "$ENV_FILE" ]]; then
  set -a
  # shellcheck disable=SC1090
  source "$ENV_FILE"
  set +a
fi

if [[ -z "${BL60X_SDK_PATH:-}" ]]; then
  echo "ERROR: BL60X_SDK_PATH is not set." >&2
  exit 1
fi

SDK_ROOT="$(cd "$BL60X_SDK_PATH" && pwd)"
mkdir -p "$SDK_ROOT/customer_app"

ensure_customer_app_link(){
  local role="$1"
  local dest="$SDK_ROOT/customer_app/$role"
  local src="$ROOT/$role"
  if [[ ! -d "$src" ]]; then
    echo "ERROR: role folder not found: $src" >&2
    exit 1
  fi
  if [[ -L "$dest" ]]; then
    local cur
    cur="$(readlink -f "$dest" || true)"
    if [[ "$cur" == "$src" ]]; then
      return 0
    fi
    rm -f "$dest"
  elif [[ -e "$dest" ]]; then
    local ts
    ts="$(date +%Y%m%d_%H%M%S)"
    echo "INFO: moving existing $dest to $dest.backup.$ts"
    mv "$dest" "$dest.backup.$ts"
  fi
  ln -sfnT "$src" "$dest"
}

extra=""
if [[ -n "${SPLUNK_HEC_TOKEN:-}" && "${SPLUNK_HEC_TOKEN}" != "REPLACE_WITH_YOUR_SPLUNK_HEC_TOKEN" ]]; then
  extra+=" -DSPLUNK_HEC_TOKEN=\\\"${SPLUNK_HEC_TOKEN}\\\""
else
  echo "WARN: SPLUNK_HEC_TOKEN not set; firmware will build with Splunk event sending disabled." >&2
fi
if [[ -n "${SPLUNK_HEC_PORT:-}" ]]; then
  extra+=" -DSPLUNK_HEC_PORT=\\\"${SPLUNK_HEC_PORT}\\\""
fi
if [[ -n "${SPLUNK_STATIC_HOST:-}" ]]; then
  extra+=" -DSPLUNK_STATIC_HOST=\\\"${SPLUNK_STATIC_HOST}\\\""
else
  echo "INFO: SPLUNK_STATIC_HOST unset; firmware will use auto discovery + gateway fallback."
fi
export PQC_EXTRA_CFLAGS="$extra"

build_one(){
  local role="$1"
  ensure_customer_app_link "$role"
  echo "==> Building $role"
  echo "    source: $ROOT/$role"
  echo "    sdk customer_app link: $SDK_ROOT/customer_app/$role"
  if [[ "$CLEAN" == "1" ]]; then
    rm -rf "$ROOT/$role/build_out"
  fi
  mkdir -p "$ROOT/$role/build_out"
  (cd "$ROOT/$role" && ./genromap)
}

if [[ "$BUILD_ALL" == "1" ]]; then
  build_one Receiver
  build_one sender
  build_one sniffer
else
  [[ -n "$ROLE" ]] || { usage; exit 2; }
  case "$ROLE" in sender|Receiver|sniffer) build_one "$ROLE";; *) echo "Invalid role: $ROLE" >&2; exit 2;; esac
fi
