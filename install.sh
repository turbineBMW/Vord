#!/usr/bin/env sh
# Install Vord for the current user (no Flatpak).
#   sh install.sh             -> ~/.local (binary in ~/.local/bin)
#   PREFIX=/usr sh install.sh -> system-wide (run with sudo)
set -eu
PREFIX="${PREFIX:-$HOME/.local}"
APP_ID=io.github.turbinebmw.Vord
BIN="$PREFIX/bin"
SHARE="$PREFIX/share"

if command -v pacman >/dev/null 2>&1; then distro=arch
elif command -v apt-get >/dev/null 2>&1; then distro=debian
elif command -v dnf >/dev/null 2>&1; then distro=fedora
else distro=unknown; fi

missing=""
what=""
# need <what> <arch pkg> <debian pkg> <fedora pkg>
need() {
  case $distro in
    arch) pkg=$2 ;; debian) pkg=$3 ;; fedora) pkg=$4 ;; *) pkg=$1 ;;
  esac
  what="$what
  - $1"
  case " $missing " in *" $pkg "*) ;; *) missing="$missing $pkg" ;; esac
}
have_cmd() { command -v "$1" >/dev/null 2>&1; }
have_lib() { pkg-config --exists "$1${2:+ >= $2}" 2>/dev/null; }

have_cmd cargo || need cargo rust cargo cargo
if have_cmd pkg-config; then
  have_lib gtk4 4.18 || need "gtk4 >= 4.18" gtk4 libgtk-4-dev gtk4-devel
  have_lib libadwaita-1 1.8 || need "libadwaita >= 1.8" libadwaita libadwaita-1-dev libadwaita-devel
else
  need pkg-config pkgconf pkg-config pkgconf-pkg-config
fi

if [ -n "$missing" ]; then
  echo "Vord can't be built yet; missing:$what" >&2
  echo "Install them with:" >&2
  case $distro in
    arch) echo "  sudo pacman -S --needed$missing" >&2 ;;
    debian) echo "  sudo apt install$missing" >&2 ;;
    fedora) echo "  sudo dnf install$missing" >&2 ;;
    *) echo " $missing" >&2 ;;
  esac
  exit 1
fi

cargo build --release
install -Dm755 target/release/vord "$BIN/vord"
install -d "$SHARE/applications"
sed "s|^Exec=vord|Exec=$BIN/vord|" data/$APP_ID.desktop.in > "$SHARE/applications/$APP_ID.desktop"
for size in 16 24 32 48 64 128 256 512; do
  install -Dm644 "data/icons/hicolor/${size}x${size}/apps/$APP_ID.png" \
    "$SHARE/icons/hicolor/${size}x${size}/apps/$APP_ID.png"
done
install -Dm644 "data/icons/hicolor/scalable/apps/$APP_ID.svg" "$SHARE/icons/hicolor/scalable/apps/$APP_ID.svg"
install -Dm644 "data/icons/hicolor/symbolic/apps/$APP_ID-symbolic.svg" "$SHARE/icons/hicolor/symbolic/apps/$APP_ID-symbolic.svg"
gtk-update-icon-cache -q -t -f "$SHARE/icons/hicolor" 2>/dev/null || true
update-desktop-database -q "$SHARE/applications" 2>/dev/null || true
echo "Installed to $PREFIX. Run: $BIN/vord"
