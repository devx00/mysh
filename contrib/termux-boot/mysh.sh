#!/data/data/com.termux/files/usr/bin/sh
# Termux:Boot start script for `mysh serve`.
#
#   mkdir -p ~/.termux/boot
#   cp contrib/termux-boot/mysh.sh ~/.termux/boot/
#   chmod +x ~/.termux/boot/mysh.sh
#
# Install the Termux:Boot app once and open it so Android lets it run at
# boot. The binary is expected at ~/bin/mysh (adb push or copy it there);
# keys live in ~/.config/mysh. Listening on the wildcard address is fine on a
# phone behind NAT; narrow it with --listen if the device has a public IP.
set -eu

: "${MYSH_BIN:=$HOME/bin/mysh}"
: "${MYSH_LISTEN:=[::]:7722}"
LOG="$HOME/.config/mysh/serve.log"

mkdir -p "$HOME/.config/mysh"

# Keep the CPU awake while the server is up; released when it exits.
command -v termux-wake-lock >/dev/null 2>&1 && termux-wake-lock

exec "$MYSH_BIN" serve --listen "$MYSH_LISTEN" >>"$LOG" 2>&1
