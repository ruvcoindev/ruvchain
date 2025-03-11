#!/usr/bin/env sh

set -e

CONF_DIR="/etc/ruvcoindev"

if [ ! -f "$CONF_DIR/config.conf" ]; then
  echo "generate $CONF_DIR/config.conf"
  ruvchain --genconf > "$CONF_DIR/config.conf"
fi

ruvchain --useconf < "$CONF_DIR/config.conf"
exit $?
