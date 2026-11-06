#!/usr/bin/env bash
# ip-pbx-manager entrypoint — picks the container role.
set -e

ROLE="${PBX_ROLE:-all}"
DATA_DIR="${IPBX_DATA_DIR:-/data}"

# Prepare persistent data directories
mkdir -p "$DATA_DIR/asterisk" "$DATA_DIR/cdr" "$DATA_DIR/recordings" \
         "$DATA_DIR/astdb" "$DATA_DIR/log" "$DATA_DIR/spool"

# Stub include-files so Asterisk starts cleanly before the wizard generates real ones
for f in pjsip_endpoints.conf pjsip_trunk.conf extensions_internal.conf \
         extensions_inbound.conf globals.conf; do
    [ -f "$DATA_DIR/asterisk/$f" ] || touch "$DATA_DIR/asterisk/$f"
done

# Render AMI manager config (password comes from the environment)
sed "s|__AMI_PASSWORD__|${AMI_PASSWORD}|g" /opt/ipbx/manager.conf.template \
    > /etc/asterisk/manager.conf

case "$ROLE" in
  asterisk)
    echo "[ipbx] starting Asterisk engine..."
    exec asterisk -f
    ;;
  panel)
    echo "[ipbx] starting management panel on port ${PANEL_PORT}..."
    cd /opt/ipbx/app
    exec python3 -m gunicorn --bind "0.0.0.0:${PANEL_PORT}" \
         --workers 1 --threads 8 --timeout 60 wsgi:app
    ;;
  all)
    echo "[ipbx] starting all-in-one mode (Asterisk + panel)..."
    exec supervisord -n -c /opt/ipbx/supervisord-all.conf
    ;;
  *)
    echo "[ipbx] unknown PBX_ROLE='$ROLE' (use: asterisk | panel | all)" >&2
    exit 1
    ;;
esac
