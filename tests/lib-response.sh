RESPONSE_NODE="${P:-clab-dmz}-siem-responder"
RESPONSE_PREV=""

response_cmd() { docker exec "${RESPONSE_NODE}" respond "$@"; }

response_suspend() {
  docker inspect "${RESPONSE_NODE}" >/dev/null 2>&1 || return 0
  RESPONSE_PREV=$(response_cmd mode 2>/dev/null || echo enforce)
  response_cmd mode monitor >/dev/null 2>&1
  response_cmd flush >/dev/null 2>&1
  response_cmd reset >/dev/null 2>&1
  echo "== Automatic response in monitor mode for this test (was ${RESPONSE_PREV}), blocks lifted"
  trap response_resume EXIT
}

response_resume() {
  [ -n "${RESPONSE_PREV}" ] || return 0
  response_cmd flush >/dev/null 2>&1
  response_cmd reset >/dev/null 2>&1
  response_cmd mode "${RESPONSE_PREV}" >/dev/null 2>&1
  echo "== Automatic response restored (${RESPONSE_PREV})"
}
