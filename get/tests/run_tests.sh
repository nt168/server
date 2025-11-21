#!/usr/bin/env bash
set -euo pipefail

GET_BIN=${1:-./get_client}
FAKE_SERVER=${2:-./tests/fake_server}

TMP_DIR=$(mktemp -d -t get-tests-XXXX)
CHANNEL_DIR="$TMP_DIR/channel"
mkdir -p "$CHANNEL_DIR"
mkfifo "$CHANNEL_DIR/Read" "$CHANNEL_DIR/Write"

CONFIG_FILE="$TMP_DIR/phy_server.cnf"
cat > "$CONFIG_FILE" <<CFG
TmpDir=$TMP_DIR
MessChannelDir=channel
CFG

EXPECTED_TYPE="DDR"

# test control agent insert path
$FAKE_SERVER --read "$CHANNEL_DIR/Read" --write "$CHANNEL_DIR/Write" --expect-type "$EXPECTED_TYPE" &
FAKE_PID=$!

set +e
OUTPUT=$($GET_BIN --config "$CONFIG_FILE" 1 1 127.0.0.1 testuser testpwd --timeout 2)
STATUS=$?
set -e

wait $FAKE_PID || true

if [ $STATUS -ne 0 ]; then
  echo "Get command failed" >&2
  echo "$OUTPUT" >&2
  exit 1
fi

echo "$OUTPUT" | grep -q "insert ok: 127.0.0.1 testuser testpwd"

# test history path remains functional
$FAKE_SERVER --read "$CHANNEL_DIR/Read" --write "$CHANNEL_DIR/Write" --expect-type "$EXPECTED_TYPE" &
FAKE_PID=$!

set +e
OUTPUT=$($GET_BIN --config "$CONFIG_FILE" history --receiver 127.0.0.1 --type "$EXPECTED_TYPE" --timeout 2)
STATUS=$?
set -e

wait $FAKE_PID || true

if [ $STATUS -ne 0 ]; then
  echo "Get history command failed" >&2
  echo "$OUTPUT" >&2
  exit 1
fi

echo "$OUTPUT" | grep -q "${EXPECTED_TYPE} history ok"

rm -rf "$TMP_DIR"
echo "Tests completed successfully"
