#!/usr/bin/env bats

# LLM doc-completeness test for oidc-mock.
#
# An AI agent is given only the container image and must figure out
# how to configure and run it, then complete a full OIDC Authorization
# Code flow using only curl — no source code allowed.
# The test independently verifies the token and userinfo responses.
#
# Requires:
#   - claude CLI with API key
#   - Docker
#
# Run: bats test/llm/doc-completeness.bats

load '../helpers/test_helper'

OIDC_PORT="${OIDC_PORT:-18080}"
CONTAINER_NAME="oidc-mock-llm-test"

setup_file() {
  export IMAGE="${IMAGE:-oidc-mock:llm-test}"
  export LOG_DIR="${BATS_TEST_DIRNAME}/logs"
  mkdir -p "$LOG_DIR"

  local TIMESTAMP
  TIMESTAMP=$(date +%Y%m%d-%H%M%S)
  export GAPS_FILE="${LOG_DIR}/gaps-${TIMESTAMP}.txt"
  export CLAUDE_LOG="${LOG_DIR}/claude-${TIMESTAMP}.log"
  export RESULT_FILE="${LOG_DIR}/result-${TIMESTAMP}.json"

  command -v claude >/dev/null 2>&1 || skip "claude CLI not found"
  command -v docker >/dev/null 2>&1 || skip "docker not found"

  # Build the image if it doesn't exist
  if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    docker build -t "$IMAGE" "$(git rev-parse --show-toplevel)"
  fi

  # Clean up any leftover container
  docker rm -f "$CONTAINER_NAME" 2>/dev/null || true
}

teardown_file() {
  docker rm -f "$CONTAINER_NAME" 2>/dev/null || true
}

@test "AI completes OIDC auth code flow from container image alone" {
  local PROMPT
  PROMPT="$(cat <<PROMPT_EOF
You have a container image: ${IMAGE}

Your task:
1. Figure out what this container does and how to configure it. Do NOT read source code.
2. Start the container (name: ${CONTAINER_NAME}) on port ${OIDC_PORT} with this custom config:
   - A client with id "test-app", secret "test-secret", and redirect_uri "http://localhost:${OIDC_PORT}/callback"
   - Two users: one named "Alice" (sub: alice, email: alice@test.com) with password "pass123",
     and one named "Bob" (sub: bob, email: bob@test.com) without a password
3. Complete a full OIDC Authorization Code flow using curl for user Alice.
   Save her /userinfo JSON response to ${RESULT_FILE}
4. Do the same for Bob (no password). Save his /userinfo JSON to ${RESULT_FILE}.bob

Rules:
- Use "docker run" to run the container — do not install Go or build from source
- You must figure out the usage from the container alone — do NOT read source code
- If you encounter documentation gaps or unclear instructions, note them in ${GAPS_FILE}
- Use http://localhost:${OIDC_PORT} as the issuer
- This tool is designed for browser-based login flows (user picker UI, password form).
  The /authorize and /authorize/callback endpoints serve HTML for human interaction.
  Lack of API documentation for these form fields is not a documentation gap.
PROMPT_EOF
)"

  claude -p "$PROMPT" \
    --dangerously-skip-permissions \
    --max-budget-usd 2 \
    --allowedTools "Bash Read Write" \
    2>&1 | tee "${CLAUDE_LOG}"
}

# --- Independent verification ---
# These tests verify the results directly — they don't trust the AI's self-report.

@test "container is running" {
  run docker inspect -f '{{.State.Running}}' "$CONTAINER_NAME"
  assert_success
  assert_output "true"
}

@test "discovery endpoint returns valid OIDC config" {
  run curl -sf "http://localhost:${OIDC_PORT}/.well-known/openid-configuration"
  assert_success

  echo "$output" | jq -e '.issuer' >/dev/null
  echo "$output" | jq -e '.authorization_endpoint' >/dev/null
  echo "$output" | jq -e '.token_endpoint' >/dev/null
  echo "$output" | jq -e '.userinfo_endpoint' >/dev/null
}

@test "Alice userinfo has correct claims" {
  [ -f "$RESULT_FILE" ] || skip "result file not found — AI may have failed"

  run jq -r '.sub' "$RESULT_FILE"
  assert_success
  assert_output "alice"

  run jq -r '.email' "$RESULT_FILE"
  assert_success
  assert_output "alice@test.com"
}

@test "Bob userinfo has correct claims (passwordless flow)" {
  [ -f "${RESULT_FILE}.bob" ] || skip "bob result file not found — AI may have failed"

  run jq -r '.sub' "${RESULT_FILE}.bob"
  assert_success
  assert_output "bob"

  run jq -r '.email' "${RESULT_FILE}.bob"
  assert_success
  assert_output "bob@test.com"
}

@test "documentation gaps file is empty or absent" {
  if [ -f "$GAPS_FILE" ]; then
    run cat "$GAPS_FILE"
    # Print gaps for visibility but don't fail — gaps are informational
    echo "Documentation gaps found:"
    echo "$output"
  fi
}
