#!/bin/bash
# test/e2e/ssh-askpass-e2e.sh
# SSH_ASKPASS handler for E2E keyboard-interactive authentication.
#
# PAM keyboard-interactive conversation (see pam-prmana/src/lib.rs):
#   Round 1: DPOP_NONCE:<value>  — server-issued nonce (PROMPT_ECHO_ON)
#   Round 2: DPOP_PROOF:        — DPoP proof request (PROMPT_ECHO_OFF)
#   Round 3: OIDC Token:        — access token request (PROMPT_ECHO_OFF)
#
# Environment:
#   PRMANA_E2E_TOKEN_FILE — path to file containing the JWT access token
#   PRMANA_E2E_ASKPASS_LOG — optional path to append per-round diagnostics
#
# With dpop_required=warn, rounds 1-2 return empty (no DPoP proof).
# Round 3 returns the real JWT for JWKS signature validation.

PROMPT="${1:-}"
TOKEN_FILE="${PRMANA_E2E_TOKEN_FILE:-}"
ASKPASS_LOG="${PRMANA_E2E_ASKPASS_LOG:-/tmp/prmana-e2e-askpass.log}"

# Best-effort diagnostics. Writes one line per invocation to a file on the
# client side so the test harness can assert the full conversation actually
# reached the askpass script and in the expected order. Failure to write
# the log must not block the authentication response.
log_invocation() {
    local outcome="$1"
    local token_len="${2:-0}"
    {
        printf '%s prompt=%q outcome=%s token_len=%s\n' \
            "$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)" \
            "$PROMPT" "$outcome" "$token_len"
    } >> "$ASKPASS_LOG" 2>/dev/null || true
}

if [[ "$PROMPT" == *DPOP_NONCE:* ]]; then
    # Round 1: Acknowledge nonce delivery. PAM discards this response.
    # Note: SSH prepends "(user@host) " to prompts, so use *contains* match.
    log_invocation "round1_nonce_ack"
    echo ""
elif [[ "$PROMPT" == *DPOP_PROOF* ]]; then
    # Round 2: No DPoP proof (dpop_required=warn accepts bearer tokens).
    log_invocation "round2_proof_empty"
    echo ""
elif [[ "$PROMPT" == *"OIDC Token"* ]] || [[ "$PROMPT" == *"token"* ]] || [[ "$PROMPT" == *"Token"* ]]; then
    # Round 3: Provide the real JWT access token.
    if [ -n "$TOKEN_FILE" ] && [ -f "$TOKEN_FILE" ]; then
        TOKEN_CONTENT=$(cat "$TOKEN_FILE")
        log_invocation "round3_token_delivered" "${#TOKEN_CONTENT}"
        printf '%s' "$TOKEN_CONTENT"
    else
        log_invocation "round3_token_missing_file"
        echo ""
    fi
else
    # Unknown prompt: safe default.
    log_invocation "unknown_prompt"
    echo ""
fi
