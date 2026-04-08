#!/bin/bash
# test/e2e/ssh-askpass-e2e.sh
# SSH_ASKPASS handler for E2E keyboard-interactive authentication.
#
# PAM keyboard-interactive conversation (see pam-unix-oidc/src/lib.rs):
#   Round 1: DPOP_NONCE:<value>  — server-issued nonce (PROMPT_ECHO_ON)
#   Round 2: DPOP_PROOF:        — DPoP proof request (PROMPT_ECHO_OFF)
#   Round 3: OIDC Token:        — access token request (PROMPT_ECHO_OFF)
#
# Environment:
#   UNIX_OIDC_E2E_TOKEN_FILE — path to file containing the JWT access token
#
# With dpop_required=warn, rounds 1-2 return empty (no DPoP proof).
# Round 3 returns the real JWT for JWKS signature validation.

PROMPT="${1:-}"
TOKEN_FILE="${UNIX_OIDC_E2E_TOKEN_FILE:-}"

if [[ "$PROMPT" == *DPOP_NONCE:* ]]; then
    # Round 1: Acknowledge nonce delivery. PAM discards this response.
    # Note: SSH prepends "(user@host) " to prompts, so use *contains* match.
    echo ""
elif [[ "$PROMPT" == *DPOP_PROOF* ]]; then
    # Round 2: No DPoP proof (dpop_required=warn accepts bearer tokens).
    echo ""
elif [[ "$PROMPT" == *"OIDC Token"* ]] || [[ "$PROMPT" == *"token"* ]] || [[ "$PROMPT" == *"Token"* ]]; then
    # Round 3: Provide the real JWT access token.
    if [ -n "$TOKEN_FILE" ] && [ -f "$TOKEN_FILE" ]; then
        cat "$TOKEN_FILE"
    else
        echo ""
    fi
else
    # Unknown prompt: safe default.
    echo ""
fi
