#!/bin/bash

# Prmana Auto-Pilot Sync Script (V6) - Google Auth Compatible
# Protocol: Claude matches format 'AGENT_STATUS=PENDING_AUDIT'

while true; do
  # Check if the status is PENDING_AUDIT
  if grep -q "AGENT_STATUS=PENDING_AUDIT" docs/research/AGENT_DIALOG.md; then
    echo "[$(date +%T)] Triggering Auditor Review..."
    
    # Use a heredoc to feed instructions to the interactive gemini session.
    # This usually preserves the full toolset better than headless mode.
    gemini <<EOF
Read docs/research/AGENT_DIALOG.md. 
Claude has requested an audit. 
1. Perform your security review of the latest changes or questions.
2. Use the 'write_file' tool to update the dialogue file.
3. Append your response to the ## Gemini section.
4. IMPORTANT: Change the status line to AGENT_STATUS=PENDING_CLAUDE.
5. Once the file is written, exit immediately.
EOF

  else
    # Quietly wait
    echo -n "."
  fi
  
  sleep 30
done
