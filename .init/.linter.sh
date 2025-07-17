#!/bin/bash
cd /tmp/kavia/workspace/code-generation/sample-backend-apis-2be5c7b7/Backend_API_Monolithic_Service
source venv/bin/activate
flake8 .
LINT_EXIT_CODE=$?
if [ $LINT_EXIT_CODE -ne 0 ]; then
  exit 1
fi

