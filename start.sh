#!/usr/bin/bash
uwsgi -s /tmp/dl-jwtserver.sock --manage-script-name --mount /=server:app --virtualenv venv-run --plugin python3
