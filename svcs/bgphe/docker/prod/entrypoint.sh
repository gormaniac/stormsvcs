#!/bin/sh
exec uv run --no-sync --directory /opt/stormsvcs/bgphe/ python -O -m bgphesvc /vertex/storage
