"""Run the yarastorm service, ex. ``python -m yarastorm /vertex/storage``."""

import asyncio
import sys

from . import YaraSvc

if __name__ == "__main__":
    asyncio.run(YaraSvc.execmain(sys.argv[1:]))
