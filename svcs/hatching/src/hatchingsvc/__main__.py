import asyncio
import sys

from . import HatchingSvc

if __name__ == "__main__":
    asyncio.run(HatchingSvc.execmain(sys.argv[1:]))
