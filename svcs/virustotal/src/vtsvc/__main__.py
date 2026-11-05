import asyncio
import sys

from . import VtSvc

if __name__ == "__main__":
    asyncio.run(VtSvc.execmain(sys.argv[1:]))
