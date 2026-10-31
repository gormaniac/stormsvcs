import asyncio
import sys

from . import CrtshSvc

if __name__ == "__main__":
    asyncio.run(CrtshSvc.execmain(sys.argv[1:]))
