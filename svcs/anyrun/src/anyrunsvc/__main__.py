import asyncio
import sys

from . import AnyRunSvc

if __name__ == "__main__":
    asyncio.run(AnyRunSvc.execmain(sys.argv[1:]))
