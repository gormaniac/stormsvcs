import asyncio
import sys

from . import SnortSvc

if __name__ == "__main__":
    asyncio.run(SnortSvc.execmain(sys.argv[1:]))
