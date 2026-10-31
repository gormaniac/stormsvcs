import sys
import asyncio

from . import CapaSvc

if __name__ == "__main__":
    asyncio.run(CapaSvc.execmain(sys.argv[1:]))
