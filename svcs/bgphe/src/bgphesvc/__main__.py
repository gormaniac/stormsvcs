import asyncio
import sys

from . import BgpHeSvc

if __name__ == "__main__":
    asyncio.run(BgpHeSvc.execmain(sys.argv[1:]))
