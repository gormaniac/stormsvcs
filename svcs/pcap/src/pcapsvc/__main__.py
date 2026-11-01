import asyncio
import sys

from . import PcapSvc

if __name__ == "__main__":
    asyncio.run(PcapSvc.execmain(sys.argv[1:]))
