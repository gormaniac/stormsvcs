import sys
import asyncio

from . import IpApiSvc

if __name__ == "__main__":
    asyncio.run(IpApiSvc.execmain(sys.argv[1:]))
