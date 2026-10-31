import asyncio
import sys

from . import ShodanSvc

if __name__ == "__main__":
    asyncio.run(ShodanSvc.execmain(sys.argv[1:]))
