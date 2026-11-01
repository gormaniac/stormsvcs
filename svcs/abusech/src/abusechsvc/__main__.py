import asyncio
import sys

from . import AbuseChSvc

if __name__ == "__main__":
    asyncio.run(AbuseChSvc.execmain(sys.argv[1:]))
