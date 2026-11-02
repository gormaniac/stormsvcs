import asyncio
import sys

from . import MalpediaSvc

if __name__ == "__main__":
    asyncio.run(MalpediaSvc.execmain(sys.argv[1:]))
