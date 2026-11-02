import os

# The fake Hatching Triage server listens on localhost, make sure no proxy gets in the way.
for _var in ("NO_PROXY", "no_proxy"):
    os.environ[_var] = ",".join(filter(None, (os.environ.get(_var), "127.0.0.1", "localhost")))
