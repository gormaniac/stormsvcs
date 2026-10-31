"""Errors for the slib.hatching service."""


class HatchingApiError(Exception):
    """An error from the Hatching Triage API (or the service's handling of a request).

    ``mesg`` is returned to Storm in the ``TelepathRetn``.
    """

    def __init__(self, mesg: str) -> None:
        super().__init__(mesg)
        self.mesg = mesg
