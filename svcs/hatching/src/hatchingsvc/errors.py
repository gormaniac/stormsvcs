"""Errors for the slib.hatching service."""


class HatchingApiError(Exception):
    """An error from the Hatching Triage API (or the service's handling of a request).

    ``mesg`` is returned to Storm in the ``TelepathRetn``. ``error`` is the API's error
    name (ex. ``NOT_FOUND``, ``REPORT_NOT_AVAILABLE``), and ``status`` the HTTP status,
    when the error came from the API.
    """

    def __init__(self, mesg: str, error: str | None = None, status: int | None = None) -> None:
        super().__init__(mesg)
        self.mesg = mesg
        self.error = error
        self.status = status
