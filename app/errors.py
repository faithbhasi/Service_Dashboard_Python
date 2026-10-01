class ApiException(Exception):
    """A request that must fail with a specific HTTP status and a safe message (safeguards, validation, conflicts)."""

    def __init__(self, status: int, title: str, detail: str, code: str = "error"):
        super().__init__(detail)
        self.status = status
        self.title = title
        self.detail = detail
        self.code = code


class ModuleUnavailableError(Exception):
    """A module's backend system (for example a domain controller) cannot be reached. safe_message is shown to the user."""

    def __init__(self, safe_message: str, inner: Exception | None = None):
        super().__init__(safe_message)
        self.safe_message = safe_message
        self.inner = inner
