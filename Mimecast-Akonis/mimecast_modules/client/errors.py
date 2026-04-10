class MimecastError(Exception):
    """Base exception for all Mimecast client errors."""


class MimecastAuthError(MimecastError):
    """Raised when authentication fails (invalid credentials or token cannot be obtained)."""


class MimecastRateLimitError(MimecastError):
    """Raised when the API returns HTTP 429 Too Many Requests."""

    def __init__(self, retry_after: int = 60) -> None:
        self.retry_after = retry_after
        super().__init__(f"Rate limit exceeded. Retry after {retry_after} seconds.")


class MimecastAPIError(MimecastError):
    """Raised for non-2xx HTTP responses that are not auth or rate-limit errors."""

    def __init__(self, status_code: int, message: str = "") -> None:
        self.status_code = status_code
        super().__init__(f"Mimecast API error {status_code}: {message}")
