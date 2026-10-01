class EnrollmentError(RuntimeError):
    """Base error safe to present to an operator."""


class AuthenticationError(EnrollmentError):
    pass


class ApiError(EnrollmentError):
    def __init__(self, message: str, *, code: int | None = None):
        super().__init__(message)
        self.code = code


class ConfigurationError(EnrollmentError):
    pass


class BackendError(EnrollmentError):
    pass

