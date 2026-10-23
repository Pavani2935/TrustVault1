class TrustVaultError(Exception):
    status = 400
    public_message = "The request could not be completed."

    def __init__(self, message: str | None = None):
        super().__init__(message or self.public_message)
        self.message = message or self.public_message


class NotFound(TrustVaultError):
    """Used for BOTH 'does not exist' and 'exists but you may not touch it', so that an
    unauthorised caller cannot learn whether a document id is real."""
    status = 404
    public_message = "Not found."


class Forbidden(TrustVaultError):
    """Role-level refusals (e.g. a viewer calling an admin endpoint). Never used for
    document access, which always answers NotFound."""
    status = 403
    public_message = "You do not have permission to do that."


class Unauthenticated(TrustVaultError):
    status = 401
    public_message = "Sign in required."


class Invalid(TrustVaultError):
    status = 400


class Conflict(TrustVaultError):
    status = 409


class TooMany(TrustVaultError):
    status = 429
    public_message = "Too many requests. Slow down and try again later."
