package security

type AccessDeniedError struct {
	message string
	reasons []string
}

func NewAccessDeniedError(reasons []string) *AccessDeniedError {
	return &AccessDeniedError{
		message: "access denied",
		reasons: reasons,
	}
}

func (e *AccessDeniedError) Error() string {
	return e.message
}

func (e *AccessDeniedError) Reasons() []string {
	return e.reasons
}
