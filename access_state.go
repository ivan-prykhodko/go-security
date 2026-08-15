package security

const (
	AccessGranted AccessState = iota
	AccessAbstain
	AccessDenied
)

type AccessState int8

func (a AccessState) Equal(b AccessState) bool {
	return a == b
}
