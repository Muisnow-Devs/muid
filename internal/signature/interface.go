package signature

type SignatureService interface {
	Sign(data []byte) ([]byte, error)
	Verify(data, signature []byte) (bool, error)
	Close()
}
