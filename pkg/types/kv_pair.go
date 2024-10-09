package types

type KVPair struct {
	Key      string
	Value    string
	Revision string
}

type KVPairList struct {
	KVPairs  []*KVPair
	Revision string
}

type KeyData interface {
	Key() string
	Serialize() (*KVPair, error)
	UpdateTs()
}
