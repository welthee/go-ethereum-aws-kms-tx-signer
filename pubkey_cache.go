package ethawskmssigner

import (
	"crypto/ecdsa"
	"sync"
)

type pubKeyCache struct {
	pubKeys map[string]*ecdsa.PublicKey
	mutex   sync.RWMutex
}

func newPubKeyCache() *pubKeyCache {
	return &pubKeyCache{
		pubKeys: make(map[string]*ecdsa.PublicKey),
	}
}

func (c *pubKeyCache) Add(keyId string, key *ecdsa.PublicKey) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.pubKeys[keyId] = key
}

func (c *pubKeyCache) Get(keyId string) *ecdsa.PublicKey {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	return c.pubKeys[keyId]
}
