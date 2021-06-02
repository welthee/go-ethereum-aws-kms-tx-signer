package ethawskmssigner

import (
	"crypto"
	"sync"
)

type pubKeyCache struct {
	pubKeys map[string]crypto.PublicKey
	mutex   sync.RWMutex
}

func newPubKeyCache() *pubKeyCache {
	return &pubKeyCache{
		pubKeys: make(map[string]crypto.PublicKey),
	}
}

func (c *pubKeyCache) Add(keyId string, key crypto.PublicKey) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.pubKeys[keyId] = key
}

func (c *pubKeyCache) Get(keyId string) crypto.PublicKey {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	return c.pubKeys[keyId]
}
