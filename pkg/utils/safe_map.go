package utils

import (
	"net"
	"sync"
)

type SafeMap struct {
	mu    sync.RWMutex
	store map[string]string
}

func NewSafeMap() *SafeMap {
	return &SafeMap{
		store: make(map[string]string),
	}
}

func (sm *SafeMap) Set(key, value string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.store[key] = value
}

func (sm *SafeMap) Get(key string) (string, bool) {
	sm.mu.RLock() // Allows multiple readers to access concurrently
	defer sm.mu.RUnlock()
	val, ok := sm.store[key]
	return val, ok
}

func (sm *SafeMap) Delete(key string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	delete(sm.store, key)
}

////////////////////////////////////////////////////////////////////////

type SafeNetMap struct {
	mu    sync.RWMutex
	store map[string]*net.IPNet
}

func NewSafeNetMap() *SafeNetMap {
	return &SafeNetMap{
		store: make(map[string]*net.IPNet),
	}
}

func (sm *SafeNetMap) Set(key string, value *net.IPNet) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.store[key] = value
}

func (sm *SafeNetMap) Get(key string) (*net.IPNet, bool) {
	sm.mu.RLock() // Allows multiple readers to access concurrently
	defer sm.mu.RUnlock()
	val, ok := sm.store[key]
	return val, ok
}

func (sm *SafeNetMap) Range() []*net.IPNet {
	sm.mu.RLock() // Allows multiple readers to access concurrently
	defer sm.mu.RUnlock()
	res := make([]*net.IPNet, 0, len(sm.store))
	for _, net := range sm.store {
		ne := *net
		res = append(res, &ne)
	}
	return res
}

func (sm *SafeNetMap) Delete(key string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	delete(sm.store, key)
}
