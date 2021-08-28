package externaldata

import (
	"fmt"
	"strings"
	"sync"

	"github.com/open-policy-agent/frameworks/constraint/pkg/apis/externaldata/v1alpha1"
)

type ProviderCache struct {
	cache     map[string]v1alpha1.Provider
	dataCache map[ProviderCacheKey]string
	mux       sync.RWMutex
}

func NewCache() *ProviderCache {
	return &ProviderCache{
		cache: make(map[string]v1alpha1.Provider),
	}
}

func (c *ProviderCache) Get(key string) (v1alpha1.Provider, error) {
	c.mux.RLock()
	defer c.mux.RUnlock()

	if v, ok := c.cache[key]; ok {
		dc := *v.DeepCopy()
		return dc, nil
	}
	return v1alpha1.Provider{}, fmt.Errorf("key is not found in provider cache")
}

func (c *ProviderCache) Upsert(provider *v1alpha1.Provider) error {
	c.mux.Lock()
	defer c.mux.Unlock()

	if !isValidName(provider.Name) {
		return fmt.Errorf("provider name can not be empty. value %s", provider.Name)
	}
	if !isValidURL(provider.Spec.ProxyURL) {
		return fmt.Errorf("invalid provider proxy url. value: %s", provider.Spec.ProxyURL)
	}
	if !isValidTimeout(provider.Spec.Timeout) {
		return fmt.Errorf("provider timeout should be a positive integer. value: %d", provider.Spec.Timeout)
	}
	if !isValidFailurePolicy(string(provider.Spec.FailurePolicy)) {
		return fmt.Errorf("provider failure policy should be either Ignore or Fail. value: %s", provider.Spec.FailurePolicy)
	}

	c.cache[provider.GetName()] = *provider.DeepCopy()
	return nil
}

func (c *ProviderCache) Remove(name string) {
	c.mux.Lock()
	defer c.mux.Unlock()

	delete(c.cache, name)
}

func isValidName(name string) bool {
	return len(name) != 0
}

func isValidURL(url string) bool {
	if len(url) == 0 {
		return false
	}
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		return false
	}
	return true
}

func isValidTimeout(timeout int) bool {
	return timeout >= 0
}

func isValidFailurePolicy(policy string) bool {
	if strings.EqualFold(policy, string(v1alpha1.Ignore)) || strings.EqualFold(policy, string(v1alpha1.Fail)) {
		return true
	}
	return false
}

// ProviderCacheKey is the map key for provider requests.
type ProviderCacheKey struct {
	ProviderName string `json:"providerName,omitempty"`
	OutboundData string `json:"outboundData,omitempty"`
}

func (c *ProviderCache) CheckCache(key ProviderCacheKey) (string, error) {
	c.initializeCache()
	if v, ok := c.dataCache[key]; ok {
		return v, nil
	}
	return "", fmt.Errorf("external data cache key not found")
}

func (c *ProviderCache) initializeCache() {
	if len(c.dataCache) == 0 {
		// Initialize if it isn't there
		c.dataCache = make(map[ProviderCacheKey]string)
	}
}

func (c *ProviderCache) InsertIntoCache(key ProviderCacheKey, value string) {
	c.initializeCache()
	if c.dataCache == nil {
		return
	}
	c.dataCache[key] = value
}
