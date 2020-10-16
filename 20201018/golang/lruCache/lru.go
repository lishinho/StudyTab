package lruCache

import (
	"container/list"
	"time"
)

// Cache is a LRU cache. It is not safe for concurrent access.
// support get with expiration
// need mutex lock support
type Cache struct {
	capacity    int64
	size        int64

	// list & table of *entry objects
	ll          *list.List
	table       map[string]*list.Element

	// set expired time for cache clear on time
	expiredTime time.Duration

	// optional and executed when an entry is purged.
	OnEvicted   func(key string, value Value)
}

type entry struct {
	key          string
	value        Value
	size         int64
	timeAccessed time.Time
}

// Value use Len to count how many bytes it takes
type Value interface {
	Len() int
}

// New is the Constructor of Cache
func New(maxBytes int64, onEvicted func(string, Value)) *Cache {
	return &Cache{
		capacity:  maxBytes,
		ll:        list.New(),
		table:     make(map[string]*list.Element),
		OnEvicted: onEvicted,
	}
}

// NewCacheWithExpiredTime creates a new empty cache with the given capacity and limited expired time.
func NewCacheWithExpiration(capacity int64, expiredTime time.Duration) *Cache {
	return &Cache{
		ll:          list.New(),
		table:       make(map[string]*list.Element),
		capacity:    capacity,
		expiredTime: expiredTime,
	}
}

// Add value to the table
func (c *Cache) Add(key string, value Value) {
	if ele, ok := c.table[key]; ok {
		c.ll.MoveToFront(ele)
		ele.Value.(*entry).timeAccessed = time.Now()
		kv := ele.Value.(*entry)
		c.size += int64(value.Len()) - int64(kv.value.Len())
		kv.value = value
	} else {
		ele := c.ll.PushFront(&entry{key,value,int64(value.Len()),time.Now()})
		c.table[key] = ele
		c.size += int64(len(key)) + int64(value.Len())
	}
	for c.capacity != 0 && c.capacity < c.size {
		c.RemoveOldest()
	}
}

// Get look ups a key's value
func (c *Cache) Get(key string) (value Value, ok bool) {
	if ele, ok := c.table[key]; ok {
		c.ll.MoveToFront(ele)
		kv := ele.Value.(*entry)
		return kv.value, true
	}
	return
}

// GetWithExpired returns a value from the cache
// and clear the key if it is expired
func (c *Cache) GetWithExpired(key string) (v Value, ok bool) {

	element := c.table[key]
	if element == nil {
		return nil, false
	}
	if c.expiredTime > 0 {
		accessTime := element.Value.(*entry).timeAccessed
		if accessTime.Add(c.expiredTime).Before(time.Now()) {
			c.ll.Remove(element)
			delete(c.table, key)
			c.size -= element.Value.(*entry).size
			return nil, false
		}
	}
	c.ll.MoveToFront(element)
	element.Value.(*entry).timeAccessed = time.Now()
	return element.Value.(*entry).value, true
}

// RemoveOldest removes the oldest item
func (c *Cache) RemoveOldest() {
	ele := c.ll.Back()
	if ele != nil {
		c.ll.Remove(ele)
		kv := ele.Value.(*entry)
		delete(c.table, kv.key)
		c.size -= int64(len(kv.key)) + int64(kv.value.Len())
		if c.OnEvicted != nil {
			c.OnEvicted(kv.key, kv.value)
		}
	}
}

// Len the number of table entries
func (c *Cache) Len() int {
	return c.ll.Len()
}