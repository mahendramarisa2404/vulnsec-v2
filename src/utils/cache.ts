interface CacheItem<T> {
  data: T;
  timestamp: number;
  expiry: number;
}

class SimpleCache<T> {
  private cache = new Map<string, CacheItem<T>>();
  private defaultTTL: number;

  constructor(defaultTTLMinutes: number = 5) {
    this.defaultTTL = defaultTTLMinutes * 60 * 1000; // Convert to milliseconds
  }

  set(key: string, data: T, ttlMinutes?: number): void {
    const ttl = ttlMinutes ? ttlMinutes * 60 * 1000 : this.defaultTTL;
    const timestamp = Date.now();
    
    this.cache.set(key, {
      data,
      timestamp,
      expiry: timestamp + ttl
    });
  }

  get(key: string): T | null {
    const item = this.cache.get(key);
    
    if (!item) {
      return null;
    }

    if (Date.now() > item.expiry) {
      this.cache.delete(key);
      return null;
    }

    return item.data;
  }

  has(key: string): boolean {
    const item = this.cache.get(key);
    if (!item) return false;
    
    if (Date.now() > item.expiry) {
      this.cache.delete(key);
      return false;
    }
    
    return true;
  }

  delete(key: string): boolean {
    return this.cache.delete(key);
  }

  clear(): void {
    this.cache.clear();
  }

  size(): number {
    return this.cache.size;
  }

  // Clean up expired entries
  cleanup(): void {
    const now = Date.now();
    for (const [key, item] of this.cache.entries()) {
      if (now > item.expiry) {
        this.cache.delete(key);
      }
    }
  }
}

// Create cache instances for different data types  
export const urlScanCache = new SimpleCache<any>(10); // 10 minutes for URL scans
export const fileScanCache = new SimpleCache<any>(30); // 30 minutes for file scans

// Auto cleanup every 5 minutes
setInterval(() => {
  urlScanCache.cleanup();
  fileScanCache.cleanup();
}, 5 * 60 * 1000);