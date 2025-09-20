import { useState, useCallback } from 'react';

interface UseRetryOptions {
  maxAttempts?: number;
  delayMs?: number;
  exponentialBackoff?: boolean;
}

export const useRetry = (options: UseRetryOptions = {}) => {
  const { maxAttempts = 3, delayMs = 1000, exponentialBackoff = true } = options;
  const [isRetrying, setIsRetrying] = useState(false);
  const [attempt, setAttempt] = useState(0);

  const retry = useCallback(async <T>(fn: () => Promise<T>): Promise<T> => {
    setIsRetrying(true);
    let lastError: Error;

    for (let i = 0; i < maxAttempts; i++) {
      setAttempt(i + 1);
      
      try {
        const result = await fn();
        setIsRetrying(false);
        setAttempt(0);
        return result;
      } catch (error) {
        lastError = error as Error;
        
        if (i < maxAttempts - 1) {
          const delay = exponentialBackoff ? delayMs * Math.pow(2, i) : delayMs;
          await new Promise(resolve => setTimeout(resolve, delay));
        }
      }
    }

    setIsRetrying(false);
    setAttempt(0);
    throw lastError!;
  }, [maxAttempts, delayMs, exponentialBackoff]);

  return { retry, isRetrying, attempt };
};