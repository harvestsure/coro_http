#pragma once

#include <chrono>
#include <deque>
#include <mutex>
#include <condition_variable>

namespace coro_http {

// Token bucket rate limiter
class RateLimiter {
public:
    RateLimiter(int max_requests, std::chrono::milliseconds window)
        : max_requests_(max_requests),
          window_(window),
          enabled_(max_requests > 0) {
    }
    
    // Synchronous wait until rate limit allows request
    void acquire() {
        if (!enabled_) return;
        
        std::unique_lock<std::mutex> lock(mutex_);
        
        auto now = std::chrono::steady_clock::now();
        
        // Remove expired timestamps
        while (!timestamps_.empty() && 
               now - timestamps_.front() > window_) {
            timestamps_.pop_front();
        }
        
        // Wait if rate limit exceeded
        while (timestamps_.size() >= static_cast<size_t>(max_requests_)) {
            auto oldest = timestamps_.front();
            auto wait_until = oldest + window_;
            
            cv_.wait_until(lock, wait_until);
            
            now = std::chrono::steady_clock::now();
            while (!timestamps_.empty() && 
                   now - timestamps_.front() > window_) {
                timestamps_.pop_front();
            }
        }
        
        // Add current request
        timestamps_.push_back(now);
    }
    
    // Try to acquire without blocking
    bool try_acquire() {
        if (!enabled_) return true;
        
        std::lock_guard<std::mutex> lock(mutex_);
        
        auto now = std::chrono::steady_clock::now();
        
        // Remove expired timestamps
        while (!timestamps_.empty() && 
               now - timestamps_.front() > window_) {
            timestamps_.pop_front();
        }
        
        // Check if we can add request
        if (timestamps_.size() >= static_cast<size_t>(max_requests_)) {
            return false;
        }
        
        timestamps_.push_back(now);
        return true;
    }
    
    // Get remaining capacity
    int remaining() const {
        if (!enabled_) return max_requests_;
        
        std::lock_guard<std::mutex> lock(mutex_);
        
        auto now = std::chrono::steady_clock::now();
        
        // Count valid timestamps
        int valid_count = 0;
        for (const auto& ts : timestamps_) {
            if (now - ts <= window_) {
                valid_count++;
            }
        }
        
        return max_requests_ - valid_count;
    }
    
    // Reset the rate limiter
    void reset() {
        std::lock_guard<std::mutex> lock(mutex_);
        timestamps_.clear();
        cv_.notify_all();
    }

private:
    int max_requests_;
    std::chrono::milliseconds window_;
    bool enabled_;
    std::deque<std::chrono::steady_clock::time_point> timestamps_;
    mutable std::mutex mutex_;
    std::condition_variable cv_;
};

}
