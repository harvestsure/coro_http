# CI/CD and Testing Guide

## 1. GitHub Actions CI Workflow

### Workflow Features

#### 1. **Multi-Compiler Support**
- **Linux**: GCC 12, Clang 18
- **macOS**: Apple Clang (default)
- **Windows**: MSVC (default)

#### 2. **Sanitizer Builds (ASAN + UBSAN)**
- Dedicated `sanitizer-build` job
- Automatic detection of:
  - Memory leaks
  - Use-after-free
  - Undefined behavior
  - Buffer overflow

#### 3. **Automated Testing**
- Runs all test cases after compilation
- Timeout control (30 seconds per test)
- Parallel compilation (4 cores)

#### 4. **Example Verification**
- 5-second timeout for each example
- Tests: coro, https, keepalive, proxy, retry, sse

### Workflow Configuration

**Trigger conditions**:
```yaml
on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main, develop ]
```

**Build matrix**:
```
- OS: ubuntu-latest, macos-latest, windows-latest
- Compiler: gcc 12, clang 18, apple-clang, msvc
```

## 2. Local Build and Testing

### 1. Enable Test Compilation

```bash
cd build
cmake .. -DBUILD_TESTS=ON -DENABLE_SANITIZER=ON
cmake --build . --parallel 4
```

### 2. Run All Tests

```bash
ctest --output-on-failure --timeout 30
```

### 3. Run Specific Tests

```bash
# Run only timeout tests
ctest -R timeout --output-on-failure

# Run only connection pool tests
ctest -R connection_pool --output-on-failure

# Verbose output
ctest --verbose
```

### 4. Testing with Sanitizer

```bash
# ASAN - detect memory issues
export ASAN_OPTIONS=detect_leaks=1:abort_on_error=1

# UBSAN - detect undefined behavior
export UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1

ctest --output-on-failure
```

### 5. Disable Sanitizer (if needed)

```bash
cmake .. -DENABLE_SANITIZER=OFF
```

## 3. Core Test Cases

### 1. **Timeout and Cancellation (test_timeout.cpp)**

```
Scenario                   Purpose
├─ Basic timeout          Check timeout properly cancels coroutine
├─ Timeout + Retry        Verify retry mechanism with timeout
├─ Concurrent timeout     Independent timeout handling for multiple requests
└─ Promise release        Verify promise is released on cancellation
```

**Key Points**:
- Promise must be released when cancelled
- Use ASAN to detect use-after-free
- No memory leaks

### 2. **HTTP Redirect Handling (test_redirect.cpp)**

```
Scenario                    Purpose
├─ Single redirect          301/302 redirect
├─ Redirect chain           Multiple consecutive redirects (3+ hops)
├─ Redirect + auth          Maintain auth state across redirects
├─ Concurrent redirects     Different redirect chains in parallel
└─ Loop detection           Detect redirect loops
```

**Key Points (Coroutine-specific)**:
- Multiple co_await calls must preserve coroutine state
- Promise must survive across multiple suspend/resume points
- Local variables remain valid across all co_await crossings

### 3. **Connection Pool Reuse (test_connection_pool.cpp)**

```
Scenario                      Purpose
├─ Connection reuse         Reuse ≤5 connections for 10 requests
├─ Concurrent pool access   20 concurrent requests with queue scheduling
├─ Stale connection         Detect and remove dead connections
├─ Pool exhaustion          Wait when resources exhausted
├─ Different hosts          Separate pools for different hosts
├─ No stagnation            Resources eventually released (verify with ASAN/Valgrind)
└─ Exception releases       Release connection even on exception
```

**Key Points**:
- Each coroutine must release connection after completion
- Cleanup required even on exception
- Prevent connection leaks causing resource exhaustion

### 4. **Error Handling (test_error_handling.cpp)**

```
Scenario                      Purpose
├─ Network error           Handle unreachable host
├─ Timeout exception       Exception when timer expires
├─ TLS error              SSL/TLS handshake failure
├─ Invalid URL            Parameter validation failure
├─ Partial response       Handle connection interruption
├─ Concurrent errors      Errors don't affect other requests
├─ Error recovery         Retry strategy
├─ Exception in handler   Cleanup when user code throws
└─ Memory limit           Memory protection for large responses
```

**Key Points**:
- All error paths must clean up resources properly
- No RAII violations
- Exception safety guarantees

## 4. Sanitizer Report Interpretation

### ASAN Report Example

```
=================================================================
==1234==ERROR: LeakSanitizer: detected memory leaks

...

SUMMARY: AddressSanitizer: 1024 byte(s) leaked in 1 allocation(s).
```

**Solution**:
- Check promise destructor
- Verify all allocations have corresponding deallocations
- Pay special attention to exception paths

### UBSAN Report Example

```
runtime error: index 5 out of bounds for type 'int [5]'
```

**Solution**:
- Check array/container access boundaries
- Verify pointer arithmetic
- Check integer overflow

## 5. Performance Checks

### Run Tests with Timing

```bash
time ctest --output-on-failure
```

### Memory Usage Check (macOS)

```bash
/usr/bin/time -v ./build/test_connection_pool
```

### Detect File Descriptor Leaks (macOS)

```bash
lsof -p $$  # Get process id
# Run tests
lsof -p $$  # Compare before and after
```

## 6. CI Failure Debugging

### Replicate Linux Environment Locally

```bash
# Using Docker
docker run -it --rm -v $(pwd):/work ubuntu:24.04 bash
apt-get update && apt-get install -y \
  build-essential cmake libssl-dev zlib1g-dev gcc-12 g++-12 clang-18
cd /work && mkdir build_docker && cd build_docker
cmake .. -DENABLE_SANITIZER=ON -DBUILD_TESTS=ON
cmake --build .
ctest --output-on-failure
```

### Detailed Logging

```bash
# CMake configuration log
cmake .. -DENABLE_SANITIZER=ON --debug-output 2>&1 | tee cmake.log

# Build detailed log
cmake --build . --verbose 2>&1 | tee build.log

# Test detailed log
ctest --verbose 2>&1 | tee test.log
```

## 7. Adding New Tests

### Steps

1. **Create test file**: `tests/test_feature.cpp`

2. **Register in CMakeLists.txt**:
```cmake
add_executable(test_feature tests/test_feature.cpp)
target_link_libraries(test_feature PRIVATE coro_http)
add_test(NAME feature COMMAND test_feature TIMEOUT 30)
```

3. **Build and run**:
```bash
cmake --build .
ctest -R feature --output-on-failure
```

### Best Practices

- ✅ Each test completes in ≤ 30 seconds
- ✅ Independent test cases, runnable individually
- ✅ Clear success/failure conditions
- ✅ Detailed comments explaining test purpose
- ✅ Minimize external dependencies (e.g., network calls)

## 8. Troubleshooting

### Common Issues

| Issue | Cause | Solution |
|-------|-------|----------|
| ASAN timeout | Sanitizer overhead | Increase timeout or disable ASAN |
| Windows build fails | MSVC doesn't support `-fsanitize` | Windows auto-skips ASAN |
| Network timeout | Tests depend on network | Use local mock server |
| Permission denied | Script permissions | `chmod +x scripts/*.sh` |

## 9. Integration Recommendations

### Branch Protection Rules

In GitHub repository settings:
```
Require status checks to pass before merging:
  ✓ CI / build-and-test (ubuntu-latest)
  ✓ CI / sanitizer-build
  ✓ code-quality
```

### Badge (add to README)

```markdown
![CI](https://github.com/.../workflows/CI/badge.svg)
```

---

**Important**: Sanitizers are critical for coroutine libraries, as promise lifecycle errors cause hard-to-debug bugs. Always enable in CI.
