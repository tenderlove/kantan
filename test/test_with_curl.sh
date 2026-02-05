#!/bin/bash
# Integration test with real curl

set -e

echo "======================================================================"
echo "HTTP/2 Integration Test with curl"
echo "======================================================================"

# Start server in background
echo ""
echo "Starting HTTP/2 server..."
ruby server_example.rb > /tmp/http2_server.log 2>&1 &
SERVER_PID=$!
echo "Server PID: $SERVER_PID"

# Wait for server to start
sleep 2

# Test function
test_endpoint() {
    local endpoint=$1
    local expected_pattern=$2
    local description=$3

    echo ""
    echo "Test: $description"
    echo "  Endpoint: $endpoint"

    response=$(curl -s --http2-prior-knowledge "http://localhost:8080$endpoint" 2>&1)
    exit_code=$?

    if [ $exit_code -eq 0 ]; then
        if echo "$response" | grep -q "$expected_pattern"; then
            echo "  ✓ PASS: Response contains expected content"
            echo "  Response: ${response:0:60}..."
            return 0
        else
            echo "  ✗ FAIL: Response doesn't match expected pattern"
            echo "  Expected: $expected_pattern"
            echo "  Got: $response"
            return 1
        fi
    else
        echo "  ✗ FAIL: curl returned error code $exit_code"
        echo "  Output: $response"
        return 1
    fi
}

# Run tests
echo ""
echo "======================================================================"
echo "Running Tests..."
echo "======================================================================"

# Track results
PASSED=0
FAILED=0

# Test 1: GET /
if test_endpoint "/" "Hello, HTTP/2" "GET /"; then
    ((PASSED++))
else
    ((FAILED++))
fi

# Test 2: GET /json
if test_endpoint "/json" "message" "GET /json"; then
    ((PASSED++))
else
    ((FAILED++))
fi

# Test 3: POST /echo
echo ""
echo "Test: POST /echo"
echo "  Endpoint: /echo"
response=$(curl -s --http2-prior-knowledge -d "test data" "http://localhost:8080/echo" 2>&1)
exit_code=$?

if [ $exit_code -eq 0 ]; then
    if echo "$response" | grep -q "test data"; then
        echo "  ✓ PASS: Echo response correct"
        echo "  Response: $response"
        ((PASSED++))
    else
        echo "  ✗ FAIL: Echo response incorrect"
        echo "  Got: $response"
        ((FAILED++))
    fi
else
    echo "  ✗ FAIL: curl returned error code $exit_code"
    ((FAILED++))
fi

# Test 4: HTTP/2 headers verification
echo ""
echo "Test: Verify HTTP/2 protocol"
http_version=$(curl -s -w "%{http_version}" --http2-prior-knowledge "http://localhost:8080/" -o /dev/null 2>&1)
if [ "$http_version" == "2" ]; then
    echo "  ✓ PASS: HTTP/2 protocol confirmed"
    ((PASSED++))
else
    echo "  ✗ FAIL: Expected HTTP/2, got: $http_version"
    ((FAILED++))
fi

# Cleanup
echo ""
echo "======================================================================"
echo "Cleaning up..."
echo "======================================================================"
kill $SERVER_PID 2>/dev/null || true
sleep 1

# Results
echo ""
echo "======================================================================"
echo "RESULTS"
echo "======================================================================"
echo "Passed: $PASSED"
echo "Failed: $FAILED"
echo "Total:  $((PASSED + FAILED))"

if [ $FAILED -eq 0 ]; then
    echo ""
    echo "✓ ALL TESTS PASSED"
    echo ""
    exit 0
else
    echo ""
    echo "✗ SOME TESTS FAILED"
    echo ""
    exit 1
fi
