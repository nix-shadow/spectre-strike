# Load Testing Your Website with Spectre-Strike

## Overview
Use the enhanced `adaptive.go` module to stress-test **your own website** to find performance limits and bottlenecks.

## ⚠️ IMPORTANT - Legal Notice
- **ONLY** test websites you own or have explicit written permission to test
- Unauthorized load testing is illegal and unethical
- This tool can cause service disruptions if misused

## Quick Start

### 1. Basic Load Test (Interactive Mode)
```bash
./bin/adaptive --target https://your-website.com \
               --duration 5m \
               --mode find-limit \
               --max-rate 10000 \
               --max-threads 500
```

### 2. Unattended Auto-Test
```bash
./bin/adaptive --target https://your-website.com \
               --duration 10m \
               --mode find-limit \
               --auto-increase \
               --keep-alive \
               --http2
```

## Configuration Options

### Basic Settings
- `--target` - Your website URL (required)
- `--duration` - How long to run (e.g., `5m`, `30s`, `1h`)
- `--mode` - Test pattern: `find-limit`, `sustained`, `spike`, `ramp`, `chaos`

### Performance Settings
- `--max-rate` - Maximum requests per second (default: 10000)
- `--max-threads` - Maximum concurrent workers (default: 500)
- `--connection-pool` - Connection pool size (default: 200)
- `--keep-alive` - Enable HTTP keep-alive (recommended)
- `--http2` - Enable HTTP/2 support
- `--auto-increase` - Auto-increase load without prompts

### Test Modes Explained

#### 1. find-limit (Recommended for initial tests)
Gradually increases load until it finds your server's breaking point:
- Starts slow (50 req/s)
- Ramps up when success rate > 85%
- Asks before each increase (unless `--auto-increase`)
- Identifies the exact breaking point

#### 2. sustained
Maintains steady load at 50% of max capacity:
- Good for endurance testing
- Tests memory leaks and resource exhaustion
- Monitors degradation over time

#### 3. spike
Alternates between normal and extreme load:
- Tests auto-scaling and recovery
- Simulates traffic surges (e.g., viral posts)
- Pattern: 10s normal → 5s spike → repeat

#### 4. ramp
Linear increase from low to max:
- Smooth, predictable growth
- Good for capacity planning
- 20 steps from minimum to maximum

#### 5. chaos
Random, unpredictable patterns:
- Tests resilience and stability
- Random rate & thread counts
- Good for finding edge cases

## Understanding Results

### Key Metrics
```
📊 RPS: 2500      Current requests per second
✅ 2400           Successful requests
❌ 100            Failed requests
⏱️ 45ms          Average response time
Rate: 500        Current configured rate
Threads: 50      Current worker threads
```

### Breaking Point Analysis
When a breaking point is detected, you'll see:
```
💥 BREAKING POINT DETECTED at Rate=2500
   Safe Capacity: ~1750 (70% of breaking point)
```

**Recommended production limits:**
- Set auto-scaling trigger at 60% of breaking point
- Set hard limit at 70% of breaking point
- Keep 30% headroom for traffic spikes

### Error Tracking
The tool tracks specific error types:
- **Timeouts** - Server too slow to respond
- **Connection Errors** - Server refusing connections
- **DNS Errors** - DNS resolution issues
- **TLS Errors** - SSL/TLS handshake problems

## Example Test Scenarios

### Scenario 1: Find Your Website's Limit
```bash
# Start conservative and find the breaking point
./bin/adaptive --target https://your-site.com \
               --duration 10m \
               --mode find-limit \
               --max-rate 5000 \
               --max-threads 200 \
               --keep-alive
```

### Scenario 2: Test Auto-Scaling
```bash
# Spike test to verify your auto-scaling works
./bin/adaptive --target https://your-site.com \
               --duration 15m \
               --mode spike \
               --max-rate 10000 \
               --auto-increase
```

### Scenario 3: Endurance Test
```bash
# Sustained load for 1 hour to find memory leaks
./bin/adaptive --target https://your-site.com \
               --duration 1h \
               --mode sustained \
               --max-rate 3000 \
               --keep-alive \
               --http2
```

### Scenario 4: API Endpoint Test
```bash
# Test specific API endpoints
./bin/adaptive --target https://api.your-site.com \
               --duration 5m \
               --mode ramp \
               --paths "/api/users,/api/posts,/api/search" \
               --max-rate 8000
```

## Performance Tips

### For Maximum Throughput
1. Enable `--keep-alive` (reuses connections)
2. Enable `--http2` (multiplexing)
3. Increase `--connection-pool` to 500+
4. Use `--auto-increase` for unattended tests
5. Run from a machine with good network bandwidth

### For Realistic Simulation
1. Use varied `--paths` (simulates real users)
2. Enable `--keep-alive` (like browsers)
3. Use `chaos` or `spike` mode
4. Add delays between requests (not implemented yet)

## Interpreting Success Rates

- **> 95%** - Server handling load well
- **85-95%** - Server stressed but stable
- **70-85%** - Near capacity, approaching limits
- **< 70%** - Breaking point reached

## Common Issues

### "Connection refused"
- Server hit connection limit
- Firewall blocking requests
- Rate limiting active

### "Timeout" errors
- Server processing too slow
- Database bottleneck
- External API delays

### "TLS handshake" errors
- SSL certificate issues
- Server SSL config problems
- Too many SSL negotiations

## Best Practices

1. **Start Small**: Begin with low rates (100-500 req/s)
2. **Monitor Server**: Watch CPU, memory, disk I/O during tests
3. **Test Off-Peak**: Don't test during production traffic
4. **Have Rollback Plan**: Be ready to stop if issues occur
5. **Document Results**: Save output for capacity planning
6. **Test Components**: Database, cache, CDN separately
7. **Use Staging First**: Test on staging before production

## Safety Features

- Interactive prompts before increasing load (unless `--auto-increase`)
- Gradual ramp-up to avoid sudden shocks
- Detailed error tracking to identify issues early
- Real-time monitoring to catch problems immediately

## Need Help?

- Check server logs during tests
- Use monitoring tools (New Relic, Datadog, etc.)
- Profile your application to find bottlenecks
- Consider CDN/caching before scaling servers

## Remember

**Load testing is for finding limits, not for attacking systems you don't own!**
