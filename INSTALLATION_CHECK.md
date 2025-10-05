# ✅ Installation Verification Checklist

Run this checklist to verify your AI-NGFW installation is complete and ready.

## 📋 Pre-Installation Check

### Required Software

```bash
# Check Python version (need 3.11+)
python3 --version

# Check pip
pip3 --version

# Optional: Check Docker
docker --version
docker-compose --version
```

## 📦 Installation Steps

### 1. Create Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

**Verify:**
```bash
which python  # Should show path inside venv/
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

**Verify:**
```bash
pip list | grep fastapi
pip list | grep tensorflow
pip list | grep scikit-learn
```

### 3. Create Directories

```bash
mkdir -p logs models data
```

**Verify:**
```bash
ls -ld logs models data
```

### 4. Setup Environment

```bash
cp .env.example .env
```

**Verify:**
```bash
cat .env | grep SECRET_KEY
```

## 🧪 Functionality Check

### Test 1: Import Check

```bash
python3 -c "
from src.core.engine import WAFEngine
from src.detection.rule_engine import RuleEngine
from src.ml.anomaly_detector import AnomalyDetector
print('✅ All imports successful')
"
```

**Expected Output:** `✅ All imports successful`

### Test 2: Configuration Check

```bash
python3 -c "
from src.core.config import Settings, load_config
settings = Settings()
config = load_config()
print(f'✅ Config loaded: {len(config)} sections')
"
```

**Expected Output:** `✅ Config loaded: X sections`

### Test 3: Model Creation

```bash
python3 -c "
from src.ml.anomaly_detector import AnomalyDetector
from src.core.config import Settings
detector = AnomalyDetector(Settings())
print('✅ ML models initialized')
"
```

**Expected Output:** `✅ ML models initialized`

## 🚀 Startup Check

### Test 4: Start Server (Quick Test)

```bash
# Start server in background
python main.py &
SERVER_PID=$!

# Wait for startup
sleep 5

# Test health endpoint
curl http://localhost:8000/health

# Stop server
kill $SERVER_PID
```

**Expected Output:** `{"status": "healthy", ...}`

### Test 5: API Endpoints

```bash
# With server running
curl http://localhost:8000/
curl http://localhost:8000/health
curl http://localhost:8000/metrics
curl http://localhost:8000/api/stats
```

**All should return JSON responses**

### Test 6: Attack Detection

```bash
# This should be BLOCKED (403)
curl -i "http://localhost:8000/test?id=1' OR '1'='1"

# This should be ALLOWED (200 or 404)
curl -i "http://localhost:8000/test?id=123"
```

**Expected:** First request blocked, second allowed

## 🧪 Test Suite Check

### Test 7: Run Unit Tests

```bash
pytest tests/ -v
```

**Expected:** All tests pass

### Test 8: Run Demo Scripts

```bash
# Should show attacks being blocked
python demo_attack.py

# Should show API usage
python demo_api.py
```

**Expected:** Colorful output showing blocked attacks

## 📊 Dashboard Check

### Test 9: Dashboard Access

```bash
# With server running, open browser to:
# http://localhost:8050
```

**Expected:** Beautiful dashboard loads

### Test 10: Prometheus Metrics

```bash
curl http://localhost:8000/metrics | grep ai_ngfw
```

**Expected:** Prometheus-format metrics

## 🐳 Docker Check (Optional)

### Test 11: Docker Build

```bash
docker-compose build
```

**Expected:** Build succeeds

### Test 12: Docker Run

```bash
docker-compose up -d
docker-compose ps
```

**Expected:** All services running

### Test 13: Docker Stop

```bash
docker-compose down
```

## 📁 File Structure Check

### Test 14: Verify Files

```bash
# Should list all key files
ls -1 \
  main.py \
  requirements.txt \
  config.yaml \
  .env \
  Dockerfile \
  docker-compose.yml \
  run.sh
```

**Expected:** All files exist

### Test 15: Verify Source Code

```bash
# Count Python files (should be 20+)
find src/ -name "*.py" | wc -l

# Count tests (should be 2+)
find tests/ -name "test_*.py" | wc -l
```

**Expected:** 20+ source files, 2+ test files

### Test 16: Verify Documentation

```bash
ls -1 *.md
```

**Expected Output:**
```
ARCHITECTURE.md
DEMO_GUIDE.md
FEATURES.md
HACKATHON_SUBMISSION.md
INSTALLATION_CHECK.md
PROJECT_SUMMARY.md
QUICKSTART.md
README.md
START_HERE.md
```

## 🔒 Security Check

### Test 17: No Hardcoded Secrets

```bash
# Should not find any hardcoded passwords
grep -r "password.*=.*\"" src/ --include="*.py" | grep -v "password_hash"
```

**Expected:** No matches (or only safe examples)

### Test 18: Environment Variables

```bash
# Check .env has required variables
grep -E "^[A-Z_]+=.+" .env | head -5
```

**Expected:** Shows environment variables

## 📊 Performance Check

### Test 19: Latency Test

```bash
# Time a simple request (should be <100ms)
time curl -s http://localhost:8000/health > /dev/null
```

**Expected:** real < 0.100s

### Test 20: Load Test (Optional)

```bash
# Install Apache Bench if available
# ab -n 1000 -c 10 http://localhost:8000/
```

**Expected:** >100 requests/sec

## ✅ Final Verification

### Comprehensive Check

Run all at once:

```bash
#!/bin/bash

echo "🔍 AI-NGFW Installation Verification"
echo "===================================="

# 1. Python version
echo -n "Python 3.11+: "
python3 -c "import sys; exit(0 if sys.version_info >= (3, 11) else 1)" && echo "✅" || echo "❌"

# 2. Virtual environment
echo -n "Virtual env: "
test -d venv && echo "✅" || echo "❌"

# 3. Dependencies
echo -n "Dependencies: "
pip show fastapi &>/dev/null && echo "✅" || echo "❌"

# 4. Directories
echo -n "Directories: "
test -d logs && test -d models && test -d data && echo "✅" || echo "❌"

# 5. Config files
echo -n "Config files: "
test -f config.yaml && test -f .env && echo "✅" || echo "❌"

# 6. Source code
echo -n "Source code: "
test -f src/core/engine.py && echo "✅" || echo "❌"

# 7. Documentation
echo -n "Documentation: "
test -f README.md && test -f QUICKSTART.md && echo "✅" || echo "❌"

# 8. Executables
echo -n "Run scripts: "
test -x run.sh && echo "✅" || echo "❌"

# 9. Tests
echo -n "Test suite: "
test -f tests/test_waf.py && echo "✅" || echo "❌"

# 10. Demo scripts
echo -n "Demo scripts: "
test -x demo_attack.py && test -x demo_api.py && echo "✅" || echo "❌"

echo ""
echo "===================================="
echo "If all checks show ✅, you're ready!"
echo "Run: ./run.sh"
```

**Save as:** `verify_installation.sh` and run:
```bash
chmod +x verify_installation.sh
./verify_installation.sh
```

## 🎯 Quick Start After Verification

Once all checks pass:

```bash
# 1. Start the WAF
./run.sh

# 2. In new terminal, run demo
python demo_attack.py

# 3. Open browser
open http://localhost:8050      # Dashboard
open http://localhost:8000/api/docs  # API Docs
```

## 🐛 Common Issues

### Issue: ModuleNotFoundError

**Solution:**
```bash
# Reinstall dependencies
pip install --upgrade -r requirements.txt

# Or use absolute imports
export PYTHONPATH="${PYTHONPATH}:$(pwd)"
```

### Issue: Port Already in Use

**Solution:**
```bash
# Change port in .env
echo "API_PORT=8001" >> .env
```

### Issue: Permission Denied

**Solution:**
```bash
chmod +x run.sh demo_attack.py demo_api.py
```

### Issue: MongoDB/Redis Connection Error

**Solution:**
```bash
# Don't worry! WAF works without them
# Or start with Docker:
docker-compose up -d mongodb redis
```

## 📞 Getting Help

If any check fails:

1. Check error messages
2. Review logs: `tail -f logs/ai_ngfw.log`
3. Check dependencies: `pip list`
4. Verify Python version: `python3 --version`
5. Read QUICKSTART.md for detailed setup

## ✅ Success Criteria

Your installation is successful when:

- ✅ All imports work
- ✅ Server starts without errors
- ✅ Health endpoint returns 200
- ✅ Demo scripts run successfully
- ✅ Dashboard loads
- ✅ Tests pass
- ✅ Attacks are detected and blocked

## 🎉 You're Ready!

If all checks pass, you have a fully functional AI-NGFW!

Next steps:
1. Read [QUICKSTART.md](QUICKSTART.md) for usage
2. Run [demo_attack.py](demo_attack.py) to see it in action
3. Explore [README.md](README.md) for features
4. Check [DEMO_GUIDE.md](DEMO_GUIDE.md) for presentation

**Happy hacking! 🛡️**
