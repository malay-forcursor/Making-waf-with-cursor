#!/bin/bash

echo ""
echo "🔍 AI-NGFW Installation Verification"
echo "========================================="
echo ""

# Color codes
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Check counter
PASS=0
FAIL=0

check() {
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✅${NC} $1"
        ((PASS++))
    else
        echo -e "${RED}❌${NC} $1"
        ((FAIL++))
    fi
}

# 1. Python version
python3 -c "import sys; exit(0 if sys.version_info >= (3, 11) else 1)" 2>/dev/null
check "Python 3.11+"

# 2. Virtual environment exists
test -d venv
check "Virtual environment (venv/)"

# 3. Config files
test -f config.yaml && test -f .env
check "Configuration files"

# 4. Directories
test -d logs && test -d models && test -d data
check "Working directories"

# 5. Source code
test -f src/core/engine.py && test -f src/core/models.py
check "Source code"

# 6. Documentation
test -f README.md && test -f QUICKSTART.md && test -f START_HERE.md
check "Documentation"

# 7. Demo scripts
test -f demo_attack.py && test -f demo_api.py
check "Demo scripts"

# 8. Tests
test -f tests/test_waf.py
check "Test suite"

# 9. Docker files
test -f Dockerfile && test -f docker-compose.yml
check "Docker files"

# 10. Run script
test -x run.sh
check "Run script (executable)"

echo ""
echo "========================================="
echo "Results: ${GREEN}${PASS} passed${NC}, ${RED}${FAIL} failed${NC}"
echo "========================================="

if [ $FAIL -eq 0 ]; then
    echo ""
    echo -e "${GREEN}✅ All checks passed! You're ready to go!${NC}"
    echo ""
    echo "Next steps:"
    echo "  1. Run: ./run.sh"
    echo "  2. Open: http://localhost:8050"
    echo "  3. Demo: python demo_attack.py"
    echo ""
else
    echo ""
    echo -e "${RED}❌ Some checks failed. Please review:${NC}"
    echo "  - Missing dependencies? Run: pip install -r requirements.txt"
    echo "  - Missing .env? Run: cp .env.example .env"
    echo "  - Need directories? Run: mkdir -p logs models data"
    echo ""
fi
