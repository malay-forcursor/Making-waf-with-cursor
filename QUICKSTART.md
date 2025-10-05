# ⚡ Quick Start Guide - AI-NGFW

Get your AI-Driven Next-Generation Firewall up and running in 5 minutes!

## 🚀 Fastest Way to Start

### Option 1: One-Command Start (Recommended)

```bash
./run.sh
```

That's it! The script will:
- Create virtual environment
- Install all dependencies
- Start the WAF
- Open the dashboard

### Option 2: Manual Setup

```bash
# 1. Create virtual environment
python3 -m venv venv
source venv/bin/activate

# 2. Install dependencies
pip install -r requirements.txt

# 3. Create logs directory
mkdir -p logs models data

# 4. Set up environment
cp .env.example .env

# 5. Start the WAF
python main.py
```

### Option 3: Docker (If you have Docker installed)

```bash
docker-compose up -d
```

## 🎯 What You Get

Once started, you'll have access to:

1. **WAF API** → http://localhost:8000
   - Core firewall functionality
   - Protection against attacks

2. **API Documentation** → http://localhost:8000/api/docs
   - Interactive API documentation
   - Try out endpoints

3. **Real-time Dashboard** → http://localhost:8050
   - Beautiful visualization
   - Live threat monitoring
   - Attack statistics

4. **Metrics** → http://localhost:8000/metrics
   - Prometheus-compatible metrics
   - Performance statistics

## 🧪 Test It Out

### 1. Run Attack Simulation

In a new terminal:

```bash
python demo_attack.py
```

This will simulate various attacks and show you how the WAF blocks them:
- SQL Injection ✅
- XSS ✅
- Command Injection ✅
- Path Traversal ✅

### 2. Try the API

```bash
python demo_api.py
```

This demonstrates:
- Authentication
- Threat checking
- Statistics
- Incident management

### 3. Manual Testing

**Check if WAF is running:**
```bash
curl http://localhost:8000/health
```

**Simulate SQL Injection (will be blocked):**
```bash
curl "http://localhost:8000/search?q=1' OR '1'='1"
```

**Normal request (will be allowed):**
```bash
curl "http://localhost:8000/search?q=hello"
```

**Get statistics:**
```bash
curl http://localhost:8000/api/stats
```

## 📊 Open the Dashboard

1. Open browser: http://localhost:8050
2. Watch real-time threat detection
3. View attack visualizations
4. Monitor performance metrics

## 🔐 Default Credentials

For API authentication:

```
Username: admin
Password: admin123
```

Or:

```
Username: user
Password: user123
```

## 🛠️ Troubleshooting

### Port Already in Use

If port 8000 is already in use:

1. Edit `.env` file:
```bash
API_PORT=8001
```

2. Restart the WAF

### Dependencies Error

If you see import errors:

```bash
pip install --upgrade -r requirements.txt
```

### MongoDB/Redis Not Available

The WAF works without MongoDB/Redis, but with reduced features:
- No persistent storage
- No caching
- In-memory operation only

To install MongoDB/Redis:

**macOS:**
```bash
brew install mongodb-community redis
brew services start mongodb-community
brew services start redis
```

**Ubuntu/Debian:**
```bash
sudo apt-get install mongodb redis-server
sudo systemctl start mongodb
sudo systemctl start redis
```

**Windows:**
- Download MongoDB: https://www.mongodb.com/try/download/community
- Download Redis: https://github.com/microsoftarchive/redis/releases

Or just use Docker:
```bash
docker-compose up -d mongodb redis
```

## 🎓 Next Steps

1. **Explore the API**
   - Visit http://localhost:8000/api/docs
   - Try different endpoints
   - Check authentication

2. **Run Tests**
   ```bash
   pytest tests/ -v
   ```

3. **Customize Configuration**
   - Edit `config.yaml` for rules
   - Modify `.env` for settings
   - Add custom patterns

4. **Read Documentation**
   - `README.md` - Full documentation
   - `ARCHITECTURE.md` - Technical details
   - `DEMO_GUIDE.md` - Presentation guide

## 🎬 Demo for Hackathon

### 5-Minute Demo Flow

1. **Start the WAF** (30 seconds)
   ```bash
   ./run.sh
   ```

2. **Show Dashboard** (1 minute)
   - Open http://localhost:8050
   - Explain the metrics

3. **Run Attack Demo** (2 minutes)
   ```bash
   python demo_attack.py
   ```
   - Show SQL injection blocked
   - Show XSS blocked
   - Show normal traffic allowed

4. **Show API** (1 minute)
   - Open http://localhost:8000/api/docs
   - Demonstrate threat checking

5. **Highlight Features** (30 seconds)
   - Multi-layer ML detection
   - Zero Trust architecture
   - Automated response
   - Real-time monitoring

## 💡 Tips

### For Development

- Enable debug mode in `.env`:
  ```bash
  DEBUG=true
  LOG_LEVEL=DEBUG
  ```

### For Production

- Change secret keys in `.env`
- Enable MongoDB and Redis
- Set up proper SSL/TLS
- Configure firewall rules
- Set up monitoring alerts

### For Hackathon Demo

- Pre-start the WAF before presenting
- Have browser tabs ready
- Run `demo_attack.py` in advance to populate dashboard
- Keep terminals organized
- Prepare talking points from `DEMO_GUIDE.md`

## 🆘 Getting Help

### Check Logs

```bash
tail -f logs/ai_ngfw.log
```

### Health Check

```bash
curl http://localhost:8000/health
```

### System Status

```bash
curl http://localhost:8000/api/health/detailed
```

## 🎉 You're Ready!

Your AI-NGFW is now protecting your system with:
- ✅ AI/ML-based threat detection
- ✅ Zero Trust architecture
- ✅ Automated incident response
- ✅ Real-time monitoring

**Happy hacking! 🛡️**

---

**Need more help?** Check out:
- 📖 README.md - Full documentation
- 🏗️ ARCHITECTURE.md - System design
- 🎯 DEMO_GUIDE.md - Presentation guide
- 🏆 HACKATHON_SUBMISSION.md - Submission details
