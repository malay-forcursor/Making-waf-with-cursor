#!/bin/bash

# AI-NGFW Startup Script

echo "=========================================="
echo "AI-Driven Next-Generation Firewall"
echo "=========================================="
echo ""

# Check Python version
python_version=$(python3 --version 2>&1 | awk '{print $2}')
echo "✓ Python version: $python_version"

# Create necessary directories
echo "✓ Creating directories..."
mkdir -p logs models data

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
fi

# Activate virtual environment
echo "✓ Activating virtual environment..."
source venv/bin/activate

# Install/upgrade dependencies
echo "✓ Installing dependencies..."
pip install -q --upgrade pip
pip install -q -r requirements.txt

# Check if .env exists
if [ ! -f ".env" ]; then
    echo "✓ Creating .env from template..."
    cp .env.example .env
fi

echo ""
echo "=========================================="
echo "Starting AI-NGFW..."
echo "=========================================="
echo ""
echo "API: http://localhost:8000"
echo "Docs: http://localhost:8000/api/docs"
echo "Dashboard: http://localhost:8050"
echo "Metrics: http://localhost:8000/metrics"
echo ""
echo "Press Ctrl+C to stop"
echo ""

# Start the application
python main.py
