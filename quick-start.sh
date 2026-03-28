#!/bin/bash
# Quick Start Script for NIDS Local Testing

echo "🚀 NIDS Quick Start Script"
echo "=========================="
echo ""

# Check if virtual environment is activated
if [[ "$VIRTUAL_ENV" == "" ]]; then
    echo "📦 Activating virtual environment..."
    source .venv/bin/activate
fi

# Check if dependencies are installed
if ! python -c "import fastapi" 2>/dev/null; then
    echo "📥 Installing Python dependencies..."
    pip install -r config/requirements.txt
fi

# Ensure logs directory exists
mkdir -p logs

echo ""
echo "✅ Environment ready!"
echo ""
echo "🎯 Choose an option:"
echo ""
echo "1. Start Backend API (http://localhost:8000)"
echo "2. Start Frontend Dev Server (http://localhost:3000)"
echo "3. Run Tests"
echo "4. Start with Docker Compose (all services)"
echo ""
read -p "Enter choice (1-4): " choice

case $choice in
    1)
        echo ""
        echo "🔧 Starting Backend API..."
        echo "📖 API Docs: http://localhost:8000/docs"
        echo "🔐 Login: admin / admin"
        echo ""
        uvicorn api.main:app --reload --host 0.0.0.0 --port 8000
        ;;
    2)
        echo ""
        echo "⚛️  Starting Frontend Dev Server..."
        echo "🌐 Dashboard: http://localhost:3000"
        echo "🔐 Login: admin / admin"
        echo ""
        cd frontend
        if [ ! -d "node_modules" ]; then
            echo "📥 Installing Node dependencies (first time)..."
            npm install
        fi
        npm run dev
        ;;
    3)
        echo ""
        echo "🧪 Running Tests..."
        echo ""
        pytest tests/ --cov=config --cov=api --cov-report=term-missing -v
        ;;
    4)
        echo ""
        echo "🐳 Starting with Docker Compose..."
        echo ""
        docker-compose up -d
        echo ""
        echo "⏳ Waiting for services to start (30 seconds)..."
        sleep 30
        echo ""
        docker-compose ps
        echo ""
        echo "✅ Services started!"
        echo "🌐 Frontend: http://localhost:3000"
        echo "📖 API Docs: http://localhost:8000/docs"
        echo "🔐 Login: admin / admin"
        echo ""
        echo "📋 View logs: docker-compose logs -f"
        echo "🛑 Stop: docker-compose down"
        ;;
    *)
        echo "Invalid choice. Exiting."
        exit 1
        ;;
esac
