# Flask Application

This is a simple Flask web application containerized with Docker.

## Features
- Flask web server
- Multi-stage Docker build for optimized image size
- Security best practices (non-root user, read-only filesystem)
- Health check endpoint
- Environment variable configuration

## Files
- `app.py` - Main Flask application
- `Dockerfile` - Multi-stage Docker build configuration
- `requirements.txt` - Python dependencies
- `run-secure.sh` - Security-focused startup script

## Running Locally

### Manual Docker Build
```bash
cd app
docker build -t flask-app .
docker run -d -p 3000:3000 --name flask-app flask-app
```

## Endpoints
- `GET /` - Home page
- `GET /health` - Health check endpoint

## Environment Variables
- `APP_HOST` - Host to bind to (default: 0.0.0.0)
- `APP_PORT` - Port to listen on (default: 5000)
- `ENVIRONMENT` - Environment name (default: production)
- `DEBUG` - Enable debug mode (default: false)

## Testing
```bash
# Direct access
curl http://localhost:3000
curl http://localhost:3000/health
```
