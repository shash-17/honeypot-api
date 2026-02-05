# Agentic Honey-Pot API

AI-powered honeypot for scam detection and intelligence extraction.

## Features

- **Scam Detection**: Uses LLM + keyword/pattern matching to detect scam intent
- **AI Agent Engagement**: Human-like persona that engages scammers
- **Intelligence Extraction**: Extracts bank accounts, UPI IDs, phone numbers, phishing links
- **GUVI Integration**: Sends final results to evaluation endpoint

## Setup

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Configure Environment

```bash
cp .env.example .env
```

Edit `.env` with your API keys:
```
GEMINI_API_KEY=your_gemini_api_key
API_SECRET_KEY=your_secret_api_key
```

### 3. Run Locally

```bash
uvicorn main:app --reload --port 8000
```

## API Endpoints

### POST /analyze

Analyze an incoming message and get agent response.

**Headers:**
```
x-api-key: YOUR_SECRET_API_KEY
Content-Type: application/json
```

**Request:**
```json
{
  "sessionId": "unique-session-id",
  "message": {
    "sender": "scammer",
    "text": "Your bank account will be blocked today.",
    "timestamp": 1770005528731
  },
  "conversationHistory": [],
  "metadata": {
    "channel": "SMS",
    "language": "English",
    "locale": "IN"
  }
}
```

**Response:**
```json
{
  "status": "success",
  "reply": "Why is my account being suspended?"
}
```

### GET /health

Health check endpoint.

### GET /session/{session_id}

Get session info (requires API key).

## Deployment

### Railway

```bash
# Install Railway CLI
npm install -g @railway/cli

# Login and deploy
railway login
railway init
railway up
```

### Render

Create a new Web Service with:
- Build Command: `pip install -r requirements.txt`
- Start Command: `uvicorn main:app --host 0.0.0.0 --port $PORT`

## Testing

```bash
curl -X POST http://localhost:8000/analyze \
  -H "x-api-key: YOUR_SECRET_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "sessionId": "test-123",
    "message": {
      "sender": "scammer",
      "text": "Your bank account will be blocked today. Verify immediately.",
      "timestamp": 1770005528731
    },
    "conversationHistory": [],
    "metadata": {"channel": "SMS", "language": "English", "locale": "IN"}
  }'
```
