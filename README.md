# 🍯 Agentic Honey-Pot API

AI-powered honeypot for scam detection and intelligence extraction. Built for the GUVI Hackathon.

## ✨ Features

- **🎭 AI Agent Persona**: Shanti Devi - a believable 62-year-old retired teacher persona that engages scammers naturally
- **🔍 Scam Detection**: LLM + keyword/pattern matching to detect scam intent
- **📊 Intelligence Extraction**: Extracts bank accounts, UPI IDs, phone numbers, phishing links
- **💬 Multi-turn Conversations**: Maintains conversation history and context
- **🚀 Low Latency**: Fast responses using Groq LLM (llama-3.3-70b-versatile)

## 🛠️ Tech Stack

- **Framework**: FastAPI
- **LLM**: Groq API (llama-3.3-70b-versatile)
- **Language**: Python 3.10+

## 📦 Setup

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Configure Environment

Create `.env` file:
```env
GROQ_API_KEY=your_groq_api_key
API_SECRET_KEY=secret_123
```

### 3. Run Locally

```bash
uvicorn main:app --reload --port 8000
```

## 🔌 API Endpoints

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
    "language": "English"
  }
}
```

**Response:**
```json
{
  "status": "success",
  "reply": "Arre! Which account beta? SBI or ICICI?",
  "sessionId": "unique-session-id",
  "scamDetected": true,
  "extractedIntelligence": {
    "phoneNumbers": ["+919876543210"],
    "upiIds": ["verify@ybl"],
    "bankAccounts": ["1234567890"],
    "phishingLinks": ["http://fake.com/kyc"]
  },
  "totalMessagesExchanged": 2,
  "conversationStage": 2
}
```

### GET /health

Health check endpoint.

### GET /session/{session_id}

Get session info (requires API key).

## 🎭 The Persona: Shanti Devi

Shanti Devi is a 62-year-old retired school teacher from Delhi who:
- Uses Hindi-English mix naturally ("Arre beta", "Haan ji", "Theek hai")
- Is worried about her pension money
- Gets confused with technology
- Asks many questions to extract scammer details
- Never reveals she knows it's a scam

## 📈 Hackathon Metrics

| Metric | Status |
|--------|--------|
| Scam Detection | ✅ |
| Multi-turn Conversations | ✅ |
| Intelligence Extraction | ✅ |
| Bank Accounts | ✅ |
| UPI IDs | ✅ |
| Phone Numbers | ✅ |
| Phishing Links | ✅ |
| Realistic Persona | ✅ |

## 🚀 Deployment

### Railway

```bash
railway login
railway up
```

### Render

- Build: `pip install -r requirements.txt`
- Start: `uvicorn main:app --host 0.0.0.0 --port $PORT`

## 📝 License

MIT
