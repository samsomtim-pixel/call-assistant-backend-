# Call Assistant Backend

Backend server for AI-powered outbound sales call assistant with real-time transcription.

## Features

- **Twilio Voice Integration**: Browser-based outbound calling via Twilio Voice SDK
- **Real-time Audio Streaming**: Receives audio streams from Twilio Media Streams
- **Deepgram Transcription**: Real-time Dutch speech-to-text transcription
- **WebSocket Support**: Real-time transcript delivery to frontend clients

## Tech Stack

- Node.js with Express
- Twilio Voice SDK
- Deepgram SDK (Nova-2 model)
- WebSocket (ws library)

## Setup

1. **Install dependencies:**
   ```bash
   npm install
   ```

2. **Configure environment variables:**
   Copy `env.example.txt` to `.env` and fill in your credentials:
   ```bash
   cp env.example.txt .env
   ```

   Required variables:
   - `TWILIO_ACCOUNT_SID`: Your Twilio Account SID
   - `TWILIO_AUTH_TOKEN`: Your Twilio Auth Token
   - `TWILIO_API_KEY`: Your Twilio API Key
   - `TWILIO_API_SECRET`: Your Twilio API Secret
   - `TWILIO_TWIML_APP_SID`: Your Twilio TwiML App SID
   - `TWILIO_PHONE_NUMBER`: Your Twilio phone number (E.164 format)
   - `DEEPGRAM_API_KEY`: Your Deepgram API key
   - `MEDIA_STREAM_URL`: WebSocket URL for Twilio Media Streams (use ngrok for local dev)
   - `PORT`: Server port (default: 3001)

3. **Start the server:**
   ```bash
   npm run dev
   ```

## Local Development with ngrok

For local development, use ngrok to expose your local server:

```bash
ngrok http 3001
```

Then update `MEDIA_STREAM_URL` in `.env`:
```
MEDIA_STREAM_URL=wss://your-ngrok-url.ngrok.io/api/stream
```

Also update your Twilio TwiML App URL in the Twilio Console:
```
https://your-ngrok-url.ngrok.io/api/voice
```

## API Endpoints

- `GET /api/token` - Generate Twilio access token
- `POST /api/voice` - TwiML endpoint for outbound calls
- `WebSocket /api/stream` - Twilio Media Stream WebSocket
- `WebSocket /api/transcripts` - Frontend transcript WebSocket
- `GET /health` - Health check endpoint

## Architecture

1. Frontend requests access token from `/api/token`
2. Frontend uses Twilio Device SDK to make outbound call
3. Twilio calls `/api/voice` endpoint, which returns TwiML with `<Stream>` directive
4. Twilio connects to `/api/stream` WebSocket and streams audio
5. Backend buffers audio and sends to Deepgram for transcription
6. Transcripts are sent to frontend via `/api/transcripts` WebSocket

## Notes

- Twilio Media Streams is **receive-only** - do not send messages to Twilio
- Audio is buffered and transcribed at the end of the call using Deepgram's prerecorded API
- Supports Dutch language transcription (`nl`)
- Uses μ-law (PCMU) audio format, 8kHz, mono

## License

MIT

