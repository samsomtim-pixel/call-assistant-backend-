import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import twilio from 'twilio';
import { WebSocketServer } from 'ws';
import http from 'http';
import https from 'https';
import { createClient } from '@deepgram/sdk';
import { Readable } from 'stream';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3001;

// Create HTTP server for Express and WebSocket
const server = http.createServer(app);

// Middleware
// IMPORTANT: WebSocket upgrade requests must be handled BEFORE Express middleware
// The WebSocketServer will handle /api/stream and /api/transcripts upgrades
// CORS and body parsers should NOT interfere with WebSocket upgrades

// Skip middleware for WebSocket upgrade requests
app.use((req, res, next) => {
  // Check if this is a WebSocket upgrade request
  const isUpgrade = req.headers.upgrade === 'websocket';
  const isWebSocketPath = req.path === '/api/stream' || req.path === '/api/transcripts';
  
  if (isUpgrade || isWebSocketPath) {
    // Skip all middleware for WebSocket paths - let WebSocketServer handle it
    console.log(`⏭️  Skipping middleware for WebSocket request: ${req.path}`);
    return next();
  }
  
  // Apply middleware for regular HTTP requests
  next();
});

// CORS configuration - allow frontend to make requests
// This only applies to HTTP requests, not WebSocket upgrades
app.use(cors({
  origin: ['http://localhost:3000', 'http://127.0.0.1:3000'],
  credentials: true,
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Initialize Twilio client
// You'll need to set these in your .env file:
// TWILIO_ACCOUNT_SID=your_account_sid
// TWILIO_AUTH_TOKEN=your_auth_token
// TWILIO_API_KEY=your_api_key
// TWILIO_API_SECRET=your_api_secret
// TWILIO_PHONE_NUMBER=your_twilio_phone_number
const accountSid = process.env.TWILIO_ACCOUNT_SID;
const authToken = process.env.TWILIO_AUTH_TOKEN;
const apiKey = process.env.TWILIO_API_KEY;
const apiSecret = process.env.TWILIO_API_SECRET;
const twilioPhoneNumber = process.env.TWILIO_PHONE_NUMBER;
const deepgramApiKey = process.env.DEEPGRAM_API_KEY;

if (!accountSid || !authToken || !apiKey || !apiSecret || !twilioPhoneNumber) {
  console.error('Missing required Twilio environment variables!');
  console.error('Required: TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, TWILIO_API_KEY, TWILIO_API_SECRET, TWILIO_PHONE_NUMBER');
}

if (!deepgramApiKey) {
  console.warn('⚠️  DEEPGRAM_API_KEY not set. Transcription will be disabled.');
} else {
  console.log('✅ Deepgram API key configured');
}

const twilioClient = twilio(accountSid, authToken);

/**
 * Generate Twilio Access Token for the frontend
 * This token allows the browser to make calls via Twilio Voice SDK
 * 
 * For outbound calls, we use a TwiML URL approach:
 * - The token grants permission to make calls
 * - When Device.connect() is called, we pass a TwiML URL
 * - Twilio fetches that TwiML URL to get call instructions
 * 
 * Supports both GET and POST methods:
 * - GET: identity can be passed as query parameter
 * - POST: identity can be passed in request body
 */
const generateToken = async (req, res) => {
  try {
    // Support both GET (query param) and POST (body) for identity
    const identity = req.body?.identity || req.query?.identity;
    
    console.log('🔑 Token request received');
    
    if (!apiKey || !apiSecret) {
      console.error('❌ Missing Twilio API credentials');
      return res.status(500).json({ 
        error: 'Twilio API credentials not configured' 
      });
    }

    // Create access token with Voice grant
    const AccessToken = twilio.jwt.AccessToken;
    const VoiceGrant = AccessToken.VoiceGrant;

    // For browser-based outbound calls, we MUST use a TwiML App SID
    // The TwiML App SID tells Twilio where to get TwiML instructions
    const twimlAppSid = process.env.TWILIO_TWIML_APP_SID;
    
    if (!twimlAppSid) {
      console.warn('⚠️  No TwiML App SID configured. Calls may fail.');
    }

    const voiceGrant = new VoiceGrant({
      // TwiML App SID is REQUIRED for browser-based outbound calls
      outgoingApplicationSid: twimlAppSid,
      incomingAllow: false, // Set to false for outbound-only
    });

    const token = new AccessToken(accountSid, apiKey, apiSecret, {
      identity: identity || 'call-assistant-user',
      ttl: 3600, // Token expires in 1 hour
    });

    token.addGrant(voiceGrant);

    const tokenJwt = token.toJwt();
    console.log('✅ Token generated successfully');
    console.log(`   Identity: ${identity || 'call-assistant-user'}`);
    console.log(`   TwiML App SID: ${twimlAppSid || 'NOT SET'}`);

    res.json({
      token: tokenJwt,
      identity: identity || 'call-assistant-user',
    });
  } catch (error) {
    console.error('❌ Error generating token:', error);
    res.status(500).json({ 
      error: 'Failed to generate access token',
      details: error.message 
    });
  }
};

// Register both GET and POST endpoints
app.get('/api/token', generateToken);
app.post('/api/token', generateToken);

/**
 * TwiML endpoint for outbound calls
 * This tells Twilio how to handle the call when it connects
 * 
 * For browser-based outbound calls:
 * 1. Browser calls Device.connect() with phone number
 * 2. Twilio makes POST request to this endpoint when call connects
 * 3. We extract the 'To' parameter (destination phone number)
 * 4. We return TwiML that:
 *    - Dials the destination number
 *    - Records the call (both sides)
 *    - Calls /api/recording-complete when recording is done
 */
app.post('/api/voice', (req, res) => {
  try {
    console.log('📞 TwiML request received');
    console.log('   Request body:', JSON.stringify(req.body, null, 2));
    console.log('   Request query:', JSON.stringify(req.query, null, 2));
    
    const twiml = new twilio.twiml.VoiceResponse();
    
    // Get the destination phone number from the request
    // Twilio passes this as 'To' parameter when Device.connect() is called
    // It can be in body (POST) or query string
    const toNumber = req.body.To || req.query.To || req.body.Called || req.query.Called;
    
    if (!toNumber) {
      console.error('❌ No "To" parameter found in request');
      console.error('   Available body keys:', Object.keys(req.body));
      console.error('   Available query keys:', Object.keys(req.query));
      twiml.say('Error: No phone number provided.');
      res.type('text/xml');
      return res.send(twiml.toString());
    }
    
    console.log('📞 Dialing number:', toNumber);
    
    // Get the base URL for recording callback
    // Priority: BACKEND_URL env var > Railway public domain > construct from request
    const baseUrl = process.env.BACKEND_URL 
      ? process.env.BACKEND_URL
      : process.env.RAILWAY_PUBLIC_DOMAIN 
      ? `https://${process.env.RAILWAY_PUBLIC_DOMAIN}`
      : `${req.protocol}://${req.get('host')}`;
    
    const recordingCallbackUrl = `${baseUrl}/api/recording-complete`;
    console.log('📹 Recording callback URL:', recordingCallbackUrl);
    
    // Dial the destination number with recording enabled
    // record-from-answer-dual records both sides of the conversation
    try {
      const dial = twiml.dial({
        callerId: twilioPhoneNumber, // Use your Twilio phone number as caller ID
        record: 'record-from-answer-dual', // Record both sides after answer
        recordingStatusCallback: recordingCallbackUrl, // Callback when recording is complete
        recordingStatusCallbackMethod: 'POST',
        timeout: 30, // Wait up to 30 seconds for answer
        action: undefined, // No action URL needed for simple dial
      });
      
      dial.number(toNumber);
      console.log('✅ Dial directive added to TwiML with recording enabled');
    } catch (dialError) {
      console.error('❌ Error adding dial directive:', dialError);
      twiml.say('Sorry, there was an error connecting your call.');
    }
    
    // Generate TwiML response
    res.type('text/xml');
    const twimlResponse = twiml.toString();
    console.log('📤 TwiML response:');
    console.log(twimlResponse);
    
    // Validate TwiML is valid XML
    if (!twimlResponse || twimlResponse.trim().length === 0) {
      console.error('❌ Empty TwiML response generated!');
      const errorTwiml = new twilio.twiml.VoiceResponse();
      errorTwiml.say('Sorry, there was an error processing your call.');
      return res.status(500).send(errorTwiml.toString());
    }
    
    res.send(twimlResponse);
  } catch (error) {
    console.error('❌ Error generating TwiML:', error);
    console.error('   Error stack:', error.stack);
    res.type('text/xml');
    const errorTwiml = new twilio.twiml.VoiceResponse();
    errorTwiml.say('Sorry, there was an error processing your call.');
    res.status(500).send(errorTwiml.toString());
  }
});

// Also handle GET requests (for testing/debugging)
app.get('/api/voice', (req, res) => {
  console.log('⚠️  GET request to /api/voice - Twilio uses POST');
  res.type('text/xml');
  const twiml = new twilio.twiml.VoiceResponse();
  twiml.say('This endpoint requires a POST request. Twilio will use POST when making calls.');
  res.send(twiml.toString());
});

/**
 * Recording completion callback endpoint
 * Twilio calls this when a recording is complete
 * 
 * This endpoint:
 * 1. Receives RecordingUrl from Twilio
 * 2. Downloads the recording file
 * 3. Sends to Deepgram for transcription
 * 4. Logs/returns the transcript
 */
app.post('/api/recording-complete', async (req, res) => {
  try {
    console.log('📹 Recording completion callback received');
    console.log('   Request body:', JSON.stringify(req.body, null, 2));
    
    const recordingUrl = req.body.RecordingUrl;
    const recordingSid = req.body.RecordingSid;
    const callSid = req.body.CallSid;
    const recordingStatus = req.body.RecordingStatus;
    const recordingDuration = req.body.RecordingDuration;
    
    if (!recordingUrl) {
      console.error('❌ No RecordingUrl in callback');
      return res.status(400).json({ error: 'RecordingUrl is required' });
    }
    
    console.log('📥 Recording details:');
    console.log(`   Recording SID: ${recordingSid}`);
    console.log(`   Call SID: ${callSid}`);
    console.log(`   Status: ${recordingStatus}`);
    console.log(`   Duration: ${recordingDuration} seconds`);
    console.log(`   URL: ${recordingUrl}`);
    
    // Send acknowledgment to Twilio immediately
    res.status(200).json({ status: 'received' });
    
    // Process recording asynchronously
    processRecording(recordingUrl, recordingSid, callSid).catch(error => {
      console.error('❌ Error processing recording:', error);
    });
    
  } catch (error) {
    console.error('❌ Error in recording callback:', error);
    // Still return 200 to Twilio to avoid retries
    res.status(200).json({ error: error.message });
  }
});

/**
 * Download recording and transcribe with Deepgram
 */
async function processRecording(recordingUrl, recordingSid, callSid) {
  try {
    console.log('🔄 ========================================');
    console.log('🔄 Processing recording...');
    console.log(`   Recording SID: ${recordingSid}`);
    console.log(`   Call SID: ${callSid}`);
    console.log(`   Original URL: ${recordingUrl}`);
    
    if (!deepgramApiKey) {
      console.warn('⚠️  Deepgram API key not configured. Skipping transcription.');
      return;
    }
    
    // Ensure we request WAV format from Twilio (add .wav extension if not present)
    let downloadUrl = recordingUrl;
    if (!recordingUrl.endsWith('.wav') && !recordingUrl.endsWith('.mp3')) {
      // Twilio supports .wav format - append it to get WAV format
      downloadUrl = recordingUrl.endsWith('/') 
        ? `${recordingUrl}.wav`
        : `${recordingUrl}.wav`;
      console.log(`📝 Modified URL to request WAV format: ${downloadUrl}`);
    } else {
      console.log(`📝 Using original URL format: ${downloadUrl}`);
    }
    
    // Download the recording file
    console.log('📥 Downloading recording from Twilio...');
    const recordingBuffer = await downloadFile(downloadUrl);
    console.log(`✅ Downloaded recording: ${recordingBuffer.length} bytes`);
    console.log(`   Buffer type: ${recordingBuffer.constructor.name}`);
    console.log(`   First 20 bytes (hex): ${Array.from(recordingBuffer.slice(0, 20)).map(b => '0x' + b.toString(16).padStart(2, '0')).join(' ')}`);
    
    // Check if buffer looks like WAV (should start with "RIFF")
    const header = recordingBuffer.slice(0, 4).toString('ascii');
    console.log(`   File header: "${header}" (expected "RIFF" for WAV)`);
    
    // Initialize Deepgram client
    console.log('🔧 Initializing Deepgram client...');
    const deepgramClient = createClient(deepgramApiKey);
    
    // Create a readable stream from the buffer
    const audioStream = Readable.from(recordingBuffer);
    console.log('✅ Created readable stream from buffer');
    
    // Prepare Deepgram options
    const deepgramOptions = {
      model: 'nova-2', // Better for phone audio
      language: 'nl', // Dutch - explicitly set
      punctuate: true,
      // Let Deepgram auto-detect the format, but we're sending WAV
    };
    
    console.log('📤 ========================================');
    console.log('📤 Sending recording to Deepgram for transcription...');
    console.log('📤 Deepgram Options:');
    console.log(JSON.stringify(deepgramOptions, null, 2));
    console.log(`   Audio buffer size: ${recordingBuffer.length} bytes`);
    console.log(`   Stream type: ${audioStream.constructor.name}`);
    
    const startTime = Date.now();
    const { result, error } = await deepgramClient.listen.prerecorded.transcribeFile(
      audioStream,
      deepgramOptions
    ).catch(err => {
      console.error('❌ Deepgram API promise rejection:', err);
      console.error('   Error type:', err?.constructor?.name);
      console.error('   Error message:', err?.message);
      console.error('   Error code:', err?.code);
      console.error('   Full error object:', JSON.stringify(err, null, 2));
      return { result: null, error: err };
    });
    
    const duration = ((Date.now() - startTime) / 1000).toFixed(2);
    console.log(`⏱️  Deepgram API call completed in ${duration}s`);
    
    if (error) {
      console.error('❌ ========================================');
      console.error('❌ Deepgram transcription error:');
      console.error('   Error type:', error?.constructor?.name);
      console.error('   Error code:', error?.code);
      console.error('   Error message:', error?.message);
      console.error('   Full error object:', JSON.stringify(error, null, 2));
      return;
    }
    
    if (result) {
      console.log('✅ ========================================');
      console.log('✅ Deepgram transcription complete');
      console.log('📥 FULL Deepgram Response Object:');
      console.log(JSON.stringify(result, null, 2));
      console.log('📥 ========================================');
      
      // Extract transcripts
      const channels = result.results?.channels || [];
      console.log(`📊 Found ${channels.length} channel(s) in response`);
      
      if (channels.length === 0) {
        console.warn('⚠️  No channels found in Deepgram response!');
        console.warn('   Response structure:', Object.keys(result));
        if (result.results) {
          console.warn('   Results structure:', Object.keys(result.results));
        }
      }
      
      const transcripts = [];
      
      channels.forEach((channel, index) => {
        console.log(`📊 Processing channel ${index}:`);
        const alternatives = channel.alternatives || [];
        console.log(`   Found ${alternatives.length} alternative(s)`);
        
        alternatives.forEach((alt, altIndex) => {
          console.log(`   Alternative ${altIndex}:`);
          console.log(`     Has transcript: ${!!alt.transcript}`);
          console.log(`     Transcript length: ${alt.transcript?.length || 0}`);
          console.log(`     Confidence: ${alt.confidence || 'N/A'}`);
          console.log(`     Words count: ${alt.words?.length || 0}`);
          
          if (alt.transcript) {
            const transcriptEntry = {
              text: alt.transcript,
              confidence: alt.confidence || 0,
              words: alt.words || [],
              recordingSid: recordingSid,
              callSid: callSid,
              timestamp: new Date().toISOString(),
            };
            
            transcripts.push(transcriptEntry);
            
            console.log(`📝 [TRANSCRIPT] "${alt.transcript}"`);
            console.log(`   Confidence: ${(alt.confidence * 100).toFixed(1)}%`);
            console.log(`   Words: ${alt.words?.length || 0}`);
            
            // Send transcript to frontend via WebSocket
            broadcastTranscript({
              text: alt.transcript,
              confidence: alt.confidence || 0,
              words: alt.words || [],
              isFinal: true,
              recordingSid: recordingSid,
              callSid: callSid,
            });
          } else {
            console.warn(`   ⚠️  Alternative ${altIndex} has no transcript!`);
            console.warn(`   Alternative object:`, JSON.stringify(alt, null, 2));
          }
        });
      });
      
      console.log(`✅ Transcription complete: ${transcripts.length} transcript(s) extracted`);
      console.log('🔄 ========================================');
      return transcripts;
    } else {
      console.warn('⚠️  Deepgram returned no result (result is null/undefined)');
      console.warn('   This might indicate an issue with the API call');
    }
  } catch (error) {
    console.error('❌ ========================================');
    console.error('❌ Exception during recording processing:');
    console.error('   Error type:', error.constructor.name);
    console.error('   Error message:', error.message);
    console.error('   Error stack:', error.stack);
    console.error('   Full error:', JSON.stringify(error, Object.getOwnPropertyNames(error), 2));
    throw error;
  }
}

/**
 * Download a file from a URL
 * For Twilio recordings, we need to add Basic Auth with Account SID and Auth Token
 */
function downloadFile(url) {
  return new Promise((resolve, reject) => {
    // Check if this is a Twilio URL (requires authentication)
    const isTwilioUrl = url.includes('twilio.com');
    
    const options = {
      headers: {}
    };
    
    // Add Basic Auth for Twilio URLs
    if (isTwilioUrl && accountSid && authToken) {
      const auth = Buffer.from(`${accountSid}:${authToken}`).toString('base64');
      options.headers['Authorization'] = `Basic ${auth}`;
    }
    
    https.get(url, options, (response) => {
      if (response.statusCode !== 200) {
        reject(new Error(`Failed to download file: ${response.statusCode} ${response.statusMessage}`));
        return;
      }
      
      const chunks = [];
      response.on('data', (chunk) => {
        chunks.push(chunk);
      });
      
      response.on('end', () => {
        const buffer = Buffer.concat(chunks);
        resolve(buffer);
      });
      
      response.on('error', (error) => {
        reject(error);
      });
    }).on('error', (error) => {
      reject(error);
    });
  });
}

/**
 * WebSocket server for receiving audio stream from Twilio Media Streams
 * 
 * NOTE: Media Streams are currently disabled in favor of call recording.
 * This code is kept for future use but not actively used.
 * 
 * Twilio Media Streams Protocol:
 * - Twilio connects to this WebSocket when <Stream> is executed in TwiML
 * - Audio is sent as base64-encoded μ-law (PCMU) in JSON messages
 * - Messages include metadata (JSON) and audio payloads
 * - We forward audio to Deepgram for real-time transcription
 */
// Track active Media Stream connections to prevent duplicates
// Key format: "streamSid:callSid" or "streamSid" if callSid not available
const activeStreamConnections = new Map(); // key -> { ws, streamSid, callSid, connectedAt }

// Create WebSocket server for Twilio Media Streams
// This must be created BEFORE server.listen() to properly handle upgrades
const wss = new WebSocketServer({ 
  server,
  path: '/api/stream',
  verifyClient: (info, callback) => {
    // Log incoming WebSocket upgrade requests
    console.log('🔌 WebSocket upgrade verification for /api/stream');
    console.log(`   Path: ${info.req.url}`);
    console.log(`   Origin: ${info.req.headers.origin || 'none'}`);
    console.log(`   User-Agent: ${info.req.headers['user-agent'] || 'unknown'}`);
    console.log(`   Timestamp: ${new Date().toISOString()}`);
    
    // Extract stream SID and call SID from URL to check for duplicates
    const url = new URL(info.req.url, `http://${info.req.headers.host}`);
    const streamSid = url.searchParams.get('streamSid') || 'unknown';
    const callSid = url.searchParams.get('callSid') || null;
    
    console.log(`   Stream SID: ${streamSid}`);
    if (callSid) {
      console.log(`   Call SID: ${callSid}`);
    }
    
    // Create a unique key for this connection
    // Prefer streamSid:callSid if both are available, otherwise just streamSid
    const connectionKey = (streamSid !== 'unknown' && callSid) 
      ? `${streamSid}:${callSid}` 
      : streamSid;
    
    // Check if we already have an active connection for this stream/call
    if (activeStreamConnections.has(connectionKey)) {
      const existing = activeStreamConnections.get(connectionKey);
      if (existing && existing.ws && existing.ws.readyState === 1) {
        const age = ((Date.now() - existing.connectedAt) / 1000).toFixed(2);
        console.warn(`⚠️  DUPLICATE connection attempt detected!`);
        console.warn(`   Stream SID: ${streamSid}`);
        console.warn(`   Call SID: ${callSid || 'none'}`);
        console.warn(`   Existing connection age: ${age}s`);
        console.warn(`   Rejecting duplicate - keeping existing connection`);
        console.warn(`   This is normal Twilio behavior - rejecting duplicate to preserve first connection`);
        callback(false, 400, 'Duplicate connection - stream already connected');
        return;
      } else {
        // Old connection is closed, remove it
        console.log(`   Removing stale connection entry for ${connectionKey}`);
        activeStreamConnections.delete(connectionKey);
      }
    }
    
    // Accept new connections
    console.log(`   ✅ Accepting NEW connection for key: ${connectionKey}`);
    callback(true);
  },
  clientTracking: true, // Track connected clients
});

// Log when WebSocket server is ready
wss.on('listening', () => {
  console.log('✅ WebSocket server listening on /api/stream');
  console.log(`   Ready to accept connections from Twilio Media Streams`);
});

wss.on('error', (error) => {
  console.error('❌ WebSocket server error:', error);
  console.error('   Error details:', error.message);
});

/**
 * WebSocket server for sending transcripts to frontend
 * Frontend connects to this to receive real-time transcripts
 */
const transcriptWss = new WebSocketServer({
  server,
  path: '/api/transcripts'
});

// Store connected frontend clients
const frontendClients = new Set();

transcriptWss.on('connection', (ws, req) => {
  console.log('📱 Frontend client connected for transcripts');
  console.log(`   Total connected clients: ${frontendClients.size + 1}`);
  frontendClients.add(ws);
  
  // Send welcome message
  try {
    ws.send(JSON.stringify({
      type: 'connected',
      message: 'Connected to transcript stream'
    }));
    console.log('   ✅ Welcome message sent to frontend');
  } catch (error) {
    console.error('   ❌ Error sending welcome message:', error);
  }
  
  ws.on('close', () => {
    console.log('📱 Frontend client disconnected from transcript stream');
    console.log(`   Remaining clients: ${frontendClients.size - 1}`);
    frontendClients.delete(ws);
  });
  
  ws.on('error', (error) => {
    console.error('❌ Frontend WebSocket error:', error);
    frontendClients.delete(ws);
  });
  
  ws.on('message', (data) => {
    console.log('📥 Message received from frontend:', data.toString());
  });
});

// Function to broadcast transcripts to all connected frontend clients
const broadcastTranscript = (transcript) => {
  const message = JSON.stringify({
    type: 'transcript',
    data: transcript,
    timestamp: new Date().toISOString()
  });
  
  console.log(`📤 Broadcasting transcript to ${frontendClients.size} frontend client(s)`);
  console.log(`   Transcript text: "${transcript.text}"`);
  console.log(`   Confidence: ${(transcript.confidence * 100).toFixed(1)}%`);
  
  if (frontendClients.size === 0) {
    console.warn('⚠️  WARNING: No frontend clients connected! Transcript will not be displayed.');
    console.warn('   Make sure frontend is running and WebSocket connection is established.');
  }
  
  let sentCount = 0;
  frontendClients.forEach((client) => {
    if (client.readyState === 1) { // WebSocket.OPEN
      try {
        client.send(message);
        sentCount++;
        console.log(`   ✅ Sent to frontend client #${sentCount}`);
      } catch (error) {
        console.error('❌ Error sending transcript to frontend:', error);
        frontendClients.delete(client);
      }
    } else {
      // Remove closed connections
      console.log(`   ⚠️  Removing closed client connection (state: ${client.readyState})`);
      frontendClients.delete(client);
    }
  });
  
  console.log(`📊 Transcript broadcast complete: ${sentCount}/${frontendClients.size} clients received`);
};

wss.on('connection', (ws, req) => {
  // Track connection start time at the very beginning
  const connectionStartTime = Date.now();
  const connectionId = `conn_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  
  console.log('📞 ========================================');
  console.log(`📞 New Media Stream connection from Twilio - CONNECTED!`);
  console.log(`   Connection ID: ${connectionId}`);
  console.log(`   Request URL: ${req.url}`);
  console.log(`   Request Method: ${req.method}`);
  console.log(`   Request Headers:`, JSON.stringify(req.headers, null, 2));
  console.log(`   WebSocket ready state: ${ws.readyState} (1 = OPEN, 0 = CONNECTING, 2 = CLOSING, 3 = CLOSED)`);
  console.log(`   WebSocket protocol: ${ws.protocol || 'none'}`);
  console.log(`   WebSocket extensions: ${ws.extensions || 'none'}`);
  console.log(`   Timestamp: ${new Date().toISOString()}`);
  
  // Track this stream connection
  const url = new URL(req.url, `http://${req.headers.host}`);
  const streamSid = url.searchParams.get('streamSid') || 'unknown';
  const callSid = url.searchParams.get('callSid') || null;
  
  console.log(`   Stream SID: ${streamSid}`);
  if (callSid) {
    console.log(`   Call SID: ${callSid}`);
  }
  
  // Create connection key (same logic as in verifyClient)
  const connectionKey = (streamSid !== 'unknown' && callSid) 
    ? `${streamSid}:${callSid}` 
    : streamSid;
  
  // CRITICAL: Check if this is a duplicate that somehow got through verifyClient
  // If so, close THIS connection (the duplicate), not the existing one
  if (activeStreamConnections.has(connectionKey)) {
    const existing = activeStreamConnections.get(connectionKey);
    if (existing && existing.ws && existing.ws.readyState === 1) {
      const age = ((Date.now() - existing.connectedAt) / 1000).toFixed(2);
      console.error(`❌ DUPLICATE connection got through verifyClient!`);
      console.error(`   This should not happen - closing the NEW duplicate connection`);
      console.error(`   Keeping existing connection (age: ${age}s)`);
      console.error(`   Connection key: ${connectionKey}`);
      
      // Close THIS connection (the duplicate), not the existing one
      ws.close(1000, 'Duplicate connection - existing connection preserved');
      return; // Don't process this connection further
    } else {
      // Old connection is stale, remove it
      console.log(`   Removing stale connection entry for ${connectionKey}`);
      activeStreamConnections.delete(connectionKey);
    }
  }
  
  // Store this connection to prevent future duplicates
  if (streamSid !== 'unknown') {
    activeStreamConnections.set(connectionKey, {
      ws: ws,
      streamSid: streamSid,
      callSid: callSid,
      connectedAt: connectionStartTime,
    });
    console.log(`   ✅ Registered connection for key: ${connectionKey}`);
    console.log(`   Active streams: ${activeStreamConnections.size}`);
  }
  
  // Verify connection is open
  if (ws.readyState === 1) {
    console.log('   ✅ WebSocket connection is OPEN and ready to receive messages');
  } else {
    console.warn(`   ⚠️  WebSocket ready state: ${ws.readyState} (expected 1 for OPEN)`);
  }
  
  // Audio buffer for Deepgram transcription (simplified approach)
  // We'll buffer all audio and send it at the end using prerecorded API
  let audioBuffer = [];
  let audioChunksReceived = 0;
  let totalAudioBytes = 0;
  let streamStarted = false;
  
  // Store Deepgram client for use when call ends
  let deepgramClient = null;
  
  if (deepgramApiKey) {
    try {
      deepgramClient = createClient(deepgramApiKey);
      console.log('✅ Deepgram client initialized (will use prerecorded API when call ends)');
    } catch (error) {
      console.error('❌ Error initializing Deepgram client:', error);
      deepgramClient = null;
    }
  } else {
    console.warn('⚠️  Deepgram not initialized - API key missing');
  }
      
  // Function to transcribe buffered audio using Deepgram prerecorded API
  const transcribeBufferedAudio = async () => {
    if (!deepgramClient || audioBuffer.length === 0) {
      console.log('⚠️  Cannot transcribe: No Deepgram client or no audio buffered');
      return;
    }
    
    try {
      console.log(`📤 Sending ${audioBuffer.length} audio chunks (${totalAudioBytes} bytes) to Deepgram for transcription...`);
      
      // Combine all audio chunks into a single buffer
      const combinedAudio = Buffer.concat(audioBuffer);
      console.log(`   Combined audio buffer size: ${combinedAudio.length} bytes`);
      
      // Create a readable stream from the buffer
      // Deepgram's API works better with streams
      const audioStream = Readable.from(combinedAudio);
      
      // Use Deepgram's prerecorded API
      // Note: We're sending mulaw (PCMU) format, 8kHz, mono
      console.log('📤 Calling Deepgram prerecorded API...');
      const { result, error } = await deepgramClient.listen.prerecorded.transcribeFile(
        audioStream,
        {
          model: 'nova-2',
          language: 'nl', // Dutch
          mimetype: 'audio/mulaw', // Specify mimetype for mulaw
          encoding: 'mulaw', // μ-law format (PCMU)
          sample_rate: 8000, // 8kHz
          channels: 1, // Mono
          punctuate: true,
        }
      ).catch(err => {
        // Handle promise rejection
        console.error('❌ Deepgram API promise rejection:', err);
        console.error('   Error type:', err?.constructor?.name);
        console.error('   Error message:', err?.message);
        console.error('   Error code:', err?.code);
        return { result: null, error: err };
      });
      
      if (error) {
        console.error('❌ Deepgram transcription error:', error);
        console.error('   Error code:', error.code);
        console.error('   Error message:', error.message);
        console.error('   Full error:', JSON.stringify(error, null, 2));
        return;
      }
      
      if (result) {
        console.log('✅ Deepgram transcription response received');
        console.log('📥 Full Deepgram response:', JSON.stringify(result, null, 2));
        
        // Extract transcripts from result
        const channels = result.results?.channels || [];
        
        if (channels.length === 0) {
          console.warn('⚠️  No channels in Deepgram response');
        }
        
        channels.forEach((channel, index) => {
          console.log(`📊 Channel ${index}:`);
          const alternatives = channel.alternatives || [];
          
          alternatives.forEach((alternative, altIndex) => {
            if (alternative.transcript) {
              const confidence = alternative.confidence || 0;
              const words = alternative.words || [];
              
              console.log(`📝 [TRANSCRIPT] "${alternative.transcript}"`);
              console.log(`   Confidence: ${(confidence * 100).toFixed(1)}%`);
              console.log(`   Words: ${words.length}`);
              
              // Log first few words for verification
              if (words.length > 0) {
                console.log(`   First words: ${words.slice(0, 5).map(w => w.word).join(' ')}`);
              }
            } else {
              console.log(`   Alternative ${altIndex}: No transcript found`);
            }
          });
        });
        
        // Store transcripts and send to frontend
        const transcripts = [];
        channels.forEach(channel => {
          channel.alternatives?.forEach(alt => {
            if (alt.transcript) {
              const transcriptEntry = {
                text: alt.transcript,
                confidence: alt.confidence || 0,
                words: alt.words || [],
                timestamp: new Date().toISOString(),
              };
              
              transcripts.push(transcriptEntry);
              
              // Send each transcript to frontend in real-time
              broadcastTranscript({
                text: alt.transcript,
                confidence: alt.confidence || 0,
                words: alt.words || [],
                isFinal: true,
              });
            }
          });
        });
        
        console.log(`✅ Transcription complete: ${transcripts.length} transcript(s) extracted and sent to frontend`);
      } else {
        console.warn('⚠️  Deepgram returned no result');
      }
    } catch (error) {
      console.error('❌ Exception during Deepgram transcription:', error);
      console.error('   Error type:', error.constructor.name);
      console.error('   Error message:', error.message);
      console.error('   Error stack:', error.stack);
    }
  };
  
  // Handle incoming messages from Twilio
  ws.on('message', (data) => {
    try {
      console.log(`📥 [${connectionId}] Message received from Twilio Media Stream`);
      console.log(`   Data type: ${typeof data}`);
      console.log(`   Data length: ${data?.length || 0}`);
      console.log(`   Is Buffer: ${Buffer.isBuffer(data)}`);
      console.log(`   Ready state: ${ws.readyState}`);
      
      // Twilio sends JSON metadata messages
      if (data[0] === 0x7B) { // '{' character indicates JSON
        const message = JSON.parse(data.toString());
        console.log(`   Message type: ${message.event || 'unknown'}`);
        
        // Handle different message types
        if (message.event === 'connected') {
          console.log('✅ Media Stream connected:', JSON.stringify(message, null, 2));
        } else if (message.event === 'start') {
          console.log('🎬 Media Stream started:', message);
          console.log('   Format:', message.start.mediaFormat);
          console.log('   Payload Type:', message.start.payloadType);
          console.log('   Channels:', message.start.channels || 1);
          console.log('   Sample Rate:', message.start.rate || 8000);
          
          // Reset audio buffer for new stream
          audioBuffer = [];
          audioChunksReceived = 0;
          totalAudioBytes = 0;
          streamStarted = true;
        } else if (message.event === 'media') {
          // This contains the audio payload
          // message.media.payload is base64-encoded μ-law audio
          if (message.media.payload) {
            try {
              // Decode base64 to get the audio bytes
              // Twilio sends μ-law (PCMU) audio as base64-encoded string
              const decodedAudio = Buffer.from(message.media.payload, 'base64');
              
              // Buffer audio for transcription at end of call
              if (decodedAudio.length > 0) {
                audioBuffer.push(decodedAudio);
                audioChunksReceived++;
                totalAudioBytes += decodedAudio.length;
                
                // Log first chunk to verify we're receiving audio
                if (audioChunksReceived === 1) {
                  console.log(`📥 First audio chunk received: ${decodedAudio.length} bytes`);
                  console.log(`   Sample bytes (first 20): ${Array.from(decodedAudio.slice(0, 20)).map(b => '0x' + b.toString(16).padStart(2, '0')).join(' ')}`);
                }
                
                // Log every 50 chunks to show progress (50 chunks ≈ 1 second at 20ms chunks)
                if (audioChunksReceived % 50 === 0) {
                  console.log(`📥 Buffering audio: ${audioChunksReceived} chunks, ${totalAudioBytes} bytes total`);
                }
              }
            } catch (error) {
              console.error('❌ Error processing audio chunk:', error);
              console.error('   Error message:', error.message);
              console.error('   Payload length:', message.media.payload?.length);
            }
          } else {
            // Log if we receive media event without payload (only once)
            if (audioChunksReceived === 0) {
              console.warn('⚠️  Received media event but no payload found');
            }
          }
        } else if (message.event === 'stop') {
          console.log('🛑 Media Stream stopped:', message);
          console.log(`📊 Stream stats: ${audioChunksReceived} audio chunks received, ${totalAudioBytes} bytes total`);
          
          // Transcribe all buffered audio using Deepgram prerecorded API
          if (audioBuffer.length > 0) {
            console.log('🚀 Starting transcription of buffered audio...');
            transcribeBufferedAudio().catch(error => {
              console.error('❌ Error in transcription callback:', error);
            });
          } else {
            console.warn('⚠️  No audio buffered to transcribe');
          }
          
          // Clear buffer
          audioBuffer = [];
          audioChunksReceived = 0;
          totalAudioBytes = 0;
          streamStarted = false;
        }
      } else {
        // Binary audio data (less common, usually comes as base64 in JSON)
        // We buffer this as well for transcription at end
        if (Buffer.isBuffer(data) && data.length > 0) {
          audioBuffer.push(data);
          audioChunksReceived++;
          totalAudioBytes += data.length;
          console.log(`📥 Binary audio chunk received: ${data.length} bytes`);
        }
      }
    } catch (error) {
      console.error('❌ Error processing Media Stream message:', error);
    }
  });
  
  // Helper function to describe close codes
  function getCloseCodeDescription(code) {
    const codes = {
      1000: 'Normal Closure',
      1001: 'Going Away',
      1002: 'Protocol Error',
      1003: 'Unsupported Data',
      1006: 'Abnormal Closure (no close frame)',
      1007: 'Invalid Data',
      1008: 'Policy Violation',
      1009: 'Message Too Big',
      1010: 'Extension Error',
      1011: 'Internal Error',
    };
    return codes[code] || 'Unknown';
  }
  
  // Log connection open event
  ws.on('open', () => {
    console.log(`✅ [${connectionId}] WebSocket OPEN event fired`);
    console.log(`   Ready state: ${ws.readyState}`);
  });
  
  // Comprehensive error logging
  ws.on('error', (error) => {
    console.error(`❌ [${connectionId}] WebSocket ERROR event fired`);
    console.error(`   Error type: ${error?.constructor?.name || 'Unknown'}`);
    console.error(`   Error message: ${error?.message || 'No message'}`);
    console.error(`   Error code: ${error?.code || 'No code'}`);
    console.error(`   Error stack: ${error?.stack || 'No stack'}`);
    console.error(`   Stream SID: ${streamSid}`);
    console.error(`   Call SID: ${callSid || 'none'}`);
    console.error(`   Connection age: ${((Date.now() - connectionStartTime) / 1000).toFixed(2)}s`);
    console.error(`   Ready state: ${ws.readyState}`);
    console.error(`   Full error object:`, error);
  });
  
  // IMPORTANT: Twilio Media Streams is RECEIVE-ONLY
  // We should NOT send any messages to Twilio - only listen for incoming events
  // Twilio will send us: 'connected', 'start', 'media', 'stop' events
  // Sending messages to Twilio causes error 31924: "WebSocket Protocol Error - Reserved bits are non-zero"
  console.log(`   📡 [${connectionId}] Ready to receive Media Stream events from Twilio (receive-only mode)`);
  
  // Monitor connection state periodically
  const connectionMonitor = setInterval(() => {
    if (ws.readyState === 1) {
      // Connection is still open - good
      if (audioChunksReceived > 0 && audioChunksReceived % 100 === 0) {
        console.log(`   💓 Connection alive - ${audioChunksReceived} chunks received, ${totalAudioBytes} bytes`);
      }
    } else {
      console.warn(`   ⚠️  WebSocket state changed to: ${ws.readyState} - stopping monitor`);
      clearInterval(connectionMonitor);
    }
  }, 5000); // Check every 5 seconds
  
  // Close handler - handles connection cleanup
  ws.on('close', (code, reason) => {
    try {
      // Stop monitoring
      clearInterval(connectionMonitor);
      
      console.log(`📞 [${connectionId}] ========================================`);
      console.log(`📞 [${connectionId}] Media Stream connection CLOSED`);
      console.log(`   Connection ID: ${connectionId}`);
      console.log(`   Close code: ${code} (${getCloseCodeDescription(code)})`);
      console.log(`   Close reason: ${reason ? reason.toString() : 'none'} (type: ${typeof reason})`);
      console.log(`   Close reason buffer: ${Buffer.isBuffer(reason) ? reason.toString('hex') : 'N/A'}`);
      console.log(`   Stream SID: ${streamSid}`);
      console.log(`   Call SID: ${callSid || 'none'}`);
      console.log(`   Audio chunks received: ${audioChunksReceived}`);
      console.log(`   Total audio bytes: ${totalAudioBytes}`);
      console.log(`   Stream started: ${streamStarted}`);
      console.log(`   Connection duration: ${((Date.now() - connectionStartTime) / 1000).toFixed(2)}s`);
      console.log(`   Final ready state: ${ws.readyState}`);
      console.log(`   Timestamp: ${new Date().toISOString()}`);
      
      // Remove from active connections
      if (streamSid !== 'unknown') {
        const connectionKey = (streamSid !== 'unknown' && callSid) 
          ? `${streamSid}:${callSid}` 
          : streamSid;
        
        const existing = activeStreamConnections.get(connectionKey);
        // Only remove if this is the actual connection we're tracking
        if (existing && existing.ws === ws) {
          activeStreamConnections.delete(connectionKey);
          console.log(`   ✅ Removed connection ${connectionKey} from active connections`);
          console.log(`   Remaining active streams: ${activeStreamConnections.size}`);
        } else {
          console.log(`   ⚠️  Connection ${connectionKey} not found in active connections (may have been replaced)`);
        }
      }
      
      // If there's buffered audio and call ended without 'stop' event, transcribe it
      if (audioBuffer.length > 0 && streamStarted) {
        console.log('🔄 Call ended without stop event, transcribing buffered audio...');
        transcribeBufferedAudio().catch(error => {
          console.error('❌ Error in transcription callback on close:', error);
        });
      }
      
      // Clear buffer
      audioBuffer = [];
      audioChunksReceived = 0;
      totalAudioBytes = 0;
      streamStarted = false;
      
      console.log(`📞 [${connectionId}] Connection cleanup complete`);
      console.log(`📞 [${connectionId}] ========================================`);
    } catch (error) {
      console.error(`❌ [${connectionId}] Error in close handler:`, error);
      console.error(`   Error message: ${error?.message}`);
      console.error(`   Error stack: ${error?.stack}`);
    }
  });
  
  // Log ping/pong events if available
  if (ws.on) {
    ws.on('ping', (data) => {
      console.log(`🏓 [${connectionId}] PING received from Twilio`);
    });
    
    ws.on('pong', (data) => {
      console.log(`🏓 [${connectionId}] PONG received from Twilio`);
    });
  }
  
  // Log unhandled errors
  ws.on('unexpected-response', (request, response) => {
    console.error(`❌ [${connectionId}] Unexpected HTTP response`);
    console.error(`   Status: ${response.statusCode}`);
    console.error(`   Headers:`, response.headers);
  });
  
  console.log(`✅ [${connectionId}] All event handlers registered for connection`);
});

/**
 * Health check endpoint
 */
app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

/**
 * Test endpoint to verify /api/stream path is accessible
 */
app.get('/api/stream', (req, res) => {
  console.log('⚠️  GET request to /api/stream - this should be a WebSocket connection');
  res.status(426).json({ 
    error: 'Upgrade Required',
    message: 'This endpoint requires a WebSocket upgrade. Use ws:// or wss:// protocol.',
    websocketUrl: `wss://${req.get('host')}/api/stream`
  });
});

// Handle HTTP upgrade requests for WebSocket
// IMPORTANT: WebSocketServer handles its own upgrades, but we log here for debugging
// DO NOT call socket.destroy() or interfere with the upgrade process
server.on('upgrade', (request, socket, head) => {
  try {
    const pathname = new URL(request.url, `http://${request.headers.host}`).pathname;
    console.log(`🔄 HTTP Upgrade request received`);
    console.log(`   Path: ${pathname}`);
    console.log(`   Headers:`, JSON.stringify(request.headers, null, 2));
    console.log(`   Method: ${request.method}`);
    
    // WebSocketServer will handle /api/stream and /api/transcripts automatically
    // We should NOT interfere - just log and let WebSocketServer handle it
    if (pathname === '/api/stream' || pathname === '/api/transcripts') {
      console.log(`   ✅ WebSocket path recognized - WebSocketServer will handle upgrade`);
    } else {
      console.log(`   ⚠️  Unknown WebSocket path: ${pathname} - WebSocketServer will handle or reject`);
      // DO NOT destroy socket - let WebSocketServer handle it
    }
  } catch (error) {
    console.error('❌ Error in upgrade handler:', error);
    // Don't destroy socket on error - let WebSocketServer handle it
  }
});

// Start the server
server.listen(PORT, () => {
  console.log(`🚀 Call Assistant Backend running on http://localhost:${PORT}`);
  console.log(`📞 Twilio Phone Number: ${twilioPhoneNumber || 'Not configured'}`);
  console.log(`🔌 WebSocket server ready at ws://localhost:${PORT}/api/stream`);
  console.log(`🔌 Transcript WebSocket ready at ws://localhost:${PORT}/api/transcripts`);
  console.log(`\n📝 Setup Instructions:`);
  console.log(`   1. For local development, use ngrok: ngrok http ${PORT}`);
  console.log(`   2. Set MEDIA_STREAM_URL=wss://your-ngrok-url.ngrok.io/api/stream in .env`);
  console.log(`   3. Make sure your Twilio phone number is verified or you have a Twilio account\n`);
});

