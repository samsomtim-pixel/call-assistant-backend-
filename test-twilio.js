import dotenv from 'dotenv';
import twilio from 'twilio';

// Load environment variables
dotenv.config();

const accountSid = process.env.TWILIO_ACCOUNT_SID;
const authToken = process.env.TWILIO_AUTH_TOKEN;
const apiKey = process.env.TWILIO_API_KEY;
const apiSecret = process.env.TWILIO_API_SECRET;
const twilioPhoneNumber = process.env.TWILIO_PHONE_NUMBER;
const twimlAppSid = process.env.TWILIO_TWIML_APP_SID;

console.log('🧪 Testing Twilio Credentials...\n');
console.log('=' .repeat(50));

// Check if required variables are set
const missingVars = [];
if (!accountSid) missingVars.push('TWILIO_ACCOUNT_SID');
if (!authToken) missingVars.push('TWILIO_AUTH_TOKEN');
if (!apiKey) missingVars.push('TWILIO_API_KEY');
if (!apiSecret) missingVars.push('TWILIO_API_SECRET');
if (!twilioPhoneNumber) missingVars.push('TWILIO_PHONE_NUMBER');

if (missingVars.length > 0) {
  console.error('❌ Missing required environment variables:');
  missingVars.forEach(v => console.error(`   - ${v}`));
  process.exit(1);
}

// Initialize Twilio client
const client = twilio(accountSid, authToken);

// Test results
const results = {
  accountSid: { status: 'pending', message: '' },
  authToken: { status: 'pending', message: '' },
  twimlApp: { status: 'pending', message: '' },
  phoneNumber: { status: 'pending', message: '' },
};

/**
 * Test 1: Verify Account SID and Auth Token
 */
async function testAccountCredentials() {
  try {
    console.log('\n1️⃣  Testing Account SID and Auth Token...');
    
    const account = await client.api.accounts(accountSid).fetch();
    
    results.accountSid.status = 'success';
    results.authToken.status = 'success';
    results.accountSid.message = `Account: ${account.friendlyName || accountSid}`;
    results.authToken.message = `Status: ${account.status}`;
    
    console.log('   ✅ Account SID is valid');
    console.log(`   ✅ Auth Token is valid`);
    console.log(`   📋 Account Name: ${account.friendlyName || 'N/A'}`);
    console.log(`   📋 Account Status: ${account.status}`);
    console.log(`   📋 Account Type: ${account.type}`);
    
    return true;
  } catch (error) {
    results.accountSid.status = 'error';
    results.authToken.status = 'error';
    results.accountSid.message = error.message;
    results.authToken.message = error.message;
    
    console.log('   ❌ Account SID or Auth Token is invalid');
    console.log(`   ⚠️  Error: ${error.message}`);
    
    if (error.code === 20003) {
      console.log('   💡 This usually means the Account SID or Auth Token is incorrect');
    }
    
    return false;
  }
}

/**
 * Test 2: Verify TwiML App SID (if configured)
 */
async function testTwiMLApp() {
  if (!twimlAppSid) {
    results.twimlApp.status = 'skipped';
    results.twimlApp.message = 'TwiML App SID not configured (optional)';
    console.log('\n2️⃣  Testing TwiML App SID...');
    console.log('   ⚠️  TwiML App SID not configured (this is optional)');
    return true;
  }
  
  try {
    console.log('\n2️⃣  Testing TwiML App SID...');
    
    const app = await client.applications(twimlAppSid).fetch();
    
    results.twimlApp.status = 'success';
    results.twimlApp.message = `App: ${app.friendlyName || twimlAppSid}`;
    
    console.log('   ✅ TwiML App SID is valid');
    console.log(`   📋 App Name: ${app.friendlyName || 'N/A'}`);
    console.log(`   📋 Voice URL: ${app.voiceUrl || 'Not configured'}`);
    console.log(`   📋 Status Callback: ${app.statusCallback || 'Not configured'}`);
    
    return true;
  } catch (error) {
    results.twimlApp.status = 'error';
    results.twimlApp.message = error.message;
    
    console.log('   ❌ TwiML App SID is invalid or not accessible');
    console.log(`   ⚠️  Error: ${error.message}`);
    
    if (error.code === 20404) {
      console.log('   💡 This means the TwiML App SID does not exist or belongs to a different account');
    }
    
    return false;
  }
}

/**
 * Test 3: Verify Phone Number
 */
async function testPhoneNumber() {
  try {
    console.log('\n3️⃣  Testing Phone Number...');
    
    // Fetch the phone number details
    const incomingNumbers = await client.incomingPhoneNumbers.list({
      phoneNumber: twilioPhoneNumber,
      limit: 1
    });
    
    if (incomingNumbers.length === 0) {
      results.phoneNumber.status = 'error';
      results.phoneNumber.message = 'Phone number not found in your account';
      
      console.log('   ❌ Phone number not found in your Twilio account');
      console.log(`   📋 Searched for: ${twilioPhoneNumber}`);
      console.log('   💡 Make sure the phone number is purchased and active in your Twilio console');
      
      return false;
    }
    
    const phoneNumber = incomingNumbers[0];
    
    results.phoneNumber.status = 'success';
    results.phoneNumber.message = `Phone: ${phoneNumber.phoneNumber}`;
    
    console.log('   ✅ Phone number is valid and active');
    console.log(`   📋 Phone Number: ${phoneNumber.phoneNumber}`);
    console.log(`   📋 Friendly Name: ${phoneNumber.friendlyName || 'N/A'}`);
    console.log(`   📋 Status: Active`);
    console.log(`   📋 Voice URL: ${phoneNumber.voiceUrl || 'Not configured'}`);
    console.log(`   📋 Voice Method: ${phoneNumber.voiceMethod || 'Not configured'}`);
    
    // Check if phone number has voice capabilities
    if (phoneNumber.capabilities) {
      console.log(`   📋 Voice Enabled: ${phoneNumber.capabilities.voice ? 'Yes' : 'No'}`);
      console.log(`   📋 SMS Enabled: ${phoneNumber.capabilities.sms ? 'Yes' : 'No'}`);
    }
    
    return true;
  } catch (error) {
    results.phoneNumber.status = 'error';
    results.phoneNumber.message = error.message;
    
    console.log('   ❌ Error checking phone number');
    console.log(`   ⚠️  Error: ${error.message}`);
    
    return false;
  }
}

/**
 * Test 4: Verify API Key and Secret (optional check)
 */
async function testAPIKey() {
  if (!apiKey || !apiSecret) {
    console.log('\n4️⃣  Testing API Key and Secret...');
    console.log('   ⚠️  API Key or Secret not configured');
    return true;
  }
  
  try {
    console.log('\n4️⃣  Testing API Key and Secret...');
    
    // Create a test token to verify API Key/Secret
    const AccessToken = twilio.jwt.AccessToken;
    const VoiceGrant = AccessToken.VoiceGrant;
    
    const voiceGrant = new VoiceGrant({
      outgoingApplicationSid: twimlAppSid || undefined,
    });
    
    const token = new AccessToken(accountSid, apiKey, apiSecret, {
      identity: 'test-user',
      ttl: 3600,
    });
    
    token.addGrant(voiceGrant);
    const jwt = token.toJwt();
    
    if (jwt && jwt.length > 0) {
      console.log('   ✅ API Key and Secret are valid');
      console.log('   📋 Test token generated successfully');
      return true;
    } else {
      console.log('   ❌ Failed to generate token with API Key/Secret');
      return false;
    }
  } catch (error) {
    console.log('   ❌ API Key or Secret is invalid');
    console.log(`   ⚠️  Error: ${error.message}`);
    return false;
  }
}

/**
 * Run all tests
 */
async function runTests() {
  const testResults = [];
  
  testResults.push(await testAccountCredentials());
  testResults.push(await testTwiMLApp());
  testResults.push(await testPhoneNumber());
  testResults.push(await testAPIKey());
  
  // Summary
  console.log('\n' + '='.repeat(50));
  console.log('📊 Test Summary\n');
  
  console.log(`Account SID & Auth Token: ${results.accountSid.status === 'success' ? '✅' : '❌'} ${results.accountSid.message}`);
  console.log(`TwiML App SID:           ${results.twimlApp.status === 'success' ? '✅' : results.twimlApp.status === 'skipped' ? '⚠️ ' : '❌'} ${results.twimlApp.message}`);
  console.log(`Phone Number:            ${results.phoneNumber.status === 'success' ? '✅' : '❌'} ${results.phoneNumber.message}`);
  
  const allPassed = testResults.every(r => r === true);
  
  if (allPassed) {
    console.log('\n🎉 All tests passed! Your Twilio credentials are configured correctly.');
    process.exit(0);
  } else {
    console.log('\n⚠️  Some tests failed. Please check the errors above.');
    process.exit(1);
  }
}

// Run the tests
runTests().catch(error => {
  console.error('\n❌ Unexpected error:', error);
  process.exit(1);
});

