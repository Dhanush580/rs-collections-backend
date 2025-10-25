require('dotenv').config();
const sgMail = require('@sendgrid/mail');

async function testSendGrid() {
  console.log('Testing SendGrid API key and configuration...');
  console.log('NODE_ENV:', process.env.NODE_ENV || 'undefined (defaults to development)');
  console.log('SENDGRID_API_KEY present:', !!process.env.SENDGRID_API_KEY);
  console.log('MAIL_FROM:', process.env.MAIL_FROM || 'not set');
  console.log('GMAIL_USER:', process.env.GMAIL_USER || 'not set');

  if (!process.env.SENDGRID_API_KEY) {
    console.error('❌ SENDGRID_API_KEY not found in environment variables');
    console.log('💡 Make sure to set SENDGRID_API_KEY in your Render environment variables');
    return;
  }

  sgMail.setApiKey(process.env.SENDGRID_API_KEY);

  const fromEmail = process.env.MAIL_FROM || process.env.GMAIL_USER;
  console.log('📧 Will use from email:', fromEmail || 'noreply@rscollections.com');

  // Test by actually trying to send an email (to yourself)
  const testEmail = process.env.GMAIL_USER || 'test@example.com';
  console.log('📧 Testing email send to:', testEmail);

  const msg = {
    to: testEmail,
    from: {
      email: fromEmail || 'noreply@rscollections.com',
      name: 'RS Collections Test'
    },
    subject: 'SendGrid Test - RS Collections',
    text: 'This is a test email from RS Collections. If you receive this, SendGrid is working!',
    html: '<strong>This is a test email from RS Collections.</strong><br>If you receive this, SendGrid is working!',
  };

  try {
    const result = await sgMail.send(msg);
    console.log('✅ SendGrid test successful! Email sent.');
    console.log('Message ID:', result[0]?.headers?.['x-message-id'] || 'N/A');
  } catch (error) {
    console.log('❌ SendGrid email test failed:');
    console.log('Error message:', error.message);
    console.log('Error code:', error.code);
    if (error.response) {
      console.log('Response body:', JSON.stringify(error.response.body, null, 2));
    }
    console.log('\n💡 Possible issues:');
    console.log('1. Sender email not verified in SendGrid');
    console.log('2. API key permissions insufficient');
    console.log('3. Domain authentication required');
    console.log('\n🔧 Solutions:');
    console.log('1. Go to SendGrid dashboard > Settings > Sender Authentication');
    console.log('2. Verify your sender email: pkveeragautham10@gmail.com');
    console.log('3. Check API key permissions in SendGrid dashboard');
  }

  console.log('\n📋 Next steps for Render deployment:');
  console.log('1. Go to your Render dashboard > Service > Environment');
  console.log('2. Add these environment variables:');
  console.log('   - SENDGRID_API_KEY = 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');
  console.log('   - MAIL_FROM = pkveeragautham10@gmail.com');
  console.log('   - NODE_ENV = production');
  console.log('3. Redeploy your service');
  console.log('4. Test email sending');
}

testSendGrid();