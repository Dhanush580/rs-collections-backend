const express = require('express');
const crypto = require('crypto');
const Razorpay = require('razorpay');

const router = express.Router();

function ensureKeys() {
  const key_id = (process.env.RAZORPAY_KEY_ID || '').trim();
  const key_secret = (process.env.RAZORPAY_KEY_SECRET || '').trim();
  if (!key_id || !key_secret) {
    const err = new Error('Missing RAZORPAY_KEY_ID/RAZORPAY_KEY_SECRET');
    err.status = 500;
    throw err;
  }
  return { key_id, key_secret };
}

function getInstance() {
  const { key_id, key_secret } = ensureKeys();
  return new Razorpay({ key_id, key_secret });
}

// GET /payments/health - returns presence (not values) of Razorpay env vars
router.get('/health', (req, res) => {
  const key_id_present = !!(process.env.RAZORPAY_KEY_ID && String(process.env.RAZORPAY_KEY_ID).trim());
  const key_secret_present = !!(process.env.RAZORPAY_KEY_SECRET && String(process.env.RAZORPAY_KEY_SECRET).trim());
  return res.json({ ok: true, key_id_present, key_secret_present });
});

// POST /payments/razorpay/order - create an order in Razorpay
router.post('/razorpay/order', async (req, res) => {
  try {
    const { amount, currency = 'INR', receipt, notes } = req.body || {};
    if (!amount || Number.isNaN(Number(amount)) || Number(amount) <= 0) {
      return res.status(400).json({ error: 'Valid amount (in paise) required' });
    }

    const instance = getInstance();
    const options = {
      amount: Math.round(Number(amount)), // in paise
      currency,
      receipt: receipt || `rcpt_${Date.now()}`,
      notes: notes || {},
    };

    const order = await instance.orders.create(options);
    return res.json({ order });
  } catch (err) {
    const msg = err?.error?.description || err?.message || 'Failed to create order';
    console.error('Razorpay order create error:', msg);
    return res.status(err.statusCode || err.status || 500).json({ error: msg });
  }
});

// POST /payments/razorpay/verify - verify signature from Razorpay checkout
router.post('/razorpay/verify', async (req, res) => {
  try {
    const { razorpay_order_id, razorpay_payment_id, razorpay_signature } = req.body || {};
    if (!razorpay_order_id || !razorpay_payment_id || !razorpay_signature) {
      return res.status(400).json({ error: 'Missing verification fields' });
    }

    const { key_secret } = ensureKeys();
    const hmac = crypto.createHmac('sha256', key_secret);
    hmac.update(`${razorpay_order_id}|${razorpay_payment_id}`);
    const digest = hmac.digest('hex');

    const valid = digest === razorpay_signature;
    if (!valid) return res.status(400).json({ error: 'Signature mismatch' });
    return res.json({ success: true });
  } catch (err) {
    const msg = err?.message || 'Verification failed';
    console.error('Razorpay verify error:', msg);
    return res.status(500).json({ error: msg });
  }
});

module.exports = router;
