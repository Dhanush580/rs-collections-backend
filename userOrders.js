// backend/userOrders.js

const express = require('express');
const router = express.Router();
const User = require('./models/User');
const Order = require('./models/Order');

// CORS is applied globally in index.js; avoid setting per-router CORS to prevent duplicate headers


// Get orders for a specific user (from Order collection by userEmail)
router.get('/:email', async (req, res) => {
  try {
    const { email } = req.params;
    // Find orders directly by userEmail instead of relying on user.orders array
    const orders = await Order.find({ userEmail: email }).sort({ createdAt: -1 });
    return res.json({ orders });
  } catch (err) {
    console.error('Get user orders error:', err);
    return res.status(500).json({ error: 'Failed to get user orders' });
  }
});

module.exports = router;
