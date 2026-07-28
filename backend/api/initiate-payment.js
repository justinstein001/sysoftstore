const axios = require('axios');

module.exports = async (req, res) => {
  // Allow only POST requests
  if (req.method !== 'POST') {
    return res.status(405).json({ success: false, error: 'Method not allowed' });
  }

  try {
    const amount = Number(req.body.amount);
    let phone = String(req.body.phone || '').trim().replace(/[\s+-]/g, '');
    if (phone.startsWith('0')) phone = `250${phone.slice(1)}`;

    if (!Number.isFinite(amount) || amount <= 0 || !/^2507\d{8}$/.test(phone)) {
      return res.status(400).json({ success: false, error: 'Enter a valid Rwandan phone number and amount.' });
    }

    if (!process.env.PAYPACK_CLIENT_ID || !process.env.PAYPACK_CLIENT_SECRET) {
      return res.status(503).json({ success: false, error: 'Payment gateway is not configured.' });
    }

    // 1. Authorize with Paypack
    const auth = await axios.post('https://payments.paypack.rw/api/auth/agents/authorize', { 
      client_id: process.env.PAYPACK_CLIENT_ID, 
      client_secret: process.env.PAYPACK_CLIENT_SECRET 
    }, { timeout: 15000 });

    // 2. Trigger Cash-in (USSD prompt to phone)
    const payment = await axios.post('https://payments.paypack.rw/api/transactions/cashin', { 
      amount, 
      number: phone 
    }, { 
      headers: { Authorization: `Bearer ${auth.data.access}` }, 
      timeout: 15000 
    });

    return res.json({ success: true, txRef: payment.data.ref });
  } catch (error) {
    const statusCode = error.response?.status || 500;
    const errorMessage = error.response?.data?.message || error.message || 'Payment request failed.';
    return res.status(statusCode).json({ success: false, error: errorMessage });
  }
};