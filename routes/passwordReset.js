const { Router } = require('express');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const { getDb } = require('../db');

const router = Router();

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

router.get('/forgot-password', (req, res) => {
  res.render('forgot-password', { error: null, success: null });
});

router.post('/forgot-password', async (req, res) => {
  const { email } = req.body;
  if (!email) {
    return res.render('forgot-password', { error: 'Email is required.', success: null });
  }

  try {
    const db = getDb();
    const members = db.collection('members');
    const admins = db.collection('admins');

    const user = await members.findOne({ email }) || await admins.findOne({ email });
    if (!user) {
      return res.render('forgot-password', { error: null, success: 'If an account with that email exists, a password reset link has been sent.' });
    }

    const token = crypto.randomBytes(32).toString('hex');
    const expiresAt = new Date(Date.now() + 60 * 60 * 1000);

    const passwordResets = db.collection('password_resets');
    await passwordResets.insertOne({
      email,
      token,
      expiresAt,
      used: false,
      created_at: new Date(),
    });

    const baseUrl = `${req.protocol}://${req.get('host')}`;
    const resetLink = `${baseUrl}/reset-password/${token}`;

    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Password Reset - Royal Rangers Nigeria Southwest Zone 2',
      html: `
        <p>You requested a password reset.</p>
        <p>Click the link below to reset your password. This link expires in 1 hour.</p>
        <p><a href="${resetLink}">${resetLink}</a></p>
        <p>If you did not request this, please ignore this email.</p>
      `,
    });

    res.render('forgot-password', { error: null, success: 'If an account with that email exists, a password reset link has been sent.' });
  } catch (err) {
    console.error('Forgot password error:', err);
    res.render('forgot-password', { error: 'Unable to process request. Please try again later.', success: null });
  }
});

router.get('/reset-password/:token', async (req, res) => {
  const { token } = req.params;

  try {
    const db = getDb();
    const passwordResets = db.collection('password_resets');

    const record = await passwordResets.findOne({ token, used: false, expiresAt: { $gt: new Date() } });
    if (!record) {
      return res.render('reset-password', { error: 'Invalid or expired reset link.', success: null, token: null });
    }

    res.render('reset-password', { error: null, success: null, token });
  } catch (err) {
    console.error('Reset password page error:', err);
    res.status(500).send('Unable to process request.');
  }
});

router.post('/reset-password/:token', async (req, res) => {
  const { token } = req.params;
  const { password, confirmPassword } = req.body;

  if (!password || !confirmPassword) {
    return res.render('reset-password', { error: 'Both password fields are required.', success: null, token });
  }

  if (password.length < 6) {
    return res.render('reset-password', { error: 'Password must be at least 6 characters.', success: null, token });
  }

  if (password !== confirmPassword) {
    return res.render('reset-password', { error: 'Passwords do not match.', success: null, token });
  }

  try {
    const db = getDb();
    const passwordResets = db.collection('password_resets');

    const record = await passwordResets.findOne({ token, used: false, expiresAt: { $gt: new Date() } });
    if (!record) {
      return res.render('reset-password', { error: 'Invalid or expired reset link.', success: null, token: null });
    }

    const password_hash = await bcrypt.hash(password, 10);

    const members = db.collection('members');
    const admins = db.collection('admins');

    const memberResult = await members.updateOne({ email: record.email }, { $set: { password_hash, updated_at: new Date() } });
    if (memberResult.matchedCount === 0) {
      await admins.updateOne({ email: record.email }, { $set: { password_hash } });
    }

    await passwordResets.updateOne({ token }, { $set: { used: true } });

    res.render('reset-password', { error: null, success: 'Password has been reset successfully. You can now log in.', token: null });
  } catch (err) {
    console.error('Reset password error:', err);
    res.render('reset-password', { error: 'Unable to reset password. Please try again.', success: null, token });
  }
});

module.exports = router;
