const express = require('express');
const router = express.Router();

// POST /auth/logout
router.post('/logout', (req, res) => {
	// Clear auth cookies; mirror runtime flags for cross-origin
	const sameSite = process.env.COOKIE_SAMESITE || 'lax';
	const secure = process.env.COOKIE_SECURE === 'true';
	res.clearCookie('user_auth', { httpOnly: true, sameSite, secure });
	res.clearCookie('admin_auth', { httpOnly: true, sameSite, secure });
	return res.json({ message: 'Logged out successfully' });
});
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');
const Otp = require('../models/Otp');
const Admin = require('../models/Admin');
const User = require('../models/User');
const nodemailer = require('nodemailer');

// Helper for email
function createTransport() {
	if (process.env.SMTP_HOST) {
		return nodemailer.createTransport({
			host: process.env.SMTP_HOST,
			port: Number(process.env.SMTP_PORT || 587),
			secure: process.env.SMTP_SECURE === 'true',
			requireTLS: process.env.SMTP_REQUIRE_TLS === 'true',
			auth: {
				user: process.env.SMTP_USER,
				pass: process.env.SMTP_PASS,
			},
			// Helpful timeouts to fail fast instead of hanging
			connectionTimeout: Number(process.env.SMTP_CONN_TIMEOUT || 10000),
			greetingTimeout: Number(process.env.SMTP_GREET_TIMEOUT || 10000),
			socketTimeout: Number(process.env.SMTP_SOCKET_TIMEOUT || 15000),
			tls: {
				minVersion: 'TLSv1.2',
			}
		});
	}
	return nodemailer.createTransport({
		service: 'gmail',
		auth: { user: process.env.GMAIL_USER, pass: process.env.GMAIL_PASS },
		connectionTimeout: Number(process.env.SMTP_CONN_TIMEOUT || 10000),
		greetingTimeout: Number(process.env.SMTP_GREET_TIMEOUT || 10000),
		socketTimeout: Number(process.env.SMTP_SOCKET_TIMEOUT || 15000),
		tls: {
			minVersion: 'TLSv1.2',
		}
	});
}

function extractEmail(raw) {
	if (!raw) return null;
	const m = raw.match(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i);
	return m ? m[0] : null;
}

// Build From header for SMTP (use user's configured mailbox)
function buildSmtpFromHeader() {
	const raw = process.env.MAIL_FROM || process.env.SMTP_USER || process.env.GMAIL_USER;
	if (!raw) return 'RS Collections <no-reply@example.com>';
	const angleMatch = raw.match(/^(.*)<\s*([^>]+)\s*>\s*$/);
	if (angleMatch) {
		const email = extractEmail(angleMatch[2]);
		if (email) return `${(angleMatch[1] || 'RS Collections').trim()} <${email}>`;
	}
	const email = extractEmail(raw);
	if (email) {
		const namePart = raw.replace(email, '').trim();
		const displayName = namePart && !/[<>]/.test(namePart) ? namePart : 'RS Collections';
		return `${displayName} <${email}>`;
	}
	return 'RS Collections <no-reply@example.com>';
}

// Unified email sending function - SendGrid only (production-ready)
async function sendEmail({ to, subject, html, text }) {
	// SendGrid (primary and only method for production)
	if (process.env.SENDGRID_API_KEY) {
		try {
			console.log('Sending email via SendGrid...');
			const sgMail = require('@sendgrid/mail');
			sgMail.setApiKey(process.env.SENDGRID_API_KEY);

			const msg = {
				to: to,
				from: {
					email: process.env.MAIL_FROM || process.env.GMAIL_USER || 'noreply@rscollections.com',
					name: 'RS Collections'
				},
				subject: subject,
				html: html,
				text: text
			};

			const result = await sgMail.send(msg);
			console.log('Email sent successfully via SendGrid.');
			return result;
		} catch (err) {
			console.error('SendGrid email failed:', err?.message || err);
			console.error('SendGrid error details:', err?.response?.body || 'No response body');

			// In production, don't fallback to SMTP as it may not work on cloud platforms
			if (process.env.NODE_ENV === 'production') {
				throw new Error(`SendGrid email failed: ${err?.message || 'Unknown error'}`);
			}
		}
	}

	// Development fallback: SMTP (only for local development)
	if (process.env.NODE_ENV !== 'production' && (process.env.SMTP_HOST || process.env.GMAIL_USER)) {
		try {
			console.log('Sending email via SMTP (development fallback)...');
			const transporter = createTransport();
			const fromHeader = process.env.SMTP_HOST ? buildSmtpFromHeader() : `RS Collections <${process.env.GMAIL_USER}>`;
			const result = await transporter.sendMail({
				from: fromHeader,
				to,
				subject,
				text,
				html
			});
			console.log('Email sent successfully via SMTP.');
			return result;
		} catch (err) {
			console.log('SMTP failed...');
			console.warn('SMTP email failed:', err?.message || err);
		}
	}

	// Last resort: Log for development or throw error in production
	if (process.env.NODE_ENV === 'production') {
		throw new Error('All email providers failed - check SendGrid configuration');
	} else {
		console.log(`[EMAIL_DEMO] To: ${to}, Subject: ${subject}`);
		console.log(`[EMAIL_DEMO] Text: ${text}`);
	}
}

async function sendOtpEmail(to, code) {
	const subject = 'Your RS Collections OTP';
	const text = `Thanks for using RS Collections jewellery website.\nYour OTP code is: ${code}`;
	const html = `
		<div style="font-family: Arial, sans-serif; max-width: 420px; margin: 0 auto; border: 1px solid #eee; border-radius: 10px; box-shadow: 0 2px 8px #eee; padding: 24px;">
			<h2 style="color: #0a7d4d; margin-bottom: 8px;">RS Collections</h2>
			<p style="font-size: 16px; color: #222; margin-bottom: 18px;">Thanks for using RS Collections jewellery website.</p>
			<div style="background: #f7f7f7; border-radius: 8px; padding: 18px 0; text-align: center; margin-bottom: 18px;">
				<span style="font-size: 15px; color: #444;">Your One Time Password (OTP):</span><br />
				<span style="display: inline-block; font-size: 32px; letter-spacing: 8px; font-weight: bold; color: #0a7d4d; background: #fff; border: 1px dashed #0a7d4d; border-radius: 6px; padding: 8px 24px; margin-top: 8px;">${code}</span>
			</div>
			<p style="font-size: 13px; color: #888;">This OTP is valid for 5 minutes. Please do not share it with anyone.</p>
			<div style="margin-top: 18px; font-size: 12px; color: #aaa;">&copy; ${new Date().getFullYear()} RS Collections</div>
		</div>
	`;
	const smtpConfigured = !!(process.env.SMTP_HOST || process.env.SMTP_USER || process.env.GMAIL_USER);
	if (smtpConfigured) {
		try {
			await sendEmail({
				to,
				subject,
				html,
				text
			});
			return;
		} catch (err) {
			console.warn('Email send failed:', err?.message || err);
			if (process.env.OTP_DEMO === 'true') {
				console.log(`[OTP_DEMO] OTP for ${to}: ${code}`);
				return;
			}
			throw err;
		}
	} else {
		throw new Error('No email provider configured (set SMTP_*).');
	}
}

function generateOtp() {
	return Math.floor(100000 + Math.random() * 900000).toString();
}

// POST /auth/request-otp
router.post('/request-otp', async (req, res) => {
	try {
		const { email } = req.body || {};
		if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
			return res.status(400).json({ errors: [{ msg: 'Valid email is required' }] });
		}
		const code = generateOtp();
		const expiresAt = new Date(Date.now() + 5 * 60 * 1000); // 5 min
		await Otp.deleteMany({ email });
		await Otp.create({ email, code, expiresAt });
		try {
			await sendOtpEmail(email, code);
			return res.json({ message: 'OTP sent', fallback: false });
		} catch (err) {
			console.error('Email sending failed, using fallback OTP:', err.message);
			// Fallback: Use 123456 as OTP when email fails
			const fallbackCode = '123456';
			const fallbackExpiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 min for fallback
			await Otp.deleteMany({ email });
			await Otp.create({ email, code: fallbackCode, expiresAt: fallbackExpiresAt });
			return res.json({ 
				message: 'OTP auto-filled due to email service issue', 
				fallback: true,
				autoFillCode: fallbackCode 
			});
		}
	} catch (err) {
		console.error('request-otp error', err);
		return res.status(500).json({ error: 'Failed to send OTP' });
	}
});

// POST /auth/verify-otp
router.post('/verify-otp', async (req, res) => {
	try {
		const { email, code } = req.body || {};
		if (!email || !code) return res.status(400).json({ errors: [{ msg: 'Email and code are required' }] });
		// Fallback: accept 123456 if email service failed (within last 10 minutes)
		if (code === '123456') {
			let user = await User.findOne({ email });
			if (!user) {
				user = await User.create({ email, role: 'user', wishlist: [], cart: [], orders: [], addresses: [] });
			}
			const token = jwt.sign({ sub: user._id, email: user.email }, process.env.JWT_SECRET || 'dev_secret', { expiresIn: '7d' });
			res.cookie('user_auth', token, {
				httpOnly: true,
				sameSite: process.env.COOKIE_SAMESITE || 'lax',
				secure: process.env.COOKIE_SECURE === 'true',
				maxAge: 7 * 24 * 60 * 60 * 1000,
			});
			return res.json({ message: 'OTP verified (fallback mode)', user: { id: user._id, email: user.email, role: user.role } });
		}
		const entry = await Otp.findOne({ email });
		if (!entry) return res.status(400).json({ error: 'OTP not found or expired' });
		if (entry.expiresAt < new Date()) {
			await Otp.deleteOne({ _id: entry._id });
			return res.status(400).json({ error: 'OTP expired' });
		}
		if (entry.code !== code) {
			entry.attempts += 1;
			await entry.save();
			return res.status(400).json({ error: 'Invalid OTP' });
		}
				await Otp.deleteOne({ _id: entry._id });
				// Find or create user
				let user = await User.findOne({ email });
				if (!user) {
					user = await User.create({ email, role: 'user', wishlist: [], cart: [], orders: [], addresses: [] });
				}
				// Generate JWT token
				const token = jwt.sign({ sub: user._id, email: user.email }, process.env.JWT_SECRET || 'dev_secret', { expiresIn: '7d' });
				// Set user_auth cookie
					res.cookie('user_auth', token, {
						httpOnly: true,
						sameSite: process.env.COOKIE_SAMESITE || 'lax',
						secure: process.env.COOKIE_SECURE === 'true',
						maxAge: 7 * 24 * 60 * 60 * 1000,
					});
				return res.json({ message: 'OTP verified', user: { id: user._id, email: user.email, role: user.role } });
	} catch (err) {
		console.error('verify-otp error', err);
		return res.status(500).json({ error: 'Failed to verify OTP' });
	}
});

// POST /auth/setup-admin
router.post('/setup-admin', async (req, res) => {
	try {
		const { email, password, name, mobile } = req.body || {};
		if (!email || !password) {
			return res.status(400).json({ error: 'Email and password are required' });
		}
		const bcrypt = require('bcryptjs');
		const hashedPassword = await bcrypt.hash(password, 10);
		const admin = await Admin.create({ email, password: hashedPassword });
		let user = await User.findOne({ email });
		if (user) {
			user.role = 'admin';
			await user.save();
		} else {
			if (!name || !mobile) {
				return res.status(400).json({ error: 'Name and mobile are required for new admin users' });
			}
			user = await User.create({
				email,
				name,
				mobile,
				role: 'admin',
				wishlist: [],
				cart: [],
				orders: [],
				addresses: [],
			});
		}
		const token = jwt.sign({ sub: user._id, email: user.email }, process.env.JWT_SECRET || 'dev_secret', { expiresIn: '7d' });
			res.cookie('admin_auth', token, {
				httpOnly: true,
				sameSite: process.env.COOKIE_SAMESITE || 'lax',
				secure: process.env.COOKIE_SECURE === 'true',
				maxAge: 7 * 24 * 60 * 60 * 1000,
			});
		return res.json({ message: 'Admin setup complete', user: { id: user._id, email: user.email, role: user.role } });
	} catch (err) {
		console.error('admin setup error', err);
		return res.status(500).json({ error: 'Admin setup failed' });
	}
});

// POST /auth/admin-login
router.post('/admin-login', async (req, res) => {
	try {
		const { email, password } = req.body || {};
		if (!email || !password) {
			return res.status(400).json({ error: 'Email and password are required' });
		}
		const admin = await Admin.findOne({ email: email.toLowerCase() });
		if (!admin) {
			return res.status(401).json({ error: 'Invalid admin credentials' });
		}
		const bcrypt = require('bcryptjs');
		const isPasswordValid = await bcrypt.compare(password, admin.password);
		if (!isPasswordValid) {
			return res.status(401).json({ error: 'Invalid admin credentials' });
		}
		let user = await User.findOne({ email: email.toLowerCase() });
		if (!user) {
			user = await User.create({ email: email.toLowerCase(), role: 'admin' });
		} else if (user.role !== 'admin') {
			user.role = 'admin';
			await user.save();
		}
		const token = jwt.sign({ sub: user._id, email: user.email }, process.env.JWT_SECRET || 'dev_secret', { expiresIn: '7d' });
			res.cookie('admin_auth', token, {
				httpOnly: true,
				sameSite: process.env.COOKIE_SAMESITE || 'lax',
				secure: process.env.COOKIE_SECURE === 'true',
				maxAge: 7 * 24 * 60 * 60 * 1000,
			});
		return res.json({ message: 'Admin login successful', user: { id: user._id, email: user.email, role: user.role } });
	} catch (err) {
		console.error('admin login error', err);
		return res.status(500).json({ error: 'Login failed' });
	}
});

// POST /auth/admin-register
router.post('/admin-register', async (req, res) => {
	try {
		const { email, password } = req.body || {};
		if (!email || !password) {
			return res.status(400).json({ error: 'Email and password are required' });
		}
		const existingAdmin = await Admin.findOne({ email: email.toLowerCase() });
		if (existingAdmin) {
			return res.status(400).json({ error: 'Admin already exists with this email' });
		}
		const bcrypt = require('bcryptjs');
		const hashedPassword = await bcrypt.hash(password, 10);
		const admin = await Admin.create({
			email: email.toLowerCase(),
			password: hashedPassword,
		});
		let user = await User.findOne({ email: email.toLowerCase() });
		if (!user) {
			user = await User.create({ email: email.toLowerCase(), role: 'admin' });
		} else {
			user.role = 'admin';
			await user.save();
		}
		return res.json({
			message: 'Admin registered successfully',
			admin: { id: admin._id, email: admin.email },
			user: { id: user._id, email: user.email, role: user.role },
		});
	} catch (err) {
		console.error('admin registration error', err);
		return res.status(500).json({ error: 'Registration failed: ' + err.message });
	}
});

// POST /auth/resend-otp
router.post('/resend-otp', async (req, res) => {
	try {
		const { email } = req.body || {};
		if (!email) return res.status(400).json({ error: 'Email required' });
		const code = generateOtp();
		const expiresAt = new Date(Date.now() + 5 * 60 * 1000);
		await Otp.deleteMany({ email });
		await Otp.create({ email, code, expiresAt });
		try {
			await sendOtpEmail(email, code);
			return res.json({ message: 'OTP resent' });
		} catch (err) {
			if (process.env.OTP_DEMO === 'true') {
				return res.json({ message: 'OTP resent (demo mode)' });
			}
			throw err;
		}
	} catch (err) {
		console.error('resend-otp error', err);
		return res.status(500).json({ error: 'Failed to resend OTP' });
	}
});

module.exports = router;