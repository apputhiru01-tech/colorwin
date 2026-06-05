require('dotenv').config();
const dns = require('dns');
dns.setServers(['8.8.8.8', '8.8.4.4', '1.1.1.1']);
const express    = require('express');
const http       = require('http');
const { Server } = require('socket.io');
const mongoose   = require('mongoose');
const bcrypt     = require('bcryptjs');
const jwt        = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const { OAuth2Client } = require('google-auth-library');
const Razorpay   = require('razorpay');
const crypto     = require('crypto');
const path       = require('path');
const cors       = require('cors');

// ════════════════════════════════════════
//  APP SETUP
// ════════════════════════════════════════
const app    = express();
const server = http.createServer(app);
const io     = new Server(server, { cors: { origin: '*' } });

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

let maintenanceMode = false;
app.get('/api/maintenance', (req, res) => res.json({ maintenance: maintenanceMode }));

// ════════════════════════════════════════
//  MONGODB
// ════════════════════════════════════════
mongoose.connect(process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/colorwin')
  .then(() => console.log('✅ MongoDB connected'))
  .catch(e  => console.error('❌ MongoDB error:', e.message));

// ── Models ──────────────────────────────
const UserSchema = new mongoose.Schema({
  name:          { type: String, required: true },
  username:      { type: String, unique: true, lowercase: true, trim: true },
  email:         { type: String, unique: true, lowercase: true, trim: true },
  password:      { type: String, default: '' },
  phone:         { type: String, default: '' },
  upiId:         { type: String, default: '' },
  wallet:        { type: Number, default: 0 },
  loginMethod:   { type: String, enum: ['email','google'], default: 'email' },
  isVerified:    { type: Boolean, default: false },
  totalBets:     { type: Number, default: 0 },
  totalWins:     { type: Number, default: 0 },
  totalWinAmount:{ type: Number, default: 0 },
  totalLost:     { type: Number, default: 0 },
}, { timestamps: true });
const User = mongoose.model('User', UserSchema);

const RoundSchema = new mongoose.Schema({
  number:      { type: Number, required: true, unique: true },
  result:      { type: String, enum: ['red','green','violet'] },
  totalBets:   { type: Number, default: 0 },
  totalAmount: { type: Number, default: 0 },
  totalPayout: { type: Number, default: 0 },
  forcedBy:    { type: String, default: null },
}, { timestamps: true });
const Round = mongoose.model('Round', RoundSchema);

const BetSchema = new mongoose.Schema({
  userId:      { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  roundNumber: { type: Number, required: true },
  color:       { type: String, enum: ['red','green','violet'], required: true },
  amount:      { type: Number, required: true },
  result:      { type: String, enum: ['red','green','violet'] },
  win:         { type: Boolean },
  payout:      { type: Number, default: 0 },
}, { timestamps: true });
const Bet = mongoose.model('Bet', BetSchema);

const WithdrawalSchema = new mongoose.Schema({
  userId:      { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  amount:      { type: Number, required: true },
  upiId:       { type: String, required: true },
  status:      { type: String, enum: ['pending','approved','rejected'], default: 'pending' },
  processedAt: { type: Date },
  adminNote:   { type: String, default: '' },
}, { timestamps: true });
const Withdrawal = mongoose.model('Withdrawal', WithdrawalSchema);

const OtpSchema = new mongoose.Schema({
  email:     { type: String, required: true, lowercase: true },
  otp:       { type: String, required: true },
  expiresAt: { type: Date, required: true },
  used:      { type: Boolean, default: false },
}, { timestamps: true });
const Otp = mongoose.model('Otp', OtpSchema);

const DepositSchema = new mongoose.Schema({
  userId:    { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  orderId:   { type: String },
  paymentId: { type: String },
  amount:    { type: Number, required: true },
  status:    { type: String, enum: ['created','paid','failed'], default: 'created' },
}, { timestamps: true });
const Deposit = mongoose.model('Deposit', DepositSchema);

// Manual UPI deposit requests
const ManualDepositSchema = new mongoose.Schema({
  userId:      { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  amount:      { type: Number, required: true },
  utrNumber:   { type: String, required: true, trim: true },
  senderUpi:   { type: String, default: '' },
  screenshot:  { type: String, default: '' },
  status:      { type: String, enum: ['pending','approved','rejected'], default: 'pending' },
  adminNote:   { type: String, default: '' },
  processedAt: { type: Date },
}, { timestamps: true });
const ManualDeposit = mongoose.model('ManualDeposit', ManualDepositSchema);

// ════════════════════════════════════════
//  CONFIG / SERVICES
// ════════════════════════════════════════
const JWT_SECRET   = process.env.JWT_SECRET   || 'colorwin_dev_secret_2024';
const ADMIN_USER   = process.env.ADMIN_USERNAME || 'admin';
const ADMIN_PASS   = process.env.ADMIN_PASSWORD || 'Admin@123';
const GOOGLE_ID    = process.env.GOOGLE_CLIENT_ID || '';
const googleClient = GOOGLE_ID ? new OAuth2Client(GOOGLE_ID) : null;

const razorpay = (process.env.RAZORPAY_KEY_ID && process.env.RAZORPAY_KEY_SECRET)
  ? new Razorpay({ key_id: process.env.RAZORPAY_KEY_ID, key_secret: process.env.RAZORPAY_KEY_SECRET })
  : null;

// Email transporter
let mailer = null;
if (process.env.EMAIL_USER && process.env.EMAIL_PASS) {
  mailer = nodemailer.createTransport({
    service: 'gmail',
    auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS },
  });
}

async function sendOtpEmail(email, otp) {
  if (!mailer) {
    console.log(`\n📧  OTP for ${email}  →  ${otp}\n`);
    return { devOtp: otp };
  }
  try {
    await mailer.sendMail({
      from: `ColorWin <${process.env.EMAIL_USER}>`,
      to: email,
      subject: `${otp} is your ColorWin OTP`,
      html: `
        <div style="background:#0d0f1a;padding:32px;border-radius:16px;font-family:sans-serif;max-width:420px;margin:auto;">
          <h2 style="color:#ffd84d;margin:0 0 6px;">ColorWin</h2>
          <p style="color:#7880a0;margin:0 0 20px;">Your verification code:</p>
          <div style="font-size:48px;font-weight:900;letter-spacing:8px;color:#5b8fff;">${otp}</div>
          <p style="color:#7880a0;margin-top:20px;font-size:13px;">Valid for 10 minutes. Never share this code.</p>
        </div>`,
    });
  } catch(emailErr) {
    console.log(`\n📧  Email failed, OTP for ${email}  →  ${otp}\n`);
    return { devOtp: otp };
  }
}

// ════════════════════════════════════════
//  MIDDLEWARE
// ════════════════════════════════════════
function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token provided' });
  try { req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch { res.status(401).json({ error: 'Invalid or expired token' }); }
}

function adminMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token' });
  try {
    const d = jwt.verify(token, JWT_SECRET);
    if (!d.isAdmin) return res.status(403).json({ error: 'Admin access only' });
    req.admin = d; next();
  } catch { res.status(401).json({ error: 'Invalid token' }); }
}

// ════════════════════════════════════════
//  PUBLIC CONFIG ENDPOINT
// ════════════════════════════════════════
app.get('/api/config', (req, res) => {
  res.json({
    googleClientId:  GOOGLE_ID || null,
    razorpayKey:     process.env.RAZORPAY_KEY_ID || null,
    hasEmail:        !!mailer,
    adminUpiId:      process.env.ADMIN_UPI_ID   || '',
    adminUpiName:    process.env.ADMIN_UPI_NAME || 'ColorWin',
    minDeposit:      parseInt(process.env.MIN_DEPOSIT || '50'),
  });
});

// ════════════════════════════════════════
//  MANUAL DEPOSIT ROUTES
// ════════════════════════════════════════

// Submit manual UPI deposit request
app.post('/api/deposit/manual', authMiddleware, async (req, res) => {
  try {
    const { amount, utrNumber, senderUpi } = req.body;
    const minDep = parseInt(process.env.MIN_DEPOSIT || '50');
    if (!amount || amount < minDep)
      return res.status(400).json({ error: `Minimum deposit is ₹${minDep}` });
    if (!utrNumber || utrNumber.trim().length < 6)
      return res.status(400).json({ error: 'Enter valid UTR / Transaction ID' });

    // Prevent duplicate UTR
    const exists = await ManualDeposit.findOne({ utrNumber: utrNumber.trim() });
    if (exists) return res.status(400).json({ error: 'This UTR number is already submitted' });

    const dep = await ManualDeposit.create({
      userId:    req.user.userId,
      amount,
      utrNumber: utrNumber.trim(),
      senderUpi: senderUpi || '',
    });

    res.json({ success: true, requestId: dep._id });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Submission failed' }); }
});

// Get user's own deposit requests
app.get('/api/deposit/my', authMiddleware, async (req, res) => {
  try {
    const deps = await ManualDeposit.find({ userId: req.user.userId }).sort({ createdAt: -1 }).limit(20);
    res.json({ deposits: deps });
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

// Admin — get all manual deposit requests
app.get('/api/admin/deposits/manual', adminMiddleware, async (req, res) => {
  try {
    const deps = await ManualDeposit.find()
      .populate('userId', 'name username email phone')
      .sort({ createdAt: -1 });
    res.json({ deposits: deps });
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

// Admin — approve or reject manual deposit
app.put('/api/admin/deposits/manual/:id', adminMiddleware, async (req, res) => {
  try {
    const { status, adminNote } = req.body;
    const dep = await ManualDeposit.findById(req.params.id);
    if (!dep) return res.status(404).json({ error: 'Request not found' });
    if (dep.status !== 'pending') return res.status(400).json({ error: 'Already processed' });

    dep.status      = status;
    dep.adminNote   = adminNote || '';
    dep.processedAt = new Date();
    await dep.save();

    if (status === 'approved') {
      const user = await User.findByIdAndUpdate(dep.userId, { $inc: { wallet: dep.amount } }, { new: true });
      // Notify player via socket
      const sid = userSockets.get(dep.userId.toString());
      if (sid) {
        io.to(sid).emit('wallet:update', {
          wallet: user.wallet,
          message: `✅ ₹${dep.amount} deposit approved and added to your wallet!`,
        });
      }
    }

    res.json({ success: true });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Update failed' }); }
});

// ════════════════════════════════════════
//  AUTH ROUTES
// ════════════════════════════════════════

// Send OTP
app.post('/api/auth/send-otp', async (req, res) => {
  try {
    const { email } = req.body;
    if (!email || !email.includes('@')) return res.status(400).json({ error: 'Valid email required' });
    const otp = String(Math.floor(100000 + Math.random() * 900000));
    await Otp.deleteMany({ email: email.toLowerCase() });
    await Otp.create({ email: email.toLowerCase(), otp, expiresAt: new Date(Date.now() + 10 * 60000) });
    const result = await sendOtpEmail(email, otp);
    res.json({ success: true, message: `OTP sent to ${email}`, devOtp: result?.devOtp || null });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Failed to send OTP' }); }
});

// Verify OTP
app.post('/api/auth/verify-otp', async (req, res) => {
  try {
    const { email, otp } = req.body;
    const record = await Otp.findOne({ email: email?.toLowerCase(), otp, used: false });
    if (!record || record.expiresAt < new Date())
      return res.status(400).json({ error: 'Invalid or expired OTP' });
    await Otp.updateOne({ _id: record._id }, { used: true });
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

// Signup
app.post('/api/auth/signup', async (req, res) => {
  try {
    const { name, username, email, phone, upiId, password } = req.body;
    if (!name || !username || !email || !phone || !password)
      return res.status(400).json({ error: 'All fields required' });
    if (password.length < 8)
      return res.status(400).json({ error: 'Password must be at least 8 characters' });
    if (phone.replace(/\D/g,'').length < 10)
      return res.status(400).json({ error: 'Enter valid phone number' });

    const existing = await User.findOne({ $or: [{ email: email.toLowerCase() }, { username: username.toLowerCase() }] });
    if (existing) {
      return res.status(400).json({
        error: existing.email === email.toLowerCase() ? 'Email already registered' : 'Username already taken'
      });
    }

    const hashed = await bcrypt.hash(password, 12);
    const user   = await User.create({
      name, username: username.toLowerCase(), email: email.toLowerCase(),
      phone, upiId: upiId || '', password: hashed, loginMethod: 'email',
      isVerified: true, wallet: 10,
    });

    const token = jwt.sign({ userId: user._id, username: user.username }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ success: true, token, user: safeUser(user) });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Signup failed' }); }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
    const user = await User.findOne({ username: username.toLowerCase() });
    if (!user || !await bcrypt.compare(password, user.password || ''))
      return res.status(400).json({ error: 'Invalid username or password' });
    const token = jwt.sign({ userId: user._id, username: user.username }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ success: true, token, user: safeUser(user) });
  } catch (e) { res.status(500).json({ error: 'Login failed' }); }
});

// Google OAuth — verify ID token
app.post('/api/auth/google', async (req, res) => {
  try {
    if (!googleClient) return res.status(400).json({ error: 'Google OAuth not configured on server' });
    const { idToken } = req.body;
    const ticket  = await googleClient.verifyIdToken({ idToken, audience: GOOGLE_ID });
    const payload = ticket.getPayload();
    const { email, name } = payload;

    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user) return res.json({ success: true, needsProfile: true, email, name });

    const token = jwt.sign({ userId: user._id, username: user.username }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ success: true, token, user: safeUser(user) });
  } catch (e) { console.error(e); res.status(400).json({ error: 'Google auth failed' }); }
});

// Google — complete profile
app.post('/api/auth/google/complete', async (req, res) => {
  try {
    const { email, name, username, phone, upiId } = req.body;
    if (!email || !username || !phone) return res.status(400).json({ error: 'All fields required' });
    const exists = await User.findOne({ username: username.toLowerCase() });
    if (exists) return res.status(400).json({ error: 'Username already taken' });

    const user = await User.create({
      name, username: username.toLowerCase(), email: email.toLowerCase(),
      phone, upiId: upiId || '', loginMethod: 'google', isVerified: true, wallet: 500,
    });
    const token = jwt.sign({ userId: user._id, username: user.username }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ success: true, token, user: safeUser(user) });
  } catch (e) { res.status(500).json({ error: 'Profile setup failed' }); }
});

// Get current user
app.get('/api/auth/me', authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId).select('-password -__v');
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json({ user: safeUser(user) });
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

// Update UPI ID
app.put('/api/auth/upi', authMiddleware, async (req, res) => {
  try {
    const { upiId } = req.body;
    await User.findByIdAndUpdate(req.user.userId, { upiId });
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: 'Update failed' }); }
});

// Admin login
app.post('/api/admin/login', (req, res) => {
  const { username, password } = req.body;
  if (username === ADMIN_USER && password === ADMIN_PASS) {
    const token = jwt.sign({ isAdmin: true, username }, JWT_SECRET, { expiresIn: '12h' });
    res.json({ success: true, token });
  } else {
    res.status(401).json({ error: 'Invalid admin credentials' });
  }
});

function safeUser(u) {
  return {
    id: u._id, name: u.name, username: u.username,
    email: u.email, phone: u.phone, upiId: u.upiId,
    wallet: u.wallet, loginMethod: u.loginMethod,
    totalBets: u.totalBets, totalWins: u.totalWins,
    createdAt: u.createdAt,
  };
}

// ════════════════════════════════════════
//  GAME ROUTES
// ════════════════════════════════════════

app.get('/api/game/state', (req, res) => {
  res.json({
    roundNumber: gameState.roundNumber,
    phase:       gameState.phase,
    timeLeft:    gameState.timeLeft,
    lastResult:  gameState.lastResult,
  });
});

app.post('/api/game/bet', authMiddleware, async (req, res) => {
  try {
    const { color, amount } = req.body;
    if (!['red','green','violet'].includes(color)) return res.status(400).json({ error: 'Invalid color' });
    if (!amount || amount < 1 || isNaN(amount))   return res.status(400).json({ error: 'Invalid amount' });
    if (gameState.phase !== 'betting')             return res.status(400).json({ error: 'Betting is closed for this round' });

    const uid = req.user.userId.toString();
    if (gameState.roundBets.find(b => b.userId === uid))
      return res.status(400).json({ error: 'Already placed a bet this round' });

    const user = await User.findById(uid);
    if (!user)           return res.status(404).json({ error: 'User not found' });
    if (user.wallet < amount) return res.status(400).json({ error: 'Insufficient wallet balance' });

    await User.findByIdAndUpdate(uid, { $inc: { wallet: -amount, totalBets: 1 } });

    const socketId = userSockets.get(uid);
    gameState.roundBets.push({ userId: uid, color, amount: parseFloat(amount), socketId });

    res.json({ success: true, newBalance: user.wallet - amount });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Bet failed' }); }
});

app.get('/api/game/history', authMiddleware, async (req, res) => {
  try {
    const bets = await Bet.find({ userId: req.user.userId }).sort({ createdAt: -1 }).limit(50);
    res.json({ bets });
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

app.get('/api/game/results', async (req, res) => {
  try {
    const rounds = await Round.find().sort({ number: -1 }).limit(30);
    res.json({ rounds });
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

// ════════════════════════════════════════
//  ADMIN ROUTES
// ════════════════════════════════════════

app.get('/api/admin/stats', adminMiddleware, async (req, res) => {
  try {
    const [users, bets, rounds, betAgg, payoutAgg] = await Promise.all([
      User.countDocuments(),
      Bet.countDocuments(),
      Round.countDocuments(),
      Bet.aggregate([{ $group: { _id: null, total: { $sum: '$amount' } } }]),
      Bet.aggregate([{ $match: { win: true } }, { $group: { _id: null, total: { $sum: '$payout' } } }]),
    ]);
    res.json({
      totalUsers: users,
      totalBets:  bets,
      totalRounds: rounds,
      housePnl:   (betAgg[0]?.total || 0) - (payoutAgg[0]?.total || 0),
      totalBetAmount: betAgg[0]?.total || 0,
    });
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

app.get('/api/admin/users', adminMiddleware, async (req, res) => {
  try {
    const users = await User.find().sort({ createdAt: -1 });
    res.json({ users });
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

app.delete('/api/admin/users/:id', adminMiddleware, async (req, res) => {
  try {
    await User.findByIdAndDelete(req.params.id);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: 'Delete failed' }); }
});

app.get('/api/admin/withdrawals', adminMiddleware, async (req, res) => {
  try {
    const list = await Withdrawal.find().populate('userId','name username email phone').sort({ createdAt: -1 });
    res.json({ withdrawals: list });
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

app.put('/api/admin/withdrawals/:id', adminMiddleware, async (req, res) => {
  try {
    const { status, adminNote } = req.body;
    const w = await Withdrawal.findById(req.params.id);
    if (!w) return res.status(404).json({ error: 'Not found' });
    w.status      = status;
    w.adminNote   = adminNote || '';
    w.processedAt = new Date();
    await w.save();
    if (status === 'rejected') {
      await User.findByIdAndUpdate(w.userId, { $inc: { wallet: w.amount } });
      const uid = w.userId.toString();
      const sid = userSockets.get(uid);
      if (sid) io.to(sid).emit('wallet:update', { message: `₹${w.amount} refunded (withdrawal rejected)` });
    }
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: 'Update failed' }); }
});

app.post('/api/admin/balance', adminMiddleware, async (req, res) => {
  try {
    const { userId, amount } = req.body;
    if (!userId || !amount || isNaN(amount)) return res.status(400).json({ error: 'userId and amount required' });
    const user = await User.findByIdAndUpdate(userId, { $inc: { wallet: parseFloat(amount) } }, { new: true });
    if (!user) return res.status(404).json({ error: 'User not found' });
    const sid = userSockets.get(userId.toString());
    if (sid) io.to(sid).emit('wallet:update', { wallet: user.wallet, message: `+₹${amount} added by admin!` });
    res.json({ success: true, newBalance: user.wallet });
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/admin/force', adminMiddleware, (req, res) => {
  gameState.forcedColor = req.body.color || null;
  io.emit('game:forced', { color: gameState.forcedColor });
  io.to('admins').emit('admin:forced', { color: gameState.forcedColor });
  res.json({ success: true, forcedColor: gameState.forcedColor });
});

app.post('/api/admin/skip', adminMiddleware, (req, res) => {
  gameState.timeLeft = 0;
  res.json({ success: true });
});

app.post('/api/admin/maintenance', adminMiddleware, (req, res) => {
  maintenanceMode = !maintenanceMode;
  io.emit('maintenance', { maintenance: maintenanceMode });
  res.json({ success: true, maintenance: maintenanceMode });
});

app.get('/api/admin/rounds', adminMiddleware, async (req, res) => {
  try {
    const rounds = await Round.find().sort({ number: -1 }).limit(100);
    res.json({ rounds });
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

// ════════════════════════════════════════
//  PAYMENT ROUTES
// ════════════════════════════════════════

// Create Razorpay deposit order
app.post('/api/payment/deposit', authMiddleware, async (req, res) => {
  try {
    if (!razorpay) return res.status(400).json({ error: 'Payment gateway not configured' });
    const { amount } = req.body;
    if (!amount || amount < 10) return res.status(400).json({ error: 'Minimum deposit ₹10' });

    const order = await razorpay.orders.create({
      amount: Math.round(amount * 100),
      currency: 'INR',
      receipt: 'cw_' + Date.now(),
    });

    await Deposit.create({ userId: req.user.userId, orderId: order.id, amount });
    res.json({ success: true, orderId: order.id, amount, key: process.env.RAZORPAY_KEY_ID });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Order creation failed' }); }
});

// Verify Razorpay payment and credit wallet
app.post('/api/payment/verify', authMiddleware, async (req, res) => {
  try {
    const { orderId, paymentId, signature } = req.body;
    const expected = crypto.createHmac('sha256', process.env.RAZORPAY_KEY_SECRET)
      .update(orderId + '|' + paymentId).digest('hex');
    if (expected !== signature) return res.status(400).json({ error: 'Signature mismatch' });

    const dep = await Deposit.findOneAndUpdate(
      { orderId, userId: req.user.userId },
      { status: 'paid', paymentId }, { new: true }
    );
    if (!dep) return res.status(404).json({ error: 'Order not found' });

    const user = await User.findByIdAndUpdate(req.user.userId, { $inc: { wallet: dep.amount } }, { new: true });
    const sid  = userSockets.get(req.user.userId.toString());
    if (sid) io.to(sid).emit('wallet:update', { wallet: user.wallet, message: `+₹${dep.amount} deposited!` });

    res.json({ success: true, newBalance: user.wallet });
  } catch (e) { res.status(500).json({ error: 'Verification failed' }); }
});

// Withdrawal request
app.post('/api/payment/withdraw', authMiddleware, async (req, res) => {
  try {
    const { amount, upiId } = req.body;
    if (!amount || amount < 100) return res.status(400).json({ error: 'Minimum withdrawal ₹100' });
    if (!upiId) return res.status(400).json({ error: 'UPI ID is required' });

    const user = await User.findById(req.user.userId);
    if (!user || user.wallet < amount) return res.status(400).json({ error: 'Insufficient balance' });

    await User.findByIdAndUpdate(req.user.userId, { $inc: { wallet: -amount } });
    const w = await Withdrawal.create({ userId: req.user.userId, amount, upiId });
    res.json({ success: true, withdrawalId: w._id, newBalance: user.wallet - amount });
  } catch (e) { res.status(500).json({ error: 'Withdrawal request failed' }); }
});

// ════════════════════════════════════════
//  SOCKET.IO
// ════════════════════════════════════════
const userSockets = new Map(); // userId → socketId

io.on('connection', (socket) => {
  // Player auth
  socket.on('auth', async (token) => {
    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      socket.userId = decoded.userId.toString();
      userSockets.set(socket.userId, socket.id);

      socket.emit('round:state', {
        roundNumber: gameState.roundNumber,
        phase:       gameState.phase,
        timeLeft:    gameState.timeLeft,
        lastResult:  gameState.lastResult,
      });

      const user = await User.findById(decoded.userId).select('wallet');
      if (user) socket.emit('wallet:sync', { wallet: user.wallet });
    } catch {
      socket.emit('auth:error', 'Invalid token');
    }
  });

  // Admin auth
  socket.on('admin:auth', (token) => {
    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      if (!decoded.isAdmin) return;
      socket.isAdmin = true;
      socket.join('admins');
      socket.emit('admin:state', buildAdminState());
    } catch {}
  });

  socket.on('disconnect', () => {
    if (socket.userId) userSockets.delete(socket.userId);
  });
});

function buildAdminState() {
  return {
    roundNumber:          gameState.roundNumber,
    phase:                gameState.phase,
    timeLeft:             gameState.timeLeft,
    forcedColor:          gameState.forcedColor,
    totalBetsThisRound:   gameState.roundBets.length,
    totalAmountThisRound: gameState.roundBets.reduce((s,b) => s + b.amount, 0),
    lastResult:           gameState.lastResult,
  };
}

// ════════════════════════════════════════
//  GAME ENGINE
// ════════════════════════════════════════
const WEIGHTS     = [...Array(45).fill('red'), ...Array(45).fill('green'), ...Array(10).fill('violet')];
const MULTIPLIERS = { red: 1.5, green: 2.5, violet: 3 };
const ROUND_SEC   = 30;
const CLOSE_AT    = 5;

const gameState = {
  roundNumber: 1,
  phase:       'betting',
  timeLeft:    ROUND_SEC,
  forcedColor: null,
  roundBets:   [],
  lastResult:  null,
};

let tickInterval = null;

async function initGame() {
  try {
    const last = await Round.findOne().sort({ number: -1 });
    if (last) {
      gameState.roundNumber = last.number + 1;
      gameState.lastResult  = last.result;
    }
  } catch {}
  startNewRound();
}

function startNewRound() {
  gameState.timeLeft  = ROUND_SEC;
  gameState.phase     = 'betting';
  gameState.roundBets = [];

  io.emit('round:start', {
    roundNumber: gameState.roundNumber,
    phase:       gameState.phase,
    timeLeft:    gameState.timeLeft,
    lastResult:  gameState.lastResult,
  });
  io.to('admins').emit('admin:state', buildAdminState());

  if (tickInterval) clearInterval(tickInterval);
  tickInterval = setInterval(gameTick, 1000);
}

function gameTick() {
  gameState.timeLeft--;

  if (gameState.timeLeft === CLOSE_AT) {
    gameState.phase = 'closing';
  }

  io.emit('round:tick', {
    roundNumber: gameState.roundNumber,
    phase:       gameState.phase,
    timeLeft:    gameState.timeLeft,
  });
  io.to('admins').emit('admin:tick', {
    timeLeft:             gameState.timeLeft,
    phase:                gameState.phase,
    totalBetsThisRound:   gameState.roundBets.length,
    totalAmountThisRound: gameState.roundBets.reduce((s,b) => s + b.amount, 0),
  });

  if (gameState.timeLeft <= 0) {
    clearInterval(tickInterval);
    tickInterval = null;
    processRound();
  }
}

async function processRound() {
  gameState.phase = 'result';
  const result    = gameState.forcedColor || WEIGHTS[Math.floor(Math.random() * WEIGHTS.length)];
  const wasForced = !!gameState.forcedColor;
  gameState.forcedColor = null;

  let totalAmount = 0, totalPayout = 0;
  const bulkBets  = [];

  for (const bet of gameState.roundBets) {
    const win    = bet.color === result;
    const payout = win ? parseFloat((bet.amount * MULTIPLIERS[result]).toFixed(2)) : 0;
    totalAmount += bet.amount;
    totalPayout += payout;

    bulkBets.push({
      userId: bet.userId, roundNumber: gameState.roundNumber,
      color: bet.color, amount: bet.amount, result, win, payout,
    });

    try {
      if (win) {
        const u = await User.findByIdAndUpdate(
          bet.userId,
          { $inc: { wallet: payout, totalWins: 1, totalWinAmount: payout } },
          { new: true }
        );
        if (bet.socketId) io.to(bet.socketId).emit('bet:result', { win: true, payout, result, newBalance: u?.wallet });
      } else {
        await User.findByIdAndUpdate(bet.userId, { $inc: { totalLost: bet.amount } });
        const u = await User.findById(bet.userId).select('wallet');
        if (bet.socketId) io.to(bet.socketId).emit('bet:result', { win: false, payout: 0, result, newBalance: u?.wallet });
      }
    } catch (e) { console.error('Bet settle error:', e.message); }
  }

  try {
    if (bulkBets.length) await Bet.insertMany(bulkBets);
    await Round.create({
      number: gameState.roundNumber, result,
      totalBets: gameState.roundBets.length, totalAmount, totalPayout,
      forcedBy: wasForced ? 'admin' : null,
    });
  } catch {}

  io.emit('round:result', { roundNumber: gameState.roundNumber, result });
  io.to('admins').emit('admin:result', {
    roundNumber: gameState.roundNumber, result,
    totalBets: gameState.roundBets.length, totalAmount, totalPayout,
    housePnl: totalAmount - totalPayout,
  });

  console.log(`🎯 Round #${gameState.roundNumber} → ${result.toUpperCase()} | Bets: ${gameState.roundBets.length} | ₹${totalAmount} in | ₹${totalPayout} out | House: ₹${(totalAmount - totalPayout).toFixed(2)}`);

  gameState.lastResult  = result;
  gameState.roundNumber++;
  gameState.roundBets   = [];

  setTimeout(startNewRound, 4000);
}

// ════════════════════════════════════════
//  AVIATOR GAME
// ════════════════════════════════════════
const avi = {
  phase: 'waiting', multiplier: 1.00, crashPoint: 2.00,
  startTime: null, bets: [], history: [], countdown: 8, roundId: 0
};

function aviCrashPoint() {
  const r = Math.random();
  if (r < 0.02) return 1.00;
  return Math.min(parseFloat((0.97 / (1 - r)).toFixed(2)), 500);
}

function aviMult() {
  if (!avi.startTime) return 1.00;
  const s = (Date.now() - avi.startTime) / 1000;
  return parseFloat(Math.pow(Math.E, 0.07 * s).toFixed(2));
}

function aviStart() {
  avi.phase = 'waiting'; avi.multiplier = 1.00;
  avi.crashPoint = aviCrashPoint(); avi.startTime = null;
  avi.bets = []; avi.countdown = 8; avi.roundId++;
  io.emit('avi:wait', { countdown: 8, history: avi.history });
  let cd = 8;
  const t = setInterval(() => {
    cd--;
    io.emit('avi:cd', { countdown: cd });
    if (cd <= 0) { clearInterval(t); aviFly(); }
  }, 1000);
}

function aviFly() {
  avi.phase = 'flying'; avi.startTime = Date.now();
  io.emit('avi:fly', { roundId: avi.roundId });
  const t = setInterval(() => {
    const m = aviMult(); avi.multiplier = m;
    io.emit('avi:tick', { multiplier: m });
    if (m >= avi.crashPoint) { clearInterval(t); aviCrash(); }
  }, 100);
}

async function aviCrash() {
  avi.phase = 'crashed';
  const at = avi.crashPoint;
  avi.history.unshift(at);
  if (avi.history.length > 15) avi.history.pop();
  for (const b of avi.bets) {
    if (!b.cashedOut) {
      const sid = userSockets.get(b.userId.toString());
      if (sid) io.to(sid).emit('avi:lost', { amount: b.amount, at });
    }
  }
  io.emit('avi:crash', { at, history: avi.history });
  setTimeout(aviStart, 5000);
}

app.get('/api/aviator/state', authMiddleware, (req, res) => {
  const myBet = avi.bets.find(b => b.userId.toString() === req.user.userId.toString()) || null;
  res.json({ phase: avi.phase, multiplier: avi.multiplier, countdown: avi.countdown, history: avi.history, myBet });
});

app.post('/api/aviator/bet', authMiddleware, async (req, res) => {
  try {
    if (avi.phase !== 'waiting') return res.status(400).json({ error: 'Betting closed — wait for next round' });
    const { amount } = req.body;
    if (!amount || amount < 10) return res.status(400).json({ error: 'Minimum bet ₹10' });
    if (avi.bets.find(b => b.userId.toString() === req.user.userId.toString()))
      return res.status(400).json({ error: 'Already placed bet this round' });
    const user = await User.findById(req.user.userId);
    if (!user || user.wallet < amount) return res.status(400).json({ error: 'Insufficient balance' });
    await User.findByIdAndUpdate(req.user.userId, { $inc: { wallet: -amount } });
    avi.bets.push({ userId: req.user.userId, username: user.username, amount, cashedOut: false, cashoutMult: null });
    res.json({ success: true, newBalance: user.wallet - amount });
  } catch (e) { res.status(500).json({ error: 'Bet failed' }); }
});

app.post('/api/aviator/cashout', authMiddleware, async (req, res) => {
  try {
    if (avi.phase !== 'flying') return res.status(400).json({ error: 'Not flying' });
    const bet = avi.bets.find(b => b.userId.toString() === req.user.userId.toString() && !b.cashedOut);
    if (!bet) return res.status(400).json({ error: 'No active bet' });
    const m = avi.multiplier;
    const win = parseFloat((bet.amount * m).toFixed(2));
    bet.cashedOut = true; bet.cashoutMult = m;
    const user = await User.findByIdAndUpdate(req.user.userId, { $inc: { wallet: win } }, { new: true });
    const sid = userSockets.get(req.user.userId.toString());
    if (sid) io.to(sid).emit('wallet:update', { wallet: user.wallet, message: `+₹${win} (${m}x) ✈️` });
    io.emit('avi:cashout_pub', { username: bet.username, amount: bet.amount, mult: m, win });
    res.json({ success: true, multiplier: m, win, newBalance: user.wallet });
  } catch (e) { res.status(500).json({ error: 'Cashout failed' }); }
});

// ════════════════════════════════════════
//  START SERVER
// ════════════════════════════════════════
const PORT = process.env.PORT || 3000;
server.listen(PORT, async () => {
  console.log(`\n🚀  ColorWin running → http://localhost:${PORT}`);
  console.log(`🎮  Game    → http://localhost:${PORT}/index.html`);
  console.log(`🔑  Login   → http://localhost:${PORT}/login.html`);
  console.log(`⚙️   Admin   → http://localhost:${PORT}/admin.html\n`);
  await initGame();
  setTimeout(aviStart, 2000);
});
