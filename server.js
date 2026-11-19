const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
require('dotenv').config();

const app = express();
app.disable('x-powered-by');
app.use(express.json({ limit: '100kb' }));
app.use(express.static(__dirname));

const PORT = process.env.PORT || 5000;
const MONGO_URI = process.env.MONGO_URI;
const JWT_SECRET = process.env.JWT_SECRET;
const ADMIN_USER_ID = process.env.ADMIN_USER_ID;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;

if (!MONGO_URI) console.error('FATAL: MONGO_URI environment variable is missing.');
if (!JWT_SECRET || JWT_SECRET.length < 32) console.error('FATAL: Set JWT_SECRET to a random secret of at least 32 characters.');
if (!ADMIN_USER_ID || !ADMIN_PASSWORD) console.error('FATAL: Set ADMIN_USER_ID and ADMIN_PASSWORD environment variables.');

const candidateSchema = new mongoose.Schema({
    regNo: { type: String, unique: true, required: true, index: true },
    name: { type: String, required: true, trim: true },
    mobile: { type: String, default: 'Not Provided' },
    studentClass: { type: String, default: '' },
    dob: { type: String, required: true },
    passwordHash: { type: String },
    // Kept only for compatibility with old records; new registrations never write this field.
    password: { type: String, select: false },
    registeredAt: { type: String, default: () => new Date().toLocaleString('en-IN') },
    examSubmitted: { type: Boolean, default: false },
    examResult: { type: mongoose.Schema.Types.Mixed, default: null }
}, { timestamps: true });

const messageSchema = new mongoose.Schema({
    date: { type: String, default: () => new Date().toLocaleString('en-IN') },
    name: { type: String, required: true, trim: true, maxlength: 100 },
    contact: { type: String, required: true, trim: true, maxlength: 100 },
    subject: { type: String, required: true, trim: true, maxlength: 150 },
    message: { type: String, required: true, trim: true, maxlength: 5000 }
}, { timestamps: true });

const Candidate = mongoose.model('Candidate', candidateSchema);
const Message = mongoose.model('Message', messageSchema);

function signToken(payload) {
    return jwt.sign(payload, JWT_SECRET, { expiresIn: '8h', issuer: 'tit-website' });
}
function requireAuth(role) {
    return (req, res, next) => {
        const header = req.headers.authorization || '';
        const token = header.startsWith('Bearer ') ? header.slice(7) : '';
        if (!token) return res.status(401).json({ success: false, message: 'Authentication required.' });
        try {
            const decoded = jwt.verify(token, JWT_SECRET, { issuer: 'tit-website' });
            if (decoded.role !== role) return res.status(403).json({ success: false, message: 'Access denied.' });
            req.auth = decoded;
            next();
        } catch (_) {
            return res.status(401).json({ success: false, message: 'Session expired. Please log in again.' });
        }
    };
}
function publicCandidate(candidate) {
    return {
        regNo: candidate.regNo,
        name: candidate.name,
        mobile: candidate.mobile,
        studentClass: candidate.studentClass,
        dob: candidate.dob,
        registeredAt: candidate.registeredAt,
        examSubmitted: candidate.examSubmitted,
        examResult: candidate.examResult
    };
}

app.get('/api/health', (_req, res) => res.json({ success: true, database: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected' }));
app.get('/', (_req, res) => res.sendFile(__dirname + '/index.html'));

// Registration: ID generation and database persistence happen on the server.
app.post('/api/candidates', async (req, res) => {
    try {
        if (mongoose.connection.readyState !== 1) return res.status(503).json({ success: false, message: 'Database is temporarily unavailable. Please try again.' });
        const { name, mobile, studentClass, dob } = req.body || {};
        if (!name || !dob) return res.status(400).json({ success: false, message: 'Name and date of birth are required.' });
        if (!/^[A-Z\s]+$/.test(String(name).trim())) return res.status(400).json({ success: false, message: 'Enter the candidate name using capital letters.' });
        if (mobile && !/^(\+91\s?)?\d{10}$/.test(String(mobile).trim())) return res.status(400).json({ success: false, message: 'Mobile number must contain 10 digits.' });

        let regNo;
        for (let attempt = 0; attempt < 5; attempt++) {
            regNo = `TIT2026${crypto.randomInt(1000, 10000)}`;
            if (!(await Candidate.exists({ regNo }))) break;
            regNo = null;
        }
        if (!regNo) return res.status(503).json({ success: false, message: 'Could not generate a registration number. Please retry.' });

        const passwordHash = await bcrypt.hash(String(dob), 12);
        const candidate = await Candidate.create({
            regNo, name: String(name).trim(), mobile: mobile ? (String(mobile).startsWith('+91') ? String(mobile).trim() : `+91 ${String(mobile).trim()}`) : 'Not Provided',
            studentClass: String(studentClass || ''), dob: String(dob), passwordHash,
            registeredAt: new Date().toLocaleString('en-IN'), examSubmitted: false, examResult: null
        });
        res.status(201).json({ success: true, message: 'Candidate registered successfully.', candidate: publicCandidate(candidate) });
    } catch (error) {
        console.error('Registration error:', error);
        if (error.code === 11000) return res.status(409).json({ success: false, message: 'Registration number already exists. Please retry.' });
        res.status(500).json({ success: false, message: 'Registration could not be saved. Please try again.' });
    }
});

app.post('/api/login', async (req, res) => {
    try {
        const regNo = String(req.body?.regNo || '').trim().toUpperCase();
        const password = String(req.body?.password || '');
        const candidate = await Candidate.findOne({ regNo }).select('+password');
        if (!candidate) return res.status(401).json({ success: false, message: 'Invalid Registration Number or Password.' });
        let valid = false;
        if (candidate.passwordHash) valid = await bcrypt.compare(password, candidate.passwordHash);
        else if (candidate.password) {
            valid = candidate.password === password;
            if (valid) {
                candidate.passwordHash = await bcrypt.hash(password, 12);
                candidate.password = undefined;
                await candidate.save();
            }
        }
        if (!valid) return res.status(401).json({ success: false, message: 'Invalid Registration Number or Password.' });
        if (candidate.examSubmitted) return res.status(403).json({ success: false, alreadySubmitted: true, message: 'Exam Already Submitted.' });
        const token = signToken({ role: 'student', regNo: candidate.regNo });
        res.json({ success: true, token, candidate: publicCandidate(candidate) });
    } catch (error) {
        console.error('Student login error:', error);
        res.status(500).json({ success: false, message: 'Unable to verify login at this time.' });
    }
});

app.put('/api/candidates/:regNo', requireAuth('student'), async (req, res) => {
    try {
        const regNo = String(req.params.regNo).toUpperCase();
        if (req.auth.regNo !== regNo) return res.status(403).json({ success: false, message: 'You can only submit your own exam.' });
        const { examResult } = req.body || {};
        if (!examResult || !Number.isInteger(Number(examResult.attempted)) || Number(examResult.attempted) < 0 || Number(examResult.attempted) > 50) {
            return res.status(400).json({ success: false, message: 'Invalid exam result.' });
        }
        const updated = await Candidate.findOneAndUpdate(
            { regNo, examSubmitted: false },
            { $set: { examSubmitted: true, examResult } },
            { new: true, runValidators: true }
        );
        if (!updated) return res.status(409).json({ success: false, message: 'Exam already submitted or candidate not found.' });
        res.json({ success: true, message: 'Exam result saved.', examResult: updated.examResult });
    } catch (error) {
        console.error('Exam submission error:', error);
        res.status(500).json({ success: false, message: 'Exam result could not be saved.' });
    }
});

app.post('/api/admin/login', (req, res) => {
    const { userId, password } = req.body || {};
    const userOk = typeof userId === 'string' && userId === ADMIN_USER_ID;
    const passOk = typeof password === 'string' && password === ADMIN_PASSWORD;
    if (!userOk || !passOk) return res.status(401).json({ success: false, message: 'Invalid Admin User ID or Password.' });
    res.json({ success: true, token: signToken({ role: 'admin', userId: ADMIN_USER_ID }) });
});

app.get('/api/admin/candidates', requireAuth('admin'), async (_req, res) => {
    try {
        const candidates = await Candidate.find().sort({ createdAt: -1 }).select('-password -passwordHash');
        res.json({ success: true, candidates });
    } catch (error) {
        console.error('Admin candidates error:', error);
        res.status(500).json({ success: false, message: 'Could not load candidate records.' });
    }
});
app.delete('/api/admin/candidates/:regNo', requireAuth('admin'), async (req, res) => {
    try {
        const result = await Candidate.deleteOne({ regNo: String(req.params.regNo).toUpperCase() });
        if (!result.deletedCount) return res.status(404).json({ success: false, message: 'Candidate not found.' });
        res.json({ success: true });
    } catch (error) { res.status(500).json({ success: false, message: 'Could not delete candidate.' }); }
});

app.post('/api/messages', async (req, res) => {
    try {
        const { name, contact, subject, message } = req.body || {};
        if (![name, contact, subject, message].every(v => typeof v === 'string' && v.trim())) return res.status(400).json({ success: false, message: 'Please complete all contact fields.' });
        const saved = await Message.create({ name, contact, subject, message });
        res.status(201).json({ success: true, id: String(saved._id) });
    } catch (error) { console.error('Message save error:', error); res.status(500).json({ success: false, message: 'Message could not be saved.' }); }
});
app.get('/api/admin/messages', requireAuth('admin'), async (_req, res) => {
    try { const messages = await Message.find().sort({ createdAt: -1 }); res.json({ success: true, messages }); }
    catch (error) { res.status(500).json({ success: false, message: 'Could not load messages.' }); }
});
app.delete('/api/admin/messages/:id', requireAuth('admin'), async (req, res) => {
    try { const result = await Message.deleteOne({ _id: req.params.id }); if (!result.deletedCount) return res.status(404).json({ success: false, message: 'Message not found.' }); res.json({ success: true }); }
    catch (error) { res.status(500).json({ success: false, message: 'Could not delete message.' }); }
});

async function start() {
    if (!MONGO_URI || !JWT_SECRET || JWT_SECRET.length < 32 || !ADMIN_USER_ID || !ADMIN_PASSWORD) {
        console.error('Server startup blocked: required environment variables are missing or invalid.');
        process.exit(1);
    }
    try {
        await mongoose.connect(MONGO_URI, { serverSelectionTimeoutMS: 15000 });
        console.log('MongoDB Atlas connected.');
        app.listen(PORT, () => console.log(`TIT server listening on port ${PORT}`));
    } catch (error) {
        console.error('MongoDB connection failed:', error.message);
        process.exit(1);
    }
}
start(); 