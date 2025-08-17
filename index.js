require('dotenv').config();

const express = require('express');
const cors = require('cors');
const fs = require('fs').promises;
const path = require('path');
const multer = require('multer');
const session = require('express-session');
const passport = require('passport');
const crypto = require('crypto');
const AuthManager = require('./auth');
const UserStore = require('./userStore');
const InputValidator = require('./validation');

const app = express();
const PORT = process.env.PORT || 3000;
const DATA_FILE = path.join(__dirname, 'data.json');

// Initialize stores and auth
const userStore = new UserStore();
const authManager = new AuthManager(userStore);
const validator = new InputValidator();

// CORS configuration
app.use(cors({
  origin: process.env.CORS_ORIGIN || 'http://localhost:3000',
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json());

// Request logging middleware (only in development)
if (process.env.NODE_ENV !== 'production') {
  app.use((req, res, next) => {
    console.log(`[${new Date().toISOString()}] ${req.method} ${req.path}`);
    next();
  });
}

app.use(express.static('public'));

// Serve setup page
app.get('/setup', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'setup.html'));
});

// Session configuration
const sessionSecret = process.env.SESSION_SECRET;
if (!sessionSecret || sessionSecret.includes('demo') || sessionSecret.length < 32) {
  if (process.env.NODE_ENV === 'production') {
    throw new Error('SESSION_SECRET must be set to a secure value (32+ characters) in production');
  }
  console.warn('⚠️  WARNING: Using insecure SESSION_SECRET. Set a secure SESSION_SECRET in production!');
}

app.use(session({
  secret: sessionSecret || 'tyton-demo-session-secret',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true, // Prevent XSS access to session cookie
    maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
  }
}));

// Passport configuration
app.use(passport.initialize());
app.use(passport.session());

// Configure multer for file uploads
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, 'public/uploads/');
  },
  filename: function (req, file, cb) {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
  }
});

// Enhanced file upload with security checks
const upload = multer({ 
  storage: storage,
  limits: { 
    fileSize: parseInt(process.env.MAX_FILE_SIZE) || 5 * 1024 * 1024, // 5MB default
    files: 1, // Only allow 1 file per upload
    fieldSize: 1024, // Limit field size
    fields: 10 // Limit number of fields
  },
  fileFilter: function (req, file, cb) {
    // Allowed image types - stricter validation
    const allowedMimes = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];
    const allowedExtensions = ['.jpg', '.jpeg', '.png', '.gif', '.webp'];
    
    // Check MIME type
    if (!allowedMimes.includes(file.mimetype)) {
      return cb(new Error(`Invalid file type. Only ${allowedMimes.join(', ')} are allowed!`));
    }
    
    // Check file extension
    const ext = path.extname(file.originalname).toLowerCase();
    if (!allowedExtensions.includes(ext)) {
      return cb(new Error(`Invalid file extension. Only ${allowedExtensions.join(', ')} are allowed!`));
    }
    
    // Sanitize filename
    const sanitizedFilename = file.originalname.replace(/[^a-zA-Z0-9.-]/g, '_');
    file.originalname = sanitizedFilename;
    
    cb(null, true);
  }
});

// Rate limiting for file uploads (simple in-memory store)
const uploadAttempts = new Map();
const UPLOAD_RATE_LIMIT = 5; // Max 5 uploads per hour per IP
const UPLOAD_WINDOW = 60 * 60 * 1000; // 1 hour

function checkUploadRateLimit(ip) {
  const now = Date.now();
  const attempts = uploadAttempts.get(ip) || [];
  
  // Remove old attempts
  const recentAttempts = attempts.filter(time => now - time < UPLOAD_WINDOW);
  
  if (recentAttempts.length >= UPLOAD_RATE_LIMIT) {
    return false;
  }
  
  recentAttempts.push(now);
  uploadAttempts.set(ip, recentAttempts);
  return true;
}

async function loadData() {
  try {
    const data = await fs.readFile(DATA_FILE, 'utf8');
    const parsed = JSON.parse(data);
    
    // Validate data structure
    if (!parsed || typeof parsed !== 'object') {
      throw new Error('Invalid data format');
    }
    
    // Ensure required fields exist
    return {
      items: Array.isArray(parsed.items) ? parsed.items : [],
      userFollowers: parsed.userFollowers || {},
      userProfiles: parsed.userProfiles || {},
      communities: Array.isArray(parsed.communities) ? parsed.communities : [],
      discussions: Array.isArray(parsed.discussions) ? parsed.discussions : [],
      discussionReplies: parsed.discussionReplies || {},
      journalPapers: Array.isArray(parsed.journalPapers) ? parsed.journalPapers : []
    };
  } catch (error) {
    if (error.code === 'ENOENT') {
      console.log('📝 Data file not found, creating new one...');
    } else if (error instanceof SyntaxError) {
      console.error('❌ Corrupted data file, backing up and creating new one...');
      // Backup corrupted file
      try {
        await fs.rename(DATA_FILE, DATA_FILE + '.backup.' + Date.now());
      } catch (backupError) {
        console.error('Failed to backup corrupted file:', backupError);
      }
    } else {
      console.error('Error loading data:', error);
    }
    
    // Return default structure
    const defaultData = { items: [], userFollowers: {}, userProfiles: {}, communities: [], discussions: [], discussionReplies: {}, journalPapers: [] };
    await saveData(defaultData);
    return defaultData;
  }
}

async function saveData(data) {
  try {
    // Validate data before saving
    if (!data || typeof data !== 'object') {
      throw new Error('Invalid data structure');
    }
    
    // Write to temporary file first (atomic write)
    const tempFile = DATA_FILE + '.tmp';
    await fs.writeFile(tempFile, JSON.stringify(data, null, 2));
    
    // Rename temp file to actual file (atomic operation)
    await fs.rename(tempFile, DATA_FILE);
    
    return true;
  } catch (error) {
    console.error('❌ Error saving data:', error);
    // Try to clean up temp file if it exists
    try {
      await fs.unlink(DATA_FILE + '.tmp');
    } catch (cleanupError) {
      // Ignore cleanup errors
    }
    return false;
  }
}

function generateId() {
  // Use crypto.randomUUID() for secure ID generation
  return crypto.randomUUID();
}

// Ensure uploads directory exists
async function ensureUploadsDir() {
  const uploadPath = process.env.UPLOAD_PATH || 'public/uploads';
  try {
    await fs.mkdir(uploadPath, { recursive: true });
    // Test write permissions
    const testFile = path.join(uploadPath, '.test');
    await fs.writeFile(testFile, 'test');
    await fs.unlink(testFile);
    console.log(`✅ Upload directory ready: ${uploadPath}`);
  } catch (error) {
    console.error('❌ Error with uploads directory:', error);
    throw new Error('Upload directory is not writable');
  }
}

// Authentication Routes
app.post('/auth/register', async (req, res) => {
  try {
    const { email, password, name, handle } = req.body;
    
    // Comprehensive input validation
    const validationResult = validator.validateUserRegistration({ email, password, name, handle });
    if (!validationResult.valid) {
      return res.status(400).json({ 
        error: 'Validation failed', 
        details: validationResult.errors 
      });
    }

    const { email: validEmail, password: validPassword, name: validName, handle: validHandle } = validationResult.sanitized;

    // Check if user already exists with this email
    const existingUser = await userStore.findByEmail(validEmail);
    if (existingUser) {
      return res.status(409).json({ 
        error: 'An account already exists with this email address. Please log in instead.',
        code: 'EMAIL_EXISTS'
      });
    }

    const hashedPassword = await authManager.hashPassword(validPassword);
    
    const userData = {
      id: authManager.generateUserId(),
      email: validEmail,
      name: validName,
      handle: validHandle || '@' + validEmail.split('@')[0],
      bio: '',
      photo: '',
      hashedPassword,
      createdAt: Date.now(),
      emailVerified: false,
      profileComplete: false
    };

    const user = await userStore.createUser(userData);
    const token = authManager.generateJWT(user);
    
    req.session.token = token;
    
    // Don't send password hash to client
    const { hashedPassword: _, ...userResponse } = user;
    
    res.status(201).json({
      message: 'User registered successfully',
      user: userResponse,
      token,
      requiresProfileSetup: true
    });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.post('/auth/login', (req, res, next) => {
  passport.authenticate('local', (err, user, info) => {
    if (err) {
      return res.status(500).json({ error: 'Authentication error' });
    }
    if (!user) {
      return res.status(401).json({ error: info.message || 'Invalid credentials' });
    }
    
    const token = authManager.generateJWT(user);
    req.session.token = token;
    
    // Don't send password hash to client
    const { hashedPassword: _, ...userResponse } = user;
    
    res.json({
      message: 'Login successful',
      user: userResponse,
      token
    });
  })(req, res, next);
});

app.get('/auth/google', passport.authenticate('google', {
  scope: ['profile', 'email']
}));

app.get('/auth/google/callback', 
  passport.authenticate('google', { failureRedirect: '/?error=auth_failed' }),
  (req, res) => {
    const token = authManager.generateJWT(req.user);
    req.session.token = token;
    
    // Check if user needs to complete profile setup
    if (!req.user.profileComplete) {
      res.redirect('/profile-setup.html?token=' + encodeURIComponent(token));
    } else {
      res.redirect('/?auth=success');
    }
  }
);

app.post('/auth/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).json({ error: 'Logout failed' });
    }
    res.json({ message: 'Logout successful' });
  });
});

app.get('/auth/me', async (req, res) => {
  try {
    let user = null;
    
    // Check for JWT token first
    const token = req.headers.authorization?.replace('Bearer ', '') || req.session?.token;
    if (token) {
      const decoded = authManager.verifyJWT(token);
      if (decoded) {
        user = await userStore.findById(decoded.id);
      }
    }
    
    // Check for passport session (Google OAuth)
    if (!user && req.user) {
      user = await userStore.findById(req.user.id);
    }
    
    if (!user) {
      return res.status(401).json({ error: 'Not authenticated' });
    }
    
    // Don't send password hash to client
    const { hashedPassword: _, ...userResponse } = user;
    res.json({ user: userResponse });
  } catch (error) {
    res.status(500).json({ error: 'Failed to get user data' });
  }
});

app.post('/auth/complete-profile', authManager.requireAuth, async (req, res) => {
  try {
    const userId = req.user.id;
    const { firstName, lastName, handle, researchArea, institution, academicLevel, bio, location } = req.body;
    
    if (!firstName || !lastName || !handle) {
      return res.status(400).json({ error: 'First name, last name, and handle are required' });
    }

    // Check if handle is already taken
    const existingUser = await userStore.findByHandle(handle);
    if (existingUser && existingUser.id !== userId) {
      return res.status(400).json({ error: 'Handle already taken. Please choose a different one.' });
    }

    // Update user profile
    const updates = {
      name: `${firstName} ${lastName}`,
      firstName,
      lastName,
      handle,
      researchArea: researchArea || '',
      institution: institution || '',
      academicLevel: academicLevel || '',
      bio: bio || '',
      location: location || '',
      profileComplete: true,
      profileCompletedAt: Date.now()
    };

    const updatedUser = await userStore.updateUser(userId, updates);
    
    // Don't send password hash to client
    const { hashedPassword: _, ...userResponse } = updatedUser;
    
    res.json({
      message: 'Profile completed successfully',
      user: userResponse
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to complete profile setup' });
  }
});

// File upload endpoint (requires authentication)
app.post('/api/upload', authManager.requireAuth, (req, res, next) => {
  // Apply rate limiting before processing upload
  const userId = req.user?.id || req.ip;
  if (!checkUploadRateLimit(userId)) {
    return res.status(429).json({ 
      error: 'Upload rate limit exceeded. Please wait before uploading again.' 
    });
  }

  upload.single('file')(req, res, function(err) {
    if (err instanceof multer.MulterError) {
      // Multer-specific errors
      if (err.code === 'LIMIT_FILE_SIZE') {
        return res.status(413).json({ error: 'File too large. Maximum size is 5MB.' });
      }
      return res.status(400).json({ error: `Upload error: ${err.message}` });
    } else if (err) {
      // Other errors (like file type validation)
      return res.status(400).json({ error: err.message });
    }
    
    // No error, proceed to handle the upload
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }
    
    const fileUrl = `/uploads/${req.file.filename}`;
    res.json({ 
      message: 'File uploaded successfully',
      url: fileUrl,
      filename: req.file.filename,
      size: req.file.size,
      mimetype: req.file.mimetype
    });
  });
});

app.get('/api/data', authManager.optionalAuth, async (req, res) => {
  try {
    const data = await loadData();
    const userId = req.user?.id;
    
    // Return user-specific data if authenticated
    if (userId) {
      const userFollowers = data.userFollowers[userId] || {};
      const userProfile = data.userProfiles[userId] || {};
      
      // Get full user data from database, not just JWT payload
      const fullUser = await userStore.findById(userId);
      const { hashedPassword: _, ...currentUser } = fullUser || {};
      
      res.json({
        items: data.items,
        followers: userFollowers,
        profile: userProfile,
        currentUser: currentUser,
        communities: data.communities
      });
    } else {
      // Return public data only
      res.json({
        items: data.items,
        followers: {},
        profile: {},
        currentUser: null,
        communities: data.communities
      });
    }
  } catch (error) {
    res.status(500).json({ error: 'Failed to load data' });
  }
});

app.post('/api/items', authManager.requireAuth, async (req, res) => {
  try {
    const { type, title, description, tags, location } = req.body;
    
    // Comprehensive input validation
    const validationResult = validator.validateItemData({ type, title, description, tags, location });
    if (!validationResult.valid) {
      return res.status(400).json({ 
        error: 'Validation failed', 
        details: validationResult.errors 
      });
    }

    const { type: validType, title: validTitle, description: validDescription, 
            tags: validTags, location: validLocation } = validationResult.sanitized;

    const data = await loadData();
    const newItem = {
      id: generateId(),
      type: validType,
      title: validTitle,
      description: validDescription,
      tags: validTags,
      owner: req.user.handle,
      ownerId: req.user.id,
      location: validLocation,
      likes: 0,
      likedBy: [],
      createdAt: Date.now()
    };

    if (type === 'equipment') {
      newItem.bookings = [];
    }

    data.items.unshift(newItem);
    
    if (await saveData(data)) {
      res.status(201).json(newItem);
    } else {
      res.status(500).json({ error: 'Failed to save item' });
    }
  } catch (error) {
    res.status(500).json({ error: 'Failed to create item' });
  }
});

app.put('/api/items/:id/like', authManager.requireAuth, async (req, res) => {
  try {
    const data = await loadData();
    const item = data.items.find(i => i.id === req.params.id);
    
    if (!item) {
      return res.status(404).json({ error: 'Item not found' });
    }

    item.likedBy = item.likedBy || [];
    
    if (item.likedBy.includes(req.user.id)) {
      // Unlike
      item.likedBy = item.likedBy.filter(id => id !== req.user.id);
      item.likes = item.likedBy.length;
    } else {
      // Like
      item.likedBy.push(req.user.id);
      item.likes = item.likedBy.length;
    }
    
    if (await saveData(data)) {
      res.json({ 
        likes: item.likes,
        liked: item.likedBy.includes(req.user.id)
      });
    } else {
      res.status(500).json({ error: 'Failed to update likes' });
    }
  } catch (error) {
    res.status(500).json({ error: 'Failed to like item' });
  }
});

app.put('/api/items/:id/follow', authManager.requireAuth, async (req, res) => {
  try {
    const data = await loadData();
    const itemId = req.params.id;
    const userId = req.user.id;
    
    data.userFollowers[userId] = data.userFollowers[userId] || {};
    
    if (data.userFollowers[userId][itemId]) {
      delete data.userFollowers[userId][itemId];
    } else {
      data.userFollowers[userId][itemId] = true;
    }
    
    if (await saveData(data)) {
      res.json({ following: !!data.userFollowers[userId][itemId] });
    } else {
      res.status(500).json({ error: 'Failed to update follow status' });
    }
  } catch (error) {
    res.status(500).json({ error: 'Failed to toggle follow' });
  }
});

app.post('/api/equipment/:id/book', authManager.requireAuth, async (req, res) => {
  try {
    const { date, slot } = req.body;
    
    if (!date || !slot) {
      return res.status(400).json({ error: 'Date and slot are required' });
    }

    const data = await loadData();
    const item = data.items.find(i => i.id === req.params.id && i.type === 'equipment');
    
    if (!item) {
      return res.status(404).json({ error: 'Equipment not found' });
    }

    item.bookings = item.bookings || [];
    const hasConflict = item.bookings.some(b => b.date === date && b.slot === slot);
    
    if (hasConflict) {
      return res.status(409).json({ error: 'Time slot is already booked' });
    }

    const booking = {
      date,
      slot,
      by: req.user.handle,
      userId: req.user.id,
      createdAt: Date.now()
    };

    item.bookings.push(booking);
    
    if (await saveData(data)) {
      res.status(201).json(booking);
    } else {
      res.status(500).json({ error: 'Failed to save booking' });
    }
  } catch (error) {
    res.status(500).json({ error: 'Failed to book equipment' });
  }
});

app.put('/api/profile', authManager.requireAuth, async (req, res) => {
  try {
    const { name, handle, bio, photo } = req.body;
    const data = await loadData();
    const userId = req.user.id;
    
    // Update user in user store
    const updates = {
      name: name?.trim() || '',
      bio: bio?.trim() || '',
      photo: photo?.trim() || ''
    };
    
    // Handle updates (check for uniqueness)
    if (handle && handle.trim()) {
      const trimmedHandle = handle.trim();
      const existingUser = await userStore.findByHandle(trimmedHandle);
      if (existingUser && existingUser.id !== userId) {
        return res.status(400).json({ error: 'Handle already taken' });
      }
      updates.handle = trimmedHandle;
    }
    
    const updatedUser = await userStore.updateUser(userId, updates);
    
    // Also update in data.json for backward compatibility
    data.userProfiles[userId] = {
      name: updatedUser.name,
      handle: updatedUser.handle,
      bio: updatedUser.bio,
      photo: updatedUser.photo
    };
    
    if (await saveData(data)) {
      const { hashedPassword: _, ...userResponse } = updatedUser;
      res.json(userResponse);
    } else {
      res.status(500).json({ error: 'Failed to save profile' });
    }
  } catch (error) {
    res.status(500).json({ error: 'Failed to update profile' });
  }
});

// Communities endpoints
app.get('/api/communities', authManager.optionalAuth, async (req, res) => {
  try {
    const data = await loadData();
    const { q, type, location } = req.query;
    
    let communities = data.communities || [];
    
    // Apply filters if provided
    if (q) {
      const query = q.toLowerCase();
      communities = communities.filter(community => 
        community.name?.toLowerCase().includes(query) ||
        community.description?.toLowerCase().includes(query) ||
        community.tags?.toLowerCase().includes(query)
      );
    }
    
    if (type) {
      communities = communities.filter(community => community.type === type);
    }
    
    if (location) {
      communities = communities.filter(community => community.location === location);
    }
    
    res.json({
      count: communities.length,
      communities: communities
    });
  } catch (error) {
    console.error('Communities fetch error:', error);
    res.status(500).json({ error: 'Failed to fetch communities' });
  }
});

app.post('/api/communities', authManager.requireAuth, async (req, res) => {
  try {
    const { name, description, type, location, tags, avatar } = req.body;
    
    if (!name || !name.trim()) {
      return res.status(400).json({ error: 'Community name is required' });
    }

    const data = await loadData();
    const newCommunity = {
      id: generateId(),
      name: name.trim(),
      description: description?.trim() || '',
      type: type || 'research',
      location: location?.trim() || 'global',
      tags: tags?.trim() || '',
      avatar: avatar?.trim() || '',
      createdBy: req.user.handle,
      createdById: req.user.id,
      memberCount: 1,
      members: [req.user.id],
      createdAt: Date.now(),
      public: true
    };

    if (!data.communities) {
      data.communities = [];
    }
    data.communities.unshift(newCommunity);
    
    if (await saveData(data)) {
      res.status(201).json(newCommunity);
    } else {
      res.status(500).json({ error: 'Failed to save community' });
    }
  } catch (error) {
    console.error('Create community error:', error);
    res.status(500).json({ error: 'Failed to create community' });
  }
});

app.put('/api/communities/:id/join', authManager.requireAuth, async (req, res) => {
  try {
    const data = await loadData();
    const community = data.communities?.find(c => c.id === req.params.id);
    
    if (!community) {
      return res.status(404).json({ error: 'Community not found' });
    }

    community.members = community.members || [];
    const isMember = community.members.includes(req.user.id);
    
    if (isMember) {
      // Leave community
      community.members = community.members.filter(id => id !== req.user.id);
      community.memberCount = Math.max(0, (community.memberCount || 0) - 1);
    } else {
      // Join community
      community.members.push(req.user.id);
      community.memberCount = (community.memberCount || 0) + 1;
    }
    
    if (await saveData(data)) {
      res.json({ 
        joined: !isMember,
        memberCount: community.memberCount
      });
    } else {
      res.status(500).json({ error: 'Failed to update membership' });
    }
  } catch (error) {
    console.error('Join community error:', error);
    res.status(500).json({ error: 'Failed to join/leave community' });
  }
});

// Discussions endpoints
app.get('/api/discussions', authManager.optionalAuth, async (req, res) => {
  try {
    const data = await loadData();
    
    // Sort discussions by creation date (newest first)
    const discussions = data.discussions.sort((a, b) => b.createdAt - a.createdAt);
    
    // Add reply count to each discussion
    const discussionsWithCounts = discussions.map(discussion => ({
      ...discussion,
      replies: data.discussionReplies[discussion.id] ? data.discussionReplies[discussion.id].length : 0
    }));
    
    res.json(discussionsWithCounts);
  } catch (error) {
    console.error('Error loading discussions:', error);
    res.status(500).json({ error: 'Failed to load discussions' });
  }
});

app.post('/api/discussions', authManager.requireAuth, async (req, res) => {
  try {
    const { title, content, tags } = req.body;
    
    if (!title || !content) {
      return res.status(400).json({ error: 'Title and content are required' });
    }
    
    const data = await loadData();
    
    // Get user from session/token
    const user = req.user;
    const userHandle = user.handle || user.email?.split('@')[0] || 'anonymous';
    
    const discussion = {
      id: generateId(),
      title: title.trim(),
      content: content.trim(),
      tags: tags ? tags.trim() : null,
      owner: userHandle,
      ownerId: user.id,
      likes: 0,
      likedBy: [],
      views: 0,
      createdAt: Date.now()
    };
    
    data.discussions.push(discussion);
    
    const success = await saveData(data);
    if (!success) {
      return res.status(500).json({ error: 'Failed to save discussion' });
    }
    
    res.status(201).json({ 
      message: 'Discussion created successfully',
      discussion: discussion
    });
  } catch (error) {
    console.error('Error creating discussion:', error);
    res.status(500).json({ error: 'Failed to create discussion' });
  }
});

app.get('/api/discussions/:id', authManager.optionalAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const data = await loadData();
    
    const discussion = data.discussions.find(d => d.id === id);
    if (!discussion) {
      return res.status(404).json({ error: 'Discussion not found' });
    }
    
    // Increment view count
    discussion.views = (discussion.views || 0) + 1;
    await saveData(data);
    
    // Add reply count
    const replies = data.discussionReplies[id] ? data.discussionReplies[id].length : 0;
    
    res.json({
      ...discussion,
      replies
    });
  } catch (error) {
    console.error('Error loading discussion:', error);
    res.status(500).json({ error: 'Failed to load discussion' });
  }
});

app.put('/api/discussions/:id/like', authManager.requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const data = await loadData();
    const user = req.user;
    
    const discussion = data.discussions.find(d => d.id === id);
    if (!discussion) {
      return res.status(404).json({ error: 'Discussion not found' });
    }
    
    if (!discussion.likedBy) {
      discussion.likedBy = [];
    }
    
    const userIndex = discussion.likedBy.indexOf(user.id);
    let liked = false;
    
    if (userIndex === -1) {
      // User hasn't liked, so add like
      discussion.likedBy.push(user.id);
      discussion.likes = discussion.likedBy.length;
      liked = true;
    } else {
      // User has liked, so remove like
      discussion.likedBy.splice(userIndex, 1);
      discussion.likes = discussion.likedBy.length;
      liked = false;
    }
    
    const success = await saveData(data);
    if (!success) {
      return res.status(500).json({ error: 'Failed to update like' });
    }
    
    res.json({ 
      likes: discussion.likes,
      liked: liked
    });
  } catch (error) {
    console.error('Error toggling discussion like:', error);
    res.status(500).json({ error: 'Failed to update like' });
  }
});

app.get('/api/discussions/:id/replies', authManager.optionalAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const data = await loadData();
    
    const discussion = data.discussions.find(d => d.id === id);
    if (!discussion) {
      return res.status(404).json({ error: 'Discussion not found' });
    }
    
    const replies = data.discussionReplies[id] || [];
    
    // Build threaded structure
    function buildThreadedReplies(replies) {
      const repliesMap = new Map();
      const topLevelReplies = [];
      
      // First pass: create a map of all replies and identify top-level replies
      replies.forEach(reply => {
        const replyWithChildren = { ...reply, children: [] };
        repliesMap.set(reply.id, replyWithChildren);
        
        if (!reply.parentId) {
          topLevelReplies.push(replyWithChildren);
        }
      });
      
      // Second pass: attach children to their parents
      replies.forEach(reply => {
        if (reply.parentId) {
          const parent = repliesMap.get(reply.parentId);
          if (parent) {
            parent.children.push(repliesMap.get(reply.id));
          }
        }
      });
      
      // Sort top-level replies by creation date (oldest first)
      topLevelReplies.sort((a, b) => a.createdAt - b.createdAt);
      
      // Recursively sort children
      function sortChildren(reply) {
        reply.children.sort((a, b) => a.createdAt - b.createdAt);
        reply.children.forEach(sortChildren);
      }
      
      topLevelReplies.forEach(sortChildren);
      
      return topLevelReplies;
    }
    
    const threadedReplies = buildThreadedReplies(replies);
    
    res.json(threadedReplies);
  } catch (error) {
    console.error('Error loading replies:', error);
    res.status(500).json({ error: 'Failed to load replies' });
  }
});

app.post('/api/discussions/:id/replies', authManager.requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const { content, parentId } = req.body;
    
    if (!content) {
      return res.status(400).json({ error: 'Content is required' });
    }
    
    const data = await loadData();
    
    const discussion = data.discussions.find(d => d.id === id);
    if (!discussion) {
      return res.status(404).json({ error: 'Discussion not found' });
    }
    
    // If parentId is provided, verify the parent reply exists
    if (parentId) {
      const replies = data.discussionReplies[id] || [];
      const parentReply = replies.find(r => r.id === parentId);
      if (!parentReply) {
        return res.status(404).json({ error: 'Parent reply not found' });
      }
    }
    
    const user = req.user;
    const userHandle = user.handle || user.email?.split('@')[0] || 'anonymous';
    
    const reply = {
      id: generateId(),
      content: content.trim(),
      owner: userHandle,
      ownerId: user.id,
      likes: 0,
      likedBy: [],
      createdAt: Date.now(),
      parentId: parentId || null
    };
    
    // Initialize replies array if it doesn't exist
    if (!data.discussionReplies[id]) {
      data.discussionReplies[id] = [];
    }
    
    data.discussionReplies[id].push(reply);
    
    const success = await saveData(data);
    if (!success) {
      return res.status(500).json({ error: 'Failed to save reply' });
    }
    
    res.status(201).json({ 
      message: 'Reply posted successfully',
      reply: reply
    });
  } catch (error) {
    console.error('Error creating reply:', error);
    res.status(500).json({ error: 'Failed to create reply' });
  }
});

app.put('/api/discussions/:id/replies/:replyId/like', authManager.requireAuth, async (req, res) => {
  try {
    const { id, replyId } = req.params;
    const data = await loadData();
    const user = req.user;
    
    const discussion = data.discussions.find(d => d.id === id);
    if (!discussion) {
      return res.status(404).json({ error: 'Discussion not found' });
    }
    
    const replies = data.discussionReplies[id] || [];
    const reply = replies.find(r => r.id === replyId);
    if (!reply) {
      return res.status(404).json({ error: 'Reply not found' });
    }
    
    if (!reply.likedBy) {
      reply.likedBy = [];
    }
    
    const userIndex = reply.likedBy.indexOf(user.id);
    let liked = false;
    
    if (userIndex === -1) {
      // User hasn't liked, so add like
      reply.likedBy.push(user.id);
      reply.likes = reply.likedBy.length;
      liked = true;
    } else {
      // User has liked, so remove like
      reply.likedBy.splice(userIndex, 1);
      reply.likes = reply.likedBy.length;
      liked = false;
    }
    
    const success = await saveData(data);
    if (!success) {
      return res.status(500).json({ error: 'Failed to update like' });
    }
    
    res.json({ 
      likes: reply.likes,
      liked: liked
    });
  } catch (error) {
    console.error('Error toggling reply like:', error);
    res.status(500).json({ error: 'Failed to update like' });
  }
});

// Search endpoint
app.get('/api/search', authManager.optionalAuth, async (req, res) => {
  try {
    const { q, type, tags } = req.query;
    const data = await loadData();
    
    if (!q && !type && !tags) {
      return res.status(400).json({ error: 'Please provide a search query, type, or tags' });
    }
    
    let results = data.items || [];
    
    // Filter by type if specified
    if (type) {
      results = results.filter(item => item.type === type);
    }
    
    // Search by query if provided
    if (q) {
      const query = q.toLowerCase();
      results = results.filter(item => 
        item.title?.toLowerCase().includes(query) ||
        item.description?.toLowerCase().includes(query) ||
        item.tags?.toLowerCase().includes(query) ||
        item.owner?.toLowerCase().includes(query) ||
        item.location?.toLowerCase().includes(query)
      );
    }
    
    // Filter by tags if provided
    if (tags) {
      const searchTags = tags.toLowerCase().split(',').map(t => t.trim());
      results = results.filter(item => {
        const itemTags = (item.tags || '').toLowerCase().split(',').map(t => t.trim());
        return searchTags.some(tag => itemTags.includes(tag));
      });
    }
    
    // Sort by relevance (likes and recency)
    results.sort((a, b) => {
      // Prioritize exact title matches
      if (q) {
        const aExact = a.title?.toLowerCase() === q.toLowerCase();
        const bExact = b.title?.toLowerCase() === q.toLowerCase();
        if (aExact && !bExact) return -1;
        if (!aExact && bExact) return 1;
      }
      
      // Then sort by likes and recency
      const aScore = (a.likes || 0) + (a.createdAt ? 1 / (Date.now() - a.createdAt) * 1000000 : 0);
      const bScore = (b.likes || 0) + (b.createdAt ? 1 / (Date.now() - b.createdAt) * 1000000 : 0);
      return bScore - aScore;
    });
    
    res.json({
      query: q,
      type: type,
      tags: tags,
      count: results.length,
      results: results.slice(0, 50) // Limit to 50 results
    });
  } catch (error) {
    console.error('Search error:', error);
    res.status(500).json({ error: 'Search failed' });
  }
});

// Seed demo data endpoint (public for demo purposes, restrict in production)
app.post('/api/seed', async (req, res) => {
  try {
    const data = await loadData();
    const now = Date.now();
    
    const sampleProjects = [
      {
        id: generateId(), type: 'project', title: 'Quantum Entanglement Communication Array',
        description: 'Revolutionary quantum communication system using entangled photon pairs for instantaneous data transmission across vast distances.',
        tags: 'quantum,communications,photonics,physics', owner: '@quantum_alice', location: 'MIT Quantum Lab',
        likes: 142, likedBy: [], createdAt: now - 86400000 * 1
      },
      {
        id: generateId(), type: 'project', title: 'Bio-Luminescent Neural Interface',
        description: 'Engineering bioluminescent proteins for real-time neural activity visualization in living brain tissue.',
        tags: 'neuroscience,bioluminescence,brain-interface,biotech', owner: '@neuro_pioneer', location: 'Stanford Neuroscience',
        likes: 89, likedBy: [], createdAt: now - 86400000 * 2
      },
      {
        id: generateId(), type: 'project', title: 'Atmospheric Carbon Harvester',
        description: 'Large-scale atmospheric processor that converts CO2 directly into solid carbon materials for construction.',
        tags: 'climate,carbon-capture,materials,sustainability', owner: '@climate_engineer', location: 'Remote/Global',
        likes: 156, likedBy: [], createdAt: now - 86400000 * 3
      },
      {
        id: generateId(), type: 'project', title: 'Gravitational Wave Detector Miniaturization',
        description: 'Developing tabletop gravitational wave detectors using metamaterials and quantum sensing techniques.',
        tags: 'gravity,physics,metamaterials,quantum-sensing', owner: '@wave_detector', location: 'Caltech Physics',
        likes: 73, likedBy: [], createdAt: now - 86400000 * 4
      },
      {
        id: generateId(), type: 'project', title: 'Self-Assembling Space Habitats',
        description: 'Modular habitat systems that self-construct in zero gravity using programmable matter and robotic swarms.',
        tags: 'space,robotics,self-assembly,habitats', owner: '@space_architect', location: 'NASA Ames',
        likes: 198, likedBy: [], createdAt: now - 86400000 * 5
      },
      {
        id: generateId(), type: 'project', title: 'Synthetic Biology Protein Computers',
        description: 'Living computers made from engineered proteins that process information using biological pathways.',
        tags: 'synthetic-biology,proteins,biocomputing,dna', owner: '@bio_coder', location: 'Harvard Wyss Institute',
        likes: 124, likedBy: [], createdAt: now - 86400000 * 6
      },
      {
        id: generateId(), type: 'project', title: 'Plasma Fusion Reactor Optimization',
        description: 'AI-driven plasma control system for maintaining stable fusion reactions in tokamak reactors.',
        tags: 'fusion,plasma,ai,energy,tokamak', owner: '@fusion_ai', location: 'ITER Consortium',
        likes: 211, likedBy: [], createdAt: now - 86400000 * 7
      },
      {
        id: generateId(), type: 'project', title: 'Metamaterial Invisibility Cloaking',
        description: 'Broadband optical cloaking device using engineered metamaterials for electromagnetic wave manipulation.',
        tags: 'metamaterials,optics,cloaking,electromagnetics', owner: '@invisible_engineer', location: 'Duke University',
        likes: 167, likedBy: [], createdAt: now - 86400000 * 8
      },
      {
        id: generateId(), type: 'project', title: 'Time Crystal Energy Storage',
        description: 'Perpetual motion energy storage using non-equilibrium time crystal formations in quantum systems.',
        tags: 'time-crystals,energy,quantum,storage', owner: '@time_physicist', location: 'Princeton Quantum',
        likes: 95, likedBy: [], createdAt: now - 86400000 * 9
      },
      {
        id: generateId(), type: 'project', title: 'Holographic Data Archive',
        description: 'Ultra-dense holographic storage system capable of archiving exabytes in crystal matrices.',
        tags: 'holography,data-storage,crystals,optics', owner: '@holo_storage', location: 'IBM Research',
        likes: 83, likedBy: [], createdAt: now - 86400000 * 10
      },
      {
        id: generateId(), type: 'project', title: 'Molecular Robot Swarm Therapeutics',
        description: 'Programmable molecular robots that target and repair cellular damage at the nanoscale level.',
        tags: 'nanorobots,therapeutics,molecular,medicine', owner: '@nano_medic', location: 'Johns Hopkins',
        likes: 189, likedBy: [], createdAt: now - 86400000 * 11
      },
      {
        id: generateId(), type: 'project', title: 'Anti-Gravity Propulsion Research',
        description: 'Investigating electromagnetic field manipulation for reactionless propulsion systems.',
        tags: 'propulsion,anti-gravity,electromagnetics,aerospace', owner: '@gravity_hacker', location: 'Skunk Works',
        likes: 234, likedBy: [], createdAt: now - 86400000 * 12
      },
      {
        id: generateId(), type: 'project', title: 'Consciousness Upload Protocol',
        description: 'Neural pattern mapping and digitization for potential consciousness transfer to quantum substrates.',
        tags: 'consciousness,neural-mapping,ai,philosophy', owner: '@mind_mapper', location: 'OpenMind Institute',
        likes: 156, likedBy: [], createdAt: now - 86400000 * 13
      },
      {
        id: generateId(), type: 'project', title: 'Weather Control Atmospheric Processors',
        description: 'Large-scale atmospheric manipulation using ionospheric heating and cloud seeding technologies.',
        tags: 'weather,atmosphere,climate-control,geoengineering', owner: '@weather_wizard', location: 'NOAA Advanced',
        likes: 178, likedBy: [], createdAt: now - 86400000 * 14
      },
      {
        id: generateId(), type: 'project', title: 'Telepathic Brain-Computer Interface',
        description: 'Direct thought-to-thought communication using quantum field fluctuations in neural microtubules.',
        tags: 'telepathy,bci,quantum-biology,consciousness', owner: '@thought_link', location: 'MIT Media Lab',
        likes: 267, likedBy: [], createdAt: now - 86400000 * 15
      },
      {
        id: generateId(), type: 'project', title: 'Dimensional Portal Generator',
        description: 'Experimental wormhole creation using exotic matter and space-time curvature manipulation.',
        tags: 'wormholes,spacetime,exotic-matter,physics', owner: '@portal_physicist', location: 'CERN Theoretical',
        likes: 198, likedBy: [], createdAt: now - 86400000 * 16
      },
      {
        id: generateId(), type: 'project', title: 'Synthetic Life Genesis Chamber',
        description: 'Creating entirely synthetic life forms from non-biological substrates using artificial evolution.',
        tags: 'synthetic-life,artificial-evolution,xenobiology', owner: '@life_creator', location: 'Venter Institute',
        likes: 145, likedBy: [], createdAt: now - 86400000 * 17
      },
      {
        id: generateId(), type: 'project', title: 'Quantum Superposition Computer',
        description: 'Room-temperature quantum computer using macroscopic superposition states in engineered materials.',
        tags: 'quantum-computing,superposition,room-temperature', owner: '@quantum_dev', location: 'Google Quantum AI',
        likes: 223, likedBy: [], createdAt: now - 86400000 * 18
      },
      {
        id: generateId(), type: 'project', title: 'Psychokinetic Field Generator',
        description: 'Amplifying human psychokinetic abilities using focused electromagnetic field resonance chambers.',
        tags: 'psychokinesis,consciousness,fields,parapsychology', owner: '@psi_researcher', location: 'Rhine Research',
        likes: 167, likedBy: [], createdAt: now - 86400000 * 19
      },
      {
        id: generateId(), type: 'project', title: 'Immortality Cellular Reprogramming',
        description: 'Reversing cellular aging through telomere regeneration and DNA repair optimization protocols.',
        tags: 'immortality,aging,telomeres,genetics,longevity', owner: '@eternal_biologist', location: 'Life Extension Labs',
        likes: 289, likedBy: [], createdAt: now - 86400000 * 20
      }
    ];

    const sampleMarketplace = [
      {
        id: generateId(), type: 'equipment', title: 'Quantum Flux Capacitor Array',
        description: 'Industrial-grade quantum field manipulator with 99.7% coherence stability. Perfect for temporal research.',
        tags: 'quantum,flux,temporal,research', owner: '@flux_industries', location: 'On-site (Quantum Labs)',
        likes: 45, likedBy: [], bookings: [], createdAt: now - 86400000 * 1
      },
      {
        id: generateId(), type: 'equipment', title: 'Holographic Projection Matrix',
        description: 'Full-room holographic display system with tactile feedback. 8K resolution per cubic meter.',
        tags: 'holography,display,tactile,visualization', owner: '@holo_tech', location: 'Remote Setup Available',
        likes: 67, likedBy: [], bookings: [], createdAt: now - 86400000 * 2
      },
      {
        id: generateId(), type: 'equipment', title: 'Anti-Gravity Levitation Chamber',
        description: 'Electromagnetic levitation system for zero-G experiments. Supports objects up to 500kg.',
        tags: 'anti-gravity,levitation,zero-g,electromagnetics', owner: '@levitation_lab', location: 'NASA Facility Access',
        likes: 89, likedBy: [], bookings: [
          { date: '2025-08-25', slot: '10:00–12:00', by: '@researcher1' },
          { date: '2025-08-28', slot: '14:00–16:00', by: '@antigrav_student' }
        ], createdAt: now - 86400000 * 3
      },
      {
        id: generateId(), type: 'equipment', title: 'Neural Interface Headset Array',
        description: 'Multi-channel brain-computer interface with 10,000 electrode resolution. Non-invasive setup.',
        tags: 'bci,neural,electrodes,non-invasive', owner: '@neural_tech', location: 'Stanford Medical',
        likes: 78, likedBy: [], bookings: [], createdAt: now - 86400000 * 4
      },
      {
        id: generateId(), type: 'equipment', title: 'Plasma Fusion Reactor (Tabletop)',
        description: 'Compact tokamak reactor for fusion research. Reaches 100 million degrees Celsius.',
        tags: 'fusion,plasma,tokamak,high-temperature', owner: '@fusion_miniaturization', location: 'MIT Plasma Lab',
        likes: 134, likedBy: [], bookings: [], createdAt: now - 86400000 * 5
      },
      {
        id: generateId(), type: 'equipment', title: 'Time Dilation Field Generator',
        description: 'Localized temporal field manipulation. Create time differential zones for accelerated research.',
        tags: 'time,dilation,temporal,acceleration', owner: '@temporal_dynamics', location: 'Theoretical Physics Lab',
        likes: 156, likedBy: [], bookings: [], createdAt: now - 86400000 * 6
      },
      {
        id: generateId(), type: 'equipment', title: 'Metamaterial Invisibility Cloak',
        description: 'Functional invisibility device using negative refractive index materials. Works in visible spectrum.',
        tags: 'invisibility,metamaterials,optics,stealth', owner: '@invisible_materials', location: 'Duke Physics',
        likes: 203, likedBy: [], bookings: [
          { date: '2025-08-26', slot: '09:00–11:00', by: '@optics_researcher' }
        ], createdAt: now - 86400000 * 7
      },
      {
        id: generateId(), type: 'equipment', title: 'DNA Sequencing Quantum Computer',
        description: 'Quantum-enhanced genomic analysis system. Complete genome sequencing in under 1 hour.',
        tags: 'dna,sequencing,quantum,genomics', owner: '@quantum_genomics', location: 'Broad Institute',
        likes: 92, likedBy: [], bookings: [], createdAt: now - 86400000 * 8
      },
      {
        id: generateId(), type: 'equipment', title: 'Gravitational Wave Detector (Portable)',
        description: 'Miniaturized LIGO-class detector. Detect spacetime ripples from your desktop.',
        tags: 'gravity-waves,spacetime,detection,physics', owner: '@wave_instruments', location: 'Caltech LIGO',
        likes: 118, likedBy: [], bookings: [], createdAt: now - 86400000 * 9
      },
      {
        id: generateId(), type: 'equipment', title: 'Molecular 3D Bioprinter',
        description: 'Print living tissue at molecular resolution. Compatible with all organic cell types.',
        tags: 'bioprinting,molecular,tissue,organic', owner: '@bio_fabrication', location: 'Harvard Medical',
        likes: 87, likedBy: [], bookings: [
          { date: '2025-08-27', slot: '13:00–17:00', by: '@tissue_engineer' }
        ], createdAt: now - 86400000 * 10
      },
      {
        id: generateId(), type: 'equipment', title: 'Telepathic Amplification Chamber',
        description: 'Enhances natural psychic abilities through quantum field resonance. Research use only.',
        tags: 'telepathy,psychic,quantum,resonance', owner: '@psi_enhancement', location: 'Rhine Institute',
        likes: 145, likedBy: [], bookings: [], createdAt: now - 86400000 * 11
      },
      {
        id: generateId(), type: 'equipment', title: 'Weather Control Ionosphere Array',
        description: 'HAARP-class atmospheric manipulation system. Localized weather pattern generation.',
        tags: 'weather,ionosphere,haarp,atmospheric', owner: '@weather_control', location: 'Alaska Research Station',
        likes: 167, likedBy: [], bookings: [], createdAt: now - 86400000 * 12
      },
      {
        id: generateId(), type: 'equipment', title: 'Consciousness Transfer Pod',
        description: 'Experimental neural pattern recording and playback system. Upload/download memories.',
        tags: 'consciousness,neural-patterns,memory,transfer', owner: '@mind_tech', location: 'Consciousness Labs',
        likes: 198, likedBy: [], bookings: [], createdAt: now - 86400000 * 13
      },
      {
        id: generateId(), type: 'equipment', title: 'Zero-Point Energy Harvester',
        description: 'Extract energy from quantum vacuum fluctuations. Provides unlimited clean power.',
        tags: 'zero-point,energy,quantum-vacuum,unlimited', owner: '@vacuum_energy', location: 'Energy Research Facility',
        likes: 234, likedBy: [], bookings: [
          { date: '2025-08-29', slot: '08:00–18:00', by: '@energy_physicist' },
          { date: '2025-09-02', slot: '10:00–15:00', by: '@vacuum_researcher' }
        ], createdAt: now - 86400000 * 14
      },
      {
        id: generateId(), type: 'equipment', title: 'Dimensional Portal Gateway',
        description: 'Stable wormhole generator for interdimensional research. Safety protocols included.',
        tags: 'portal,wormhole,dimensional,interdimensional', owner: '@portal_technologies', location: 'CERN Portal Lab',
        likes: 267, likedBy: [], bookings: [], createdAt: now - 86400000 * 15
      },
      {
        id: generateId(), type: 'equipment', title: 'Synthetic Life Genesis Incubator',
        description: 'Create artificial life forms from base elements. Full evolutionary acceleration chambers.',
        tags: 'synthetic-life,genesis,evolution,artificial', owner: '@genesis_systems', location: 'Synthetic Biology Lab',
        likes: 178, likedBy: [], bookings: [], createdAt: now - 86400000 * 16
      },
      {
        id: generateId(), type: 'equipment', title: 'Psychokinetic Amplification Matrix',
        description: 'Boost telekinetic abilities 1000x using quantum field manipulation. Mind over matter.',
        tags: 'psychokinesis,telekinesis,amplification,quantum', owner: '@psycho_kinetic_lab', location: 'Parapsychology Institute',
        likes: 145, likedBy: [], bookings: [], createdAt: now - 86400000 * 17
      },
      {
        id: generateId(), type: 'equipment', title: 'Cellular Immortality Treatment Pod',
        description: 'Reverse aging at the cellular level. Telomere repair and DNA optimization system.',
        tags: 'immortality,aging,telomeres,cellular-repair', owner: '@longevity_systems', location: 'Life Extension Institute',
        likes: 289, likedBy: [], bookings: [
          { date: '2025-09-01', slot: '09:00–17:00', by: '@anti_aging_researcher' }
        ], createdAt: now - 86400000 * 18
      },
      {
        id: generateId(), type: 'equipment', title: 'Quantum Superposition Processor',
        description: 'Room-temperature quantum computer with 10,000 qubit capacity. Unlimited parallel processing.',
        tags: 'quantum-computer,superposition,qubits,parallel', owner: '@quantum_processing', location: 'IBM Quantum Lab',
        likes: 223, likedBy: [], bookings: [], createdAt: now - 86400000 * 19
      },
      {
        id: generateId(), type: 'equipment', title: 'Reality Manipulation Engine',
        description: 'Alter local physics constants within 10m radius. Research applications only.',
        tags: 'reality,physics,constants,manipulation', owner: '@reality_labs', location: 'Advanced Physics Facility',
        likes: 345, likedBy: [], bookings: [], createdAt: now - 86400000 * 20
      }
    ];

    const sampleCommunities = [
      {
        id: generateId(), name: 'MIT Quantum Computing Research',
        description: 'Collaborative research group focused on advancing quantum computing technologies and applications.',
        type: 'university', location: 'north-america', tags: 'quantum,computing,research,physics',
        avatar: '⚛️', memberCount: 156, members: [], createdAt: now - 86400000 * 5
      },
      {
        id: generateId(), name: 'Stanford AI Ethics Forum',
        description: 'Interdisciplinary community discussing ethical implications of artificial intelligence development.',
        type: 'university', location: 'north-america', tags: 'ai,ethics,philosophy,technology',
        avatar: '🤖', memberCount: 234, members: [], createdAt: now - 86400000 * 8
      },
      {
        id: generateId(), name: 'Berkeley Open Science Initiative',
        description: 'Promoting open access research and collaborative scientific methodologies across disciplines.',
        type: 'university', location: 'north-america', tags: 'open-science,collaboration,research',
        avatar: '🔬', memberCount: 189, members: [], createdAt: now - 86400000 * 12
      },
      {
        id: generateId(), name: 'European Fusion Energy Consortium',
        description: 'International collaboration advancing fusion energy research and development across European institutions.',
        type: 'professional', location: 'europe', tags: 'fusion,energy,physics,collaboration',
        avatar: '⚡', memberCount: 312, members: [], createdAt: now - 86400000 * 15
      },
      {
        id: generateId(), name: 'Global Climate Research Network',
        description: 'Worldwide network of climate scientists sharing data, methodologies, and research findings.',
        type: 'professional', location: 'global', tags: 'climate,environment,data,research',
        avatar: '🌍', memberCount: 478, members: [], createdAt: now - 86400000 * 20
      },
      {
        id: generateId(), name: 'Bioengineering Innovation Hub',
        description: 'Community of bioengineers developing revolutionary medical devices and therapeutic solutions.',
        type: 'research', location: 'north-america', tags: 'bioengineering,medical,innovation,devices',
        avatar: '🧬', memberCount: 145, members: [], createdAt: now - 86400000 * 18
      },
      {
        id: generateId(), name: 'Asian Nanotechnology Alliance',
        description: 'Collaborative network advancing nanotechnology research and applications across Asian institutions.',
        type: 'professional', location: 'asia', tags: 'nanotechnology,materials,research,innovation',
        avatar: '🔬', memberCount: 267, members: [], createdAt: now - 86400000 * 25
      },
      {
        id: generateId(), name: 'Space Technology Enthusiasts',
        description: 'Community of researchers, engineers, and enthusiasts passionate about space exploration technologies.',
        type: 'hobby', location: 'global', tags: 'space,technology,exploration,engineering',
        avatar: '🚀', memberCount: 423, members: [], createdAt: now - 86400000 * 30
      },
      {
        id: generateId(), name: 'Renewable Energy Makers',
        description: 'DIY community focused on building and testing renewable energy solutions and sustainable technologies.',
        type: 'hobby', location: 'global', tags: 'renewable,energy,diy,sustainability',
        avatar: '⚡', memberCount: 198, members: [], createdAt: now - 86400000 * 22
      },
      {
        id: generateId(), name: 'Open Source Hardware Initiative',
        description: 'Global community developing open-source hardware designs for scientific research and education.',
        type: 'nonprofit', location: 'global', tags: 'open-source,hardware,education,research',
        avatar: '⚙️', memberCount: 356, members: [], createdAt: now - 86400000 * 28
      },
      {
        id: generateId(), name: 'Neural Interface Research Collective',
        description: 'Interdisciplinary group researching brain-computer interfaces and neural augmentation technologies.',
        type: 'research', location: 'north-america', tags: 'neural,interface,brain,augmentation',
        avatar: '🧠', memberCount: 134, members: [], createdAt: now - 86400000 * 35
      },
      {
        id: generateId(), name: 'Synthetic Biology Collaborative',
        description: 'International network of synthetic biology researchers designing biological systems for various applications.',
        type: 'professional', location: 'global', tags: 'synthetic-biology,design,systems,applications',
        avatar: '🔬', memberCount: 289, members: [], createdAt: now - 86400000 * 14
      },
      {
        id: generateId(), name: 'Quantum Biology Study Group',
        description: 'Research community exploring quantum effects in biological systems and their potential applications.',
        type: 'research', location: 'europe', tags: 'quantum,biology,systems,research',
        avatar: '🌱', memberCount: 167, members: [], createdAt: now - 86400000 * 40
      },
      {
        id: generateId(), name: 'Materials Science Innovation Lab',
        description: 'Collaborative laboratory developing next-generation materials for aerospace and electronics applications.',
        type: 'university', location: 'north-america', tags: 'materials,aerospace,electronics,innovation',
        avatar: '⚗️', memberCount: 112, members: [], createdAt: now - 86400000 * 10
      },
      {
        id: generateId(), name: 'Citizen Science Network',
        description: 'Community enabling public participation in scientific research projects across multiple disciplines.',
        type: 'nonprofit', location: 'global', tags: 'citizen-science,public,participation,research',
        avatar: '👥', memberCount: 567, members: [], createdAt: now - 86400000 * 32
      }
    ];

    const sampleItems = [...sampleProjects, ...sampleMarketplace];

    data.items = [...sampleItems, ...data.items];
    data.communities = [...sampleCommunities, ...(data.communities || [])];
    
    if (await saveData(data)) {
      res.json({ 
        message: `Seeded ${sampleItems.length} items and ${sampleCommunities.length} communities`, 
        items: sampleItems,
        communities: sampleCommunities
      });
    } else {
      res.status(500).json({ error: 'Failed to seed data' });
    }
  } catch (error) {
    res.status(500).json({ error: 'Failed to seed data' });
  }
});

// Reset data endpoint (requires authentication in production)
app.delete('/api/reset', authManager.optionalAuth, async (req, res) => {
  try {
    const defaultData = {
      items: [],
      userFollowers: {},
      userProfiles: {},
      communities: [],
      discussions: [],
      discussionReplies: {},
      journalPapers: []
    };
    
    if (await saveData(defaultData)) {
      res.json({ message: 'Data reset successfully' });
    } else {
      res.status(500).json({ error: 'Failed to reset data' });
    }
  } catch (error) {
    res.status(500).json({ error: 'Failed to reset data' });
  }
});

// =================
// JOURNAL PAPERS API
// =================

// Get all journal papers
app.get('/api/journal', authManager.optionalAuth, async (req, res) => {
  try {
    const data = await loadData();
    const { category, status, search } = req.query;
    
    let papers = data.journalPapers || [];
    
    // Apply filters
    if (category && category !== '') {
      papers = papers.filter(paper => paper.category === category);
    }
    
    if (status && status !== '') {
      papers = papers.filter(paper => paper.status === status);
    }
    
    if (search && search.trim() !== '') {
      const searchTerm = search.toLowerCase();
      papers = papers.filter(paper => 
        paper.title.toLowerCase().includes(searchTerm) ||
        paper.abstract.toLowerCase().includes(searchTerm) ||
        paper.authors.some(author => author.toLowerCase().includes(searchTerm)) ||
        (paper.keywords && paper.keywords.some(keyword => keyword.toLowerCase().includes(searchTerm)))
      );
    }
    
    // Sort papers by creation date (newest first)
    papers.sort((a, b) => b.createdAt - a.createdAt);
    
    res.json(papers);
  } catch (error) {
    console.error('Error loading journal papers:', error);
    res.status(500).json({ error: 'Failed to load journal papers' });
  }
});

// Create new journal paper
app.post('/api/journal', authManager.requireAuth, async (req, res) => {
  try {
    const { title, abstract, authors, category, status, keywords, fileUrl } = req.body;
    
    // Comprehensive input validation
    const validationResult = validator.validateJournalPaper({ title, abstract, authors, category, status, keywords, fileUrl });
    if (!validationResult.valid) {
      return res.status(400).json({ 
        error: 'Validation failed', 
        details: validationResult.errors 
      });
    }

    const { title: validTitle, abstract: validAbstract, authors: validAuthors, 
            category: validCategory, status: validStatus, keywords: validKeywords, 
            fileUrl: validFileUrl } = validationResult.sanitized;
    
    const data = await loadData();
    const user = req.user;
    const userHandle = user.handle || user.email?.split('@')[0] || 'anonymous';
    
    const paper = {
      id: generateId(),
      title: validTitle,
      abstract: validAbstract,
      authors: validAuthors,
      category: validCategory,
      status: validStatus,
      keywords: validKeywords,
      fileUrl: validFileUrl,
      submittedBy: userHandle,
      submittedById: user.id,
      likes: 0,
      likedBy: [],
      downloads: 0,
      views: 0,
      createdAt: Date.now(),
      updatedAt: Date.now()
    };
    
    if (!data.journalPapers) {
      data.journalPapers = [];
    }
    
    data.journalPapers.push(paper);
    
    const success = await saveData(data);
    if (!success) {
      return res.status(500).json({ error: 'Failed to save paper' });
    }
    
    res.status(201).json({ 
      message: 'Paper submitted successfully',
      paper: paper
    });
  } catch (error) {
    console.error('Error creating journal paper:', error);
    res.status(500).json({ error: 'Failed to create journal paper' });
  }
});

// Like/unlike journal paper
app.put('/api/journal/:id/like', authManager.requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const data = await loadData();
    const user = req.user;
    
    const paper = data.journalPapers.find(p => p.id === id);
    if (!paper) {
      return res.status(404).json({ error: 'Paper not found' });
    }
    
    if (!paper.likedBy) {
      paper.likedBy = [];
    }
    
    const userIndex = paper.likedBy.indexOf(user.id);
    let liked;
    
    if (userIndex === -1) {
      // Like the paper
      paper.likedBy.push(user.id);
      paper.likes = paper.likedBy.length;
      liked = true;
    } else {
      // Unlike the paper
      paper.likedBy.splice(userIndex, 1);
      paper.likes = paper.likedBy.length;
      liked = false;
    }
    
    const success = await saveData(data);
    if (!success) {
      return res.status(500).json({ error: 'Failed to update like' });
    }
    
    res.json({
      likes: paper.likes,
      liked: liked
    });
  } catch (error) {
    console.error('Error toggling paper like:', error);
    res.status(500).json({ error: 'Failed to update like' });
  }
});

app.listen(PORT, async () => {
  await ensureUploadsDir();
  console.log(`Tyton API server running on port ${PORT}`);
  console.log(`Visit http://localhost:${PORT} to view the Tyton demo`);
});