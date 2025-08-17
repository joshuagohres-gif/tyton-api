require('dotenv').config();

const express = require('express');
const cors = require('cors');
const fs = require('fs').promises;
const path = require('path');
const multer = require('multer');
const session = require('express-session');
const passport = require('passport');
const AuthManager = require('./auth');
const UserStore = require('./userStore');

const app = express();
const PORT = process.env.PORT || 3000;
const DATA_FILE = path.join(__dirname, 'data.json');

// Initialize stores and auth
const userStore = new UserStore();
const authManager = new AuthManager(userStore);

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
app.use(session({
  secret: process.env.SESSION_SECRET || 'tyton-demo-session-secret',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
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

const upload = multer({ 
  storage: storage,
  limits: { 
    fileSize: parseInt(process.env.MAX_FILE_SIZE) || 5 * 1024 * 1024, // 5MB default
    files: 1 // Only allow 1 file per upload
  },
  fileFilter: function (req, file, cb) {
    // Allowed image types
    const allowedMimes = ['image/jpeg', 'image/jpg', 'image/png', 'image/gif', 'image/webp'];
    if (allowedMimes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error(`Invalid file type. Only ${allowedMimes.join(', ')} are allowed!`));
    }
  }
});

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
      userProfiles: parsed.userProfiles || {}
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
    const defaultData = { items: [], userFollowers: {}, userProfiles: {} };
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
  return Math.random().toString(36).slice(2,11) + Date.now().toString(36);
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
    
    if (!email || !password || !name) {
      return res.status(400).json({ error: 'Email, password, and name are required' });
    }

    if (password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters long' });
    }

    // Check if user already exists with this email
    const existingUser = await userStore.findByEmail(email.toLowerCase());
    if (existingUser) {
      return res.status(409).json({ 
        error: 'An account already exists with this email address. Please log in instead.',
        code: 'EMAIL_EXISTS'
      });
    }

    const hashedPassword = await authManager.hashPassword(password);
    
    const userData = {
      id: authManager.generateUserId(),
      email: email.toLowerCase(),
      name: name.trim(),
      handle: handle ? handle.trim() : '@' + email.split('@')[0].toLowerCase(),
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
        currentUser: currentUser
      });
    } else {
      // Return public data only
      res.json({
        items: data.items,
        followers: {},
        profile: {},
        currentUser: null
      });
    }
  } catch (error) {
    res.status(500).json({ error: 'Failed to load data' });
  }
});

app.post('/api/items', authManager.requireAuth, async (req, res) => {
  try {
    const { type, title, description, tags, location } = req.body;
    
    if (!title || !title.trim()) {
      return res.status(400).json({ error: 'Title is required' });
    }

    const data = await loadData();
    const newItem = {
      id: generateId(),
      type: type || 'project',
      title: title.trim(),
      description: description?.trim() || '',
      tags: tags?.trim() || '',
      owner: req.user.handle,
      ownerId: req.user.id,
      location: location?.trim() || '',
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

    const sampleItems = [...sampleProjects, ...sampleMarketplace];

    data.items = [...sampleItems, ...data.items];
    
    if (await saveData(data)) {
      res.json({ message: `Seeded ${sampleItems.length} items`, items: sampleItems });
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
      followers: {},
      profile: { name: '', handle: '@josh', bio: '', photo: '' }
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

app.listen(PORT, async () => {
  await ensureUploadsDir();
  console.log(`Tyton API server running on port ${PORT}`);
  console.log(`Visit http://localhost:${PORT} to view the Tyton demo`);
});