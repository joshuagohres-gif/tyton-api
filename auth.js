const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

class AuthManager {
  constructor(userStore) {
    this.userStore = userStore;
    
    // Enforce secure JWT secret
    this.JWT_SECRET = process.env.JWT_SECRET;
    if (!this.JWT_SECRET || this.JWT_SECRET.includes('demo') || this.JWT_SECRET.length < 32) {
      if (process.env.NODE_ENV === 'production') {
        throw new Error('JWT_SECRET must be set to a secure value (32+ characters) in production');
      }
      console.warn('⚠️  WARNING: Using insecure JWT_SECRET. Set a secure JWT_SECRET in production!');
      this.JWT_SECRET = 'tyton-demo-secret-key-change-in-production';
    }
    
    this.setupPassport();
  }

  setupPassport() {
    // Local Strategy (Email/Password)
    passport.use(new LocalStrategy({
      usernameField: 'email',
      passwordField: 'password'
    }, async (email, password, done) => {
      try {
        const user = await this.userStore.findByEmail(email);
        if (!user) {
          return done(null, false, { message: 'Invalid email or password' });
        }

        const isValid = await bcrypt.compare(password, user.hashedPassword);
        if (!isValid) {
          return done(null, false, { message: 'Invalid email or password' });
        }

        return done(null, user);
      } catch (error) {
        return done(error);
      }
    }));

    // Google OAuth Strategy
    passport.use(new GoogleStrategy({
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: process.env.GOOGLE_CALLBACK_URL || `/auth/google/callback`,
      scope: ['profile', 'email']
    }, async (accessToken, refreshToken, profile, done) => {
      try {
        // Check if user already exists
        let user = await this.userStore.findByGoogleId(profile.id);
        
        if (user) {
          return done(null, user);
        }

        // Check if user exists with same email
        user = await this.userStore.findByEmail(profile.emails[0].value);
        if (user) {
          // Link Google account to existing user
          user.googleId = profile.id;
          await this.userStore.updateUser(user.id, user);
          return done(null, user);
        }

        // Create new user with Google data - mark as incomplete profile
        const newUser = {
          id: this.generateUserId(),
          email: profile.emails[0].value,
          name: profile.displayName,
          handle: '', // Will be set during onboarding
          bio: '',
          photo: profile.photos[0]?.value || '',
          googleId: profile.id,
          createdAt: Date.now(),
          emailVerified: true,
          profileComplete: false, // Flag for onboarding
          googleData: {
            name: profile.displayName,
            email: profile.emails[0].value,
            photo: profile.photos[0]?.value || ''
          }
        };

        await this.userStore.createUser(newUser);
        return done(null, newUser);
      } catch (error) {
        return done(error);
      }
    }));

    passport.serializeUser((user, done) => {
      done(null, user.id);
    });

    passport.deserializeUser(async (id, done) => {
      try {
        const user = await this.userStore.findById(id);
        done(null, user);
      } catch (error) {
        done(error);
      }
    });
  }

  generateUserId() {
    return 'user_' + crypto.randomUUID();
  }

  async hashPassword(password) {
    return await bcrypt.hash(password, 12);
  }

  generateJWT(user) {
    return jwt.sign(
      { 
        id: user.id, 
        email: user.email,
        handle: user.handle 
      }, 
      this.JWT_SECRET, 
      { expiresIn: '7d' }
    );
  }

  verifyJWT(token) {
    try {
      return jwt.verify(token, this.JWT_SECRET);
    } catch (error) {
      return null;
    }
  }

  // Middleware to protect routes
  requireAuth = (req, res, next) => {
    // Check for JWT token
    const token = req.headers.authorization?.replace('Bearer ', '') || 
                  req.session?.token || 
                  req.cookies?.token;

    if (token) {
      const decoded = this.verifyJWT(token);
      if (decoded) {
        req.user = decoded;
        return next();
      }
    }

    // Check for Passport session (Google OAuth)
    if (req.user) {
      return next();
    }

    return res.status(401).json({ error: 'Authentication required' });
  };

  // Optional auth middleware
  optionalAuth = (req, res, next) => {
    // Check for JWT token
    const token = req.headers.authorization?.replace('Bearer ', '') || 
                  req.session?.token || 
                  req.cookies?.token;

    if (token) {
      const decoded = this.verifyJWT(token);
      if (decoded) {
        req.user = decoded;
      }
    }
    
    // If no token auth, check for Passport session (req.user is set by Passport)
    // Passport already sets req.user if session exists, so we don't need to override it
    
    next();
  };
}

module.exports = AuthManager;