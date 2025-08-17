# Tyton API - Claude Project Data

## Project Overview

**Tyton** is a research collaboration platform that connects researchers, enables project sharing, and facilitates equipment booking across academic institutions.

## Architecture

- **Backend**: Node.js + Express.js REST API
- **Authentication**: Passport.js (Local + Google OAuth)
- **Database**: JSON file storage (users.json, data.json)
- **File Upload**: Multer with image validation
- **Frontend**: Static HTML/CSS/JS with responsive design

## Key Features

### ✅ Implemented
- User registration/login (email/password + Google OAuth)
- Profile management with completion flow
- Project posting and browsing
- Equipment marketplace with booking system
- Like/follow functionality for projects
- File upload with image validation
- Search with filtering by type, tags, query
- Demo data seeding endpoint
- Complete responsive frontend

### API Endpoints

#### Authentication
- `POST /auth/register` - User registration
- `POST /auth/login` - User login
- `GET /auth/google` - Google OAuth start
- `GET /auth/google/callback` - Google OAuth callback
- `POST /auth/logout` - User logout
- `GET /auth/me` - Get current user
- `POST /auth/complete-profile` - Complete profile setup

#### Data Management
- `GET /api/data` - Get all data (projects/equipment)
- `POST /api/items` - Create new project/equipment
- `PUT /api/items/:id/like` - Like/unlike item
- `PUT /api/items/:id/follow` - Follow/unfollow item
- `POST /api/equipment/:id/book` - Book equipment
- `GET /api/search` - Search projects/equipment
- `PUT /api/profile` - Update user profile
- `POST /api/upload` - File upload

#### Admin/Demo
- `POST /api/seed` - Seed demo data
- `DELETE /api/reset` - Reset data

## Environment Variables

```env
# Server
PORT=3000
NODE_ENV=development

# JWT & Sessions
JWT_SECRET=your-jwt-secret-here
SESSION_SECRET=your-session-secret-here

# Google OAuth
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret

# File Upload
MAX_FILE_SIZE=5242880
UPLOAD_PATH=public/uploads

# CORS
CORS_ORIGIN=http://localhost:3000
```

## Development Commands

```bash
# Install dependencies
npm install

# Start development server
npm start

# Test API endpoints
npm run test

# Lint code
npm run lint
```

## File Structure

```
tyton-api/
├── public/                 # Frontend files
│   ├── index.html         # Main homepage
│   ├── marketplace.html   # Equipment marketplace
│   ├── project.html       # Project details
│   ├── search.html        # Search interface
│   ├── profile-setup.html # Profile completion
│   ├── setup.html         # Initial setup
│   └── assets/            # Images and static files
├── index.js               # Main server file
├── auth.js                # Authentication manager
├── userStore.js           # User data management
├── data.json              # Project/equipment data
├── users.json             # User accounts
├── package.json           # Dependencies
└── .env                   # Environment variables
```

## Database Schema

### User Object
```javascript
{
  id: "user_abc123",
  email: "user@example.com", 
  name: "User Name",
  handle: "@username",
  bio: "User bio",
  photo: "photo-url",
  hashedPassword: "bcrypt-hash",
  googleId: "google-id", // optional
  createdAt: timestamp,
  emailVerified: boolean,
  profileComplete: boolean
}
```

### Item Object (Project/Equipment)
```javascript
{
  id: "item_xyz789",
  type: "project" | "equipment",
  title: "Item Title",
  description: "Item description",
  tags: "comma,separated,tags",
  owner: "@username",
  ownerId: "user_id",
  location: "Location",
  likes: 0,
  likedBy: ["user_id1", "user_id2"],
  bookings: [{ // equipment only
    date: "2025-08-20",
    slot: "09:00-11:00", 
    by: "@username",
    userId: "user_id",
    createdAt: timestamp
  }],
  createdAt: timestamp
}
```

## Deployment Notes

### Security Considerations
- Change default JWT/session secrets
- Use environment variables for sensitive data
- Enable HTTPS in production
- Implement rate limiting
- Add input validation/sanitization
- Consider moving to proper database (PostgreSQL/MongoDB)

### Production Setup
1. Set `NODE_ENV=production`
2. Configure proper CORS origins
3. Set up reverse proxy (nginx)
4. Enable SSL/TLS
5. Configure file upload limits
6. Set up monitoring and logging

## Testing

### Manual API Testing
```bash
# Test data endpoint
curl http://localhost:3000/api/data

# Test search
curl "http://localhost:3000/api/search?q=quantum"

# Test seeding
curl -X POST http://localhost:3000/api/seed
```

## Known Issues & TODOs

- [ ] Add proper database (PostgreSQL/MongoDB)
- [ ] Implement email verification
- [ ] Add real-time notifications
- [ ] Improve error handling
- [ ] Add API rate limiting
- [ ] Add unit/integration tests
- [ ] Implement soft delete for items
- [ ] Add admin panel
- [ ] Add user roles/permissions
- [ ] Optimize search with full-text search

## Recent Changes

- **2025-08-17**: Initial implementation completed
  - Full authentication system
  - Complete API with all endpoints
  - Responsive frontend
  - Demo data seeding
  - Git repository setup

---

*Generated with Claude Code - This file helps Claude understand the project structure and maintain context across sessions.*