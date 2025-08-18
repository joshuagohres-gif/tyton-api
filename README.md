# Tyton Beta - Research Collaboration Platform

A modern research collaboration platform for projects and equipment sharing. Currently in beta development with dynamic UI features and enhanced user experience.

## Features

- ✨ **Project Management** - Create and share research projects
- 🔧 **Equipment Sharing** - List and book shared equipment
- 👤 **User Profiles** - Customizable user profiles with avatars
- 📱 **Offline Support** - Works offline with localStorage fallback
- 🌐 **Real-time API** - RESTful API with JSON data persistence
- 📸 **File Upload** - Image upload for profile pictures
- 🎨 **Modern UI** - Beautiful dark theme with responsive design and animated beta branding

## Quick Start

1. **Install dependencies:**
   ```bash
   npm install
   ```

2. **Add the Tyton logo:**
   - Save the provided Tyton owl logo image as `public/assets/logo.png`
   - The image should be 400x400px or similar square format

3. **Start the server:**
   ```bash
   npm start
   ```

4. **Open your browser:**
   - Visit `http://localhost:3000`
   - The demo will load with offline support if the server isn't running

## API Endpoints

- `GET /api/data` - Get all data (items, followers, profile)
- `POST /api/items` - Create new project or equipment
- `PUT /api/items/:id/like` - Like an item
- `PUT /api/items/:id/follow` - Follow/unfollow an item
- `POST /api/equipment/:id/book` - Book equipment
- `PUT /api/profile` - Update user profile
- `POST /api/upload` - Upload image files
- `POST /api/seed` - Seed demo data
- `DELETE /api/reset` - Reset all data

## File Structure

```
tyton-api/
├── index.js              # Express server with API endpoints
├── public/
│   ├── index.html        # Main frontend application
│   ├── assets/
│   │   └── logo.png      # Tyton logo (add this file)
│   └── uploads/          # User uploaded images
├── data.json             # Persistent data storage
└── package.json          # Dependencies and scripts
```

## Technology Stack

- **Backend**: Node.js, Express.js, Multer
- **Frontend**: Vanilla JavaScript, CSS3
- **Data**: JSON file storage with localStorage fallback
- **Styling**: CSS Grid, Flexbox, CSS Variables

## Deployment

For production deployment:

1. Set `NODE_ENV=production`
2. Configure a reverse proxy (nginx)
3. Use a process manager (PM2)
4. Set up file backup for `data.json`

## Contributing

This is a demo application showcasing modern web development practices with offline-first design and beautiful UI/UX.