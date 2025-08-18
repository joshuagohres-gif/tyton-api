# Tyton Beta Development Setup

This guide helps you quickly set up the Tyton Beta project on any device with Claude Code.

## Quick Setup for Development

### Option 1: Clone and Run (Recommended)

```bash
# Clone the repository
git clone https://github.com/joshuagohres-gif/tyton-api.git
cd tyton-api

# Install dependencies
npm install

# Start development server
npm start
```

Then open `http://localhost:3000` in your browser.

### Option 2: One-Line Setup

```bash
git clone https://github.com/joshuagohres-gif/tyton-api.git && cd tyton-api && npm install && npm start
```

## Claude Code Workflow

When working with Claude Code on this project:

1. **Clone the repo** in your terminal or use Claude Code's file operations
2. **Install dependencies** with `npm install`
3. **Start the dev server** with `npm start`
4. **Make changes** to files in `public/` for frontend or `index.js` for backend
5. **Test changes** by refreshing `http://localhost:3000`
6. **Commit changes** when ready

## Development Commands

```bash
# Start development server
npm start

# Install new dependencies
npm install [package-name]

# View git status
git status

# Commit changes
git add .
git commit -m "Your commit message"
git push
```

## Project Structure

- `public/index.html` - Main frontend application
- `index.js` - Express.js backend server
- `data.json` - Database file (auto-created)
- `public/assets/` - Static assets and images
- `CLAUDE.md` - Project documentation for Claude

## Key Features to Work On

- **Navigation**: All icons and routing in `public/index.html`
- **API**: RESTful endpoints in `index.js`
- **Styling**: CSS-in-JS in the `<style>` section of `index.html`
- **Data**: JSON persistence with localStorage fallback

## Common Development Tasks

### Adding New Icons
Icons use SVG with base64 fallbacks. See navigation section in `index.html`.

### Adding New Pages
1. Add button to navigation in sidebar
2. Add page section with `id="[page]-page"`
3. Add route handling in `setRoute()` function

### API Changes
Edit `index.js` for backend changes. The server auto-serves static files from `public/`.

### Styling Updates
Main styles are in the `<style>` section of `index.html`. Uses CSS variables for theming.

## Environment

- **Node.js**: Required for backend
- **Port**: 3000 (configurable via `PORT` env var)
- **Data**: Persisted in `data.json` file
- **Uploads**: Stored in `public/uploads/`

## Deployment

The project is ready for deployment on any Node.js hosting platform:
- Vercel
- Netlify
- Railway
- Heroku
- DigitalOcean

Just ensure `npm start` runs successfully and the repository is connected.