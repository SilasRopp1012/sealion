# 🦁 SeaLion Security Scanner

A modern web application security scanner that detects vulnerabilities like exposed secrets, database misconfigurations, and missing security headers.

**🔗 [Live Demo](https://sea-lion.netlify.app/)**

## Features

- **Secret Detection**: Scans for exposed API keys and tokens
- **Database Security**: Detects Firebase/Supabase misconfigurations  
- **API Security**: Finds unprotected endpoints
- **Security Headers**: Analyzes missing security headers
- **Modern UI**: Responsive glassmorphism design

## Tech Stack

- **Frontend**: Next.js 15, React 19, TypeScript, Tailwind CSS
- **Backend**: FastAPI (Python), httpx, BeautifulSoup4
- **Deployment**: Netlify + Render

## Getting Started

1. **Backend**:
   ```bash
   cd backend
   pip install -r requirements.txt
   python3 -m uvicorn main:app --reload --port 8000
   ```

2. **Frontend**:
   ```bash
   cd frontend
   npm install
   npm run dev
   ```

3. Open `http://localhost:3000`

## Usage

Simply enter a URL and click "Scan Now" to perform a comprehensive security analysis.

---

⭐ **Star this repo if you find it useful!**
