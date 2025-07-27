from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from routes import scan

app = FastAPI(
    title="Sealion Security Scanner",
    description="AI-powered security scanner for web applications",
    version="0.1.0"
)

# Set up CORS middleware
origins = [
    "http://localhost",
    "http://localhost:3000",
    "https://sea-lion.netlify.app",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(scan.router, tags=["scan"])

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
