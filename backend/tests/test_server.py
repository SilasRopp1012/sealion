from fastapi import FastAPI
from fastapi.responses import HTMLResponse
import uvicorn
import json

app = FastAPI()

@app.get("/")
async def test_page():
    return HTMLResponse("""
<!DOCTYPE html>
<html>
<head>
    <title>Secret Scanner Test</title>
    <script>
        // Real API Keys
        const STRIPE_KEY = 'sk_live_1234567890abcdefghijklmnopqrstuvwxyz';
        const OPENAI_KEY = 'sk-0123456789abcdefghijklmnopqrstuvwxyz';
        
        // AWS
        const AWS_KEY = 'AKIAIOSFODNN7EXAMPLE';
        const AWS_SECRET = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';
        
        // Database
        const DB_URL = 'postgresql://user:password123@localhost:5432/mydb';
        
        // JWT
        const JWT_TOKEN = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U';
        
        // GitHub
        const GITHUB_TOKEN = 'ghp_012345678901234567890123456789abcdef';
        
        // Generic secrets
        const API_KEY = '1234567890abcdef1234567890abcdef';
        const a_secret_value = 'this_is_a_very_secret_value_12345';
        
        // High entropy string that shouldn't be flagged without context
        const normal_string = 'this_is_a_normal_looking_string_with_low_entropy';
        const high_entropy_with_context_secret = 'a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6';
    </script>
</head>
<body>
    <h1>Test Page</h1>
    <script src="config.js"></script>
    <div data-config='{"apiKey": "1234567890abcdef1234567890abcdef"}'></div>
</body>
</html>
    """)

@app.get("/config.js")
async def config_js():
    return HTMLResponse("""
const config = {
    database: {
        connection: 'postgresql://user:password123@localhost:5432/db'
    },
    apis: {
        stripe: {
            secretKey: 'sk_live_1234567890abcdefghijklmnopqrstuvwxyz'
        },
        aws: {
            accessKeyId: 'AKIAIOSFODNN7EXAMPLE',
            secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
        }
    }
};
    """, media_type="application/javascript")

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8001) 