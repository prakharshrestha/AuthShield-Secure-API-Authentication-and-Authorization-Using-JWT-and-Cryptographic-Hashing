"""
main.py — AuthShield Entry Point

Run with:
    python main.py
or:
    uvicorn main:app --reload --host 127.0.0.1 --port 8000
"""

import uvicorn
from authshield.app import app

if __name__ == "__main__":
    print("================================================================")
    print(" 🛡️  Starting AuthShield Secure Authentication & Authorization API")
    print(" 📖 Interactive Swagger UI: http://127.0.0.1:8000/docs")
    print(" 📖 Alternative ReDoc:     http://127.0.0.1:8000/redoc")
    print("================================================================")
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
