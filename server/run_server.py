import uvicorn
import os
import sys

# Ensure repository root is on sys.path
repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if repo_root not in sys.path:
    sys.path.insert(0, repo_root)

if __name__ == "__main__":
    print("==================================================")
    print("      USBIPS CENTRAL MANAGEMENT SERVER (PHASE 1)")
    print("==================================================")
    print("Starting server at: http://127.0.0.1:8000")
    print("Access the Web Dashboard at: http://127.0.0.1:8000")
    print("Swagger API Docs available at: http://127.0.0.1:8000/docs")
    print("==================================================")
    uvicorn.run("server.app.main:app", host="127.0.0.1", port=8000, reload=True)
