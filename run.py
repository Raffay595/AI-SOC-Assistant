"""
SOC AI Assistant — Process Manager Launch Script

Runs both FastAPI backend and Streamlit frontend concurrently.
Handles graceful termination.
"""

import subprocess
import sys
import time
import os
import signal

# Get current workspace directory
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

def start_backend():
    """Starts FastAPI server using uvicorn on port 8000."""
    print("[LAUNCH] Starting FastAPI Backend on port 8000...")
    backend_cmd = [
        sys.executable, "-m", "uvicorn", 
        "backend.main:app", 
        "--host", "0.0.0.0", 
        "--port", "8000"
    ]
    return subprocess.Popen(backend_cmd, cwd=BASE_DIR)

def start_frontend():
    """Starts a simple Python HTTP static server on port 8501."""
    print("[LAUNCH] Starting Static HTML Frontend on port 8501...")
    frontend_cmd = [
        sys.executable, "-m", "http.server", "8501",
        "--directory", "frontend"
    ]
    return subprocess.Popen(frontend_cmd, cwd=BASE_DIR)

def main():
    # Make sure we have dependencies installed
    print("[INIT] Launching SOC AI Assistant Environment...")
    
    # Run DB seeds
    print("[INIT] Preparing database baseline...")
    try:
        subprocess.run(
            [sys.executable, "-m", "backend.init_db"], 
            cwd=BASE_DIR, 
            check=True
        )
    except Exception as e:
        print(f"[ERROR] DB initialization failed: {str(e)}")
        sys.exit(1)

    # Spawn processes
    backend_proc = start_backend()
    time.sleep(2) # Give backend a moment to bind port
    frontend_proc = start_frontend()

    print("\n" + "="*50)
    print("🛡️ SOC AI Assistant is running!")
    print("👉 Frontend: http://localhost:8501")
    print("👉 API Documentation: http://localhost:8000/docs")
    print("="*50 + "\n")
    print("Press Ctrl+C to terminate both servers.")

    try:
        while True:
            # Check if any process died
            if backend_proc.poll() is not None:
                print("[FATAL] Backend server exited unexpectedly.")
                break
            if frontend_proc.poll() is not None:
                print("[FATAL] Streamlit server exited unexpectedly.")
                break
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[SHUTDOWN] Terminating servers...")
    finally:
        # Gracefully kill processes
        try:
            backend_proc.terminate()
            frontend_proc.terminate()
            backend_proc.wait(timeout=5)
            frontend_proc.wait(timeout=5)
        except Exception:
            backend_proc.kill()
            frontend_proc.kill()
        print("[SHUTDOWN] Console processes stopped.")

if __name__ == "__main__":
    main()
