import os
import sys
import time
import threading
import webbrowser
import uvicorn
import subprocess

def start_server():
    # Start uvicorn programmatically
    print("Starting Web UI server...")
    uvicorn.run("app:app", host="127.0.0.1", port=8000, log_level="warning")

def open_browser():
    # Wait a moment for the server to start, then open the browser
    time.sleep(1.5)
    url = "http://127.0.0.1:8000"
    print(f"\nOpening browser at {url} ...")
    print("Press Ctrl+C in this console to stop the server.")
    webbrowser.open(url)

if __name__ == "__main__":
    # Ensure dependencies are installed silently first (optional convenience)
    try:
        import fastapi
        import python_multipart
    except ImportError:
        print("Missing required packages. Installing them now...")
        subprocess.run([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"], check=True)

    # Start the server thread
    server_thread = threading.Thread(target=start_server, daemon=True)
    server_thread.start()

    # Open the browser
    open_browser()

    # Keep the main thread alive
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nShutting down server...")
