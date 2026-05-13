#!/usr/bin/env python3
"""
SmartPatch Dashboard - Integrated Startup Script
Launches API backend + Frontend, performs real-time system scan, 
and displays recommendations in professional security dashboard.

NO MOCKS. NO HARDCODED DATA. PURE REAL-TIME SCANNING.
"""

import subprocess
import sys
import time
import signal
import logging
import json
import requests
import threading
from pathlib import Path

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s'
)
logger = logging.getLogger('SmartPatch-Dashboard')

# Configuration
API_PORT = 8888
FRONTEND_PORT = 8000
API_URL = f'http://localhost:{API_PORT}'
FRONTEND_URL = f'http://localhost:{FRONTEND_PORT}'
FRONTEND_PAGE = 'login.html'

# Process handles
processes = []

def signal_handler(signum, frame):
    """Handle Ctrl+C gracefully"""
    logger.info("Shutting down SmartPatch Dashboard...")
    for proc in processes:
        try:
            proc.terminate()
            proc.wait(timeout=5)
        except Exception as e:
            logger.warning(f"Error terminating process: {e}")
            proc.kill()
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)


def start_backend_api():
    """Start Flask backend API server"""
    logger.info(f"Starting SmartPatch API on port {API_PORT}...")
    
    cmd = [
        sys.executable, '-m', 'flask',
        '--app', 'src.api.backend_api_fixed:app',
        'run',
        '--host', '0.0.0.0',
        '--port', str(API_PORT)
    ]
    
    proc = subprocess.Popen(
        cmd,
        cwd=str(Path(__file__).parent),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1
    )
    
    # Stream output in a background thread
    def stream_output():
        for line in proc.stdout:
            if line.strip():
                logger.info(f"[API] {line.rstrip()}")
    
    thread = threading.Thread(target=stream_output, daemon=True)
    thread.start()
    
    processes.append(proc)
    
    # Wait for API to be ready
    for attempt in range(30):
        try:
            resp = requests.get(f'{API_URL}/api/system', timeout=2)
            if resp.status_code == 200:
                logger.info(f"✓ API ready at {API_URL}")
                return True
        except Exception:
            pass
        
        time.sleep(1)
    
    logger.error("API failed to start")
    return False


def start_frontend():
    """Start the html5up-spectral static frontend server"""
    frontend_dir = Path(__file__).parent / 'html5up-spectral'
    logger.info(f"Starting SmartPatch html5up-spectral frontend on port {FRONTEND_PORT}...")
    logger.info(f"Frontend directory: {frontend_dir}")

    if not frontend_dir.exists():
        logger.error(f"Frontend directory not found: {frontend_dir}")
        return False

    cmd = [sys.executable, '-m', 'http.server', str(FRONTEND_PORT), '--bind', '0.0.0.0']

    proc = subprocess.Popen(
        cmd,
        cwd=str(frontend_dir),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1
    )
    
    # Stream output in a background thread
    def stream_output():
        for line in proc.stdout:
            if line.strip():
                logger.info(f"[Frontend] {line.rstrip()}")
    
    thread = threading.Thread(target=stream_output, daemon=True)
    thread.start()
    
    processes.append(proc)
    
    # Wait for frontend to be ready
    for attempt in range(30):
        try:
            resp = requests.get(f'{FRONTEND_URL}/{FRONTEND_PAGE}', timeout=2)
            if resp.status_code == 200:
                logger.info(f"✓ Frontend ready at {FRONTEND_URL}/{FRONTEND_PAGE}")
                return True
        except Exception:
            pass

        time.sleep(1)
    
    logger.warning("Frontend may still be starting...")
    return True


def trigger_system_scan():
    """Trigger a real-time system scan via API"""
    logger.info("Triggering real-time system scan...")
    
    time.sleep(3)  # Wait for API to fully start
    
    try:
        resp = requests.post(
            f'{API_URL}/api/scan',
            json={'type': 'full'},
            timeout=120
        )
        
        if resp.status_code in [200, 202]:
            logger.info("System scan initiated successfully")
            return True
        else:
            logger.warning(f"Scan request failed: {resp.status_code}")
            return False
    except Exception as e:
        logger.warning(f"Could not trigger scan: {e}")
        return False


def display_banner():
    """Display startup banner"""
    banner = """
    
    ====================================================================
                    SMARTPATCH DETECTION DASHBOARD
                  Real-Time Vulnerability Analysis
    ====================================================================
    
    API Server:       http://localhost:8888
    Dashboard UI:     http://localhost:8000/login.html
    
    FEATURES:
    - Real-time system scanning (no mock data)
    - Live missing KB detection with CVE mapping
    - HARS-scored recommendations
    - Professional security dashboard
    - Rule-based + RAG-powered mitigations
    
    OPENING DASHBOARD IN BROWSER...
    
    ====================================================================
    
    """
    print(banner)


def main():
    """Main entry point"""
    display_banner()
    
    # Start API backend
    if not start_backend_api():
        logger.error("Failed to start API backend")
        sys.exit(1)
    
    # Start Frontend
    if not start_frontend():
        logger.error("Failed to start frontend")
        sys.exit(1)
    
    # Trigger system scan
    trigger_system_scan()
    
    # Open browser
    logger.info(f"Opening dashboard at {FRONTEND_URL}/{FRONTEND_PAGE}...")
    import webbrowser
    try:
        webbrowser.open(f'{FRONTEND_URL}/{FRONTEND_PAGE}')
    except Exception as e:
        logger.warning(f"Could not open browser: {e}")

    logger.info(f"Open this URL in your browser: {FRONTEND_URL}/{FRONTEND_PAGE}")
    
    logger.info("SmartPatch Dashboard is running!")
    logger.info("Press Ctrl+C to stop...")
    
    # Keep processes running
    try:
        for proc in processes:
            proc.wait()
    except KeyboardInterrupt:
        signal_handler(None, None)


if __name__ == '__main__':
    main()
