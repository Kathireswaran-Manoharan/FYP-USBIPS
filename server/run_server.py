import uvicorn
import os
import sys
import socket
import argparse

# Ensure repository root is on sys.path
repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if repo_root not in sys.path:
    sys.path.insert(0, repo_root)

from server.app.database.db import init_db

def validate_bind_address(host: str, port: int) -> bool:
    """Validate that the server can bind to the specified host and port."""
    test_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        test_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        test_sock.bind((host, port))
        return True
    except OSError as e:
        print(f"[ERROR] Cannot bind to {host}:{port} - {e}")
        print("[HINT] Available local host IPs on this machine:")
        try:
            hostname = socket.gethostname()
            for ip in socket.gethostbyname_ex(hostname)[2]:
                print(f"       - {ip}")
        except Exception:
            pass
        print("       - 127.0.0.1 (Local loopback)")
        print("       - 0.0.0.0 (All interfaces - ensure Private/Domain firewall rule only)")
        return False
    finally:
        test_sock.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="USBIPS Central Management Server")
    parser.add_argument("--host", default=None, help="Server bind host/IP (default: USBIPS_SERVER_BIND_HOST env or 127.0.0.1)")
    parser.add_argument("--port", type=int, default=None, help="Server bind port (default: USBIPS_SERVER_PORT env or 8000)")
    args = parser.parse_args()

    host = args.host or os.environ.get("USBIPS_SERVER_BIND_HOST") or os.environ.get("USBIPS_SERVER_HOST") or "127.0.0.1"
    port = args.port or int(os.environ.get("USBIPS_SERVER_PORT", "8000"))

    print("==================================================")
    print("      USBIPS CENTRAL MANAGEMENT SERVER")
    print("==================================================")
    print("Initializing SQLite database tables...")
    init_db()

    if host == "0.0.0.0":
        print(f"[SECURITY NOTICE] Binding to all network interfaces (0.0.0.0).")
        print(f"                  Ensure Windows Firewall restricts port {port} to authorized Private/Domain networks.")
    elif host == "127.0.0.1":
        print("[NOTICE] Running on localhost (127.0.0.1) for local development.")
        print("         For fleet laptops across the LAN, pass --host <LAN_IP> or set USBIPS_SERVER_BIND_HOST.")
    else:
        print(f"[NOTICE] Bound to configured network interface: {host}")

    if not validate_bind_address(host, port):
        print("[FATAL] Server startup aborted due to network bind error.")
        sys.exit(1)

    print(f"Starting server at: http://{host}:{port}")
    print(f"Access the Web Dashboard at: http://{host}:{port}")
    print(f"Swagger API Docs available at: http://{host}:{port}/docs")
    print("==================================================")
    uvicorn.run("server.app.main:app", host=host, port=port, reload=True)

