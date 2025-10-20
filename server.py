#!/usr/bin/env python3
"""
Vulnerable pyquokka FlightServer for CVE-2025-62515 PoC.
Binds to 0.0.0.0:5005 for remote exposure.
"""

from pyquokka.flight import FlightServer

def main():
    print("🚨 Starting VULNERABLE FlightServer (pyquokka <=0.3.1)...")
    print("Listening on grpc+tcp://0.0.0.0:5005")
    print("Run 'python exploit.py' from another terminal to test RCE.")
    print("Expected: Command output here on exploit.")
    
    server = FlightServer("0.0.0.0", location="grpc+tcp://0.0.0.0:5005")
    server.serve()  # Blocks indefinitely

if __name__ == "__main__":
    main()
