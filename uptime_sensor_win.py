# uptime_sensor_win.py
import time, json, base64, socket, ctypes
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from datetime import datetime, timezone

# ── Config ────────────────────────────────────────────────────────────────────
VALIDATOR_HOST = "10.101.169.146"   # ← swap in Person 2's IP
VALIDATOR_PORT = 5500             # ← swap in Person 2's port
SEND_INTERVAL  = 60               # seconds between uptime records
# ─────────────────────────────────────────────────────────────────────────────

# Load keys
with open("keys/device_keys.json") as f:
    keys = json.load(f)

private_key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(keys["private_key"]))

def get_uptime_seconds() -> int:
    """
    Uses Windows API GetTickCount64() — no extra dependencies needed.
    Returns milliseconds since last boot, converted to whole seconds.
    """
    return ctypes.windll.kernel32.GetTickCount64() // 1000


def make_uptime_record() -> dict:
    record = {
        "timestamp":      time.time(),
        "device_id":      keys["public_key"],
        "uptime_seconds": get_uptime_seconds(),
    }
    payload = json.dumps(record, sort_keys=True).encode()
    record["signature"] = base64.b64encode(private_key.sign(payload)).decode()
    return record


def send_record(record: dict) -> bool:
    raw = (json.dumps(record) + "\n").encode()

    try:
        with socket.create_connection((VALIDATOR_HOST, VALIDATOR_PORT), timeout=10) as sock:
            sock.sendall(raw)

            sock.settimeout(5)
            ack = b""
            while not ack.endswith(b"\n"):
                chunk = sock.recv(1024)
                if not chunk:
                    break
                ack += chunk

        response = json.loads(ack.strip())
        if response.get("status") == "ok":
            print(f"[ACK] Validator accepted record at {record['timestamp']}")
            return True
        else:
            print(f"[WARN] Validator responded with: {response}")
            return False

    except ConnectionRefusedError:
        print(f"[ERROR] Connection refused — is Person 2's validator running on {VALIDATOR_HOST}:{VALIDATOR_PORT}?")
    except TimeoutError:
        print(f"[ERROR] Timed out connecting to {VALIDATOR_HOST}:{VALIDATOR_PORT}")
    except json.JSONDecodeError as e:
        print(f"[ERROR] Bad ACK from validator: {e}")
    except OSError as e:
        print(f"[ERROR] Network error: {e}")

    return False


def run():
    print(f"Starting uptime sensor (Windows) → {VALIDATOR_HOST}:{VALIDATOR_PORT}")
    print(f"Device ID : {keys['device_id']}")
    print(f"Public key: {keys['public_key']}\n")

    consecutive_failures = 0

    while True:
        record = make_uptime_record()
        print(f"[SEND] uptime={record['uptime_seconds']}s  ts={record['timestamp']}")

        success = send_record(record)

        if success:
            consecutive_failures = 0
        else:
            consecutive_failures += 1
            if consecutive_failures >= 5:
                print(f"[WARN] {consecutive_failures} consecutive failures — check your connection")

        time.sleep(SEND_INTERVAL)


if __name__ == "__main__":
    run()