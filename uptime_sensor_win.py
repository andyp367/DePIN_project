# uptime_sensor_win.py
import time, json, socket, ctypes
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from datetime import datetime, timezone

# ── Config ────────────────────────────────────────────────────────────────────
VALIDATOR_HOST = "10.101.169.146"
VALIDATOR_PORT = 5504
SEND_INTERVAL  = 10
# ─────────────────────────────────────────────────────────────────────────────

with open("keys/device_keys.json") as f:
    keys = json.load(f)

private_key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(keys["private_key"]))


def get_uptime_seconds() -> int:
    return ctypes.windll.kernel32.GetTickCount64() // 1000


def fmt_time(unix_ts: float) -> str:
    """Convert a Unix timestamp to a readable local time string."""
    return datetime.fromtimestamp(unix_ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def fmt_uptime(seconds: int) -> str:
    """Convert raw seconds into d/h/m/s string."""
    d, rem = divmod(seconds, 86400)
    h, rem = divmod(rem, 3600)
    m, s   = divmod(rem, 60)
    parts = []
    if d: parts.append(f"{d}d")
    if h: parts.append(f"{h}h")
    if m: parts.append(f"{m}m")
    parts.append(f"{s}s")
    return " ".join(parts)


def make_uptime_record() -> dict:
    record = {
        "timestamp":      time.time(),        # ← must stay Unix float for validator
        "device_id":      keys["public_key"],
        "uptime_seconds": get_uptime_seconds(),
    }
    payload = json.dumps(record, sort_keys=True, separators=(',', ':')).encode()
    record["signature"] = private_key.sign(payload).hex()
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
            print(f"[ACK] Accepted at {fmt_time(record['timestamp'])}")
            return True
        else:
            print(f"[WARN] Validator rejected: {response}")
            return False
    except ConnectionRefusedError:
        print(f"[ERROR] Connection refused — is validator up on {VALIDATOR_HOST}:{VALIDATOR_PORT}?")
    except TimeoutError:
        print("[ERROR] Timed out waiting for ACK")
    except json.JSONDecodeError as e:
        print(f"[ERROR] Bad ACK: {e}")
    except OSError as e:
        print(f"[ERROR] Network error: {e}")
    return False


def run():
    print(f"Starting uptime sensor (Windows) → {VALIDATOR_HOST}:{VALIDATOR_PORT}")
    print(f"Public key: {keys['public_key']}\n")
    consecutive_failures = 0
    while True:
        record = make_uptime_record()
        print(f"[SEND] {fmt_time(record['timestamp'])}  uptime={fmt_uptime(record['uptime_seconds'])}")
        if send_record(record):
            consecutive_failures = 0
        else:
            consecutive_failures += 1
            if consecutive_failures >= 5:
                print(f"[WARN] {consecutive_failures} consecutive failures")
        time.sleep(SEND_INTERVAL)


if __name__ == "__main__":
    run()