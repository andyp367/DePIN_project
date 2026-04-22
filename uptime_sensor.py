# uptime_sensor.py
import time, json, socket
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

# ── Config ────────────────────────────────────────────────────────────────────
VALIDATOR_HOST = "10.101.169.146"
VALIDATOR_PORT = 5502             # ← updated from 5500
SEND_INTERVAL  = 30
# ─────────────────────────────────────────────────────────────────────────────

with open("keys/device_keys.json") as f:
    keys = json.load(f)

private_key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(keys["private_key"]))


def get_uptime_seconds() -> int:
    with open("/proc/uptime") as f:
        return int(float(f.read().split()[0]))


def make_uptime_record() -> dict:
    record = {
        "timestamp":      time.time(),
        "device_id":      keys["public_key"],
        "uptime_seconds": get_uptime_seconds(),
    }
    # ← separators=(',', ':') must match validator's canonical JSON exactly
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
            print(f"[ACK] Validator accepted record at {record['timestamp']}")
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
    print(f"Starting uptime sensor (Linux) → {VALIDATOR_HOST}:{VALIDATOR_PORT}")
    print(f"Public key: {keys['public_key']}\n")
    consecutive_failures = 0
    while True:
        record = make_uptime_record()
        print(f"[SEND] uptime={record['uptime_seconds']}s  ts={record['timestamp']}")
        if send_record(record):
            consecutive_failures = 0
        else:
            consecutive_failures += 1
            if consecutive_failures >= 5:
                print(f"[WARN] {consecutive_failures} consecutive failures")
        time.sleep(SEND_INTERVAL)


if __name__ == "__main__":
    run()