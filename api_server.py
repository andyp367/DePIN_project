"""
api_server.py
Wraps DePINValidator with a Flask HTTP API so the dashboard can poll live data.
Run this instead of validator.py directly.
"""

import json
import threading
import time
import types

from validator import DePINValidator

try:
    from flask import Flask, jsonify
    from flask_cors import CORS
except ImportError:
    print("Missing deps — run: .venv/bin/pip install flask flask-cors")
    raise

node = DePINValidator()


def _handle_client_with_ack(client_socket):
    try:
        raw_data = client_socket.recv(4096).decode('utf-8')
        if raw_data:
            msg_data = json.loads(raw_data)
            ok = node.process_message(msg_data)
            ack = json.dumps({"status": "ok" if ok else "rejected"}) + "\n"
            client_socket.sendall(ack.encode('utf-8'))
    except Exception as e:
        print(f"⚠️ TCP Error: {e}")
        try:
            client_socket.sendall((json.dumps({"status": "error", "message": str(e)}) + "\n").encode())
        except Exception:
            pass
    finally:
        client_socket.close()


import types
node._handle_client = types.MethodType(lambda self, sock: _handle_client_with_ack(sock), node)

app = Flask(__name__)
CORS(app)


@app.route('/api/stats')
def stats():
    total_tokens = sum(node.balances.values())
    return jsonify({
        "total_blocks":   len(node.blockchain),
        "tokens_minted":  round(total_tokens, 4),
        "active_wallets": len(node.balances),
        "validator_online": True,
        "tcp_port": node.port,
    })


@app.route('/api/blocks')
def blocks():
    return jsonify(node.blockchain)


@app.route('/api/balances')
def balances():
    return jsonify(node.balances)


def block_miner():
    while True:
        time.sleep(10)
        if node.pending_records:
            node._create_block()


TCP_PORT  = 5500
HTTP_PORT = 5501

if __name__ == "__main__":
    node.port = TCP_PORT
    threading.Thread(target=node.start_tcp_listener, daemon=True).start()
    threading.Thread(target=block_miner, daemon=True).start()
    print(f"🔌 TCP  listener on port {TCP_PORT}")
    print(f"🌐 HTTP API       on http://0.0.0.0:{HTTP_PORT}")
    app.run(host='0.0.0.0', port=HTTP_PORT, use_reloader=False, threaded=True)
