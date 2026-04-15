# DePIN Dashboard

**Person 4 — Alseny | CPE 4020 Spring 2026**

A web-based dashboard for monitoring the DePIN (Decentralized Physical Infrastructure Network) system in real time.

## Overview

The dashboard provides a visual interface for reading the blockchain ledger, tracking wallet balances, and monitoring the status of the validator node and uptime sensor. It is built with plain HTML, CSS, and JavaScript — no frameworks or dependencies required.

## Features

- **Stats Bar** — At-a-glance view of total blocks mined, total tokens minted via Proof-of-Uptime, number of active wallets, and live validator status.
- **Validator & Sensor Status** — Cards showing the connection state of the validator node (Alex), the Raspberry Pi uptime sensor (Andy), and the wallet (Brandon).
- **Block Ledger** — Scrollable list of all blocks on the chain, showing block index, truncated hash, previous hash, record count, and relative timestamp.
- **Wallet Balances** — Lists all known wallet public keys alongside their current UPT token balances.

## How to Run

Open `index.html` directly in a browser, or serve it with Python for API compatibility:

```bash
python3 -m http.server 8080
```

Then visit `http://localhost:8080` in your browser.

## Next Steps

- Add a Flask REST API to the validator (`/api/blocks`, `/api/balances`, `/api/status`)
- Replace static mock data in `index.html` with live `fetch()` calls
- Poll the API on an interval for real-time updates
