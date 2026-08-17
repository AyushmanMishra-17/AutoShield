# 🛡️ AutoShield — Autonomous Cyber Defense

> Detect. Decide. Defend. Instantly.

AutoShield is an ML-powered defensive security platform for real-time HTTP traffic analysis, behavioral anomaly detection, threat assessment, automated application-level IP mitigation, and live security visualization.

The current release keeps the existing dashboard UI while hardening the detection pipeline and backend behavior.

## Architecture

```text
Browser / protected application
          │
          ▼
 React + Recharts + Leaflet :5173
          │ Socket.IO / HTTP
          ▼
 Node.js + Express :5000
          │
          ├── IP / traffic tracking
          ├── rolling RPS baseline
          ├── behavioral rules
          ├── application-level IP blocklist
          └── ML inference
                    │
                    ▼
             Flask :8000
                    │
             Isolation Forest
```

MongoDB is optional. When available, alert records are persisted; the application still runs with in-memory state when MongoDB is unavailable.

## Detection pipeline

Every request is counted. ML inference is throttled per source IP instead of randomly sampling requests.

Features sent to the ML service:

- `requests`
- `failedLogins`
- `requestRate`
- `timeGap`

The decision engine combines:

1. Isolation Forest anomaly detection
2. Rolling traffic baseline
3. Request-rate rules
4. Failed-login behavior
5. Request-gap behavior
6. Risk scoring

### Model confidence

Isolation Forest's `decision_function()` is not a probability. AutoShield therefore does **not** label the raw score as probability. The ML service exposes a normalized confidence proxy based on the observation's separation from the model's decision boundary.

## Real traffic only

There is no background traffic generator in the backend. Dashboard request counts come from requests that actually reach the Express server.

The included `stresstest.js` is an optional k6 test for systems you own or are authorized to test.

## IP geolocation

AutoShield never fabricates coordinates.

- Public IP + successful GeoIP lookup → plotted.
- Private/local IP → not plotted.
- Unresolved public IP → not plotted.

This prevents the dashboard from presenting an invented attack location.

## Risk scoring

Risk combines multiple signals instead of simply mapping RPS to a score:

```text
request-rate pressure
+ failed-login pressure
+ request-gap behavior
+ ML anomaly confidence
            ↓
        risk score
```

Risk labels remain:

| Score | Classification |
|---:|---|
| 0–39 | Low |
| 40–64 | Medium |
| 65–84 | High |
| 85–100 | Critical |

## Administrative IP unblocking

`/unblock` and `/unblock-all` require a bearer token configured through `ADMIN_TOKEN`.

The dashboard asks for the token when an administrator chooses **Unblock**. The token is not hard-coded into the frontend build.

## Security hardening

The backend includes:

- Helmet security headers
- Express rate limiting
- Morgan request logging
- Configurable CORS
- Configurable trusted proxy behavior
- Input validation for administrative actions
- Authenticated administrative unblock operations
- Request-size limits
- Graceful shutdown

### Trusted proxy

By default, `TRUST_PROXY=false`. This prevents arbitrary clients from supplying a forged `X-Forwarded-For` value.

Set `TRUST_PROXY=true` only when the application is actually behind a trusted reverse proxy that correctly sanitizes the forwarding header.

## Local setup

### 1. ML service

```powershell
cd ml-service
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
python app.py
```

ML service:

```text
http://localhost:8000
```

Check:

```powershell
Invoke-WebRequest http://localhost:8000/health -UseBasicParsing
```

### 2. Backend

Create `backend/.env` from `backend/.env.example`.

```powershell
cd backend
npm install
node server.js
```

Backend:

```text
http://localhost:5000
```

Check:

```powershell
Invoke-WebRequest http://localhost:5000/health -UseBasicParsing
```

### 3. Frontend

```powershell
cd frontend
npm install
npm run dev
```

Dashboard:

```text
http://localhost:5173
```

## k6 testing

Install k6 separately. It is not an npm dependency of the application.

Run:

```powershell
k6 run stresstest.js
```

The test targets:

```text
http://localhost:5000/test
```

Only use the traffic generator against infrastructure you own or are explicitly authorized to test.

## Project structure

```text
AutoShield/
├── backend/
│   ├── server.js
│   ├── package.json
│   └── .env.example
├── frontend/
│   ├── src/
│   │   ├── AttackMap.jsx
│   │   ├── Dashboard.jsx
│   │   ├── app.jsx
│   │   ├── index.css
│   │   └── main.jsx
│   └── package.json
├── ml-service/
│   ├── app.py
│   └── requirements.txt
├── stresstest.js
├── .gitignore
└── README.md
```

## Important limitation

AutoShield's IP blocking is currently **application-level mitigation**: blocked sources receive HTTP 403 from the protected Express service. It is not a replacement for a network firewall, WAF, IPS, or enterprise DDoS mitigation service.

## Defensive-use disclaimer

AutoShield is intended for authorized security testing, research, education, and defensive use. Do not use the traffic-generation components against systems you do not own or have explicit permission to test.
