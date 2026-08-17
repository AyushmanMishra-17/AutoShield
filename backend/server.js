require("dotenv").config();

const express = require("express");
const cors = require("cors");
const axios = require("axios");
const mongoose = require("mongoose");
const http = require("http");
const { Server } = require("socket.io");
const geoip = require("geoip-lite");

const PORT = process.env.PORT || 5000;
const ML_SERVICE_URL = process.env.ML_SERVICE_URL || "http://localhost:8000";
const MONGO_URL = process.env.MONGO_URL || "mongodb://127.0.0.1:27017/autoshield";

const ENABLE_BLOCKING = process.env.ENABLE_BLOCKING !== "false"; // Default to true

const MAX_ALERTS = 80;
const MAX_BLOCKED = 60;

const app = express();
app.set("trust proxy", true);

app.use(cors());
app.use(express.json());

// Optional logging - install morgan if needed
try {
  const morgan = require("morgan");
  app.use(morgan("combined"));
} catch (e) {
  console.log("Morgan not installed - skipping request logging");
}

// Connect to MongoDB (optional)
mongoose.connect(MONGO_URL)
  .then(() => console.log("✅ MongoDB connected"))
  .catch(() => console.log("⚠️  MongoDB not available - running without persistence"));

const server = http.createServer(app);
const io = new Server(server, { 
  cors: { origin: "*" },
  transports: ['websocket', 'polling']
});

// 🔥 GLOBAL STATE
const state = {
  alerts: [],
  blockedIPs: [],
  requestBuffer: [],
  metrics: {
    totalRequests: 0,
    anomalies: 0,
    blocked: 0,
    rps: 0,
    riskScore: 0,
    activeAttack: "Normal traffic"
  },
  insights: {
    title: "System stable",
    detail: "Traffic is within baseline",
    confidence: 0
  }
};

const trafficMap = new Map();
let mlServiceAvailable = true;

// 🔥 SAFE IP EXTRACTION
function getRealIP(req) {
  let ip = req.headers["x-forwarded-for"] || req.socket.remoteAddress || "";

  if (ip.includes(",")) ip = ip.split(",")[0].trim();
  if (ip === "::1" || ip === "::ffff:127.0.0.1") ip = "127.0.0.1";

  return ip;
}

// 🔥 EMIT FUNCTION WITH ERROR HANDLING
function emitUpdate() {
  try {
    const payload = {
      alerts: state.alerts,
      metrics: state.metrics,
      blockedIPs: state.blockedIPs,
      insights: state.insights
    };
    
    io.emit("update", payload);
    console.log(`📡 Update emitted - Blocked IPs: ${state.blockedIPs.length}, Alerts: ${state.alerts.length}`);
  } catch (error) {
    console.error("❌ Error emitting update:", error.message);
  }
}

// 🔥 BLOCK CHECK MIDDLEWARE
app.use((req, res, next) => {
  const ip = getRealIP(req);

  if (ENABLE_BLOCKING && state.blockedIPs.find(b => b.ip === ip)) {
    console.log(`🚫 Blocked request from ${ip}`);
    return res.status(403).json({ error: "Blocked by AutoShield" });
  }

  next();
});

// 🔥 TRAFFIC ANALYSIS MIDDLEWARE
app.use((req, res, next) => {
  const ip = getRealIP(req);

  if (!trafficMap.has(ip)) {
    trafficMap.set(ip, { timestamps: [], failedLogins: 0 });
  }

  const data = trafficMap.get(ip);
  data.timestamps.push(Date.now());

  const now = Date.now();
  data.timestamps = data.timestamps.filter(t => now - t < 5000);

  const requestRate = data.timestamps.length;

  // Track failed logins
  if (req.path.includes("login") && req.method === "POST") {
    data.failedLogins++;
  }

  // Analyze traffic (30% sampling to reduce load)
  if (Math.random() < 0.3) {
    setImmediate(() => {
      analyzeTraffic(ip, requestRate, data.failedLogins).catch(err => {
        console.error("❌ Traffic analysis error:", err.message);
      });
    });
  }

  state.metrics.totalRequests++;
  state.requestBuffer.push(Date.now());

  next();
});

// 🔥 ML ANALYSIS WITH ROBUST ERROR HANDLING
async function analyzeTraffic(ip, requestRate, failedLogins) {
  try {
    // Calculate time gap between requests
    const data = trafficMap.get(ip);
    const timeGap = data.timestamps.length >= 2 
      ? (data.timestamps[data.timestamps.length - 1] - data.timestamps[data.timestamps.length - 2]) / 1000
      : 1;

    // Try ML service with timeout
    if (mlServiceAvailable) {
      try {
        const mlResponse = await axios.post(
          `${ML_SERVICE_URL}/predict`,
          {
            requests: requestRate,
            failedLogins: failedLogins,
            requestRate: requestRate,
            timeGap: Math.max(0.1, timeGap)
          },
          { 
            timeout: 2000, // 2 second timeout
            validateStatus: (status) => status < 500
          }
        );

        const confidence = Math.round((mlResponse.data.confidence || 0) * 100);
        const isAnomaly = mlResponse.data.is_anomaly;

        // Update insights
        state.insights = {
          title: isAnomaly ? "⚠️ Threat detected" : "✅ System stable",
          detail: mlResponse.data.explanation || "Traffic within normal range",
          confidence: confidence
        };

        // Create alert if anomaly detected
        if (isAnomaly && requestRate > 15) {
          createAlert(ip, requestRate, "ML Detection");
        }

      } catch (mlError) {
        // ML service unavailable - fall back to heuristic detection
        mlServiceAvailable = false;
        console.log("⚠️  ML service unavailable - using heuristic detection");
        
        setTimeout(() => {
          mlServiceAvailable = true;
          console.log("🔄 Re-enabling ML service checks");
        }, 10000);
        
        // Fallback heuristic
        if (requestRate > 250 || failedLogins > 10) {
          createAlert(ip, requestRate, "Heuristic Detection");
        }
      }
    } else {
      // Use heuristic while ML is down
      if (requestRate > 250 || failedLogins > 10) {
        createAlert(ip, requestRate, "Heuristic Detection");
      }
    }

  } catch (error) {
    console.error("❌ Analysis error:", error.message);
  }
}

// 🔥 CREATE ALERT AND BLOCK IP
function createAlert(ip, requestRate, detectionType) {
  // Don't alert on localhost
  if (ip === "127.0.0.1") return;
  
  // Don't create duplicate alerts for already blocked IPs
  if (state.blockedIPs.find(b => b.ip === ip)) return;

  const geo = geoip.lookup(ip);

  const alert = {
    ip,
    attackType: detectionType === "ML Detection" ? "ML Detected Threat" : "High Volume Attack",
    severity: requestRate > 250 ? "Critical" : requestRate > 100 ? "High" : "Medium",
    riskScore: Math.min(100, Math.round(requestRate * 0.8)),
    timestamp: new Date().toISOString(),
    lat: geo ? geo.ll[0] : (Math.random() * 140 - 70),
    lon: geo ? geo.ll[1] : (Math.random() * 360 - 180),
    country: geo ? geo.country : "Unknown"
  };

  console.log(`🚨 ALERT: ${ip} - ${alert.attackType} (${alert.severity})`);

  // Add alert
  state.alerts.unshift(alert);
  state.alerts = state.alerts.slice(0, MAX_ALERTS);

  // Block IP if enabled
  if (ENABLE_BLOCKING) {
    const blockedEntry = {
      ip,
      timestamp: new Date().toISOString(),
      reason: `${alert.attackType} - ${alert.severity} severity`
    };
    
    state.blockedIPs.unshift(blockedEntry);
    state.blockedIPs = state.blockedIPs.slice(0, MAX_BLOCKED);
    
    console.log(`🔒 BLOCKED: ${ip} - Total blocked: ${state.blockedIPs.length}`);
  }

  // Update metrics
  state.metrics.anomalies++;
  state.metrics.blocked = state.blockedIPs.length;
  state.metrics.riskScore = Math.min(100, Math.max(state.metrics.riskScore, alert.riskScore));
  state.metrics.activeAttack = requestRate > 250 ? "DDoS Attack Detected" : "Anomalous Traffic";

  // CRITICAL: Emit update immediately after blocking
  emitUpdate();
}

// 🔥 REAL-TIME METRICS UPDATE (every second)
setInterval(() => {
  const now = Date.now();

  // Calculate RPS from last second
  state.requestBuffer = state.requestBuffer.filter(t => now - t < 1000);
  state.metrics.rps = state.requestBuffer.length;

  // Decay risk score over time
  if (state.metrics.riskScore > 0) {
    state.metrics.riskScore = Math.max(0, Math.floor(state.metrics.riskScore * 0.92));
  }

  // Reset active attack status if RPS is low
  if (state.metrics.rps < 50 && state.metrics.activeAttack !== "Normal traffic") {
    state.metrics.activeAttack = "Normal traffic";
  }

  // Emit periodic updates
  emitUpdate();
}, 1000);

// 🔥 CLEANUP OLD TRAFFIC DATA (every 30 seconds)
setInterval(() => {
  const now = Date.now();
  for (const [ip, data] of trafficMap.entries()) {
    data.timestamps = data.timestamps.filter(t => now - t < 10000);
    if (data.timestamps.length === 0) {
      trafficMap.delete(ip);
    }
  }
  console.log(`🧹 Cleaned up traffic map - Active IPs: ${trafficMap.size}`);
}, 30000);

// 🔓 UNBLOCK SINGLE IP
app.post("/unblock", (req, res) => {
  try {
    const { ip } = req.body;

    if (!ip) {
      return res.status(400).json({ error: "IP address required" });
    }

    const beforeCount = state.blockedIPs.length;
    state.blockedIPs = state.blockedIPs.filter(b => b.ip !== ip);
    const afterCount = state.blockedIPs.length;

    state.metrics.blocked = state.blockedIPs.length;

    console.log(`🔓 Unblocked ${ip} - Blocked count: ${beforeCount} → ${afterCount}`);
    
    emitUpdate();

    res.json({ 
      success: true, 
      ip,
      removed: beforeCount > afterCount
    });
  } catch (error) {
    console.error("❌ Unblock error:", error.message);
    res.status(500).json({ error: "Failed to unblock IP" });
  }
});

// 🧹 UNBLOCK ALL IPS
app.post("/unblock-all", (req, res) => {
  try {
    const count = state.blockedIPs.length;
    state.blockedIPs = [];
    state.metrics.blocked = 0;

    console.log(`🔓 Unblocked all IPs - Removed ${count} entries`);
    
    emitUpdate();

    res.json({ success: true, count });
  } catch (error) {
    console.error("❌ Unblock-all error:", error.message);
    res.status(500).json({ error: "Failed to unblock IPs" });
  }
});

// 🔥 TEST ENDPOINTS
app.get("/test", (req, res) => {
  res.send("OK");
});

app.get("/health", (req, res) => {
  res.json({ 
    status: "ok",
    metrics: state.metrics,
    mlServiceAvailable,
    blockedCount: state.blockedIPs.length,
    alertCount: state.alerts.length
  });
});

// 🔥 WEBSOCKET CONNECTION HANDLING
io.on("connection", (socket) => {
  console.log(`✅ Client connected - Socket ID: ${socket.id}`);
  
  // Send current state immediately on connection
  socket.emit("update", {
    alerts: state.alerts,
    metrics: state.metrics,
    blockedIPs: state.blockedIPs,
    insights: state.insights
  });

  socket.on("disconnect", () => {
    console.log(`❌ Client disconnected - Socket ID: ${socket.id}`);
  });
});

// 🔥 GRACEFUL SHUTDOWN
process.on("SIGTERM", () => {
  console.log("🛑 SIGTERM received - shutting down gracefully");
  server.close(() => {
    console.log("✅ Server closed");
    mongoose.connection.close(false, () => {
      console.log("✅ MongoDB connection closed");
      process.exit(0);
    });
  });
});

// 🚀 START SERVER
server.listen(PORT, () => {
  console.log(`🚀 AutoShield running on port ${PORT}`);
  console.log(`🔒 IP Blocking: ${ENABLE_BLOCKING ? "ENABLED" : "DISABLED"}`);
  console.log(`🤖 ML Service: ${ML_SERVICE_URL}`);
});