require("dotenv").config();

const express = require("express");
const cors = require("cors");
const axios = require("axios");
const mongoose = require("mongoose");
const http = require("http");
const { Server } = require("socket.io");
const geoip = require("geoip-lite");
const helmet = require("helmet");
const morgan = require("morgan");
const rateLimit = require("express-rate-limit");
const net = require("net");

const PORT = Number(process.env.PORT || 5000);
const ML_SERVICE_URL = process.env.ML_SERVICE_URL || "http://localhost:8000";
const MONGO_URL = process.env.MONGO_URL || "mongodb://127.0.0.1:27017/autoshield";
const ENABLE_BLOCKING = process.env.ENABLE_BLOCKING !== "false";
const TRUST_PROXY = process.env.TRUST_PROXY === "true";
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || "";
const ML_ANALYSIS_INTERVAL_MS = Number(process.env.ML_ANALYSIS_INTERVAL_MS || 250);

const MAX_ALERTS = 80;
const MAX_BLOCKED = 60;
const BASELINE_WINDOW = 60;
const ANALYSIS_COOLDOWN_MS = 1000;

const app = express();
app.set("trust proxy", TRUST_PROXY ? 1 : false);

app.use(helmet({ crossOriginResourcePolicy: { policy: "cross-origin" } }));
app.use(cors({ origin: process.env.CORS_ORIGIN ? process.env.CORS_ORIGIN.split(",") : "*" }));
app.use(express.json({ limit: "100kb" }));
app.use(morgan("combined"));

const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: Number(process.env.RATE_LIMIT_MAX || 600),
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Rate limit exceeded" }
});
app.use(apiLimiter);

let mongoReady = false;
const AlertSchema = new mongoose.Schema({
  ip: String,
  attackType: String,
  severity: String,
  riskScore: Number,
  modelConfidence: Number,
  anomalyScore: Number,
  country: String,
  lat: Number,
  lon: Number,
  timestamp: { type: Date, default: Date.now }
}, { versionKey: false });
const Alert = mongoose.models.Alert || mongoose.model("Alert", AlertSchema);

mongoose.connect(MONGO_URL)
  .then(() => { mongoReady = true; console.log("✅ MongoDB connected"); })
  .catch(() => console.log("⚠️ MongoDB unavailable - running with in-memory state"));

const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: "*" },
  transports: ["websocket", "polling"]
});

const state = {
  alerts: [],
  blockedIPs: [],
  requestBuffer: [],
  rpsHistory: [],
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
    detail: "Traffic is within the learned baseline.",
    confidence: 0
  },
  baseline: {
    meanRps: 0,
    standardDeviation: 0,
    threshold: 20
  }
};

const trafficMap = new Map();
let mlServiceAvailable = true;

function isPrivateOrLocalIP(ip) {
  if (!ip) return true;
  const normalized = ip.replace(/^::ffff:/, "");
  if (normalized === "127.0.0.1" || normalized === "::1") return true;
  if (net.isIPv4(normalized)) {
    const [a, b] = normalized.split(".").map(Number);
    return a === 10 || a === 127 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168);
  }
  return normalized.includes(":") && (normalized.startsWith("fc") || normalized.startsWith("fd") || normalized.startsWith("fe80"));
}

function getRealIP(req) {
  if (TRUST_PROXY) {
    const forwarded = req.headers["x-forwarded-for"];
    if (forwarded) return forwarded.split(",")[0].trim();
  }
  let ip = req.socket.remoteAddress || "";
  if (ip === "::1" || ip === "::ffff:127.0.0.1") ip = "127.0.0.1";
  return ip.replace(/^::ffff:/, "");
}

function requireAdmin(req, res, next) {
  if (!ADMIN_TOKEN) return res.status(503).json({ error: "Administrative API is not configured" });
  const token = req.headers.authorization?.replace(/^Bearer\s+/i, "");
  if (!token || token !== ADMIN_TOKEN) return res.status(401).json({ error: "Unauthorized" });
  next();
}

function emitUpdate() {
  io.emit("update", {
    alerts: state.alerts,
    metrics: state.metrics,
    blockedIPs: state.blockedIPs,
    insights: state.insights,
    baseline: state.baseline
  });
}

function updateBaseline(rps) {
  state.rpsHistory.push(rps);
  if (state.rpsHistory.length > BASELINE_WINDOW) state.rpsHistory.shift();
  const values = state.rpsHistory;
  const mean = values.length ? values.reduce((a, b) => a + b, 0) / values.length : 0;
  const variance = values.length > 1
    ? values.reduce((sum, v) => sum + ((v - mean) ** 2), 0) / values.length
    : 0;
  const sd = Math.sqrt(variance);
  const threshold = Math.max(20, Math.ceil(mean + Math.max(2, sd * 2)));
  state.baseline = { meanRps: Number(mean.toFixed(2)), standardDeviation: Number(sd.toFixed(2)), threshold };
  return threshold;
}

function classifyThreat({ requestRate, failedLogins, timeGap, isAnomaly, detectionType }) {
  if (failedLogins >= 10) return "Brute Force Pattern";
  if (requestRate >= 100 || timeGap <= 0.2) return "High-Volume / DDoS-like Traffic";
  if (isAnomaly && timeGap <= 0.5) return "Automated Traffic Anomaly";
  return detectionType === "ML Detection" ? "ML Detected Threat" : "Behavioral Anomaly";
}

function calculateRisk({ requestRate, failedLogins, timeGap, anomalyConfidence, threshold }) {
  const rateComponent = Math.min(45, (requestRate / Math.max(threshold, 1)) * 45);
  const loginComponent = Math.min(20, failedLogins * 2);
  const gapComponent = timeGap < 0.5 ? 15 : timeGap < 1 ? 8 : 0;
  const mlComponent = Math.min(20, anomalyConfidence * 20);
  return Math.max(0, Math.min(100, Math.round(rateComponent + loginComponent + gapComponent + mlComponent)));
}

function addAlert(alert) {
  state.alerts.unshift(alert);
  state.alerts = state.alerts.slice(0, MAX_ALERTS);
  if (mongoReady) Alert.create(alert).catch(() => {});
}

function blockIP(ip, reason) {
  if (!ENABLE_BLOCKING || isPrivateOrLocalIP(ip)) return false;
  if (state.blockedIPs.some(b => b.ip === ip)) return false;
  state.blockedIPs.unshift({ ip, timestamp: new Date().toISOString(), reason });
  state.blockedIPs = state.blockedIPs.slice(0, MAX_BLOCKED);
  state.metrics.blocked = state.blockedIPs.length;
  return true;
}

function createAlert({ ip, requestRate, failedLogins, timeGap, detectionType, isAnomaly = true, anomalyScore = 0, modelConfidence = 0 }) {
  if (state.blockedIPs.some(b => b.ip === ip)) return;

  const geo = isPrivateOrLocalIP(ip) ? null : geoip.lookup(ip);
  const threshold = state.baseline.threshold;
  const riskScore = calculateRisk({ requestRate, failedLogins, timeGap, anomalyConfidence: modelConfidence / 100, threshold });
  const attackType = classifyThreat({ requestRate, failedLogins, timeGap, isAnomaly, detectionType });
  const severity = riskScore >= 85 ? "Critical" : riskScore >= 65 ? "High" : riskScore >= 40 ? "Medium" : "Low";

  const alert = {
    ip,
    attackType,
    severity,
    riskScore,
    modelConfidence: Math.round(modelConfidence),
    anomalyScore: Number(anomalyScore.toFixed(4)),
    timestamp: new Date().toISOString()
  };

  if (geo) {
    alert.lat = geo.ll[0];
    alert.lon = geo.ll[1];
    alert.country = geo.country;
  } else {
    alert.country = "Unknown";
  }

  addAlert(alert);
  const blocked = riskScore >= 65 && blockIP(ip, `${attackType} - ${severity} severity`);
  state.metrics.anomalies++;
  state.metrics.riskScore = Math.max(state.metrics.riskScore, riskScore);
  state.metrics.activeAttack = attackType;
  emitUpdate();
  console.log(`🚨 ALERT ${ip} | ${attackType} | risk=${riskScore} | blocked=${blocked}`);
}

async function analyzeTraffic(ip, requestRate, failedLogins, timeGap) {
  const data = trafficMap.get(ip);
  if (!data) return;

  const now = Date.now();
  if (now - data.lastAnalysis < ANALYSIS_COOLDOWN_MS) return;
  data.lastAnalysis = now;

  try {
    if (!mlServiceAvailable) throw new Error("ML service cooling down");
    const mlResponse = await axios.post(`${ML_SERVICE_URL}/predict`, {
      requests: requestRate,
      failedLogins,
      requestRate,
      timeGap: Math.max(0.05, timeGap)
    }, { timeout: 1200 });

    mlServiceAvailable = true;
    const isAnomaly = Boolean(mlResponse.data.is_anomaly);
    const confidence = Number(mlResponse.data.confidence || 0) * 100;
    state.insights = {
      title: isAnomaly ? "⚠️ Threat detected" : "✅ System stable",
      detail: mlResponse.data.explanation || "Traffic remains within the learned baseline.",
      confidence: Math.round(confidence)
    };

    const threshold = state.baseline.threshold;
    if (isAnomaly || requestRate > threshold) {
      createAlert({
        ip, requestRate, failedLogins, timeGap,
        detectionType: isAnomaly ? "ML Detection" : "Behavioral Detection",
        isAnomaly,
        anomalyScore: Number(mlResponse.data.anomaly_score || 0),
        modelConfidence: confidence
      });
    }
  } catch (error) {
    if (error.message !== "ML service cooling down") {
      mlServiceAvailable = false;
      setTimeout(() => { mlServiceAvailable = true; }, 5000);
    }
    const threshold = state.baseline.threshold;
    if (requestRate > Math.max(250, threshold * 3) || failedLogins > 10) {
      createAlert({ ip, requestRate, failedLogins, timeGap, detectionType: "Heuristic Detection", modelConfidence: 0 });
    }
  }
}

// Block check intentionally occurs before traffic analysis: blocked traffic is not counted as normal traffic.
app.use((req, res, next) => {
  const ip = getRealIP(req);
  if (ENABLE_BLOCKING && state.blockedIPs.some(b => b.ip === ip)) {
    return res.status(403).json({ error: "Blocked by AutoShield" });
  }
  next();
});

// Every request is counted. ML inference is rate-limited per IP, not randomly sampled.
app.use((req, res, next) => {
  const ip = getRealIP(req);
  if (!trafficMap.has(ip)) trafficMap.set(ip, { timestamps: [], failedLogins: 0, lastAnalysis: 0, lastRequestAt: 0 });
  const data = trafficMap.get(ip);
  const now = Date.now();
  const timeGap = data.lastRequestAt ? (now - data.lastRequestAt) / 1000 : 1;
  data.lastRequestAt = now;
  data.timestamps.push(now);
  data.timestamps = data.timestamps.filter(t => now - t < 5000);
  if (req.path.toLowerCase().includes("login") && req.method === "POST") data.failedLogins++;
  const requestRate = data.timestamps.length;

  state.metrics.totalRequests++;
  state.requestBuffer.push(now);
  setImmediate(() => analyzeTraffic(ip, requestRate, data.failedLogins, timeGap));
  next();
});

setInterval(() => {
  const now = Date.now();
  state.requestBuffer = state.requestBuffer.filter(t => now - t < 1000);
  state.metrics.rps = state.requestBuffer.length;
  const threshold = updateBaseline(state.metrics.rps);

  if (state.metrics.rps <= threshold && state.metrics.riskScore > 0) {
    state.metrics.riskScore = Math.max(0, Math.floor(state.metrics.riskScore * 0.92));
  }
  if (state.metrics.rps < threshold && state.metrics.riskScore < 40) state.metrics.activeAttack = "Normal traffic";
  emitUpdate();
}, 1000);

setInterval(() => {
  const now = Date.now();
  for (const [ip, data] of trafficMap.entries()) {
    data.timestamps = data.timestamps.filter(t => now - t < 10000);
    if (!data.timestamps.length) trafficMap.delete(ip);
  }
}, 30000);

app.get("/api/data", (req, res) => res.json({ secure: true, message: "Protected by AutoShield" }));
app.get("/test", (req, res) => res.send("OK"));
app.get("/health", (req, res) => res.json({ status: "ok", metrics: state.metrics, mlServiceAvailable, blockedCount: state.blockedIPs.length, alertCount: state.alerts.length, baseline: state.baseline, persistence: mongoReady }));

app.post("/unblock", requireAdmin, (req, res) => {
  const ip = String(req.body?.ip || "").trim();
  if (!ip) return res.status(400).json({ error: "IP address required" });
  const before = state.blockedIPs.length;
  state.blockedIPs = state.blockedIPs.filter(b => b.ip !== ip);
  state.metrics.blocked = state.blockedIPs.length;
  emitUpdate();
  res.json({ success: true, ip, removed: before > state.blockedIPs.length });
});

app.post("/unblock-all", requireAdmin, (req, res) => {
  const count = state.blockedIPs.length;
  state.blockedIPs = [];
  state.metrics.blocked = 0;
  emitUpdate();
  res.json({ success: true, count });
});

io.on("connection", socket => {
  socket.emit("update", { alerts: state.alerts, metrics: state.metrics, blockedIPs: state.blockedIPs, insights: state.insights, baseline: state.baseline });
});

process.on("SIGTERM", () => {
  server.close(async () => {
    if (mongoose.connection.readyState === 1) await mongoose.connection.close();
    process.exit(0);
  });
});

server.listen(PORT, () => {
  console.log(`🚀 AutoShield running on port ${PORT}`);
  console.log(`🔒 IP Blocking: ${ENABLE_BLOCKING ? "ENABLED" : "DISABLED"}`);
  console.log(`🤖 ML Service: ${ML_SERVICE_URL}`);
  console.log(`🧠 ML analysis cadence: ${ML_ANALYSIS_INTERVAL_MS}ms/IP`);
});
