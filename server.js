const http  = require("http");
const https = require("https");
const fs    = require("fs");
const path  = require("path");
const url   = require("url");

// ── Optional dependencies (graceful degradation if missing) ───────────────────

let yaml;
try { yaml = require("js-yaml"); } catch { yaml = null; }

// ── Self-signed cert generation via system openssl binary ─────────────────────

function generateCaptureCert(san) {
  const { execSync } = require("child_process");
  const tmpDir   = require("os").tmpdir();
  const keyFile  = path.join(tmpDir, "gk-capture-key.pem");
  const certFile = path.join(tmpDir, "gk-capture-cert.pem");
  // Validate SAN to prevent command injection (hostname-safe chars only)
  if (!/^[a-zA-Z0-9.\-]+$/.test(san)) throw new Error(`Invalid SAN value: ${san}`);
  execSync(
    `openssl req -x509 -newkey rsa:2048 -nodes` +
    ` -keyout "${keyFile}" -out "${certFile}"` +
    ` -days 365 -subj "/CN=${san}"` +
    ` -addext "subjectAltName=DNS:${san},DNS:${san}.cluster.local,IP:127.0.0.1"`,
    { stdio: "pipe" }
  );
  return {
    private: fs.readFileSync(keyFile, "utf8"),
    cert:    fs.readFileSync(certFile, "utf8"),
  };
}

// ── Kubernetes in-cluster API helpers ─────────────────────────────────────────

const K8S_SA   = "/var/run/secrets/kubernetes.io/serviceaccount";
const VWC_PATH = "/apis/admissionregistration.k8s.io/v1/validatingwebhookconfigurations";

function k8sRequest(method, apiPath, body, contentType = "application/json") {
  return new Promise((resolve, reject) => {
    const token   = fs.readFileSync(`${K8S_SA}/token`, "utf8").trim();
    const ca      = fs.readFileSync(`${K8S_SA}/ca.crt`);
    const reqBody = body ? JSON.stringify(body) : null;
    const headers = { "Authorization": `Bearer ${token}` };
    if (reqBody) {
      headers["Content-Type"]   = contentType;
      headers["Content-Length"] = Buffer.byteLength(reqBody);
    }
    const req = https.request(
      { hostname: "kubernetes.default.svc", port: 443, path: apiPath, method, headers, ca },
      (res) => {
        let data = "";
        res.on("data", chunk => data += chunk);
        res.on("end", () => {
          try { resolve({ statusCode: res.statusCode, body: JSON.parse(data) }); }
          catch  { resolve({ statusCode: res.statusCode, body: data }); }
        });
      }
    );
    req.on("error", reject);
    if (reqBody) req.write(reqBody);
    req.end();
  });
}

async function applyVWC(vwc) {
  // Server-side apply — creates or replaces atomically, no resourceVersion needed
  const res = await k8sRequest(
    "PATCH",
    `${VWC_PATH}/${vwc.metadata.name}?fieldManager=gatekeeper-tester&force=true`,
    vwc,
    "application/apply-patch+yaml"
  );
  if (res.statusCode >= 400)
    throw new Error(res.body?.message || `k8s API returned ${res.statusCode}`);
}

async function removeVWC(name) {
  const res = await k8sRequest("DELETE", `${VWC_PATH}/${name}`);
  if (res.statusCode >= 400 && res.statusCode !== 404)
    throw new Error(res.body?.message || `k8s API returned ${res.statusCode}`);
}

// ── Environment ───────────────────────────────────────────────────────────────

const GATEKEEPER_URL  = process.env.GATEKEEPER_URL || "https://gatekeeper-webhook.gatekeeper-system.svc:8443/v1/admit";
const IGNORE_TLS      = process.env.IGNORE_TLS === "true";
const PORT            = parseInt(process.env.PORT)         || 3000;
const CAPTURE_PORT    = parseInt(process.env.CAPTURE_PORT) || 8443;
const SERVICE_NAME    = process.env.SERVICE_NAME    || "gatekeeper-tester";
const POD_NAMESPACE   = process.env.POD_NAMESPACE   || "gatekeeper-system";
const CAPTURE_MAX     = parseInt(process.env.CAPTURE_MAX)  || 100;

// Outbound mTLS certs (for forwarding to Gatekeeper)
const TLS_CERT = process.env.TLS_CERT_PATH ? fs.readFileSync(process.env.TLS_CERT_PATH) : null;
const TLS_KEY  = process.env.TLS_KEY_PATH  ? fs.readFileSync(process.env.TLS_KEY_PATH)  : null;
const TLS_CA   = process.env.TLS_CA_PATH   ? fs.readFileSync(process.env.TLS_CA_PATH)   : null;

const MIME_TYPES = {
  ".html": "text/html",
  ".js":   "application/javascript",
  ".css":  "text/css",
  ".json": "application/json",
  ".png":  "image/png",
  ".ico":  "image/x-icon",
};

// ── Self-signed TLS cert for the capture HTTPS server ─────────────────────────

const CAPTURE_SAN = `${SERVICE_NAME}.${POD_NAMESPACE}.svc`;
let capturePems   = null;
let CAPTURE_CA_BUNDLE = null;
let captureServerStarted = false;

try {
  capturePems = generateCaptureCert(CAPTURE_SAN);
  CAPTURE_CA_BUNDLE = Buffer.from(capturePems.cert).toString("base64");
  console.log(`Capture cert generated (SAN=${CAPTURE_SAN})`);
} catch (e) {
  console.error("Failed to generate capture cert:", e.message);
}

// ── Capture ring buffer ────────────────────────────────────────────────────────

let capturedRequests = [];   // newest first
let captureActive    = false;
let captureConfig    = {};

function addCaptured(admissionReview) {
  const r = admissionReview.request || {};
  capturedRequests.unshift({
    id:        `${Date.now()}-${Math.random().toString(36).slice(2, 7)}`,
    timestamp: new Date().toISOString(),
    kind:      r.kind?.kind      || "Unknown",
    name:      r.name            || "",
    namespace: r.namespace       || "",
    operation: r.operation       || "",
    username:  r.userInfo?.username || "",
    review:    admissionReview,
  });
  if (capturedRequests.length > CAPTURE_MAX) capturedRequests.length = CAPTURE_MAX;
}

// ── HTTPS capture server (receives real AdmissionReview from kube-apiserver) ──

if (capturePems) {
  const captureServer = https.createServer(
    { key: capturePems.private, cert: capturePems.cert },
    (req, res) => {
      const { pathname } = url.parse(req.url);
      if (req.method === "POST" && pathname === "/capture") {
        readBody(req).then(body => {
          let ar;
          try { ar = JSON.parse(body); } catch {
            res.writeHead(400); res.end(); return;
          }
          // Always respond allowed:true — this webhook must never block the cluster.
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(JSON.stringify({
            apiVersion: "admission.k8s.io/v1",
            kind: "AdmissionReview",
            response: { uid: ar.request?.uid || "", allowed: true },
          }));
          // Store after responding so latency is unaffected.
          if (captureActive) addCaptured(ar);
        }).catch(() => { res.writeHead(500); res.end(); });
      } else {
        res.writeHead(404); res.end();
      }
    }
  );

  captureServer.on("error", (e) => {
    console.error(`Capture HTTPS server error (port ${CAPTURE_PORT}):`, e.message);
  });

  captureServer.listen(CAPTURE_PORT, () => {
    captureServerStarted = true;
    console.log(`Capture webhook listening on :${CAPTURE_PORT} (HTTPS)`);
  });
}

// ── Generic helpers ────────────────────────────────────────────────────────────

function sendJson(res, status, obj) {
  res.writeHead(status, { "Content-Type": "application/json" });
  res.end(JSON.stringify(obj));
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let body = "";
    req.on("data", chunk => body += chunk);
    req.on("end",  () => resolve(body));
    req.on("error", reject);
  });
}

function serveStatic(req, res) {
  const filePath = path.join(__dirname, "public", req.url === "/" ? "index.html" : req.url);
  const ext = path.extname(filePath);
  const contentType = MIME_TYPES[ext] || "text/plain";

  fs.readFile(filePath, (err, data) => {
    if (err) { res.writeHead(404); res.end("Not found"); return; }
    res.writeHead(200, { "Content-Type": contentType });
    res.end(data);
  });
}

function parseManifest(input) {
  if (input !== null && typeof input === "object") return input;
  if (typeof input !== "string") throw new Error("Manifest must be a string or object.");
  try { return JSON.parse(input); } catch {}
  if (yaml) {
    try {
      const parsed = yaml.load(input);
      if (parsed && typeof parsed === "object") return parsed;
    } catch (e) {
      throw new Error(`YAML parse error: ${e.message}`);
    }
  }
  throw new Error("Could not parse input as JSON or YAML. Install js-yaml for YAML support.");
}

function buildAdmissionReview(parsedManifest) {
  const apiVersion = parsedManifest.apiVersion || "v1";
  const hasGroup   = apiVersion.includes("/");
  return {
    apiVersion: "admission.k8s.io/v1",
    kind: "AdmissionReview",
    request: {
      uid:    `test-${Date.now()}`,
      kind: {
        group:   hasGroup ? apiVersion.split("/")[0] : "",
        version: hasGroup ? apiVersion.split("/")[1] : apiVersion,
        kind:    parsedManifest.kind || "Unknown",
      },
      resource: {
        group:    "",
        version:  "v1",
        resource: (parsedManifest.kind || "unknown").toLowerCase() + "s",
      },
      name:      parsedManifest.metadata?.name      || "test-resource",
      namespace: parsedManifest.metadata?.namespace || "default",
      operation: "CREATE",
      userInfo: {
        username: "system:serviceaccount:default:default",
        groups:   ["system:serviceaccounts", "system:authenticated"],
      },
      object: parsedManifest,
    },
  };
}

function forwardToGatekeeper(admissionReview, targetUrl, ignoreTls) {
  return new Promise((resolve, reject) => {
    const parsedUrl         = new URL(targetUrl);
    const isHttps           = parsedUrl.protocol === "https:";
    const effectiveIgnoreTls = ignoreTls !== undefined ? ignoreTls : IGNORE_TLS;
    const reqBody           = JSON.stringify(admissionReview);

    const options = {
      hostname: parsedUrl.hostname,
      port:     parsedUrl.port || (isHttps ? 443 : 80),
      path:     parsedUrl.pathname,
      method:   "POST",
      headers: {
        "Content-Type":   "application/json",
        "Content-Length": Buffer.byteLength(reqBody),
      },
      rejectUnauthorized: !effectiveIgnoreTls,
      ...(TLS_CERT && TLS_KEY ? { cert: TLS_CERT, key: TLS_KEY } : {}),
      ...(TLS_CA ? { ca: TLS_CA } : {}),
    };

    const lib      = isHttps ? https : http;
    const proxyReq = lib.request(options, (proxyRes) => {
      let data = "";
      proxyRes.on("data", chunk => data += chunk);
      proxyRes.on("end", () => {
        try {
          const responseJson = JSON.parse(data);
          resolve({
            status:         proxyRes.statusCode,
            raw:            responseJson,
            allowed:        responseJson?.response?.allowed,
            status_message: responseJson?.response?.status?.message || null,
            uid:            responseJson?.response?.uid || null,
          });
        } catch {
          reject({ type: "parse_error", raw: data });
        }
      });
    });

    proxyReq.on("error", (err) => reject({ type: "network_error", message: err.message }));
    proxyReq.write(reqBody);
    proxyReq.end();
  });
}

// ── Route handlers ────────────────────────────────────────────────────────────

async function handleValidate(req, res) {
  let body;
  try { body = await readBody(req); } catch {
    return sendJson(res, 400, { error: "Failed to read request body." });
  }
  let parsed;
  try { parsed = JSON.parse(body); } catch {
    return sendJson(res, 400, { error: "Request body must be valid JSON." });
  }

  const { manifest, admissionRequest, gatekeeperUrl, ignoreTls } = parsed;
  if (!manifest && !admissionRequest) {
    return sendJson(res, 400, { error: "Provide either 'manifest' or 'admissionRequest'." });
  }

  let admissionReview;
  if (admissionRequest) {
    try {
      admissionReview = typeof admissionRequest === "string"
        ? JSON.parse(admissionRequest) : admissionRequest;
    } catch {
      return sendJson(res, 400, { error: "Invalid JSON in 'admissionRequest'." });
    }
    if (!admissionReview?.request?.uid) {
      admissionReview = {
        ...admissionReview,
        request: { ...admissionReview.request, uid: `test-${Date.now()}` },
      };
    }
  } else {
    let parsedManifest;
    try {
      parsedManifest = parseManifest(manifest);
    } catch (e) {
      return sendJson(res, 400, { error: `Could not parse manifest: ${e.message}` });
    }
    admissionReview = buildAdmissionReview(parsedManifest);
  }

  const targetUrl = gatekeeperUrl || GATEKEEPER_URL;
  try {
    const result = await forwardToGatekeeper(admissionReview, targetUrl, ignoreTls);
    res.writeHead(result.status, { "Content-Type": "application/json" });
    res.end(JSON.stringify(result));
  } catch (err) {
    if (err.type === "parse_error") return sendJson(res, 500, { error: "Non-JSON response from Gatekeeper.", raw: err.raw });
    return sendJson(res, 502, { error: `Failed to reach Gatekeeper: ${err.message}` });
  }
}

async function handleBatch(req, res) {
  let body;
  try { body = await readBody(req); } catch {
    return sendJson(res, 400, { error: "Failed to read request body." });
  }
  let parsed;
  try { parsed = JSON.parse(body); } catch {
    return sendJson(res, 400, { error: "Request body must be valid JSON." });
  }

  const { manifests, admissionRequests, gatekeeperUrl, ignoreTls } = parsed;
  if (!manifests?.length && !admissionRequests?.length) {
    return sendJson(res, 400, { error: "Provide a non-empty 'manifests' or 'admissionRequests' array." });
  }

  const targetUrl = gatekeeperUrl || GATEKEEPER_URL;
  const items = [];

  if (manifests?.length) {
    for (let i = 0; i < manifests.length; i++) {
      try {
        items.push({ index: i, type: "manifest", review: buildAdmissionReview(parseManifest(manifests[i])) });
      } catch (e) {
        items.push({ index: i, type: "manifest", parseError: e.message });
      }
    }
  }

  if (admissionRequests?.length) {
    for (let i = 0; i < admissionRequests.length; i++) {
      try {
        let ar = typeof admissionRequests[i] === "string"
          ? JSON.parse(admissionRequests[i]) : admissionRequests[i];
        if (!ar?.request?.uid) ar = { ...ar, request: { ...ar.request, uid: `test-${Date.now()}-${i}` } };
        items.push({ index: i, type: "admissionRequest", review: ar });
      } catch (e) {
        items.push({ index: i, type: "admissionRequest", parseError: e.message });
      }
    }
  }

  const results = await Promise.all(items.map(async (item) => {
    if (item.parseError) return { index: item.index, type: item.type, error: `Parse error: ${item.parseError}` };
    try {
      const result = await forwardToGatekeeper(item.review, targetUrl, ignoreTls);
      return { index: item.index, type: item.type, ...result };
    } catch (err) {
      if (err.type === "parse_error") return { index: item.index, type: item.type, error: "Non-JSON response from Gatekeeper.", raw: err.raw };
      return { index: item.index, type: item.type, error: `Failed to reach Gatekeeper: ${err.message}` };
    }
  }));

  sendJson(res, 200, results);
}

// ── Capture API handlers ───────────────────────────────────────────────────────

/**
 * POST /capture/start
 * Body: { operations?: string[], resources?: string[], namespaces?: string[] }
 *
 * Creates (or replaces) the ValidatingWebhookConfiguration in the cluster so the
 * kube-apiserver forwards real AdmissionReview objects to this pod's HTTPS server.
 */
async function handleCaptureStart(req, res) {
  if (!capturePems || !captureServerStarted) {
    return sendJson(res, 503, { error: "Capture HTTPS server is not running (openssl cert generation failed or port conflict)." });
  }
  if (!CAPTURE_CA_BUNDLE) {
    return sendJson(res, 503, { error: "TLS cert was not generated. Capture is unavailable." });
  }
  if (!isInCluster()) {
    return sendJson(res, 400, {
      error: "Not running in-cluster. Cannot auto-register the ValidatingWebhookConfiguration. " +
             "Use GET /capture/status to obtain the caBundle and apply the VWC manually.",
      caBundle: CAPTURE_CA_BUNDLE,
      certSan:  CAPTURE_SAN,
      capturePort: CAPTURE_PORT,
    });
  }

  let body;
  try { body = await readBody(req); } catch { body = "{}"; }
  let config = {};
  try { config = JSON.parse(body); } catch {}

  // Normalise: split comma-separated strings into arrays
  if (typeof config.namespaces === "string") config.namespaces = config.namespaces.split(",").map(s => s.trim()).filter(Boolean);
  if (typeof config.operations === "string") config.operations = config.operations.split(",").map(s => s.trim()).filter(Boolean);
  if (typeof config.resources  === "string") config.resources  = config.resources.split(",").map(s => s.trim()).filter(Boolean);

  const vwc = buildVWC(config);

  try {
    await applyVWC(vwc);
  } catch (e) {
    return sendJson(res, 500, { error: `Failed to apply VWC: ${e.message}` });
  }

  captureActive = true;
  captureConfig = config;

  sendJson(res, 200, {
    active:      true,
    vwcName:     VWC_NAME,
    certSan:     CAPTURE_SAN,
    capturePort: CAPTURE_PORT,
    config,
  });
}

/**
 * POST /capture/stop
 * Deletes the ValidatingWebhookConfiguration and stops storing new captures.
 */
async function handleCaptureStop(req, res) {
  captureActive = false;

  if (!isInCluster()) {
    return sendJson(res, 200, { active: false, note: "Not in-cluster — no VWC to delete." });
  }

  try {
    await removeVWC(VWC_NAME);
  } catch (e) {
    return sendJson(res, 500, { error: `Failed to delete VWC: ${e.message}` });
  }

  sendJson(res, 200, { active: false, vwcName: VWC_NAME });
}

/**
 * GET /capture/status
 */
function handleCaptureStatus(req, res) {
  sendJson(res, 200, {
    active:               captureActive,
    certSan:              CAPTURE_SAN,
    capturePort:          CAPTURE_PORT,
    captureServerStarted,
    caBundle:             CAPTURE_CA_BUNDLE,
    vwcName:              VWC_NAME,
    requestCount:         capturedRequests.length,
    config:               captureConfig,
    inCluster:            isInCluster(),
    certAvailable:        !!capturePems,
  });
}

/**
 * GET /captured?limit=N
 * Returns the ring buffer of captured AdmissionReview objects (newest first).
 */
function handleGetCaptured(req, res) {
  const { query } = url.parse(req.url, true);
  const limit = query.limit ? parseInt(query.limit) : capturedRequests.length;
  sendJson(res, 200, capturedRequests.slice(0, limit));
}

/**
 * DELETE /captured
 * Clears the ring buffer.
 */
function handleDeleteCaptured(req, res) {
  capturedRequests = [];
  sendJson(res, 200, { cleared: true });
}

// ── Kubernetes helpers (non-API) ───────────────────────────────────────────────

function isInCluster() {
  return fs.existsSync(`${K8S_SA}/token`);
}

const VWC_NAME = "gatekeeper-tester-capture";

function buildVWC(config) {
  const ops       = config.operations?.length ? config.operations : ["CREATE", "UPDATE", "DELETE"];
  const resources = config.resources?.length  ? config.resources  : ["*"];
  const nsSelector = config.namespaces?.length
    ? { matchExpressions: [{ key: "kubernetes.io/metadata.name", operator: "In", values: config.namespaces }] }
    : undefined;

  return {
    apiVersion: "admissionregistration.k8s.io/v1",
    kind: "ValidatingWebhookConfiguration",
    metadata: {
      name:   VWC_NAME,
      labels: { app: "gatekeeper-tester" },
    },
    webhooks: [{
      name:                    "capture.gatekeeper-tester.io",
      admissionReviewVersions: ["v1"],
      clientConfig: {
        service: {
          name:      SERVICE_NAME,
          namespace: POD_NAMESPACE,
          port:      CAPTURE_PORT,
          path:      "/capture",
        },
        caBundle: CAPTURE_CA_BUNDLE,
      },
      rules: [{
        apiGroups:   ["*"],
        apiVersions: ["*"],
        operations:  ops,
        resources,
        scope: "*",
      }],
      ...(nsSelector ? { namespaceSelector: nsSelector } : {}),
      failurePolicy:  "Ignore",
      sideEffects:    "None",
      timeoutSeconds: 5,
    }],
  };
}

// ── HTTP server ───────────────────────────────────────────────────────────────

const server = http.createServer(async (req, res) => {
  const { pathname } = url.parse(req.url);

  if (pathname === "/health" && req.method === "GET") {
    return sendJson(res, 200, { status: "ok" });
  }

  // Capture API
  if (pathname === "/capture/start"  && req.method === "POST")   return handleCaptureStart(req, res);
  if (pathname === "/capture/stop"   && req.method === "POST")   return handleCaptureStop(req, res);
  if (pathname === "/capture/status" && req.method === "GET")    return handleCaptureStatus(req, res);
  if (pathname === "/captured"       && req.method === "GET")    return handleGetCaptured(req, res);
  if (pathname === "/captured"       && req.method === "DELETE") return handleDeleteCaptured(req, res);

  // Validation API
  if (pathname === "/validate/batch" && req.method === "POST") return handleBatch(req, res);
  if (pathname === "/validate"       && req.method === "POST") return handleValidate(req, res);

  serveStatic(req, res);
});

server.listen(PORT, () => console.log(`Gatekeeper Tester running on :${PORT}`));
