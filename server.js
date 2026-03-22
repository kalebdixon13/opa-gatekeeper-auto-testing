const http = require("http");
const https = require("https");
const fs = require("fs");
const path = require("path");
const url = require("url");

let yaml;
try { yaml = require("js-yaml"); } catch { yaml = null; }

const GATEKEEPER_URL = process.env.GATEKEEPER_URL || "https://gatekeeper-webhook.gatekeeper-system.svc:8443/v1/admit";
const IGNORE_TLS = process.env.IGNORE_TLS === "true";
const PORT = process.env.PORT || 3000;

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

// ── Helpers ──────────────────────────────────────────────────────────────────

function sendJson(res, status, obj) {
  res.writeHead(status, { "Content-Type": "application/json" });
  res.end(JSON.stringify(obj));
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let body = "";
    req.on("data", chunk => body += chunk);
    req.on("end", () => resolve(body));
    req.on("error", reject);
  });
}

function serveStatic(req, res) {
  const filePath = path.join(__dirname, req.url === "/" ? "index.html" : req.url);
  const ext = path.extname(filePath);
  const contentType = MIME_TYPES[ext] || "text/plain";

  fs.readFile(filePath, (err, data) => {
    if (err) {
      res.writeHead(404);
      res.end("Not found");
      return;
    }
    res.writeHead(200, { "Content-Type": contentType });
    res.end(data);
  });
}

/**
 * Parse a manifest string as JSON first, then YAML as fallback.
 * Accepts an already-parsed object and returns it as-is.
 */
function parseManifest(input) {
  if (input !== null && typeof input === "object") return input;
  if (typeof input !== "string") throw new Error("Manifest must be a string or object.");

  // Try JSON first (JSON is a subset of YAML, but JSON.parse is faster and stricter)
  try { return JSON.parse(input); } catch {}

  // Try YAML
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

/**
 * Wrap a parsed Kubernetes manifest in an AdmissionReview envelope.
 */
function buildAdmissionReview(parsedManifest) {
  const apiVersion = parsedManifest.apiVersion || "v1";
  const hasGroup = apiVersion.includes("/");

  return {
    apiVersion: "admission.k8s.io/v1",
    kind: "AdmissionReview",
    request: {
      uid: `test-${Date.now()}`,
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

/**
 * POST an AdmissionReview to Gatekeeper and return the structured result.
 */
function forwardToGatekeeper(admissionReview, targetUrl, ignoreTls) {
  return new Promise((resolve, reject) => {
    const parsedUrl = new URL(targetUrl);
    const isHttps = parsedUrl.protocol === "https:";
    const effectiveIgnoreTls = ignoreTls !== undefined ? ignoreTls : IGNORE_TLS;
    const reqBody = JSON.stringify(admissionReview);

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

    const lib = isHttps ? https : http;
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

    proxyReq.on("error", (err) => {
      reject({ type: "network_error", message: err.message });
    });

    proxyReq.write(reqBody);
    proxyReq.end();
  });
}

// ── Route handlers ────────────────────────────────────────────────────────────

/**
 * POST /validate
 *
 * Body (JSON):
 *   { manifest: <string|object>,       // YAML or JSON k8s manifest  — OR —
 *     admissionRequest: <object>,      // complete AdmissionReview envelope
 *     gatekeeperUrl?: string,
 *     ignoreTls?: boolean }
 */
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
    // Full AdmissionReview supplied — use it directly, stamping a UID if absent.
    try {
      admissionReview = typeof admissionRequest === "string"
        ? JSON.parse(admissionRequest)
        : admissionRequest;
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
    // Manifest supplied — parse YAML/JSON and wrap in an AdmissionReview.
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
    if (err.type === "parse_error") {
      return sendJson(res, 500, { error: "Non-JSON response from Gatekeeper.", raw: err.raw });
    }
    return sendJson(res, 502, { error: `Failed to reach Gatekeeper: ${err.message}` });
  }
}

/**
 * POST /validate/batch
 *
 * Send multiple manifests or full admission requests to Gatekeeper in one call.
 * Requests are forwarded concurrently; results are returned in the same order.
 *
 * Body (JSON):
 *   { manifests?:          Array<string|object>,   // YAML/JSON k8s manifests
 *     admissionRequests?:  Array<object>,           // complete AdmissionReview envelopes
 *     gatekeeperUrl?:      string,
 *     ignoreTls?:          boolean }
 *
 * Response: Array of result objects, each containing an `index` and `type` field
 * plus the same fields returned by /validate (or an `error` field on failure).
 */
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
    return sendJson(res, 400, {
      error: "Provide a non-empty 'manifests' or 'admissionRequests' array.",
    });
  }

  const targetUrl = gatekeeperUrl || GATEKEEPER_URL;

  // Build the list of work items (each becomes one request to Gatekeeper).
  const items = [];

  if (manifests?.length) {
    for (let i = 0; i < manifests.length; i++) {
      try {
        const parsedManifest = parseManifest(manifests[i]);
        items.push({ index: i, type: "manifest", review: buildAdmissionReview(parsedManifest) });
      } catch (e) {
        items.push({ index: i, type: "manifest", parseError: e.message });
      }
    }
  }

  if (admissionRequests?.length) {
    for (let i = 0; i < admissionRequests.length; i++) {
      try {
        let ar = typeof admissionRequests[i] === "string"
          ? JSON.parse(admissionRequests[i])
          : admissionRequests[i];
        if (!ar?.request?.uid) {
          ar = { ...ar, request: { ...ar.request, uid: `test-${Date.now()}-${i}` } };
        }
        items.push({ index: i, type: "admissionRequest", review: ar });
      } catch (e) {
        items.push({ index: i, type: "admissionRequest", parseError: e.message });
      }
    }
  }

  // Send all to Gatekeeper concurrently.
  const results = await Promise.all(items.map(async (item) => {
    if (item.parseError) {
      return { index: item.index, type: item.type, error: `Parse error: ${item.parseError}` };
    }
    try {
      const result = await forwardToGatekeeper(item.review, targetUrl, ignoreTls);
      return { index: item.index, type: item.type, ...result };
    } catch (err) {
      if (err.type === "parse_error") {
        return { index: item.index, type: item.type, error: "Non-JSON response from Gatekeeper.", raw: err.raw };
      }
      return { index: item.index, type: item.type, error: `Failed to reach Gatekeeper: ${err.message}` };
    }
  }));

  sendJson(res, 200, results);
}

// ── Server ────────────────────────────────────────────────────────────────────

const server = http.createServer(async (req, res) => {
  const { pathname } = url.parse(req.url);

  if (pathname === "/health" && req.method === "GET") {
    return sendJson(res, 200, { status: "ok" });
  }

  if (pathname === "/validate/batch" && req.method === "POST") {
    return handleBatch(req, res);
  }

  if (pathname === "/validate" && req.method === "POST") {
    return handleValidate(req, res);
  }

  serveStatic(req, res);
});

server.listen(PORT, () => console.log(`Gatekeeper Tester running on :${PORT}`));
