const http = require("http");
const https = require("https");
const fs = require("fs");
const path = require("path");
const url = require("url");

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

function serveStatic(req, res) {
  let filePath = path.join(__dirname, "public", req.url === "/" ? "index.html" : req.url);
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

function handleValidate(req, res) {
  let body = "";
  req.on("data", chunk => body += chunk);
  req.on("end", () => {
    let parsed;
    try {
      parsed = JSON.parse(body);
    } catch {
      res.writeHead(400, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Invalid JSON body" }));
      return;
    }

    const { manifest, gatekeeperUrl } = parsed;

    if (!manifest) {
      res.writeHead(400, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "No manifest provided." }));
      return;
    }

    let parsedManifest;
    try {
      parsedManifest = typeof manifest === "string" ? JSON.parse(manifest) : manifest;
    } catch {
      res.writeHead(400, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Invalid JSON manifest." }));
      return;
    }

    const admissionReview = {
      apiVersion: "admission.k8s.io/v1",
      kind: "AdmissionReview",
      request: {
        uid: `test-${Date.now()}`,
        kind: {
          group: parsedManifest.apiVersion?.includes("/") ? parsedManifest.apiVersion.split("/")[0] : "",
          version: parsedManifest.apiVersion?.includes("/") ? parsedManifest.apiVersion.split("/")[1] : parsedManifest.apiVersion || "v1",
          kind: parsedManifest.kind || "Unknown",
        },
        resource: {
          group: "",
          version: "v1",
          resource: (parsedManifest.kind || "unknown").toLowerCase() + "s",
        },
        name: parsedManifest.metadata?.name || "test-resource",
        namespace: parsedManifest.metadata?.namespace || "default",
        operation: "CREATE",
        object: parsedManifest,
      },
    };

    const targetUrl = gatekeeperUrl || GATEKEEPER_URL;
    const parsedUrl = new URL(targetUrl);
    const isHttps = parsedUrl.protocol === "https:";
    const reqBody = JSON.stringify(admissionReview);

    const options = {
      hostname: parsedUrl.hostname,
      port: parsedUrl.port || (isHttps ? 443 : 80),
      path: parsedUrl.pathname,
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Content-Length": Buffer.byteLength(reqBody),
      },
      rejectUnauthorized: !IGNORE_TLS,
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
          res.writeHead(proxyRes.statusCode, { "Content-Type": "application/json" });
          res.end(JSON.stringify({
            status: proxyRes.statusCode,
            raw: responseJson,
            allowed: responseJson?.response?.allowed,
            status_message: responseJson?.response?.status?.message || null,
            uid: responseJson?.response?.uid || null,
          }));
        } catch {
          res.writeHead(500, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: "Non-JSON response from Gatekeeper", raw: data }));
        }
      });
    });

    proxyReq.on("error", (err) => {
      res.writeHead(502, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: `Failed to reach Gatekeeper: ${err.message}` }));
    });

    proxyReq.write(reqBody);
    proxyReq.end();
  });
}

const server = http.createServer((req, res) => {
  const parsedReq = url.parse(req.url);

  if (parsedReq.pathname === "/health" && req.method === "GET") {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ status: "ok" }));
    return;
  }

  if (parsedReq.pathname === "/validate" && req.method === "POST") {
    handleValidate(req, res);
    return;
  }

  serveStatic(req, res);
});

server.listen(PORT, () => console.log(`Gatekeeper Tester running on :${PORT}`));