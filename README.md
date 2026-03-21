# Gatekeeper Admission Tester

A single-container tool for testing Kubernetes manifests against an OPA Gatekeeper validating admission webhook.

## Quick Start

```bash
# Build & run
docker compose up --build

# Open in browser
open http://localhost:3000
```

## Environment Variables

| Variable           | Default                                                            | Description                                            |
| ------------------ | ------------------------------------------------------------------ | ------------------------------------------------------ |
| `GATEKEEPER_URL` | `https://gatekeeper-webhook.gatekeeper-system.svc:8443/v1/admit` | Default Gatekeeper webhook URL                         |
| `IGNORE_TLS`     | `false`                                                          | Skip TLS certificate verification (`true`/`false`) |
| `TLS_CERT_PATH`  | —                                                                 | Path to client TLS cert (mTLS)                         |
| `TLS_KEY_PATH`   | —                                                                 | Path to client TLS key (mTLS)                          |
| `TLS_CA_PATH`    | —                                                                 | Path to CA cert for server verification                |
| `PORT`           | `3000`                                                           | Port the server listens on                             |

## How It Works

```
Browser → Express /validate (proxy) → Gatekeeper Webhook
```

The Express server:

1. Serves the static frontend at `/`
2. Exposes `POST /validate` which wraps your manifest in an `AdmissionReview` object and forwards it to Gatekeeper
3. Returns the structured response (allowed/denied, reason, raw JSON)

This single-origin design avoids CORS entirely.

## mTLS Support

If your Gatekeeper webhook requires mutual TLS, mount your certs and set the env vars:

```yaml
# docker-compose.yml
volumes:
  - ./certs:/certs:ro
environment:
  - TLS_CERT_PATH=/certs/tls.crt
  - TLS_KEY_PATH=/certs/tls.key
  - TLS_CA_PATH=/certs/ca.crt
```

## In-Cluster Deployment

### Local kind Cluster (no registry required)

You can load the image directly into kind from your local Docker daemon — no Artifactory or registry needed:

```bash
# 1. Build the image locally
docker build -t gatekeeper-tester:latest .

# 2. Load it into your kind cluster
kind load docker-image gatekeeper-tester:latest --name <your-cluster-name>

# Verify the image is present in the kind node
docker exec -it <kind-node-name> crictl images | grep gatekeeper-tester

# Find your kind node name if needed
docker ps --filter "name=kind"
```

Then deploy with `imagePullPolicy: Never` so the kubelet uses the loaded image instead of attempting a registry pull:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: gatekeeper-tester
  namespace: gatekeeper-system
spec:
  replicas: 1
  selector:
    matchLabels:
      app: gatekeeper-tester
  template:
    metadata:
      labels:
        app: gatekeeper-tester
    spec:
      containers:
        - name: tester
          image: gatekeeper-tester:latest
          imagePullPolicy: Never  # use the image loaded via kind load
          ports:
            - containerPort: 3000
          env:
            - name: GATEKEEPER_URL
              value: "https://gatekeeper-webhook-service.gatekeeper-system.svc:8443/v1/admit"
            - name: IGNORE_TLS
              value: "true"
---
apiVersion: v1
kind: Service
metadata:
  name: gatekeeper-tester
  namespace: gatekeeper-system
spec:
  selector:
    app: gatekeeper-tester
  ports:
    - port: 3000
      targetPort: 3000
```

> **Note:** `imagePullPolicy: Never` is required. Without it, Kubernetes will attempt to pull from Docker Hub and fail with `ErrImagePull`.

### Accessing the UI

**Option 1 — port-forward (simplest):**

```bash
kubectl port-forward svc/gatekeeper-tester 3000:3000 -n gatekeeper-system
# Open http://localhost:3000
```

**Option 2 — kubectl proxy:**

```bash
kubectl proxy --port=8001
# Open http://localhost:8001/api/v1/namespaces/gatekeeper-system/services/gatekeeper-tester:3000/proxy/
```

> **Note:** The trailing slash on the `kubectl proxy` URL is required — without it, asset paths won't resolve correctly and the UI may load broken.

### Registry-based Deployment

To deploy using an image from a registry, replace the image and remove `imagePullPolicy: Never`:

```yaml
image: your-registry/gatekeeper-tester:latest
# imagePullPolicy defaults to IfNotPresent
```
