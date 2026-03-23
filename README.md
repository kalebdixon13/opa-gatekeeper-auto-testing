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
| `GATEKEEPER_URL` | `https://gatekeeper-webhook-service.gatekeeper-system.svc/v1/admit` | Default Gatekeeper webhook URL                         |
| `IGNORE_TLS`     | `false`                                                          | Skip TLS certificate verification (`true`/`false`) |
| `TLS_CERT_PATH`  | —                                                                 | Path to client TLS cert (mTLS)                         |
| `TLS_KEY_PATH`   | —                                                                 | Path to client TLS key (mTLS)                          |
| `TLS_CA_PATH`    | —                                                                 | Path to CA cert for server verification                |
| `PORT`           | `3000`                                                           | Port the server listens on                             |
| `CAPTURE_PORT`   | `8443`                                                           | HTTPS port for the admission capture server            |
| `SERVICE_NAME`   | `gatekeeper-tester`                                              | Kubernetes Service name (used in the VWC `clientConfig`) |
| `POD_NAMESPACE`  | `gatekeeper-system`                                              | Namespace the pod runs in (used in the VWC `clientConfig`) |
| `CAPTURE_MAX`    | `100`                                                            | Maximum number of admission reviews to keep in memory  |

## How It Works

```
Browser → Express /validate (proxy) → Gatekeeper Webhook
```

The Express server:

1. Serves the static frontend at `/`
2. Exposes `POST /validate` which wraps your manifest in an `AdmissionReview` object and forwards it to Gatekeeper
3. Returns the structured response (allowed/denied, reason, raw JSON)

This single-origin design avoids CORS entirely.

## Admission Request Monitor (Capture Tab)

### Background: What is a Validating Admission Webhook?

When you apply a resource to Kubernetes (e.g. `kubectl apply -f pod.yaml`), the kube-apiserver does not immediately write it to etcd. First, it checks whether any registered webhooks want to review it. A **validating admission webhook** is an HTTPS endpoint you register with the cluster; the apiserver sends it an `AdmissionReview` JSON object describing the operation, and the webhook responds with `allowed: true` or `allowed: false`.

OPA Gatekeeper works exactly this way — it registers itself as a validating webhook and evaluates every incoming resource against your Rego policies before allowing or denying it.

### What the Capture Feature Does

The **Capture** tab lets you intercept and inspect the real `AdmissionReview` objects that the kube-apiserver sends for live traffic in your cluster — without writing any policy or deploying anything extra. This is useful for:

- Understanding what an admission review actually looks like before writing a policy
- Seeing exactly what fields Gatekeeper (or any webhook) receives for a given `kubectl` command
- Debugging why a policy is or isn't matching a real resource

### How It Works

When you click **Start Capture** in the UI, the image does the following automatically:

1. **Generates a self-signed TLS certificate** at startup using only Node's built-in `crypto` module (no `openssl` binary required). The cert's Subject Alternative Name is set to `<service-name>.<namespace>.svc` so the kube-apiserver can reach it inside the cluster.

2. **Runs an HTTPS capture server** on port `8443` inside the same container. This server accepts real `AdmissionReview` POSTs from the kube-apiserver and always responds `allowed: true` — it is read-only and will never block cluster operations.

3. **Creates a `ValidatingWebhookConfiguration`** in the cluster via the Kubernetes API, pointing the kube-apiserver at this pod's HTTPS endpoint. The `caBundle` field is populated automatically with the generated certificate so the apiserver can verify the TLS connection.

4. **Stores incoming reviews** in an in-memory ring buffer (up to 100 by default, configurable via `CAPTURE_MAX`). The UI polls for new entries and displays them in real time.

5. When you click **Stop**, the `ValidatingWebhookConfiguration` is deleted and the ring buffer stops accepting new entries.

### Configuring What to Capture

The UI exposes three filters that are passed to the `ValidatingWebhookConfiguration`'s `rules` field:

| Field | Default | Description |
|-------|---------|-------------|
| **Namespaces** | all | Comma-separated list of namespaces to watch (e.g. `default,kube-system`) |
| **Operations** | `CREATE,UPDATE,DELETE` | Which operation types to intercept |
| **Resources** | `*` (all) | Specific resource types to watch (e.g. `pods,deployments`) |

Leaving a field blank applies the broadest possible scope. The webhook always uses `failurePolicy: Ignore`, meaning if the capture server is unreachable, the original request proceeds normally.

### Requirements

- Must be deployed **in-cluster** (the pod needs access to the Kubernetes API to create the `ValidatingWebhookConfiguration`)
- The service account must have RBAC permission to `create`, `patch`, and `delete` `validatingwebhookconfigurations`
- The pod's HTTPS port (`8443` by default) must be reachable by the kube-apiserver

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

```bash
kubectl apply -f deploy/
```

> **Note:** `imagePullPolicy: Never` is required in `deploy/deployment.yaml`. Without it, Kubernetes will attempt to pull from Docker Hub and fail with `ErrImagePull`.

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
