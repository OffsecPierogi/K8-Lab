#!/bin/bash

# KubeHound Attack Surface Vulnerability Scanner
# Scans a Kubernetes cluster for vulnerabilities based on KubeHound attack vectors
# https://kubehound.io/reference/attacks/

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

VULNERABLE_ASSETS=()
TOTAL_CHECKS=0
VULNERABLE_CHECKS=0

# Configuration
SKIP_SLOW_CHECKS=${SKIP_SLOW_CHECKS:-false}
AUTH_TIMEOUT=${AUTH_TIMEOUT:-2}

log_header() {
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}========================================${NC}"
}

log_check() {
    echo -e "${YELLOW}[CHECK]${NC} $1"
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
}

log_vulnerable() {
    echo -e "${RED}[VULNERABLE]${NC} $1"
    VULNERABLE_CHECKS=$((VULNERABLE_CHECKS + 1))
}

log_secure() {
    echo -e "${GREEN}[SECURE]${NC} $1"
}

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

add_vulnerable_asset() {
    VULNERABLE_ASSETS+=("$1")
}

# Check 1: CE_MODULE_LOAD - Containers with CAP_SYS_MODULE
check_module_load() {
    log_header "CE_MODULE_LOAD: Load Kernel Module"
    log_check "Checking for containers with CAP_SYS_MODULE capability..."
    
    local found=0
    for ns in $(kubectl get namespaces -o jsonpath='{.items[*].metadata.name}' 2>/dev/null); do
        pods=$(kubectl get pods -n "$ns" -o json 2>/dev/null | jq -r '
            .items[] | 
            select(.spec.containers[]?.securityContext?.capabilities?.add[]? == "SYS_MODULE" or 
                   .spec.initContainers[]?.securityContext?.capabilities?.add[]? == "SYS_MODULE") |
            .metadata.name
        ' 2>/dev/null)
        
        if [ -n "$pods" ]; then
            for pod in $pods; do
                log_vulnerable "Pod: $ns/$pod has CAP_SYS_MODULE"
                add_vulnerable_asset "CE_MODULE_LOAD: $ns/$pod"
                found=1
            done
        fi
    done
    
    [ $found -eq 0 ] && log_secure "No containers with CAP_SYS_MODULE found"
    echo ""
}

# Check 2: CE_NSENTER - Privileged containers with host namespaces
check_nsenter() {
    log_header "CE_NSENTER: nsenter Container Escape"
    log_check "Checking for privileged containers with host PID/IPC namespace access..."
    
    local found=0
    for ns in $(kubectl get namespaces -o jsonpath='{.items[*].metadata.name}' 2>/dev/null); do
        pods=$(kubectl get pods -n "$ns" -o json 2>/dev/null | jq -r '
            .items[] | 
            select(.spec.hostPID == true or .spec.hostIPC == true or 
                   .spec.containers[]?.securityContext?.privileged == true) |
            "\(.metadata.name)|\(.spec.hostPID // false)|\(.spec.hostIPC // false)|\(.spec.containers[0].securityContext.privileged // false)"
        ' 2>/dev/null)
        
        if [ -n "$pods" ]; then
            while IFS='|' read -r pod hostpid hostipc privileged; do
                log_vulnerable "Pod: $ns/$pod (hostPID=$hostpid, hostIPC=$hostipc, privileged=$privileged)"
                add_vulnerable_asset "CE_NSENTER: $ns/$pod"
                found=1
            done <<< "$pods"
        fi
    done
    
    [ $found -eq 0 ] && log_secure "No privileged containers with host namespace access found"
    echo ""
}

# Check 3: CE_PRIV_MOUNT - Privileged containers that can mount host filesystem
check_priv_mount() {
    log_header "CE_PRIV_MOUNT: Mount Host Filesystem"
    log_check "Checking for privileged containers with CAP_SYS_ADMIN..."
    
    local found=0
    for ns in $(kubectl get namespaces -o jsonpath='{.items[*].metadata.name}' 2>/dev/null); do
        pods=$(kubectl get pods -n "$ns" -o json 2>/dev/null | jq -r '
            .items[] | 
            select(.spec.containers[]?.securityContext?.privileged == true or
                   .spec.containers[]?.securityContext?.capabilities?.add[]? == "SYS_ADMIN") |
            .metadata.name
        ' 2>/dev/null)
        
        if [ -n "$pods" ]; then
            for pod in $pods; do
                log_vulnerable "Pod: $ns/$pod can mount host filesystem"
                add_vulnerable_asset "CE_PRIV_MOUNT: $ns/$pod"
                found=1
            done
        fi
    done
    
    [ $found -eq 0 ] && log_secure "No containers with filesystem mount capabilities found"
    echo ""
}

# Check 4: CE_SYS_PTRACE - Containers with CAP_SYS_PTRACE
check_sys_ptrace() {
    log_header "CE_SYS_PTRACE: Attach to Host Process"
    log_check "Checking for containers with CAP_SYS_PTRACE capability..."
    
    local found=0
    for ns in $(kubectl get namespaces -o jsonpath='{.items[*].metadata.name}' 2>/dev/null); do
        pods=$(kubectl get pods -n "$ns" -o json 2>/dev/null | jq -r '
            .items[] | 
            select(.spec.containers[]?.securityContext?.capabilities?.add[]? == "SYS_PTRACE") |
            .metadata.name
        ' 2>/dev/null)
        
        if [ -n "$pods" ]; then
            for pod in $pods; do
                log_vulnerable "Pod: $ns/$pod has CAP_SYS_PTRACE"
                add_vulnerable_asset "CE_SYS_PTRACE: $ns/$pod"
                found=1
            done
        fi
    done
    
    [ $found -eq 0 ] && log_secure "No containers with CAP_SYS_PTRACE found"
    echo ""
}

# Check 5: EXPLOIT_HOST_READ/WRITE - Sensitive host path mounts
check_host_mounts() {
    log_header "EXPLOIT_HOST_READ/WRITE: Sensitive Host Mounts"
    log_check "Checking for pods with sensitive host path mounts..."
    
    local found=0
    local sensitive_paths=("/etc" "/var/run" "/proc" "/sys" "/root" "/home" "/var/log" "/var/lib/kubelet")
    
    for ns in $(kubectl get namespaces -o jsonpath='{.items[*].metadata.name}' 2>/dev/null); do
        pods=$(kubectl get pods -n "$ns" -o json 2>/dev/null | jq -r --argjson paths "$(printf '%s\n' "${sensitive_paths[@]}" | jq -R . | jq -s .)" '
            .items[] | 
            select(.spec.volumes[]?.hostPath.path as $hp | $paths | map(select($hp != null and ($hp | startswith(.)))) | length > 0) |
            "\(.metadata.name)|\(.spec.volumes[] | select(.hostPath != null) | .hostPath.path)"
        ' 2>/dev/null)
        
        if [ -n "$pods" ]; then
            while IFS='|' read -r pod path; do
                log_vulnerable "Pod: $ns/$pod mounts sensitive host path: $path"
                add_vulnerable_asset "EXPLOIT_HOST_MOUNT: $ns/$pod -> $path"
                found=1
            done <<< "$pods"
        fi
    done
    
    [ $found -eq 0 ] && log_secure "No pods with sensitive host path mounts found"
    echo ""
}

# Check 6: EXPLOIT_CONTAINERD_SOCK - Container runtime socket mounts
check_container_runtime_sock() {
    log_header "EXPLOIT_CONTAINERD_SOCK: Container Runtime Socket"
    log_check "Checking for pods with container runtime socket mounts..."
    
    local found=0
    local runtime_socks=("/var/run/docker.sock" "/var/run/containerd/containerd.sock" "/var/run/crio/crio.sock")
    
    for ns in $(kubectl get namespaces -o jsonpath='{.items[*].metadata.name}' 2>/dev/null); do
        pods=$(kubectl get pods -n "$ns" -o json 2>/dev/null | jq -r --argjson socks "$(printf '%s\n' "${runtime_socks[@]}" | jq -R . | jq -s .)" '
            .items[] | 
            select(.spec.volumes[]?.hostPath.path as $hp | $socks | map(select($hp != null and . == $hp)) | length > 0) |
            "\(.metadata.name)|\(.spec.volumes[] | select(.hostPath != null and (["/var/run/docker.sock", "/var/run/containerd/containerd.sock", "/var/run/crio/crio.sock"] | index(.hostPath.path) != null)) | .hostPath.path)"
        ' 2>/dev/null)
        
        if [ -n "$pods" ]; then
            while IFS='|' read -r pod sock; do
                log_vulnerable "Pod: $ns/$pod mounts container runtime socket: $sock"
                add_vulnerable_asset "EXPLOIT_CONTAINERD_SOCK: $ns/$pod -> $sock"
                found=1
            done <<< "$pods"
        fi
    done
    
    [ $found -eq 0 ] && log_secure "No pods with container runtime socket mounts found"
    echo ""
}

# Check 7: TOKEN_LIST - Service accounts with secrets list permission
check_token_list() {
    log_header "TOKEN_LIST: Service Account Token Access"
    log_check "Checking for service accounts that can list secrets..."
    
    if [ "$SKIP_SLOW_CHECKS" = "true" ]; then
        log_warning "Skipped (use SKIP_SLOW_CHECKS=false to enable)"
        echo ""
        return
    fi
    
    local found=0
    local checked=0
    local namespaces=$(kubectl get namespaces -o jsonpath='{.items[*].metadata.name}' 2>/dev/null)
    
    for ns in $namespaces; do
        sas=$(kubectl get serviceaccounts -n "$ns" -o jsonpath='{.items[*].metadata.name}' 2>/dev/null)
        
        for sa in $sas; do
            checked=$((checked + 1))
            echo -ne "\r${YELLOW}[CHECK]${NC} Checking SA $checked: $ns/$sa                    " >&2
            
            can_list=$(timeout $AUTH_TIMEOUT kubectl auth can-i list secrets -n "$ns" --as="system:serviceaccount:$ns:$sa" 2>/dev/null || echo "no")
            if [ "$can_list" = "yes" ]; then
                echo -ne "\r\033[K" >&2
                log_vulnerable "ServiceAccount: $ns/$sa can list secrets"
                add_vulnerable_asset "TOKEN_LIST: $ns/$sa"
                found=1
            fi
        done
    done
    
    echo -ne "\r\033[K" >&2
    [ $found -eq 0 ] && log_secure "No service accounts with secrets list permission found (checked $checked SAs)"
    echo ""
}

# Check 8: POD_EXEC - Service accounts that can exec into pods
check_pod_exec() {
    log_header "POD_EXEC: Execute Commands in Pods"
    log_check "Checking for service accounts with pod exec permissions..."
    
    if [ "$SKIP_SLOW_CHECKS" = "true" ]; then
        log_warning "Skipped (use SKIP_SLOW_CHECKS=false to enable)"
        echo ""
        return
    fi
    
    local found=0
    local checked=0
    local namespaces=$(kubectl get namespaces -o jsonpath='{.items[*].metadata.name}' 2>/dev/null)
    
    for ns in $namespaces; do
        sas=$(kubectl get serviceaccounts -n "$ns" -o jsonpath='{.items[*].metadata.name}' 2>/dev/null)
        
        for sa in $sas; do
            checked=$((checked + 1))
            echo -ne "\r${YELLOW}[CHECK]${NC} Checking SA $checked: $ns/$sa                    " >&2
            
            can_exec=$(timeout $AUTH_TIMEOUT kubectl auth can-i create pods/exec -n "$ns" --as="system:serviceaccount:$ns:$sa" 2>/dev/null || echo "no")
            if [ "$can_exec" = "yes" ]; then
                echo -ne "\r\033[K" >&2
                log_vulnerable "ServiceAccount: $ns/$sa can exec into pods"
                add_vulnerable_asset "POD_EXEC: $ns/$sa"
                found=1
            fi
        done
    done
    
    echo -ne "\r\033[K" >&2
    [ $found -eq 0 ] && log_secure "No service accounts with pod exec permission found (checked $checked SAs)"
    echo ""
}

# Check 9: POD_CREATE - Service accounts that can create pods
check_pod_create() {
    log_header "POD_CREATE: Create Privileged Pods"
    log_check "Checking for service accounts with pod creation permissions..."
    
    if [ "$SKIP_SLOW_CHECKS" = "true" ]; then
        log_warning "Skipped (use SKIP_SLOW_CHECKS=false to enable)"
        echo ""
        return
    fi
    
    local found=0
    local checked=0
    local namespaces=$(kubectl get namespaces -o jsonpath='{.items[*].metadata.name}' 2>/dev/null)
    
    for ns in $namespaces; do
        sas=$(kubectl get serviceaccounts -n "$ns" -o jsonpath='{.items[*].metadata.name}' 2>/dev/null)
        
        for sa in $sas; do
            checked=$((checked + 1))
            echo -ne "\r${YELLOW}[CHECK]${NC} Checking SA $checked: $ns/$sa                    " >&2
            
            can_create=$(timeout $AUTH_TIMEOUT kubectl auth can-i create pods -n "$ns" --as="system:serviceaccount:$ns:$sa" 2>/dev/null || echo "no")
            if [ "$can_create" = "yes" ]; then
                echo -ne "\r\033[K" >&2
                log_vulnerable "ServiceAccount: $ns/$sa can create pods"
                add_vulnerable_asset "POD_CREATE: $ns/$sa"
                found=1
            fi
        done
    done
    
    echo -ne "\r\033[K" >&2
    [ $found -eq 0 ] && log_secure "No service accounts with pod creation permission found (checked $checked SAs)"
    echo ""
}

# Check 10: IDENTITY_ASSUME - Check for automounted service account tokens
check_identity_assume() {
    log_header "IDENTITY_ASSUME: Service Account Token Access"
    log_check "Checking for pods with automounted service account tokens..."
    
    local found=0
    for ns in $(kubectl get namespaces -o jsonpath='{.items[*].metadata.name}' 2>/dev/null); do
        pods=$(kubectl get pods -n "$ns" -o json 2>/dev/null | jq -r '
            .items[] | 
            select(.spec.automountServiceAccountToken != false and 
                   .spec.serviceAccountName != "default") |
            "\(.metadata.name)|\(.spec.serviceAccountName)"
        ' 2>/dev/null)
        
        if [ -n "$pods" ]; then
            while IFS='|' read -r pod sa; do
                log_vulnerable "Pod: $ns/$pod has automounted token for SA: $sa"
                add_vulnerable_asset "IDENTITY_ASSUME: $ns/$pod -> $sa"
                found=1
            done <<< "$pods"
        fi
    done
    
    [ $found -eq 0 ] && log_secure "All pods have appropriate service account token settings"
    echo ""
}

# Check 11: IDENTITY_IMPERSONATE - Impersonation permissions
check_identity_impersonate() {
    log_header "IDENTITY_IMPERSONATE: User/Group Impersonation"
    log_check "Checking for service accounts with impersonation permissions..."
    
    if [ "$SKIP_SLOW_CHECKS" = "true" ]; then
        log_warning "Skipped (use SKIP_SLOW_CHECKS=false to enable)"
        echo ""
        return
    fi
    
    local found=0
    local checked=0
    local namespaces=$(kubectl get namespaces -o jsonpath='{.items[*].metadata.name}' 2>/dev/null)
    
    for ns in $namespaces; do
        sas=$(kubectl get serviceaccounts -n "$ns" -o jsonpath='{.items[*].metadata.name}' 2>/dev/null)
        
        for sa in $sas; do
            checked=$((checked + 1))
            echo -ne "\r${YELLOW}[CHECK]${NC} Checking SA $checked: $ns/$sa                    " >&2
            
            can_impersonate_users=$(timeout $AUTH_TIMEOUT kubectl auth can-i impersonate users --as="system:serviceaccount:$ns:$sa" 2>/dev/null || echo "no")
            can_impersonate_groups=$(timeout $AUTH_TIMEOUT kubectl auth can-i impersonate groups --as="system:serviceaccount:$ns:$sa" 2>/dev/null || echo "no")
            can_impersonate_sa=$(timeout $AUTH_TIMEOUT kubectl auth can-i impersonate serviceaccounts --as="system:serviceaccount:$ns:$sa" 2>/dev/null || echo "no")
            
            if [ "$can_impersonate_users" = "yes" ] || [ "$can_impersonate_groups" = "yes" ] || [ "$can_impersonate_sa" = "yes" ]; then
                echo -ne "\r\033[K" >&2
                log_vulnerable "ServiceAccount: $ns/$sa can impersonate identities"
                add_vulnerable_asset "IDENTITY_IMPERSONATE: $ns/$sa"
                found=1
            fi
        done
    done
    
    echo -ne "\r\033[K" >&2
    [ $found -eq 0 ] && log_secure "No service accounts with impersonation permissions found (checked $checked SAs)"
    echo ""
}

# Check 12: ROLE_BIND - Service accounts that can create role bindings
check_role_bind() {
    log_header "ROLE_BIND: Create Role Bindings"
    log_check "Checking for service accounts with role binding permissions..."
    
    if [ "$SKIP_SLOW_CHECKS" = "true" ]; then
        log_warning "Skipped (use SKIP_SLOW_CHECKS=false to enable)"
        echo ""
        return
    fi
    
    local found=0
    local checked=0
    local namespaces=$(kubectl get namespaces -o jsonpath='{.items[*].metadata.name}' 2>/dev/null)
    
    for ns in $namespaces; do
        sas=$(kubectl get serviceaccounts -n "$ns" -o jsonpath='{.items[*].metadata.name}' 2>/dev/null)
        
        for sa in $sas; do
            checked=$((checked + 1))
            echo -ne "\r${YELLOW}[CHECK]${NC} Checking SA $checked: $ns/$sa                    " >&2
            
            can_bind=$(timeout $AUTH_TIMEOUT kubectl auth can-i create rolebindings -n "$ns" --as="system:serviceaccount:$ns:$sa" 2>/dev/null || echo "no")
            can_cluster_bind=$(timeout $AUTH_TIMEOUT kubectl auth can-i create clusterrolebindings --as="system:serviceaccount:$ns:$sa" 2>/dev/null || echo "no")
            
            if [ "$can_bind" = "yes" ] || [ "$can_cluster_bind" = "yes" ]; then
                echo -ne "\r\033[K" >&2
                log_vulnerable "ServiceAccount: $ns/$sa can create role bindings"
                add_vulnerable_asset "ROLE_BIND: $ns/$sa"
                found=1
            fi
        done
    done
    
    echo -ne "\r\033[K" >&2
    [ $found -eq 0 ] && log_secure "No service accounts with role binding permissions found (checked $checked SAs)"
    echo ""
}

# Check 13: SHARE_PS_NAMESPACE - Pods sharing process namespaces
check_share_ps_namespace() {
    log_header "SHARE_PS_NAMESPACE: Shared Process Namespace"
    log_check "Checking for pods with shared process namespaces..."
    
    local found=0
    for ns in $(kubectl get namespaces -o jsonpath='{.items[*].metadata.name}' 2>/dev/null); do
        pods=$(kubectl get pods -n "$ns" -o json 2>/dev/null | jq -r '
            .items[] | 
            select(.spec.shareProcessNamespace == true) |
            .metadata.name
        ' 2>/dev/null)
        
        if [ -n "$pods" ]; then
            for pod in $pods; do
                log_vulnerable "Pod: $ns/$pod has shared process namespace"
                add_vulnerable_asset "SHARE_PS_NAMESPACE: $ns/$pod"
                found=1
            done
        fi
    done
    
    [ $found -eq 0 ] && log_secure "No pods with shared process namespaces found"
    echo ""
}

# Check 14: CONTAINER_ATTACH/POD_ATTACH - Attach permissions
check_attach_permissions() {
    log_header "POD_ATTACH/CONTAINER_ATTACH: Attach to Containers"
    log_check "Checking for service accounts with attach permissions..."
    
    if [ "$SKIP_SLOW_CHECKS" = "true" ]; then
        log_warning "Skipped (use SKIP_SLOW_CHECKS=false to enable)"
        echo ""
        return
    fi
    
    local found=0
    local checked=0
    local namespaces=$(kubectl get namespaces -o jsonpath='{.items[*].metadata.name}' 2>/dev/null)
    
    for ns in $namespaces; do
        sas=$(kubectl get serviceaccounts -n "$ns" -o jsonpath='{.items[*].metadata.name}' 2>/dev/null)
        
        for sa in $sas; do
            checked=$((checked + 1))
            echo -ne "\r${YELLOW}[CHECK]${NC} Checking SA $checked: $ns/$sa                    " >&2
            
            can_attach=$(timeout $AUTH_TIMEOUT kubectl auth can-i create pods/attach -n "$ns" --as="system:serviceaccount:$ns:$sa" 2>/dev/null || echo "no")
            if [ "$can_attach" = "yes" ]; then
                echo -ne "\r\033[K" >&2
                log_vulnerable "ServiceAccount: $ns/$sa can attach to pods"
                add_vulnerable_asset "POD_ATTACH: $ns/$sa"
                found=1
            fi
        done
    done
    
    echo -ne "\r\033[K" >&2
    [ $found -eq 0 ] && log_secure "No service accounts with attach permissions found (checked $checked SAs)"
    echo ""
}

# Check 15: POD_PATCH - Pod patch permissions
check_pod_patch() {
    log_header "POD_PATCH: Patch Running Pods"
    log_check "Checking for service accounts with pod patch permissions..."
    
    if [ "$SKIP_SLOW_CHECKS" = "true" ]; then
        log_warning "Skipped (use SKIP_SLOW_CHECKS=false to enable)"
        echo ""
        return
    fi
    
    local found=0
    local checked=0
    local namespaces=$(kubectl get namespaces -o jsonpath='{.items[*].metadata.name}' 2>/dev/null)
    
    for ns in $namespaces; do
        sas=$(kubectl get serviceaccounts -n "$ns" -o jsonpath='{.items[*].metadata.name}' 2>/dev/null)
        
        for sa in $sas; do
            checked=$((checked + 1))
            echo -ne "\r${YELLOW}[CHECK]${NC} Checking SA $checked: $ns/$sa                    " >&2
            
            can_patch=$(timeout $AUTH_TIMEOUT kubectl auth can-i patch pods -n "$ns" --as="system:serviceaccount:$ns:$sa" 2>/dev/null || echo "no")
            if [ "$can_patch" = "yes" ]; then
                echo -ne "\r\033[K" >&2
                log_vulnerable "ServiceAccount: $ns/$sa can patch pods"
                add_vulnerable_asset "POD_PATCH: $ns/$sa"
                found=1
            fi
        done
    done
    
    echo -ne "\r\033[K" >&2
    [ $found -eq 0 ] && log_secure "No service accounts with pod patch permissions found (checked $checked SAs)"
    echo ""
}

# Check 16: Exposed services (ENDPOINT_EXPLOIT)
check_exposed_endpoints() {
    log_header "ENDPOINT_EXPLOIT: Exposed Services"
    log_check "Checking for LoadBalancer and NodePort services..."
    
    local found=0
    for ns in $(kubectl get namespaces -o jsonpath='{.items[*].metadata.name}' 2>/dev/null); do
        services=$(kubectl get services -n "$ns" -o json 2>/dev/null | jq -r '
            .items[] | 
            select(.spec.type == "LoadBalancer" or .spec.type == "NodePort") |
            "\(.metadata.name)|\(.spec.type)"
        ' 2>/dev/null)
        
        if [ -n "$services" ]; then
            while IFS='|' read -r svc type; do
                log_vulnerable "Service: $ns/$svc is exposed as $type"
                add_vulnerable_asset "ENDPOINT_EXPLOIT: $ns/$svc ($type)"
                found=1
            done <<< "$services"
        fi
    done
    
    [ $found -eq 0 ] && log_secure "No externally exposed services found"
    echo ""
}

# Check 17: Host network access
check_host_network() {
    log_header "HOST_NETWORK: Host Network Access"
    log_check "Checking for pods with host network access..."
    
    local found=0
    for ns in $(kubectl get namespaces -o jsonpath='{.items[*].metadata.name}' 2>/dev/null); do
        pods=$(kubectl get pods -n "$ns" -o json 2>/dev/null | jq -r '
            .items[] | 
            select(.spec.hostNetwork == true) |
            .metadata.name
        ' 2>/dev/null)
        
        if [ -n "$pods" ]; then
            for pod in $pods; do
                log_vulnerable "Pod: $ns/$pod has host network access"
                add_vulnerable_asset "HOST_NETWORK: $ns/$pod"
                found=1
            done
        fi
    done
    
    [ $found -eq 0 ] && log_secure "No pods with host network access found"
    echo ""
}

# Main execution
main() {
    echo ""
    log_header "KubeHound Attack Surface Scanner"
    log_info "Scanning cluster for vulnerabilities based on KubeHound attack vectors"
    log_info "Reference: https://kubehound.io/reference/attacks/"
    echo ""
    
    # Check dependencies
    if ! command -v jq &> /dev/null; then
        log_error "jq is required but not installed. Install with: apt-get install jq (Debian/Ubuntu) or brew install jq (macOS)"
        exit 1
    fi
    
    # Check kubectl access
    if ! kubectl cluster-info &>/dev/null; then
        log_error "Unable to connect to Kubernetes cluster"
        exit 1
    fi
    
    log_info "Connected to cluster: $(kubectl config current-context)"
    
    if [ "$SKIP_SLOW_CHECKS" = "true" ]; then
        log_warning "SKIP_SLOW_CHECKS=true: Permission checks will be skipped"
        log_info "To run full scan: SKIP_SLOW_CHECKS=false $0"
    else
        log_info "Running full scan including permission checks (this may take a while)"
        log_info "To skip slow checks: SKIP_SLOW_CHECKS=true $0"
    fi
    
    echo ""
    
    # Run all checks
    check_module_load
    check_nsenter
    check_priv_mount
    check_sys_ptrace
    check_host_mounts
    check_container_runtime_sock
    check_host_network
    check_token_list
    check_pod_exec
    check_pod_create
    check_pod_patch
    check_attach_permissions
    check_identity_assume
    check_identity_impersonate
    check_role_bind
    check_share_ps_namespace
    check_exposed_endpoints
    
    # Summary
    log_header "SCAN SUMMARY"
    echo -e "${BLUE}Total Checks:${NC} $TOTAL_CHECKS"
    echo -e "${RED}Vulnerable Checks:${NC} $VULNERABLE_CHECKS"
    echo -e "${GREEN}Secure Checks:${NC} $((TOTAL_CHECKS - VULNERABLE_CHECKS))"
    echo ""
    
    if [ ${#VULNERABLE_ASSETS[@]} -gt 0 ]; then
        echo -e "${RED}VULNERABLE ASSETS FOUND:${NC}"
        printf '%s\n' "${VULNERABLE_ASSETS[@]}" | sort -u
        echo ""
        echo -e "${YELLOW}RECOMMENDATION:${NC} Review and remediate the above vulnerabilities"
        echo -e "${YELLOW}Refer to KubeHound documentation for remediation steps:${NC}"
        echo -e "${BLUE}https://kubehound.io/reference/attacks/${NC}"
    else
        echo -e "${GREEN}✓ No obvious vulnerabilities detected${NC}"
        echo -e "${YELLOW}Note: This is a basic scan. Consider running KubeHound for comprehensive analysis${NC}"
    fi
    
    echo ""
}

# Run the scanner
main
