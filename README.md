## NOTE: The following scripts were successfully tested on ARM-based systems.

The following scripts are labeled by their purpose.

The K8-Setup script will setup a vulnerable Kubernetes environment on your VM, it will also create an Attack Guide for some guidance in the same directory.

## K8 Setup

`chmod +x K8-Setup.sh`

`sudo ./K8-Setup.sh`

**RBAC Vulnerabilities:**

- Service account with cluster-admin privileges
- Default service accounts can read all secrets cluster-wide
- Unauthenticated users can exec into any pod
- Users can create privileged pods (container escape)
- Users can impersonate service accounts
- Everyone can read node information
- Users can create rolebindings (self-privilege escalation)
- Wildcard permissions on core resources

**Attack Scenarios:**

- Unauthenticated API access via port 8080
- Secret exfiltration (AWS creds, DB passwords, API keys)
- Service account token theft
- Privilege escalation via pod creation
- Container escape to host filesystem
- Lateral movement via impersonation
- Information disclosure (nodes, secrets, configmaps)

**Practice Targets:**

- AWS credentials extraction
- Database credential theft
- API key exfiltration
- Production secret access
- Kube-system compromise
- Cross-namespace attacks


========================================================================================


## K8-Privz

The K8-Privz script will show vulnerabilities and possible attacks that can be conducted against the environment. This script will highlight attacks from the KubeHound documentation.

`chmod +x K8-Privz.sh`

`sudo ./K8-Privz.sh`

**Container Escape Checks:**
- CE_MODULE_LOAD - Containers with CAP_SYS_MODULE (load kernel modules)
- CE_NSENTER - Privileged containers with host PID/IPC namespace access
- CE_PRIV_MOUNT - Privileged containers with CAP_SYS_ADMIN (mount host filesystem)
- CE_SYS_PTRACE - Containers with CAP_SYS_PTRACE (attach to host processes)

**Host Access Checks:**
- EXPLOIT_HOST_READ/WRITE - Sensitive host path mounts (/etc, /var/run, /proc, /sys, /root, /home, /var/log, /var/lib/kubelet)
- EXPLOIT_CONTAINERD_SOCK - Container runtime socket mounts (docker.sock, containerd.sock, crio.sock)
- HOST_NETWORK - Pods with host network access

**RBAC/Permission Checks:**
- TOKEN_LIST - Service accounts that can list secrets
- POD_EXEC - Service accounts with pod exec permissions
- POD_CREATE - Service accounts that can create pods
- POD_PATCH - Service accounts with pod patch permissions
- POD_ATTACH/CONTAINER_ATTACH - Service accounts with attach permissions
- ROLE_BIND - Service accounts that can create role/cluster role bindings
- IDENTITY_IMPERSONATE - Service accounts with user/group/serviceaccount impersonation permissions

**Token/Identity Checks:**
- IDENTITY_ASSUME - Pods with automounted service account tokens

**Pod Configuration Checks:**
- SHARE_PS_NAMESPACE - Pods sharing process namespaces

**Network Exposure Checks:**
- ENDPOINT_EXPLOIT - Exposed services (LoadBalancer and NodePort types)


========================================================================================


## K8 Webhook

This WebHook script sets up a **malicious Kubernetes admission webhook** that automatically injects token-stealing code into any new pods created in a targeted namespace.

### How It Works

### **Setup Phase**
- Creates two namespaces:
  - `webhook-attack` - hosts the malicious webhook server
  - `victim-namespace` - the target namespace where pods will be compromised

### **Webhook Server Deployment**
- Deploys a Python-based webhook server that:
  - Listens on port 8443 with TLS encryption
  - Intercepts pod creation requests via Kubernetes Admission Control
  - Automatically modifies pod specifications before they're created

### **Malicious Injection Mechanism**
When any pod is created in `victim-namespace`, the webhook:
- Intercepts the pod creation API call
- Injects a malicious `initContainer` into the pod spec
- The initContainer:
  - Runs before the main container starts
  - Installs `curl` 
  - Reads the pod's service account token from `/var/run/secrets/kubernetes.io/serviceaccount/token`
  - Exfiltrates the token to webhook.site (or your specified URL) via HTTP POST
  - Completes and allows the pod to start normally

### **Token Exfiltration**
The stolen token is sent to your webhook.site URL with:
- Pod name and namespace
- The actual JWT service account token
- This token can then be used to authenticate as that service account and potentially compromise the cluster

### **Registration**
- Creates a `MutatingWebhookConfiguration` that tells Kubernetes to send all pod creation requests in labeled namespaces to this webhook
- Labels `victim-namespace` with `exfil: enabled` to activate the webhook for that namespace


## Attack Flow
```
1. Add your webhook to the script
2. Attacker runs script → Deploys malicious webhook
3. User creates pod in victim-namespace
4. Kubernetes API sends pod spec to webhook for "validation"
5. Webhook injects token-stealing initContainer
6. Pod starts with malicious code
7. InitContainer steals token and sends to attacker's webhook.site
8. Main container starts normally (user doesn't notice)
9. Attacker receives token and can impersonate the service account
```


## Manual Exfiltration Option

The script also provides a manual pod creation option that directly creates a pod with the token-stealing initContainer, bypassing the webhook entirely - useful for testing or if webhook setup fails.
