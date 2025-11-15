# 🚀 Proxmox + pfSense + Terraform Deployment Guide

This guide walks you through deploying a pfSense virtual router using Terraform on a Proxmox environment.

---

## 🔧 Step 1: Prepare Proxmox for Terraform

### ✅ 1.1 Create API Token

1. Go to **Datacenter > Permissions > API Tokens** in Proxmox UI.
2. Click **Add > API Token**
3. Choose:
   - **User**: (e.g., `terraform@pve`)
   - **Token ID**: `terraform`
   - **Privileges**: Add `VM.Allocate`, `VM.Config.Disk`, `VM.Console`, `Datastore.AllocateSpace`, etc.
4. Save token. Copy the:
   - **Token ID**: `terraform@pve!terraform`
   - **Secret**: **store securely**

---

## 🧱 Step 2: Create pfSense Template on Proxmox

1. **Download pfSense ISO** from https://www.pfsense.org/download/
2. **Upload ISO** to Proxmox under `local > ISO Images`
3. **Create VM**:
   - UEFI + VirtIO
   - 1–2 vCPUs, 2GB RAM, 8GB Disk
   - NIC 1: `vmbr0` (WAN, VirtIO)
   - NIC 2: `vmbr1` (LAN, VirtIO)
4. **Install pfSense** using the ISO
5. Set interface mappings (e.g., WAN = em0, LAN = em1)
6. Power off VM and convert to template:
   ```bash
   qm template <VMID>
```

---

## 🧪 Step 3: Terraform Configuration

### 📄 `main.tf`

```hcl
terraform {
  required_providers {
    proxmox = {
      source  = "telmate/proxmox"
      version = "~> 2.9.11"
    }
  }
  backend "remote" {
    # Replace with your actual backend config (e.g., S3, Terraform Cloud)
  }
}

provider "proxmox" {
  pm_api_url           = "https://<proxmox-host>:8006/api2/json"
  pm_api_token_id      = "terraform@pve!terraform"
  pm_api_token_secret  = var.proxmox_api_token_secret
  pm_tls_insecure      = true
}

resource "proxmox_vm_qemu" "pfsense" {
  name        = "pfsense-router"
  target_node = "pve"
  clone       = "<template-name>"

  cores       = 2
  memory      = 2048
  scsihw      = "virtio-scsi-pci"
  boot        = "order=scsi0;net0"
  onboot      = true

  network {
    model    = "virtio"
    bridge   = "vmbr0" # WAN
  }

  network {
    model    = "virtio"
    bridge   = "vmbr1" # LAN
  }

  disk {
    type    = "scsi"
    storage = "local-lvm"
    size    = "8G"
  }

  ipconfig0 = "ip=dhcp"
  ipconfig1 = "ip=10.0.1.1/24"
}
```

---

### 📄 `variables.tf`

```hcl
variable "proxmox_api_token_secret" {
  type      = string
  sensitive = true
}
```

---

### 📄 `terraform.tfvars`

```hcl
proxmox_api_token_secret = "your-secret-token-here"
```

---

## ▶️ Step 4: Execute Deployment

```bash
# Install Terraform
brew install terraform   # Or use your OS's installer

# Initialize Terraform
terraform init

# Preview the plan
terraform plan

# Apply the plan
terraform apply
```

---

## 📝 Post-Deployment Notes

- Access the pfSense GUI at `https://192.168.1.1` from a system on `vmbr1`
    
- WAN will use DHCP; LAN uses static `192.168.1.1`
    
- pfSense has no Cloud-Init, so further automation (rules, routes, etc.) should use Ansible or manual config
    

---

## 🛠️ Optional Enhancements

- Add provisioning logic with `expect`, Ansible, or remote-exec via `terraform null_resource`
    
- Use `remote-exec` with `qm terminal` or serial console to automate initial config (advanced)
    

---

```

Would you like this saved as a downloadable `.md` file or pushed to a GitHub repo structure with `.tf` files pre-populated?
```