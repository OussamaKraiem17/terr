# ============================================================
# wazuh-deploy.tf
# Déploiement Wazuh sur cluster EKS existant
# Lance : terraform init && terraform apply
# ============================================================

# ── Variables ────────────────────────────────────────────────
variable "cluster_name" {
  description = "Nom de ton cluster EKS"
  type        = string
  default     = "soc-eks-cluster"
}

variable "region" {
  description = "Région AWS"
  type        = string
  default     = "us-east-1"
}

# ── Récupérer les infos du cluster existant ──────────────────
data "aws_eks_cluster" "existing" {
  name = var.cluster_name
}

data "aws_eks_cluster_auth" "existing" {
  name = var.cluster_name
}

# ── Providers ────────────────────────────────────────────────
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    helm = {
      source  = "hashicorp/helm"
      version = "~> 2.12"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.25"
    }
    null = {
      source  = "hashicorp/null"
      version = "~> 3.0"
    }
  }
}

provider "aws" {
  region = var.region
}

provider "kubernetes" {
  host                   = data.aws_eks_cluster.existing.endpoint
  cluster_ca_certificate = base64decode(data.aws_eks_cluster.existing.certificate_authority[0].data)
  token                  = data.aws_eks_cluster_auth.existing.token
}

provider "helm" {
  kubernetes {
    host                   = data.aws_eks_cluster.existing.endpoint
    cluster_ca_certificate = base64decode(data.aws_eks_cluster.existing.certificate_authority[0].data)
    token                  = data.aws_eks_cluster_auth.existing.token
  }
}

# ============================================================
# ÉTAPE 1 — StorageClass EBS gp3
# (nécessaire pour stocker les logs Wazuh)
# ============================================================
resource "kubernetes_storage_class" "gp3" {
  metadata {
    name = "gp3"
    annotations = {
      "storageclass.kubernetes.io/is-default-class" = "true"
    }
  }

  storage_provisioner    = "ebs.csi.aws.com"
  volume_binding_mode    = "WaitForFirstConsumer"
  allow_volume_expansion = true

  parameters = {
    type       = "gp3"
    iops       = "3000"
    throughput = "125"
    encrypted  = "true"
  }
}

# ============================================================
# ÉTAPE 2 — Namespace wazuh
# ============================================================
resource "kubernetes_namespace" "wazuh" {
  metadata {
    name = "wazuh"
    labels = {
      app     = "wazuh"
      project = "soc-pfe"
    }
  }
}

# ============================================================
# ÉTAPE 3 — Certificats SSL (TLS) pour Wazuh
# ============================================================
resource "null_resource" "wazuh_certs" {
  depends_on = [kubernetes_namespace.wazuh]

  provisioner "local-exec" {
    command = <<-EOT
      echo "Génération des certificats SSL Wazuh..."

      # Créer le dossier certs
      mkdir -p /tmp/wazuh-certs

      # Certificat Root CA
      openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 -nodes \
        -keyout /tmp/wazuh-certs/root-ca-key.pem \
        -out    /tmp/wazuh-certs/root-ca.pem \
        -subj "/C=TN/ST=Tunis/L=Tunis/O=SOC-PFE/CN=wazuh-root-ca"

      # Certificat Wazuh Manager
      openssl req -newkey rsa:4096 -nodes \
        -keyout /tmp/wazuh-certs/wazuh-manager-key.pem \
        -out    /tmp/wazuh-certs/wazuh-manager.csr \
        -subj "/C=TN/O=SOC-PFE/CN=wazuh-manager"

      openssl x509 -req -days 3650 \
        -in   /tmp/wazuh-certs/wazuh-manager.csr \
        -CA   /tmp/wazuh-certs/root-ca.pem \
        -CAkey /tmp/wazuh-certs/root-ca-key.pem \
        -CAcreateserial \
        -out  /tmp/wazuh-certs/wazuh-manager.pem

      # Injecter les certs dans Kubernetes comme Secret
      kubectl create secret generic wazuh-ssl-certs \
        --namespace=wazuh \
        --from-file=root-ca.pem=/tmp/wazuh-certs/root-ca.pem \
        --from-file=wazuh-manager.pem=/tmp/wazuh-certs/wazuh-manager.pem \
        --from-file=wazuh-manager-key.pem=/tmp/wazuh-certs/wazuh-manager-key.pem \
        --dry-run=client -o yaml | kubectl apply -f -

      echo "✅ Certificats SSL créés et injectés"
    EOT
  }
}

# ============================================================
# ÉTAPE 4 — Wazuh Indexer (Elasticsearch)
# StatefulSet avec 3 replicas sur les 3 nodes
# ============================================================
resource "helm_release" "wazuh_indexer" {
  depends_on = [
    kubernetes_namespace.wazuh,
    kubernetes_storage_class.gp3,
    null_resource.wazuh_certs
  ]

  name             = "wazuh-indexer"
  repository       = "https://packages.wazuh.com/4.x/helm/"
  chart            = "wazuh-indexer"
  namespace        = "wazuh"
  version          = "4.7.0"
  wait             = true
  timeout          = 600
  cleanup_on_fail  = true

  # Nombre de replicas (1 par node)
  set {
    name  = "replicas"
    value = "3"
  }

  # Stockage persistant gp3
  set {
    name  = "storage.storageClassName"
    value = "gp3"
  }
  set {
    name  = "storage.size"
    value = "100Gi"
  }

  # Ressources CPU/RAM pour t3.medium
  set {
    name  = "resources.requests.memory"
    value = "2Gi"
  }
  set {
    name  = "resources.requests.cpu"
    value = "500m"
  }
  set {
    name  = "resources.limits.memory"
    value = "4Gi"
  }
  set {
    name  = "resources.limits.cpu"
    value = "1000m"
  }
}

# ============================================================
# ÉTAPE 5 — Wazuh Manager
# StatefulSet — reçoit les logs des agents (port 1514)
# ============================================================
resource "helm_release" "wazuh_manager" {
  depends_on = [
    helm_release.wazuh_indexer
  ]

  name             = "wazuh-manager"
  repository       = "https://packages.wazuh.com/4.x/helm/"
  chart            = "wazuh-manager"
  namespace        = "wazuh"
  version          = "4.7.0"
  wait             = true
  timeout          = 600
  cleanup_on_fail  = true

  # Port agents
  set {
    name  = "service.port"
    value = "1514"
  }
  set {
    name  = "service.type"
    value = "LoadBalancer"
  }

  # Connexion vers l'indexer
  set {
    name  = "indexer.host"
    value = "wazuh-indexer-0.wazuh-indexer.wazuh.svc.cluster.local"
  }

  # Stockage persistant
  set {
    name  = "storage.storageClassName"
    value = "gp3"
  }
  set {
    name  = "storage.size"
    value = "50Gi"
  }

  # Ressources
  set {
    name  = "resources.requests.memory"
    value = "1Gi"
  }
  set {
    name  = "resources.limits.memory"
    value = "2Gi"
  }
}

# ============================================================
# ÉTAPE 6 — Wazuh Dashboard (Kibana)
# Deployment — interface web accessible via HTTPS
# ============================================================
resource "helm_release" "wazuh_dashboard" {
  depends_on = [
    helm_release.wazuh_manager
  ]

  name             = "wazuh-dashboard"
  repository       = "https://packages.wazuh.com/4.x/helm/"
  chart            = "wazuh-dashboard"
  namespace        = "wazuh"
  version          = "4.7.0"
  wait             = true
  timeout          = 300
  cleanup_on_fail  = true

  # Exposer via LoadBalancer
  set {
    name  = "service.type"
    value = "LoadBalancer"
  }
  set {
    name  = "service.port"
    value = "443"
  }

  # Connexion vers l'indexer
  set {
    name  = "indexer.host"
    value = "wazuh-indexer-0.wazuh-indexer.wazuh.svc.cluster.local"
  }

  # Replicas (1 suffit pour le PFE)
  set {
    name  = "replicaCount"
    value = "1"
  }
}

# ============================================================
# ÉTAPE 7 — Récupérer l'URL du Dashboard automatiquement
# ============================================================
resource "null_resource" "get_dashboard_url" {
  depends_on = [helm_release.wazuh_dashboard]

  provisioner "local-exec" {
    command = <<-EOT
      echo "Attente du LoadBalancer..."
      sleep 60

      echo ""
      echo "======================================"
      echo "  URL Dashboard Wazuh :"
      kubectl get svc wazuh-dashboard -n wazuh \
        -o jsonpath='{.status.loadBalancer.ingress[0].hostname}'
      echo ""
      echo "  Login : admin"
      echo "  Password :"
      kubectl get secret wazuh-dashboard-cred -n wazuh \
        -o jsonpath='{.data.password}' | base64 -d
      echo ""
      echo "======================================"
    EOT
  }
}

# ============================================================
# OUTPUTS
# ============================================================
output "wazuh_namespace" {
  value = kubernetes_namespace.wazuh.metadata[0].name
}

output "commande_voir_pods" {
  value = "kubectl get pods -n wazuh"
}

output "commande_voir_services" {
  value = "kubectl get svc -n wazuh"
}

output "commande_logs_manager" {
  value = "kubectl logs -f wazuh-manager-0 -n wazuh"
}
