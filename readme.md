# Kubernetes Service Account JWT Authentication POC

## Overview
This project demonstrates JWT token-based authentication between microservices running in Kubernetes using Service Account (KSA) tokens.

### Services
- **be**: FastAPI service that generates and returns JWT tokens from its Kubernetes Service Account
- **be2**: FastAPI service that validates JWT tokens from other services

## How It Works

### 1. Token Generation (BE Service)
- The `be` service exposes a `/get-jwt` endpoint
- This endpoint returns the JWT token associated with the service's Kubernetes Service Account
- The token is sourced from `/var/run/secrets/kubernetes.io/serviceaccount/token`

### 2. Token Validation (BE2 Service)
- The `be2` service validates incoming JWT tokens via the `/validate-auth` endpoint
- Validation uses the Kubernetes cluster's JWKS (JSON Web Key Set)
- Configuration endpoints:
    ```
    K8S_ISSUER = "https://kubernetes.default.svc.cluster.local"
    K8S_API_SERVER = "https://kubernetes.default.svc"
    JWKS_URL = "https://kubernetes.default.svc/.well-known/openid-configuration"
    ```
- Uses CA certificate from `/var/run/secrets/kubernetes.io/serviceaccount/ca.crt`

## Testing Steps

1. **Start both services** in Docker Desktop Kubernetes
2. **Get JWT token**: Call `be` service's `/get-jwt` endpoint
3. **Copy token** to Postman
4. **Add to headers**: Set `Authorization: Bearer <token>`
5. **Validate**: Call `be2` service's `/validate-auth` endpoint
6. **Verify**: Confirm successful authentication

## Environment
- **Platform**: Docker Desktop Kubernetes
- **Note**: Full Kubernetes setup optimization is not in scope; focus is on authentication flow
