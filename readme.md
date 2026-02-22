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


## References used:
- [Kubernetes Service Account JWT Authentication](https://psaggu.com/2025/12/19/k8s-serviceaccount-jwt.html)
## Sample JWT Token

### Encoded JWT
```
eyJhbGciOiJSUzI1NiIsImtpZCI6InRfM2lXUmxFMS01STFhYXhNbjlLbkQ5dEJFcDI5OXFRRG83aldpeTRzT0EifQ.eyJhdWQiOlsiaHR0cHM6Ly9rdWJlcm5ldGVzLmRlZmF1bHQuc3ZjLmNsdXN0ZXIubG9jYWwiXSwiZXhwIjoxODAzMDE2NDU1LCJpYXQiOjE3NzE0ODA0NTUsImlzcyI6Imh0dHBzOi8va3ViZXJuZXRlcy5kZWZhdWx0LnN2Yy5jbHVzdGVyLmxvY2FsIiwianRpIjoiZGQ1ZjFkNTEtNjUyNi00ODE4LWEwOWYtOGRhYWYwYWEwYzczIiwia3ViZXJuZXRlcy5pbyI6eyJuYW1lc3BhY2UiOiJkZWZhdWx0Iiwibm9kZSI6eyJuYW1lIjoiZGVza3RvcC13b3JrZXIiLCJ1aWQiOiIwZWY1YzZmZS0xODE5LTQ2YjMtOGY4Yy04YTU3ZjkyZTE5ZjkifSwicG9kIjp7Im5hbWUiOiJiZS02YzdiNjZmN2Q4LWc5dmw0IiwidWlkIjoiYzM5OWJiMDktODA3NC00NDgyLTljYTEtMDk2M2EzZmQyM2FkIn0sInNlcnZpY2VhY2NvdW50Ijp7Im5hbWUiOiJkZWZhdWx0IiwidWlkIjoiNThiMjJlZmEtODc0Yy00OGIxLTkzN2YtMGY3MGY4ZTRlM2M5In0sIndhcm5hZnRlciI6MTc3MTQ4NDA2Mn0sIm5iZiI6MTc3MTQ4MDQ1NSwic3ViIjoic3lzdGVtOnNlcnZpY2VhY2NvdW50OmRlZmF1bHQ6ZGVmYXVsdCJ9.oQidELueCwm3sfjAWVrI92dO8sRy8noVIzbMJeTMGH7MLLVAV9HL3WGSHJlwhoiKUgPvLqbEGVzspVtOoQZjGwNIKbCCesXkev0DuIH7y5nQ7XPVOeUwLyIUr_ptMVqw_JZ1tcI-BPJGjb_Y8onf9q6_AVNRPOYOPFEYiXd1Z2pbaoZYQg21O7ezdvePWcvpifYOGFWsSVuCHd8wrGeiEgN3jWOwgfk4Hae6Bq084ttZgZ1E7nLTcOqN6w5sA1Nj031tt8-hmr1V_JkLTRul4cDjkmk9TjohBY45rxl9kpBE9tdJhLzhTxX3thw9r-mRxpTWtQTfFeTzgvz0qJTD0w
```

### Decoded Payload
```json
{
    "aud": ["https://kubernetes.default.svc.cluster.local"],
    "exp": 1803016455,
    "iat": 1771480455,
    "iss": "https://kubernetes.default.svc.cluster.local",
    "jti": "dd5f1d51-6526-4818-a09f-8daaf0aa0c73",
    "kubernetes.io": {
        "namespace": "default",
        "node": {
            "name": "desktop-worker",
            "uid": "0ef5c6fe-1819-46b3-8f8c-8a57f92e19f9"
        },
        "pod": {
            "name": "be-6c7b66f7d8-g9vl4",
            "uid": "c399bb09-8074-4482-9ca1-0963a3fd23ad"
        },
        "serviceaccount": {
            "name": "default",
            "uid": "58b22efa-874c-48b1-937f-0f70f8e4e3c9"
        },
        "warnafter": 1771484062
    },
    "nbf": 1771480455,
    "sub": "system:serviceaccount:default:default"
}
```


## Service Authorization with Kubernetes Service Accounts

Each service is assigned a unique Kubernetes Service Account (KSA) for identity and authorization purposes.

### Creating Service Accounts

Create a service account for each service:

```bash
kubectl create serviceaccount <service-name>-sa
```

### Assigning Service Accounts to Deployments

Update the deployment configuration to use the service account:

```bash
kubectl edit deployment <service-name>
```

Add the following to the deployment spec:

```yaml
spec:
    template:
        spec:
            serviceAccountName: <service-name>-sa
```

### JWT Token Validation

Each service account generates a JWT token with a unique subject claim:

```json
{
    "sub": "system:serviceaccount:<namespace>:<service-name>-sa"
}
```

Validate the token in your middleware to enforce authorization policies based on the service identity.
