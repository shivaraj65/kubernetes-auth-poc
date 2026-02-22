# be2

A project created with FastAPI CLI.

## Quick Start

### Start the development server

```bash
uv run fastapi dev
```

Visit http://localhost:8000

### Deploy to FastAPI Cloud

> FastAPI Cloud is currently in private beta. Join the waitlist at https://fastapicloud.com

```bash
uv run fastapi login
uv run fastapi deploy
```

## Project Structure

- `main.py` - Your FastAPI application
- `pyproject.toml` - Project dependencies

## Learn More

- [FastAPI Documentation](https://fastapi.tiangolo.com)
- [FastAPI Cloud](https://fastapicloud.com)

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