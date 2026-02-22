from fastapi import FastAPI, Request, HTTPException
import logging
import jwt
import requests
import os
from dotenv import load_dotenv

app = FastAPI()

# Configure logging with more detailed format
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

logger.info("Starting FastAPI application initialization")

# Kubernetes API server endpoint and JWKS configuration
K8S_ISSUER = "https://kubernetes.default.svc.cluster.local"
K8S_API_SERVER = "https://kubernetes.default.svc"
JWKS_URL = f"{K8S_API_SERVER}/.well-known/openid-configuration"

# Fetch cluster signing keys
CA_CERT_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
SA_TOKEN_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/token"

KSA_TOKEN_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/token"

logger.info("Fetching cluster signing keys from Kubernetes JWKS endpoint (using env config)")

# Read the service account token for authentication
SA_TOKEN = None
try:
    with open(SA_TOKEN_PATH, "r") as f:
        SA_TOKEN = f.read().strip()
    logger.info("Successfully read service account token")
except FileNotFoundError:
    logger.warning(f"Service account token not found at {SA_TOKEN_PATH} - running outside Kubernetes cluster")
except Exception as e:
    logger.error(f"Failed to read service account token: {str(e)}")

# Prepare headers with authentication token
def get_k8s_headers():  
    headers = {}
    if SA_TOKEN:
        headers["Authorization"] = f"Bearer {SA_TOKEN}"
    return headers

try:
    # First, try to get the OpenID configuration with service account token
    config_response = requests.get(
        JWKS_URL,
        verify=CA_CERT_PATH,
        headers=get_k8s_headers(),
        timeout=5
    )
    logger.info(f"JWKS URI from config response status: {config_response.status_code}")
    if config_response.status_code == 200:
        config = config_response.json()
        jwks_uri = config.get("jwks_uri")
        logger.info(f"JWKS URI from config: {jwks_uri}")
        
        if jwks_uri:
            jwks_response = requests.get(
                jwks_uri,
                verify=CA_CERT_PATH,
                headers=get_k8s_headers(),
                timeout=5
            )
            jwks = jwks_response.json()
            logger.info(f"Successfully1 fetched JWKS with {len(jwks.get('keys', []))} keys")
        
except requests.exceptions.RequestException as e:
    logger.error(f"Failed to fetch JWKS: Network error - {str(e)}")
    logger.warning("Continuing without JWKS - JWT verification will fail until keys are available")
    jwks = {"keys": []}
except Exception as e:
    logger.error(f"Failed to fetch JWKS: {type(e).__name__} - {str(e)}")
    logger.warning("Continuing without JWKS - JWT verification will fail until keys are available")
    jwks = {"keys": []}



def get_public_key(token):
    try:
        unverified = jwt.get_unverified_header(token)
        kid = unverified.get("kid")
        logger.debug(f"Token kid: {kid}")

        for key in jwks.get("keys", []):
            if key.get("kid") == kid:
                logger.debug(f"Found matching key for kid: {kid}")
                return jwt.algorithms.RSAAlgorithm.from_jwk(key)

        logger.error(f"Public key not found for kid: {kid}")
        raise Exception("Public key not found")
    except Exception as e:
        logger.error(f"Error in get_public_key: {str(e)}")
        raise

async def verify(auth):
    if not auth or not auth.startswith("Bearer "):
        raise HTTPException(401, "Missing token")

    token = auth.split()[1]
    public_key = get_public_key(token)

    try:
        decoded = jwt.decode(
            token,
            public_key,
            algorithms=["RS256"],
            audience="https://kubernetes.default.svc.cluster.local",
            issuer=K8S_ISSUER
        )
        logger.info("Token successfully decoded and verified")
        return {
            "status": "verified",
            "data":decoded
            }

    except jwt.PyJWTError as e:
        logger.error(f"JWT verification failed: {str(e)}")
        raise HTTPException(401, f"Invalid token: {str(e)}")
        return {
            "status": "not-verified",
            "data":{}
        }

    # ---- below parameters can verified if required
    # ksa_name = decoded.get(
    #     "kubernetes.io/serviceaccount/name"
    # )
    # logger.info(f"Service account name: {ksa_name}")

    # namespace = decoded.get(
    #     "kubernetes.io/serviceaccount/namespace"
    # )
    # logger.info(f"Namespace: {namespace}")

    # if ksa_name != "be1-ksa":
    #     logger.warning(f"Unauthorized KSA: {ksa_name} (expected: be1-ksa)")
    #     raise HTTPException(403, "Unauthorized KSA")

    # logger.info(f"Authorization successful for KSA: {ksa_name} in namespace: {namespace}")

# Get the KSA JWT token for this service
@app.get("/get-jwt")
def get_ksa_token():
     with open(KSA_TOKEN_PATH, "r") as f:
        return f.read().strip()

@app.get("/validate-auth")
async def validate_auth(request: Request):
    logger.info("Received request to /validate-auth endpoint")
    auth_header = request.headers.get("Authorization")
    
    if auth_header:
        try:
            result = await verify(auth_header)
            logger.info(f"Validation result: {result}")
            return {"message": "Auth header received and verified", "result": result}
        except HTTPException as e:
            logger.error(f"HTTP exception during validation: {e.detail}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error during validation: {str(e)}", exc_info=True)
            return {"message": "Auth validation failed", "error": str(e)}
    
    logger.warning("No authorization header provided in request")
    return {"message": "No auth header provided"}

@app.get("/")
def main():
    return {"message": "Hello World"}
