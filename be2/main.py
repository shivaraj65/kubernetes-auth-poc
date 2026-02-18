from fastapi import FastAPI, Request, HTTPException
import logging
import jwt
import requests

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
logger.info(f"Kubernetes issuer: {K8S_ISSUER}")
logger.info(f"Kubernetes API server: {K8S_API_SERVER}")
logger.info(f"OpenID configuration URL: {JWKS_URL}")

# Fetch cluster signing keys
logger.info("Fetching cluster signing keys from Kubernetes JWKS endpoint")
CA_CERT_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
SA_TOKEN_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/token"

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
    """
    Create HTTP headers for Kubernetes API requests with Bearer token authentication.
    
    Returns:
        dict: Headers containing Authorization bearer token if available
    """
    headers = {}
    if SA_TOKEN:
        headers["Authorization"] = f"Bearer {SA_TOKEN}"
    return headers

try:
    logger.debug(f"Attempting to fetch JWKS from: {JWKS_URL}")
    # First, try to get the OpenID configuration with service account token
    config_response = requests.get(
        JWKS_URL,
        verify=CA_CERT_PATH,
        headers=get_k8s_headers(),
        timeout=5
    )
    logger.debug(f"OpenID config response status: {config_response.status_code}")
    
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
            logger.info(f"Successfully fetched JWKS with {len(jwks.get('keys', []))} keys")
        else:
            logger.warning("No jwks_uri in OpenID configuration, attempting direct fetch")
            jwks_response = requests.get(
                f"{K8S_API_SERVER}/openid/v1/jwks",
                verify=CA_CERT_PATH,
                headers=get_k8s_headers(),
                timeout=5
            )
            jwks = jwks_response.json()
            logger.info(f"Successfully fetched JWKS with {len(jwks.get('keys', []))} keys")
    else:
        logger.warning(f"OpenID config request failed with status {config_response.status_code}, attempting direct JWKS fetch")
        jwks_response = requests.get(
            f"{K8S_API_SERVER}/openid/v1/jwks",
            verify=CA_CERT_PATH,
            headers=get_k8s_headers(),
            timeout=5
        )
        jwks = jwks_response.json()
        logger.info(f"Successfully fetched JWKS with {len(jwks.get('keys', []))} keys")
        
except requests.exceptions.RequestException as e:
    logger.error(f"Failed to fetch JWKS: Network error - {str(e)}")
    logger.warning("Continuing without JWKS - JWT verification will fail until keys are available")
    jwks = {"keys": []}
except Exception as e:
    logger.error(f"Failed to fetch JWKS: {type(e).__name__} - {str(e)}")
    logger.warning("Continuing without JWKS - JWT verification will fail until keys are available")
    jwks = {"keys": []}


def get_public_key(token):
    """
    Extract the public key from the JWKS (JSON Web Key Set) based on the token's key ID (kid).
    
    This function:
    - Reads the unverified JWT header to get the key ID (kid)
    - Searches through the JWKS for a key matching that kid
    - Returns the RSA public key for verification
    - Raises an exception if no matching key is found
    
    Args:
        token (str): The JWT token string to extract the kid from
        
    Returns:
        RSAAlgorithm: The RSA public key object used for token verification
        
    Raises:
        Exception: If the public key corresponding to the token's kid is not found in JWKS
    """
    logger.debug("Extracting and verifying public key from token")
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
    """
    Verify a Kubernetes Service Account (KSA) JWT token from the Authorization header.
    
    This function performs the following steps:
    1. Validates the Authorization header has the correct "Bearer" format
    2. Extracts the JWT token from the header
    3. Retrieves the corresponding public key from JWKS
    4. Decodes and verifies the JWT signature using RS256 algorithm
    5. Validates the token issuer matches the Kubernetes issuer
    6. Extracts the KSA name and namespace from the token claims
    7. Verifies the KSA name is exactly "be1-ksa" (authorized KSA)
    8. Returns verification status and KSA/namespace details
    
    Args:
        auth (str): The full Authorization header value (e.g., "Bearer <token>")
        
    Returns:
        dict: A dictionary containing:
            - status: "verified" if all checks pass
            - ksa: The Kubernetes Service Account name
            - namespace: The namespace where the KSA is located
            
    Raises:
        HTTPException(401): If Bearer token is missing or malformed
        HTTPException(401): If JWT signature verification fails
        HTTPException(403): If the KSA is not authorized (not "be1-ksa")
    """
    logger.info("Starting token verification process")
    
    if not auth or not auth.startswith("Bearer "):
        logger.warning("Missing or invalid Bearer token format")
        raise HTTPException(401, "Missing token")

    logger.debug("Extracting token from Bearer header")
    token = auth.split()[1]
    logger.debug(f"Token length: {len(token)} characters")

    logger.debug("Getting public key for token")
    public_key = get_public_key(token)
    logger.debug("Successfully obtained public key")

    try:
        logger.debug("Attempting JWT decode with RS256 algorithm")
      
        logger.info("Token successfully decoded and verified")
        logger.debug(f"Decoded token claims: {decoded}")
    except jwt.PyJWTError as e:
        logger.error(f"JWT verification failed: {str(e)}")
        raise HTTPException(401, f"Invalid token: {str(e)}")

    logger.debug("Extracting KSA and namespace from decoded token")
    ksa_name = decoded.get(
        "kubernetes.io/serviceaccount/name"
    )
    logger.info(f"Service account name: {ksa_name}")

    namespace = decoded.get(
        "kubernetes.io/serviceaccount/namespace"
    )
    logger.info(f"Namespace: {namespace}")

    if ksa_name != "be1-ksa":
        logger.warning(f"Unauthorized KSA: {ksa_name} (expected: be1-ksa)")
        raise HTTPException(403, "Unauthorized KSA")

    logger.info(f"Authorization successful for KSA: {ksa_name} in namespace: {namespace}")
    return {
        "status": "verified",
        "ksa": ksa_name,
        "namespace": namespace
    }

@app.get("/validate-auth")
async def validate_auth(request: Request):
    """
    FastAPI endpoint to validate incoming Authorization headers with Kubernetes Service Account tokens.
    
    This endpoint:
    - Receives HTTP requests and extracts the Authorization header
    - Calls the verify() function to validate the token
    - Returns detailed verification results or error messages
    - Handles various error scenarios gracefully
    
    Args:
        request (Request): The incoming HTTP request object containing headers
        
    Returns:
        dict: A JSON response containing:
            - On success: {"message": "Auth header received and verified", "result": verification_details}
            - If no header: {"message": "No auth header provided"}
            - On error: {"message": "Auth validation failed", "error": error_details}
            
    Raises:
        HTTPException: Propagated from verify() function if validation fails (401 or 403)
    """
    logger.info("Received request to /validate-auth endpoint")
    logger.debug(f"Request URL: {request.url}")
    logger.debug(f"Request method: {request.method}")
    
    auth_header = request.headers.get("Authorization")
    logger.info(f"Authorization header present: {bool(auth_header)}")
    
    if auth_header:
        logger.debug(f"Authorization header value: {auth_header[:20]}..." if len(auth_header) > 20 else f"Authorization header value: {auth_header}")
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
    """
    Health check endpoint - simple root path that confirms the FastAPI server is running.
    
    This endpoint:
    - Serves as a basic health check
    - Returns a simple message confirming the server is operational
    - Requires no authentication
    
    Returns:
        dict: A simple JSON response {"message": "Hello World"}
    """
    logger.info("Received request to / endpoint")
    return {"message": "Hello World"}
