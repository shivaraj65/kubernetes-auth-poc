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

K8S_ISSUER = "https://kubernetes.default.svc"
JWKS_URL = f"{K8S_ISSUER}/openid/v1/jwks"
logger.info(f"Kubernetes issuer: {K8S_ISSUER}")
logger.info(f"JWKS URL: {JWKS_URL}")

# Fetch cluster signing keys
logger.info("Fetching cluster signing keys from JWKS endpoint")
try:
    jwks = requests.get(
        JWKS_URL,
        verify="/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
    ).json()
    logger.info(f"Successfully fetched JWKS with {len(jwks.get('keys', []))} keys")
except Exception as e:
    logger.error(f"Failed to fetch JWKS: {str(e)}")
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
        decoded = jwt.decode(
            token,
            public_key,
            algorithms=["RS256"],
            audience=None,
            issuer=K8S_ISSUER
        )
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
