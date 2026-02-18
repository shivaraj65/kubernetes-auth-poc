from fastapi import FastAPI
import urllib.request
from dotenv import load_dotenv
import os

# Load environment variables from .env file
load_dotenv()

app = FastAPI()

# Dev mode flag - set to True for local development
DEV_MODE = True

BE2_ENDPOINT = os.getenv("http://localhost:8001/")

KSA_TOKEN_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/token"

# Get the KSA JWT token for this service
@app.get("/get-jwt")
def get_ksa_token():
     with open(KSA_TOKEN_PATH, "r") as f:
        return f.read().strip()

@app.get("/hello-without-auth-test")
def hello_without_auth():
    req = urllib.request.Request(BE2_ENDPOINT)
    try:
        response = urllib.request.urlopen(req)
        service_response = {"status": "success", "data": response.read().decode()}
    except Exception as e:
        service_response = {"status": "error", "message": str(e)}
    
    return {
        "service_call": service_response
    }


@app.get("/hello-with-KSA-auth-test")
def hello_with_auth():    
    # Get the ID token
    id_token = get_ksa_token()
    
    # Create request with authorization header
    req = urllib.request.Request(BE2_ENDPOINT)
    req.add_header("Authorization", f"Bearer {id_token}")
    
    try:
        response = urllib.request.urlopen(req)
        service_response = {"status": "success", "data": response.read().decode()}
    except Exception as e:
        service_response = {"status": "error", "message": str(e)}
    
    return {
        "service_call": service_response
    }


@app.get("/")
def main():
    return {"message": "Hello World"}
