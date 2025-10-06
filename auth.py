from fastapi import HTTPException, Security
from fastapi.security import APIKeyHeader, HTTPBearer, HTTPAuthorizationCredentials
from security import verify_api_key, verify_token

API_KEY_NAME = "X-API-Key"
api_key_scheme = APIKeyHeader(name=API_KEY_NAME, auto_error=False)
bearer_scheme = HTTPBearer(auto_error=False)

async def authorize(
    api_key: str = Security(api_key_scheme),
    credentials: HTTPAuthorizationCredentials = Security(bearer_scheme)
):
    if not api_key or not verify_api_key(api_key):
        raise HTTPException(status_code=403, detail="Invalid or missing API key")
    if not credentials or credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=401, detail="Missing or invalid bearer token")
    payload = verify_token(credentials.credentials)
    return payload

