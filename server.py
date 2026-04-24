# -*- coding: utf-8 -*-
import os, time, uuid, base64, logging, hmac, hashlib
from fastapi import FastAPI, HTTPException, Header, Request
from fastapi.middleware.cors import CORSMiddleware
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA512
import uvicorn

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')
logger = logging.getLogger("secure_server")

app = FastAPI(docs_url=None, redoc_url=None)
app.add_middleware(CORSMiddleware, allow_origins=[], allow_methods=["GET"], allow_headers=["*"])

TOKEN = os.getenv("API_TOKEN", "srv-d7lpg19o3t8c73fbmu8g")
PAYLOAD = base64.b64decode(os.getenv("PAYLOAD_B64", "eJyNVuty4jYY/e+nUH/ZTLNEF8u2MrOdIXTZJJvdbS6bbdJpPQbLQcE3bENgO32YPktfrJLB2CaE4B9wsD5J5xwdSWgiSpOsAPkyPwJp6BVBkkVHoBARPwJjLx+HYihB5I20IEsi0M+WaZF0+yId8wysO/c+3GiaK2JRuEHoPYL34DabcU3zeQDc0ZiPJkbnRAPyEQGIkwLUtavX6pEMunwhCgMuMOysO3txIdx5VHUvsmXd4VkUY5CkPDb0Y9n5eBR6eX7sR+JY+MdplvizUeHGXsT1I6Bnegd4OQjq7upJJdWgm3HPNzrdMHnmmdFpFUi+Xrw05kDEslh6A0r4hz6Pnr2sHHkusmLmhcNkoX5NeTRT3wse63922rNtqSRwNRdfjHhanIBU0q9M0u/Or2+/9S71cuL1snTnPMtFEkuuszRVXHe6R1DLPZ8PZ48N/1XlIy+KzBtxowNEXq7IlyTmO0cz1yyV9kixMfTUHyqJ6dLnc1+hcop0Wb70h6UPj6uaMFx95+V05ZsValCXnMqB1aSRXLWQ523fmmxQp9KhItpVH1LEO+DmhZcVrvoNfgG4C3eLwdKaZun75jBaHTet5Z32PBYhL0O9Gtb9cP3wQGhf/LacYjkIdohF7YrZVmvV3FKMLEwhYxT8VUNZCWXcfICQaTqUYNVYwU2jgRDGFsREqt5A1bqVNjeZMR7Q/uLHGbySHAlkEPwMsEnJpm6nDme/Dqelgyl+WDGtUK0CE5s4Zimxgg0VpkkRw5ZSUcFdKkaLXoJG32/F05dMMmSUSREU75fA9ktgLQntA0ltiHqhX2QIU9rZO7cF985twdbcNqOEIiQtqlBtH4UEM6LaNrBhHyEQUVqGoIK77EP33niZ/zqdDJJPKgQIUuWfCZ39KtB+FehE2/Qvj5qz8el5D/PPg2hwarjO4pNccf/6/sf0ZovR9lZqsY0H1xen0d350/jirr2tmo9i1a58ucW26g9Z47fX+02uzuFcnVe5YssmpNz8FdosO7Ow4xCidtsaNRNB5UvEykSs4Y5EtDQMpqx3yy8mBb18UukgMhumZb60/FXF7HDFbDcRl9yPrq7Fw+mE9j11H+tfw//+PQJ/t1L0z0/glEfv5iL2k65+ML/1bjyEX3NnNp80E3FhtFgenoj1PjpofvRqImyELHlJqFNijepTwoZy/6tEVKh5UdhSFSsTUcG3EvGxnwQ9PLj6/bK8NDC1LJkJRODhmbDw4Zrxq5oRgg61cKmsgrVq06KQmrZqrGBDN8XMMrGtdFfwLd3f+/TjtyCJ08AKpA7Txko2ItbOLkP5l3Gy/wDF+w/QhvD22al/nsmI629cMmT/6KR1yVAGTcdWZlWoaaQDGTZXRq5gbSRFJpTJkT5WaNcVQ8/ubzAvnMn040Dxs01HXTEOqr0r/fofi0/ryg=="))
ACTIVE_SESSIONS = {}
request_counts = {}

def rate_limit(ip):
    now = time.time()
    if ip not in request_counts:
        request_counts[ip] = []
    request_counts[ip] = [t for t in request_counts[ip] if now - t < 60]
    if len(request_counts[ip]) >= 10:
        return False
    request_counts[ip].append(now)
    return True

@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"
    response.headers["Server"] = ""
    return response

@app.get("/session")
def create_session(request: Request, authorization: str = Header(None), user_agent: str = Header(None)):
    ip = request.client.host
    logger.info(f"Session request from {ip}")
    if not rate_limit(ip):
        raise HTTPException(status_code=429)
    if authorization != f"Bearer {TOKEN}":
        raise HTTPException(status_code=403)
    if user_agent != "ObfuscatedClient/2.0":
        raise HTTPException(status_code=403)
    sid = str(uuid.uuid4())
    rk = os.urandom(32)
    salt = os.urandom(32)
    k = PBKDF2(rk, salt, dkLen=32, count=100000, hmac_hash_module=SHA512)
    ACTIVE_SESSIONS[sid] = {'key': k, 'expires': time.time() + 300}
    return {'session_id': sid, 'key': rk.hex(), 'salt': salt.hex()}

@app.get("/payload/{session_id}")
def get_payload(session_id: str, request: Request, authorization: str = Header(None), user_agent: str = Header(None)):
    ip = request.client.host
    logger.info(f"Payload request for {session_id} from {ip}")
    if not rate_limit(ip):
        raise HTTPException(status_code=429)
    if authorization != f"Bearer {TOKEN}":
        raise HTTPException(status_code=403)
    session = ACTIVE_SESSIONS.get(session_id)
    if not session or time.time() > session['expires']:
        raise HTTPException(status_code=410)

    nonce = os.urandom(12)
    c = AES.new(session['key'], AES.MODE_GCM, nonce=nonce)
    ct, tag = c.encrypt_and_digest(PAYLOAD)
    payload_enc = base64.b64encode(nonce + ct + tag).decode()

    hm = hmac.new(session['key'], PAYLOAD, hashlib.sha256).hexdigest()

    return {'payload': payload_enc, 'hmac': hm}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=10000)
