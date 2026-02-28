# seed.py
from db.database import SessionLocal
from auth.oauth import OAuthClient
from auth.hashing import _hash_secret  # or use hashlib directly

db = SessionLocal()
client = OAuthClient(
    client_id="frontend",
    client_secret_hash=_hash_secret("demo-secret-change-in-prod"),
    redirect_uris="http://localhost:3000/oauth-callback",
    allowed_scopes="read:profile",
    is_active=True
)
db.add(client)
db.commit()
