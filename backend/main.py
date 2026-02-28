from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from auth.routes import router as auth_router
from auth.oauth import router as oauth_router
from auth.models import User, RefreshToken        # noqa: F401 — register with Base metadata
from auth.oauth import OAuthClient, AuthCode      # noqa: F401 — register with Base metadata
from db.database import Base, engine

# Create tables on startup — use Alembic migrations in production
Base.metadata.create_all(bind=engine)

app = FastAPI(title="Auth Server", docs_url="/docs")

# CORS: allow only the known frontend origin.
# Credentials=True required for cookies to be sent cross-origin.
# Never use allow_origins=["*"] with allow_credentials=True — browsers block it anyway,
# but it signals intent. Be explicit.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["Content-Type", "X-CSRF-Token"],
)

app.include_router(auth_router)
app.include_router(oauth_router)


@app.get("/health")
def health():
    return {"status": "ok"}
