import os
import logging
from fastapi import FastAPI, Request, status, Depends, HTTPException, Security
from fastapi.responses import JSONResponse
from fastapi.security import (
    OAuth2PasswordBearer,
    OAuth2PasswordRequestForm,
    SecurityScopes,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.utils import get_openapi
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from jose import JWTError, jwt
from pydantic import BaseModel, ValidationError, Field
import uvicorn
from typing import List, Optional

# ------------- Configuration using Environment Variables -------------
DATABASE_URL = os.environ.get("POSTGRES_URL") or os.environ.get("DATABASE_URL")
JWT_SECRET = os.environ.get("JWT_SECRET", "changemeplease")
JWT_ALGORITHM = os.environ.get("JWT_ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.environ.get("ACCESS_TOKEN_EXPIRE_MINUTES", 60))

# ------------- Logging Configuration -------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger("backend-monolith")

# ------------- Database Setup (SQLAlchemy, async) -------------
engine = create_async_engine(DATABASE_URL, echo=True, future=True)
AsyncSessionLocal = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

# Dependency to get DB session
async def get_db():
    async with AsyncSessionLocal() as session:
        yield session

# ------------- RBAC Models -------------
class Role(str):
    ADMIN = "admin"
    USER = "user"

# ------------- User Models (for Auth) -------------
class User(BaseModel):
    username: str
    roles: List[str]
    disabled: bool = False

class Token(BaseModel):
    access_token: str
    token_type: str

# Example: users table would be persisted; here for demo
FAKE_USERS_DB = {
    "alice": {"username": "alice", "hashed_password": "secretalice", "roles": [Role.ADMIN], "disabled": False},
    "bob": {"username": "bob", "hashed_password": "secretbob", "roles": [Role.USER], "disabled": False},
}

def fake_hash_password(password: str) -> str:
    # Substitute with a real hashing function (bcrypt/argon2) in production
    return password

# ------------- OAuth2 JWT Authentication Setup -------------
oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl="/v1/auth/token",
    scopes={
        "admin": "Administrator privileges",
        "user": "User privileges",
    }
)

# PUBLIC_INTERFACE
async def get_current_user(
    security_scopes: SecurityScopes,
    token: str = Depends(oauth2_scheme)
) -> User:
    """Get current user from JWT token and check security scopes."""
    authenticate_value = f'Bearer scope="{security_scopes.scope_str}"'
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials.",
        headers={"WWW-Authenticate": authenticate_value},
    )
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        username: str = payload.get("sub")
        token_scopes = payload.get("scopes", [])
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    user_dict = FAKE_USERS_DB.get(username)
    if user_dict is None:
        raise credentials_exception
    user = User(**user_dict)

    if user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    # RBAC: ensure user has necessary scope
    for scope in security_scopes.scopes:
        if scope not in token_scopes:
            raise HTTPException(
                status_code=403, detail="Not enough permissions"
            )
    return user

# PUBLIC_INTERFACE
async def get_current_active_user(
    current_user: User = Security(get_current_user, scopes=[])
) -> User:
    """Require an active user (not disabled)."""
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user

# ------------- Business Models and Routers -------------
class ItemIn(BaseModel):
    name: str = Field(..., description="Name of the item")
    description: Optional[str] = Field(None, description="Item description")

class ItemOut(ItemIn):
    id: int

# ---------- FastAPI App Initialization ----------
app = FastAPI(
    title="Backend API Monolithic Service",
    description="A monolithic FastAPI backend with CRUD, auth, RBAC, docs, monitoring, versioning.",
    version="1.0.0",
    openapi_tags=[
        {"name": "health", "description": "Health check and monitoring."},
        {"name": "auth", "description": "Authentication and user management."},
        {"name": "items", "description": "CRUD operations for items."},
    ],
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json"
)

# ---------- CORS Middleware ----------
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],    # In production, restrict this
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------- Swagger/OpenAPI Versioning ----------
def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    openapi_schema = get_openapi(
        title=app.title,
        version=app.version,
        description=app.description,
        routes=app.routes,
        tags=app.openapi_tags,
    )
    app.openapi_schema = openapi_schema
    return app.openapi_schema
app.openapi = custom_openapi

# ---------------- API ROUTES ----------------

# Health & Monitoring
@app.get("/", tags=["health"], summary="Health Check", description="Check API status", operation_id="health_check")
# PUBLIC_INTERFACE
async def health_check():
    """Health check endpoint."""
    return {"message": "Healthy", "version": app.version}

# Monitoring endpoint example (add Prometheus in production)
@app.get("/metrics", tags=["health"], summary="Metrics", description="Monitoring endpoint (stub)", operation_id="metrics_endpoint")
async def metrics():
    # Implement integration with metrics provider here if needed
    return {"metrics_stub": True}

# Authentication
@app.post("/v1/auth/token", response_model=Token, tags=["auth"], summary="Get access token", description="OAuth2 compatible token login")
# PUBLIC_INTERFACE
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    """Authenticate user and return JWT."""
    user_dict = FAKE_USERS_DB.get(form_data.username)
    if not user_dict:
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    hashed_password = fake_hash_password(form_data.password)
    if not hashed_password == user_dict["hashed_password"]:
        raise HTTPException(status_code=400, detail="Incorrect username or password")

    user = User(**user_dict)
    scopes = user.roles  # Map roles directly to scopes
    to_encode = {
        "sub": user.username,
        "scopes": scopes,
    }
    from datetime import datetime, timedelta
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALGORITHM)
    logger.info(f"User '{user.username}' logged in. Token issued.")
    return {"access_token": encoded_jwt, "token_type": "bearer"}

@app.get("/v1/auth/me", response_model=User, tags=["auth"], summary="Get current user", description="Get details for current authenticated user")
# PUBLIC_INTERFACE
async def read_users_me(current_user: User = Depends(get_current_active_user)):
    """Returns current logged-in user info."""
    return current_user

# Example: CRUD for Items (Business logic)
from typing import Dict
ITEMS_DB: Dict[int, dict] = {}
ITEM_SEQ = 1

@app.post("/v1/items/", response_model=ItemOut, tags=["items"], summary="Create Item", description="Create a new item (RBAC: user or admin)")
# PUBLIC_INTERFACE
async def create_item(
    item: ItemIn,
    current_user: User = Security(get_current_user, scopes=[Role.USER]),
):
    """Create an item. Any authenticated user can create."""
    global ITEM_SEQ
    item_obj = ItemOut(id=ITEM_SEQ, **item.dict())
    ITEMS_DB[ITEM_SEQ] = item_obj.dict()
    ITEM_SEQ += 1
    logger.info(f"Item created: {item_obj}")
    return item_obj

@app.get("/v1/items/", response_model=List[ItemOut], tags=["items"], summary="List Items", description="Get all items (RBAC: user or admin)")
# PUBLIC_INTERFACE
async def list_items(
    current_user: User = Security(get_current_user, scopes=[Role.USER]),
):
    """List all items."""
    return [ItemOut(**x) for x in ITEMS_DB.values()]

@app.get("/v1/items/{item_id}", response_model=ItemOut, tags=["items"], summary="Get Item by ID", description="Retrieve item by ID (RBAC: user or admin)")
# PUBLIC_INTERFACE
async def get_item(
    item_id: int,
    current_user: User = Security(get_current_user, scopes=[Role.USER]),
):
    """Retrieve a specific item."""
    item = ITEMS_DB.get(item_id)
    if not item:
        raise HTTPException(status_code=404, detail="Item not found")
    return ItemOut(**item)

@app.put("/v1/items/{item_id}", response_model=ItemOut, tags=["items"], summary="Update Item", description="Update an item (RBAC: user or admin)")
# PUBLIC_INTERFACE
async def update_item(
    item_id: int, 
    item: ItemIn,
    current_user: User = Security(get_current_user, scopes=[Role.USER]),
):
    """Update an item."""
    if item_id not in ITEMS_DB:
        raise HTTPException(status_code=404, detail="Item not found")
    item_obj = ItemOut(id=item_id, **item.dict())
    ITEMS_DB[item_id] = item_obj.dict()
    logger.info(f"Item updated: {item_obj}")
    return item_obj

@app.delete("/v1/items/{item_id}", response_model=dict, tags=["items"], summary="Delete Item", description="Delete an item (RBAC: admin only)")
# PUBLIC_INTERFACE
async def delete_item(
    item_id: int,
    current_user: User = Security(get_current_user, scopes=[Role.ADMIN]),
):
    """Delete an item. Only admins may delete."""
    if item_id not in ITEMS_DB:
        raise HTTPException(status_code=404, detail="Item not found")
    del ITEMS_DB[item_id]
    logger.info(f"Item deleted: {item_id}")
    return {"msg": "Item deleted"}

# ------------- Error Handling -------------
@app.exception_handler(ValidationError)
async def validation_exception_handler(request: Request, exc: ValidationError):
    logger.warning(f"Validation error: {exc}")
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={"detail": exc.errors()}
    )

@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unexpected error: {exc}")
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "Internal server error"}
    )


# ------------- Startup Event ----------
@app.on_event("startup")
async def startup_event():
    logger.info("Backend Monolithic API started up.")

@app.on_event("shutdown")
async def shutdown_event():
    logger.info("Backend Monolithic API shutting down.")

# ------------- Main Entrypoint -------------
if __name__ == "__main__":
    # DO NOT use in production; use gunicorn/uvicorn externally
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 3001)))
