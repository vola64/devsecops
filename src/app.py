"""
Application FastAPI sécurisée - Projet DevSecOps
"""
import logging
import time
from typing import List, Optional
from fastapi import FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, validator

from utils import sanitize_input, setup_logger, get_app_version

# ─── Configuration du logger structuré ───────────────────────────────────────
logger = setup_logger(__name__)

# ─── Initialisation FastAPI ──────────────────────────────────────────────────
app = FastAPI(
    title="DevSecOps API",
    description="API sécurisée dans le cadre du pipeline CI/CD DevSecOps",
    version=get_app_version(),
    docs_url="/docs",
    redoc_url="/redoc",
)

# ─── Middleware CORS sécurisé ─────────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],  # Restreindre en production
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

# ─── Middleware de logging des requêtes ──────────────────────────────────────
@app.middleware("http")
async def log_requests(request: Request, call_next):
    start_time = time.time()
    response = await call_next(request)
    duration = time.time() - start_time
    logger.info(
        "request",
        extra={
            "method": request.method,
            "path": request.url.path,
            "status": response.status_code,
            "duration_ms": round(duration * 1000, 2),
            "client_ip": request.client.host if request.client else "unknown",
        },
    )
    return response


# ─── Modèles Pydantic ─────────────────────────────────────────────────────────
class Item(BaseModel):
    id: int = Field(..., gt=0, description="Identifiant unique de l'item")
    name: str = Field(..., min_length=1, max_length=100, description="Nom de l'item")
    description: Optional[str] = Field(None, max_length=500)
    price: float = Field(..., gt=0, description="Prix de l'item")
    is_active: bool = True

    @validator("name")
    def name_must_be_safe(cls, v):
        return sanitize_input(v)

    @validator("description")
    def description_must_be_safe(cls, v):
        if v is not None:
            return sanitize_input(v)
        return v

    class Config:
        schema_extra = {
            "example": {
                "id": 1,
                "name": "Widget Sécurisé",
                "description": "Un exemple d'item",
                "price": 29.99,
                "is_active": True,
            }
        }


class ItemCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    description: Optional[str] = Field(None, max_length=500)
    price: float = Field(..., gt=0)

    @validator("name")
    def name_must_be_safe(cls, v):
        return sanitize_input(v)


class HealthResponse(BaseModel):
    status: str
    version: str
    uptime_seconds: float


# ─── Stockage en mémoire (demo) ───────────────────────────────────────────────
_items_db: List[Item] = [
    Item(id=1, name="Item Alpha", description="Premier item de démo", price=10.99),
    Item(id=2, name="Item Beta", description="Deuxième item de démo", price=24.50),
]
_start_time = time.time()


# ─── Endpoints ────────────────────────────────────────────────────────────────
@app.get("/", summary="Racine de l'API")
async def root():
    """Point d'entrée principal de l'API DevSecOps."""
    return {
        "message": "DevSecOps API — Pipeline CI/CD Sécurisé",
        "version": get_app_version(),
        "docs": "/docs",
    }


@app.get("/health", response_model=HealthResponse, summary="Health check")
async def health_check():
    """Vérification de l'état de l'application (utilisé par le pipeline CI/CD)."""
    return HealthResponse(
        status="healthy",
        version=get_app_version(),
        uptime_seconds=round(time.time() - _start_time, 2),
    )


@app.get("/items", response_model=List[Item], summary="Lister les items")
async def list_items(active_only: bool = False):
    """Retourne la liste de tous les items disponibles."""
    if active_only:
        return [item for item in _items_db if item.is_active]
    return _items_db


@app.get("/items/{item_id}", response_model=Item, summary="Récupérer un item")
async def get_item(item_id: int):
    """Récupère un item par son identifiant."""
    if item_id <= 0:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="L'identifiant doit être un entier positif",
        )
    item = next((i for i in _items_db if i.id == item_id), None)
    if not item:
        logger.warning(f"Item introuvable: id={item_id}")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Item avec l'id {item_id} introuvable",
        )
    return item


@app.post(
    "/items",
    response_model=Item,
    status_code=status.HTTP_201_CREATED,
    summary="Créer un item",
)
async def create_item(item_data: ItemCreate):
    """Crée un nouvel item après validation et sanitisation des données."""
    new_id = max((i.id for i in _items_db), default=0) + 1
    new_item = Item(id=new_id, **item_data.dict())
    _items_db.append(new_item)
    logger.info(f"Nouvel item créé: id={new_id}, name={new_item.name}")
    return new_item


# ─── Gestionnaire d'erreurs global ───────────────────────────────────────────
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Erreur inattendue: {exc}", exc_info=True)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "Une erreur interne est survenue"},
    )
