from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes.scan import router as scan_router

from app.core.database import engine
from app.models.scan_model import Base

Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="isMalicious API",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(scan_router)

@app.get("/")
async def root():
    return {"message": "isMalicious API Running"}