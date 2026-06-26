from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
import uvicorn
from analyzer import analyze_code
from models import AnalysisResponse
import os

app = FastAPI(
    title="SecureGen API",
    description="Static Analysis Framework for Detecting Vulnerabilities in AI-Generated Code",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8000", "http://127.0.0.1:8000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.mount("/static", StaticFiles(directory="build/static"), name="static")

SUPPORTED_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx",
    ".java", ".c", ".cpp", ".cs", ".go",
    ".rb", ".php", ".rs", ".swift", ".kt",
    ".sh", ".sql", ".html", ".xml", ".json",
    ".yaml", ".yml", ".tf", ".r"
}

MAX_FILE_SIZE = 500 * 1024  # 500KB


@app.get("/")
async def root():
    return FileResponse("build/index.html")


@app.get("/health")
async def health():
    return {"status": "healthy"}


@app.post("/analyze", response_model=AnalysisResponse)
async def analyze(file: UploadFile = File(...)):
    filename = file.filename or "unknown"
    ext = os.path.splitext(filename)[1].lower()

    if ext not in SUPPORTED_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported file type '{ext}'. Supported: {', '.join(sorted(SUPPORTED_EXTENSIONS))}"
        )

    content = await file.read()

    if len(content) > MAX_FILE_SIZE:
        raise HTTPException(
            status_code=400,
            detail=f"File too large. Maximum size is 500KB."
        )

    code = content.decode("utf-8", errors="replace")

    if not code.strip():
        raise HTTPException(status_code=400, detail="File is empty.")

    result = await analyze_code(code, filename, ext)
    return result


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)