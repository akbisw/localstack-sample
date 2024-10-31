import enum
from fastapi import FastAPI, APIRouter, Form, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware


class KybProofType(enum.Enum):
    accredited = "accredited"
    address = "address"


app = FastAPI(
    title="Meow Web API",
    root_path="",
    version="0.0.1",
    separate_input_output_schemas=False,
)


router = APIRouter()
@router.post(
    "", tags=["/onboarding"],
)
async def upload_kyb_proof_handler(
    proof_type: KybProofType = Form(...),
    files: list[UploadFile] = File(...),
) -> dict:
    import os
    import shutil
    from tempfile import TemporaryDirectory

    file_info = []

    with TemporaryDirectory() as temp_dir:
        for file in files:
            file_location = os.path.join(temp_dir, file.filename)
            with open(file_location, "wb") as buffer:
                shutil.copyfileobj(file.file, buffer)
            file_info.append({
                "file_name": file.filename,
                "file_size": os.path.getsize(file_location),
                "proof_type": proof_type.value,
            })

    return {"files": file_info}


@router.get("/health")
def health() -> dict:
    return {"ok": True, "version": app.version}


@router.get("/auth/health")
def auth_health() -> dict:
    return {"ok": True, "version": app.version}


app.include_router(
    router=router,
    prefix="/onboarding/business/proof",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://app.meow.com",
        "https://localhost:3000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
def health() -> dict:
    return {"ok": True, "version": app.version}
