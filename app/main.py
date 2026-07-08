from fastapi import FastAPI
from fastapi.responses import JSONResponse

app = FastAPI()

@app.get("/")
async def home_dir():
    return JSONResponse(content={"message":"In root directory"}, status_code=200)