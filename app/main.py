import sys  
from pathlib import Path  
file = Path(__file__). resolve()  
package_root_directory = file.parents[1]
sys.path.append(str(package_root_directory))  


from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.config import settings
from app.routers import user, auth

app  = FastAPI(docs_url='/api/docs')

origins = [
    settings.CLIENT_ORIGIN,
]


app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router, tags=['Auth'],  prefix='/api/auth')
app.include_router(user.router, tags=['Users'],  prefix='/api/users')


@app.get('/api/healthchecker')
def root():
    return {'message': 'Hello World'}