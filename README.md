# FastAPI 的 RESTFUL API  访问和刷新令牌

参考:  https://codevoweb.com/restful-api-with-python-fastapi-access-and-refresh-tokens/

## 虚拟环境

```python
mkdir app
cd app
python3 -m venv venv
```

## 初始化 FastAPI 服务

```python
pip install fastapi[all]


# app/main.py
from fastapi import FastAPI

app = FastAPI()


@app.get('/api/healthchecker')
def root():
    return {'message': 'Hello World'}


# 启动
uvicorn app.main:app --host localhost --port 8000 --reload
```

## 设置环境变量

- .env

```python
# .env

DATABASE_HOST = 127.0.0.1
DATABASE_PORT = 3306
DATABASE_DB = fastapi
DATABASE_USER = root
DATABASE_PASSWORD = 123456
DATABASE_PREFIX = "api_"

# Token 相关, 使用公钥和私钥实现访问和刷新令牌
ACCESS_TOKEN_EXPIRES_IN = 15
REFRESH_TOKEN_EXPIRES_IN = 60
JWT_ALGORITHM = RS256

JWT_PRIVATE_KEY = LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQpNSUlCT2dJQkFBSkJBSSs3QnZUS0FWdHVQYzEzbEFkVk94TlVmcWxzMm1SVmlQWlJyVFpjd3l4RVhVRGpNaFZuCi9KVHRsd3h2a281T0pBQ1k3dVE0T09wODdiM3NOU3ZNd2xNQ0F3RUFBUUpBYm5LaENOQ0dOSFZGaHJPQ0RCU0IKdmZ2ckRWUzVpZXAwd2h2SGlBUEdjeWV6bjd0U2RweUZ0NEU0QTNXT3VQOXhqenNjTFZyb1pzRmVMUWlqT1JhUwp3UUloQU84MWl2b21iVGhjRkltTFZPbU16Vk52TGxWTW02WE5iS3B4bGh4TlpUTmhBaUVBbWRISlpGM3haWFE0Cm15QnNCeEhLQ3JqOTF6bVFxU0E4bHUvT1ZNTDNSak1DSVFEbDJxOUdtN0lMbS85b0EyaCtXdnZabGxZUlJPR3oKT21lV2lEclR5MUxaUVFJZ2ZGYUlaUWxMU0tkWjJvdXF4MHdwOWVEejBEWklLVzVWaSt6czdMZHRDdUVDSUVGYwo3d21VZ3pPblpzbnU1clBsTDJjZldLTGhFbWwrUVFzOCtkMFBGdXlnCi0tLS0tRU5EIFJTQSBQUklWQVRFIEtFWS0tLS0t

JWT_PUBLIC_KEY = LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUZ3d0RRWUpLb1pJaHZjTkFRRUJCUUFEU3dBd1NBSkJBSSs3QnZUS0FWdHVQYzEzbEFkVk94TlVmcWxzMm1SVgppUFpSclRaY3d5eEVYVURqTWhWbi9KVHRsd3h2a281T0pBQ1k3dVE0T09wODdiM3NOU3ZNd2xNQ0F3RUFBUT09Ci0tLS0tRU5EIFBVQkxJQyBLRVktLS0tLQ==


# 客户端来源
CLIENT_ORIGIN=http://localhost:3000
```

- app/config.py

```python
# app/config.py

from pydantic import BaseSettings


class Settings(BaseSettings):
    DATABASE_HOST: str
    DATABASE_PORT: int
    DATABASE_DB: str
    DATABASE_USER: str
    DATABASE_PASSWORD: str
    DATABASE_PREFIX: str

    # Token 相关
    ACCESS_TOKEN_EXPIRES_IN: int
    REFRESH_TOKEN_EXPIRES_IN: int
    JWT_ALGORITHM: str
    JWT_PRIVATE_KEY: str
    JWT_PUBLIC_KEY: str

    # 客户端来源
    CLIENT_ORIGIN: str

    class Config:
        env_file = './.env'

settings = Settings()
```

 

## 连接Mysql数据库

> pip install sqlalchemy mysql-connector-python pydantic[email]

- app/database.py

```python
# app/database.py
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from .config import settings

SQLALCHEMY_DATABASE_URL = f"mysql+mysqlconnector://{settings.DATABASE_USER}:{settings.DATABASE_PASSWORD}@{settings.DATABASE_HOST}:{settings.DATABASE_PORT}/{settings.DATABASE_DB}"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
```

## 创建数据库模型

- app/models.py

```python
# app/models.py

from .database import Base
from sqlalchemy import TIMESTAMP, Column, Integer, String, Boolean, text
from .config import settings

class User(Base):
    __tablename__ = settings.DATABASE_PREFIX + 'user'
    id = Column(Integer, primary_key = True, index = True)
    name = Column(String(255), nullable = False)
    email = Column(String(255), nullable = False, unique = True)
    password = Column(String(255), nullable = False)
    photo = Column(String(255), nullable = True)
    verified = Column(Boolean, nullable = False, server_default=text('False'))
    role = Column(String(255), nullable=False, server_default="user")
    created_at = Column(TIMESTAMP(timezone=True),nullable=False, server_default=text("now()"))
    updated_at = Column(TIMESTAMP(timezone=True),nullable=False, server_default=text("now()"))
```

## Pydantic验证请求和响应

- app/schemas.py

```python
# app/schemas.py
from datetime import datetime
from pydantic import BaseModel,EmailStr,constr


class UserBaseSchema(BaseModel):
    name: str
    email: EmailStr
    photo: str

    class Config:
        orm_mode = True

class CreateUserSchema(UserBaseSchema):
    password: constr(min_length=8)
    passwordConfirm: str
    role: str = 'user'
    verified: bool = False


class LoginUserSchema(BaseModel):
    email: EmailStr
    password: constr(min_length=8)


class UserResponse(UserBaseSchema):
    id: int
    created_at: datetime
    updated_at: datetime
```

## 密码管理

> pip install passlib bcrypt

- app/utils.py

```python
# app/utils.py
from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str):
    return pwd_context.hash(password)


def verify_password(password: str, hashed_password: str):
    return pwd_context.verify(password, hashed_password)
```

## JWT 身份验证扩展

> pip install fastapi-jwt-auth[asymmetric]

- app/oauth2.py

```python
import base64
from typing import List
from fastapi_jwt_auth import AuthJWT
from pydantic import BaseModel

from .config import settings

class Settings(BaseModel):
    authjwt_algorithm: str = settings.JWT_ALGORITHM
    authjwt_decode_algorithms: List[str] = [settings.JWT_ALGORITHM]
    authjwt_token_location: set = {'cookies', 'headers'}
    authjwt_access_cookie_key: str = 'access_token'
    authjwt_refresh_cookie_key: str = 'refresh_token'
    authjwt_cookie_csrf_protect: bool = False
    authjwt_public_key: str = base64.b64decode(
        settings.JWT_PUBLIC_KEY).decode('utf-8')
    authjwt_private_key: str = base64.b64decode(
        settings.JWT_PRIVATE_KEY).decode('utf-8')


@AuthJWT.load_config
def get_config():
    return Settings()
```

## 创建身份验证控制器

- app/routers/auth.py

```python
from datetime import timedelta
from fastapi import APIRouter, Request, Response, status, Depends, HTTPException
from pydantic import EmailStr

from app import oauth2
from .. import schemas, models, utils
from sqlalchemy.orm import Session
from ..database import get_db
from app.oauth2 import AuthJWT
from ..config import settings


router = APIRouter()
ACCESS_TOKEN_EXPIRES_IN = settings.ACCESS_TOKEN_EXPIRES_IN
REFRESH_TOKEN_EXPIRES_IN = settings.REFRESH_TOKEN_EXPIRES_IN
# [...]
```

## 用户注册控制器

- app/routers/auth.py

```python
# [... Configurations ...]

# 用户注册控制器
@router.post('/register', status_code=status.HTTP_201_CREATED, response_model=schemas.UserResponse)
async def create_user(payload: schemas.CreateUserSchema, db: Session = Depends(get_db)):
    # 判断注册邮箱是否已存在
    user = db.query(models.User).filter(models.User.email == EmailStr(payload.email.lower())).first()
    if user:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT,detail='Account already exist')

    # 判断两次密码是否一致
    if payload.password != payload.passwordConfirm:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,detail='Passwords do not match')

    # 哈希用户密码
    payload.password = utils.hash_password(payload.password)

    # 删除不需要字段
    del payload.passwordConfirm
    payload.role = 'user'
    payload.verified = True
    payload.email = EmailStr(payload.email.lower())
    new_user = models.User(**payload.dict())
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user
```

## 用户登录控制器

- app/routers/auth.py

```python
# 用户登录控制器
@router.post('/login')
def login(payload: schemas.LoginUserSchema, response: Response, db: Session = Depends(get_db), Authorize: AuthJWT = Depends()):
    # 查看用户是否存在
    user = db.query(models.User).filter(
        models.User.email == EmailStr(payload.email.lower())).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail='Incorrect Email or Password')

    # 检查用户是否验证了他的电子邮件
    if not user.verified:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail='Please verify your email address')

    # 检查密码是否有效
    if not utils.verify_password(payload.password, user.password):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail='Incorrect Email or Password')

    # 创建访问令牌
    access_token = Authorize.create_access_token(
        subject=str(user.id), expires_time=timedelta(minutes=ACCESS_TOKEN_EXPIRES_IN))

    # 创建刷新令牌
    refresh_token = Authorize.create_refresh_token(
        subject=str(user.id), expires_time=timedelta(minutes=REFRESH_TOKEN_EXPIRES_IN))

    # 在cookie中存储刷新和访问令牌
    response.set_cookie('access_token', access_token, ACCESS_TOKEN_EXPIRES_IN * 60,
                        ACCESS_TOKEN_EXPIRES_IN * 60, '/', None, False, True, 'lax')
    response.set_cookie('refresh_token', refresh_token,
                        REFRESH_TOKEN_EXPIRES_IN * 60, REFRESH_TOKEN_EXPIRES_IN * 60, '/', None, False, True, 'lax')
    response.set_cookie('logged_in', 'True', ACCESS_TOKEN_EXPIRES_IN * 60,
                        ACCESS_TOKEN_EXPIRES_IN * 60, '/', None, False, False, 'lax')

    # 返回信息
    return {'status': 'success', 'access_token': access_token}
```

## 刷新访问令牌控制器

- app/routers/auth.py

```python
# 刷新访问令牌控制器
@router.get('/refresh')
def refresh_token(response: Response, request: Request, Authorize: AuthJWT = Depends(), db: Session = Depends(get_db)):
    try:
        print(Authorize._refresh_cookie_key)
        Authorize.jwt_refresh_token_required()

        user_id = Authorize.get_jwt_subject()
        if not user_id:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                                detail='Could not refresh access token')
        user = db.query(models.User).filter(models.User.id == user_id).first()
        if not user:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                                detail='The user belonging to this token no logger exist')
        access_token = Authorize.create_access_token(
            subject=str(user.id), expires_time=timedelta(minutes=ACCESS_TOKEN_EXPIRES_IN))
    except Exception as e:
        error = e.__class__.__name__
        if error == 'MissingTokenError':
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail='Please provide refresh token')
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=error)

    response.set_cookie('access_token', access_token, ACCESS_TOKEN_EXPIRES_IN * 60,
                        ACCESS_TOKEN_EXPIRES_IN * 60, '/', None, False, True, 'lax')
    response.set_cookie('logged_in', 'True', ACCESS_TOKEN_EXPIRES_IN * 60,
                        ACCESS_TOKEN_EXPIRES_IN * 60, '/', None, False, False, 'lax')
    return {'access_token': access_token}
```

## 注销用户控制器

- app/routers/auth.py

```python
# 注销用户控制器，  require_user 路由保护
@router.get('/logout', status_code=status.HTTP_200_OK)
def logout(response: Response, Authorize: AuthJWT = Depends(), user_id: str = Depends(oauth2.require_user)):
    Authorize.unset_jwt_cookies()
    response.set_cookie('logged_in', '', -1)

    return {'status': 'success'}
```

## Auth 控制器的完整代码

- app/routers/auth.py

```python
from fastapi import APIRouter, Request, Response, status, Depends, HTTPException
from pydantic import EmailStr
from datetime import timedelta
from app import oauth2
from sqlalchemy.orm import Session
from .. import schemas, models, utils
from ..database import get_db
from ..oauth2 import AuthJWT
from ..config import settings




router = APIRouter()
ACCESS_TOKEN_EXPIRES_IN = settings.ACCESS_TOKEN_EXPIRES_IN
REFRESH_TOKEN_EXPIRES_IN = settings.REFRESH_TOKEN_EXPIRES_IN


# 用户注册控制器
@router.post('/register', status_code=status.HTTP_201_CREATED, response_model=schemas.UserResponse)
async def create_user(payload: schemas.CreateUserSchema, db: Session = Depends(get_db)):
    # 判断注册邮箱是否已存在
    user = db.query(models.User).filter(models.User.email == EmailStr(payload.email.lower())).first()
    if user:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT,detail='Account already exist')

    # 判断两次密码是否一致
    if payload.password != payload.passwordConfirm:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,detail='Passwords do not match')

    # 哈希用户密码
    payload.password = utils.hash_password(payload.password)

    # 删除不需要字段
    del payload.passwordConfirm
    payload.role = 'user'
    payload.verified = True
    payload.email = EmailStr(payload.email.lower())
    new_user = models.User(**payload.dict())
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user



# 用户登录控制器
@router.post('/login')
def login(payload: schemas.LoginUserSchema, response: Response, db: Session = Depends(get_db), Authorize: AuthJWT = Depends()):
    # 查看用户是否存在
    user = db.query(models.User).filter(
        models.User.email == EmailStr(payload.email.lower())).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail='Incorrect Email or Password')

    # 检查用户是否验证了他的电子邮件
    if not user.verified:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail='Please verify your email address')

    # 检查密码是否有效
    if not utils.verify_password(payload.password, user.password):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail='Incorrect Email or Password')

    # 创建访问令牌
    access_token = Authorize.create_access_token(
        subject=str(user.id), expires_time=timedelta(minutes=ACCESS_TOKEN_EXPIRES_IN))

    # 创建刷新令牌
    refresh_token = Authorize.create_refresh_token(
        subject=str(user.id), expires_time=timedelta(minutes=REFRESH_TOKEN_EXPIRES_IN))

    # 在cookie中存储刷新和访问令牌
    response.set_cookie('access_token', access_token, ACCESS_TOKEN_EXPIRES_IN * 60,
                        ACCESS_TOKEN_EXPIRES_IN * 60, '/', None, False, True, 'lax')
    response.set_cookie('refresh_token', refresh_token,
                        REFRESH_TOKEN_EXPIRES_IN * 60, REFRESH_TOKEN_EXPIRES_IN * 60, '/', None, False, True, 'lax')
    response.set_cookie('logged_in', 'True', ACCESS_TOKEN_EXPIRES_IN * 60,
                        ACCESS_TOKEN_EXPIRES_IN * 60, '/', None, False, False, 'lax')

    # 返回信息
    return {'status': 'success', 'access_token': access_token}


# 刷新访问令牌控制器
@router.get('/refresh')
def refresh_token(response: Response, request: Request, Authorize: AuthJWT = Depends(), db: Session = Depends(get_db)):
    try:
        print(Authorize._refresh_cookie_key)
        Authorize.jwt_refresh_token_required()

        user_id = Authorize.get_jwt_subject()
        if not user_id:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                                detail='Could not refresh access token')
        user = db.query(models.User).filter(models.User.id == user_id).first()
        if not user:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                                detail='The user belonging to this token no logger exist')
        access_token = Authorize.create_access_token(
            subject=str(user.id), expires_time=timedelta(minutes=ACCESS_TOKEN_EXPIRES_IN))
    except Exception as e:
        error = e.__class__.__name__
        if error == 'MissingTokenError':
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail='Please provide refresh token')
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=error)

    response.set_cookie('access_token', access_token, ACCESS_TOKEN_EXPIRES_IN * 60,
                        ACCESS_TOKEN_EXPIRES_IN * 60, '/', None, False, True, 'lax')
    response.set_cookie('logged_in', 'True', ACCESS_TOKEN_EXPIRES_IN * 60,
                        ACCESS_TOKEN_EXPIRES_IN * 60, '/', None, False, False, 'lax')
    return {'access_token': access_token}


# 注销用户控制器，  require_user 路由保护
@router.get('/logout', status_code=status.HTTP_200_OK)
def logout(response: Response, Authorize: AuthJWT = Depends(), user_id: str = Depends(oauth2.require_user)):
    Authorize.unset_jwt_cookies()
    response.set_cookie('logged_in', '', -1)

    return {'status': 'success'}
```

## 如何添加受保护的路由

- app/oauth2.py 更新

```python
import base64
from typing import List
from fastapi import Depends, HTTPException, status
from fastapi_jwt_auth import AuthJWT
from pydantic import BaseModel

from . import models
from .database import get_db
from sqlalchemy.orm import Session
from .config import settings


class Settings(BaseModel):
    authjwt_algorithm: str = settings.JWT_ALGORITHM
    authjwt_decode_algorithms: List[str] = [settings.JWT_ALGORITHM]
    authjwt_token_location: set = {'cookies', 'headers'}
    authjwt_access_cookie_key: str = 'access_token'
    authjwt_refresh_cookie_key: str = 'refresh_token'
    authjwt_public_key: str = base64.b64decode(
        settings.JWT_PUBLIC_KEY).decode('utf-8')
    authjwt_private_key: str = base64.b64decode(
        settings.JWT_PRIVATE_KEY).decode('utf-8')


@AuthJWT.load_config
def get_config():
    return Settings()


class NotVerified(Exception):
    pass


class UserNotFound(Exception):
    pass


def require_user(db: Session = Depends(get_db), Authorize: AuthJWT = Depends()):
    try:
        Authorize.jwt_required()
        user_id = Authorize.get_jwt_subject()
        user = db.query(models.User).filter(models.User.id == user_id).first()

        if not user:
            raise UserNotFound('User no longer exist')

        if not user.verified:
            raise NotVerified('You are not verified')

    except Exception as e:
        error = e.__class__.__name__
        print(error)
        if error == 'MissingTokenError':
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail='You are not logged in')
        if error == 'UserNotFound':
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail='User no longer exist')
        if error == 'NotVerified':
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail='Please verify your account')
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail='Token is invalid or has expired')
    return user_id
```

## 创建用户控制器

- app/routers/user.py

```python
from fastapi import APIRouter, Depends
from ..database import get_db
from sqlalchemy.orm import Session
from .. import models, schemas, oauth2

router = APIRouter()


@router.get('/me', response_model=schemas.UserResponse)
def get_me(db: Session = Depends(get_db), user_id: str = Depends(oauth2.require_user)):
    user = db.query(models.User).filter(models.User.id == user_id).first()
    return user
```

## 将路由添加到主文件

- app/main.py

```python
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.config import settings
from app.routers import user, auth

app = FastAPI()

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


app.include_router(auth.router, tags=['Auth'], prefix='/api/auth')
app.include_router(user.router, tags=['Users'], prefix='/api/users')


@app.get('/api/healthchecker')
def root():
    return {'message': 'Hello World'}
```

## 使用 Alembic 进行数据库迁移

```python
pip install alembic
```

> Alembic是一个轻量级的数据库迁移工具，旨在与 SQLAlchemy 一起使用。它可以自动拉取 SQLAlchemy 模型并生成相应的表。

- init – 准备项目以使用 alembic
- upgrade – 将数据库升级到更高版本
- downgrade - 恢复到以前的版本
- revision – 创建一个新的修订文件

```python
(fastapi) xxx@1:~/fastapi$ tree app
app
├── __init__.py
├── config.py
├── database.py
├── main.py
├── models.py
├── oauth2.py
├── schemas.py
└── utils.py
├── routers
│   ├── __init__.py
│   ├── auth.py
│   └── user.py
```

```python
# 1、使用alembic 命令创建一个迁移环境
alembic init alembic

# 2、修改 env.py 文件内容，
(fastapi) xxx@1:~/fastapi/app$ tree alembic
alembic
├── env.py
├── README
├── script.py.mako
└── versions

···
# 获取路径， 获取不到路径，所以所需获取项目路径
import sys  
from pathlib import Path  
file = Path(__file__). resolve()  
package_root_directory = file.parents[2]
sys.path.append(str(package_root_directory))  


# 导入所需环境
from app.config import settings
from app.models import Base

config = context.config


# 配置数据库
config.set_main_option(
    "sqlalchemy.url",f"mysql+mysqlconnector://{settings.DATABASE_USER}:{settings.DATABASE_PASSWORD}@{settings.DATABASE_HOST}:{settings.DATABASE_PORT}/{settings.DATABASE_DB}"
)


# 元数据
target_metadata = Base.metadata

····




# 3、创建一个修订文件, 比如我创建数据表
alembic revision --autogenerate -m "creat users table"


# 4、运行升级命令将更改推送到 Mysql 数据库
alembic upgrade head
```

## 测试 API 接口

- 如果是API方式，每次请求需要带上 Cookie,  如果刷新了Cookie,  原来的 Cookie 还是可以继续使用..(这点不安全)

```python
Cookie: access_token=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxIiwiaWF0IjoxNjY4MDcxMDk2LCJuYmYiOjE2NjgwNzEwOTYsImp0aSI6ImZlNjhmYTNmLTgxY2YtNDIyOC04NmY5LTI5NDFlZDVhNTA3NiIsImV4cCI6MTY2ODA3MTk5NiwidHlwZSI6ImFjY2VzcyIsImZyZXNoIjpmYWxzZX0.fxNmR9raPbpFA20YprecelvQIfPPni2kaHag_a_DG-Ly10M--UvO7wNcuYIMdYpvOmGvcms9n9Op1W-j6x-8_w; refresh_token=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxIiwiaWF0IjoxNjY4MDcxMDk2LCJuYmYiOjE2NjgwNzEwOTYsImp0aSI6IjMwMzliNzAwLTgwZDYtNDUwMy1hZTI5LTQyZTA2N2NmNzkxOCIsImV4cCI6MTY2ODA3NDY5NiwidHlwZSI6InJlZnJlc2gifQ.bjMUBDIg8E_cEEaMtJxV-Pbz-X6MayDe4G35FGiw7j_9KUjGqkY0CRcayg-GyE3G8otFQ8hYph8v695b1v3rvA; logged_in=True
```
