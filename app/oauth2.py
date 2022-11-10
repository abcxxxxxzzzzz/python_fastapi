import base64
from typing import List
from fastapi_jwt_auth import AuthJWT
from pydantic import BaseModel
from . import models
from .database import get_db
from sqlalchemy.orm import Session
from .config import settings
from fastapi import Depends, HTTPException, status


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



class NotVerified(Exception):
    pass


class UserNotFound(Exception):
    pass


def require_user(db: Session = Depends(get_db), Authorize: AuthJWT = Depends()):
    '''
        首先, 我们为require_user函数添加了必要的依赖项。
        然后我们调用包 jwt_required() 提供的方法 fastapi_jwt_auth 来验证 cookie 对象中存储的访问令牌。
        接下来, 我们使用该 get_jwt_subject() 方法检索有效负载并查询数据库以检查是否存在具有该 ID 的用户。
        如果用户通过了认证检查. 该 require_user 函数将用户的ID返回给路径操作函数。
    '''
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

