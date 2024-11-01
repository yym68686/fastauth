import os
import jwt
import logging
logger = logging.getLogger(__name__)

from datetime import datetime, timedelta
from passlib.context import CryptContext
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi.responses import JSONResponse
from fastapi.security import OAuth2PasswordRequestForm
from fastapi import FastAPI, HTTPException, Depends, Request

from email.mime.text import MIMEText
import smtplib

is_debug = bool(os.getenv("DEBUG", False))
# is_debug = False
# 密码加密上下文
pwd_context = CryptContext(schemes=["sha256_crypt"], deprecated="auto")

# JWT 相关设置
SECRET_KEY = "你的密钥"  # 请使用强随机密钥
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

from sqlalchemy.sql import sqltypes
from sqlalchemy.orm import declarative_base, sessionmaker
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy import Column, Integer, String, Float, DateTime, select, Boolean, Text, inspect, text

# 获取数据库路径
db_path = os.getenv('DB_PATH', './data/fastauth.db')

# 确保 data 目录存在
data_dir = os.path.dirname(db_path)
os.makedirs(data_dir, exist_ok=True)

# 创建异步引擎和会话
# engine = create_async_engine('sqlite+aiosqlite:///' + db_path, echo=False)
engine = create_async_engine('sqlite+aiosqlite:///' + db_path, echo=is_debug)
async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

# 定义get_session函数
async def get_session() -> AsyncGenerator[AsyncSession, None]:
    async with async_session() as session:
        try:
            yield session
        finally:
            await session.close()

def _map_sa_type_to_sql_type(sa_type):
    type_map = {
        sqltypes.Integer: "INTEGER",
        sqltypes.String: "TEXT",
        sqltypes.Float: "REAL",
        sqltypes.Boolean: "BOOLEAN",
        sqltypes.DateTime: "DATETIME",
        sqltypes.Text: "TEXT"
    }
    return type_map.get(type(sa_type), "TEXT")

def _get_default_sql(default):
    if default is None:
        return ""
    if isinstance(default.arg, bool):
        return f" DEFAULT {str(default.arg).upper()}"
    if isinstance(default.arg, (int, float)):
        return f" DEFAULT {default.arg}"
    if isinstance(default.arg, str):
        return f" DEFAULT '{default.arg}'"
    return ""

async def create_tables():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

        # 检查并添加缺失的列
        def check_and_add_columns(connection):
            inspector = inspect(connection)
            for table in [User]:
                table_name = table.__tablename__
                existing_columns = {col['name']: col['type'] for col in inspector.get_columns(table_name)}

                for column_name, column in table.__table__.columns.items():
                    if column_name not in existing_columns:
                        col_type = _map_sa_type_to_sql_type(column.type)
                        default = _get_default_sql(column.default)
                        connection.execute(text(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {col_type}{default}"))

        await conn.run_sync(check_and_add_columns)

# 定义数据库模型
Base = declarative_base()

# 定义用户模型
class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow)

# 定义验证码模型
class VerificationCode(Base):
    __tablename__ = 'verification_codes'
    id = Column(Integer, primary_key=True)
    email = Column(String, unique=True, index=True)
    code = Column(String)
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow)
    expires_at = Column(DateTime(timezone=True))

# 邮件配置 - 添加默认值和类型转换
EMAIL_HOST = os.getenv("EMAIL_HOST", "smtp.gmail.com")  # 替换为您的 SMTP 服务器
EMAIL_PORT = int(os.getenv("EMAIL_PORT", "587"))  # 确保端口号是整数
EMAIL_HOST_USER = os.getenv("EMAIL_HOST_USER", "your-email@example.com")
EMAIL_HOST_PASSWORD = os.getenv("EMAIL_HOST_PASSWORD", "your-password")

# 修改邮件发送函数
async def send_verification_email(email: str, code: str):
    message = MIMEText(f'您的验证码是：{code}，有效期为10分钟。', 'plain', 'utf-8')
    message['Subject'] = '邮箱验证码'
    message['From'] = EMAIL_HOST_USER
    message['To'] = email

    try:
        logger.info(f"尝试连接到 SMTP 服务器: {EMAIL_HOST}:{EMAIL_PORT}")
        server = smtplib.SMTP(EMAIL_HOST, EMAIL_PORT, timeout=10)
        try:
            # 详细的调试信息
            server.set_debuglevel(1)

            # 建立 TLS 连接
            logger.info("启动 TLS 连接")
            server.starttls()

            # 登录
            logger.info(f"尝试使用账号 {EMAIL_HOST_USER} 登录")
            server.login(EMAIL_HOST_USER, EMAIL_HOST_PASSWORD)

            # 发送邮件
            logger.info(f"发送邮件到 {email}")
            server.send_message(message)
            logger.info("邮件发送成功")

            return True
        finally:
            try:
                server.quit()
            except Exception as e:
                logger.warning(f"关闭SMTP连接时发生非致命错误: {str(e)}")
                try:
                    server.close()
                except:
                    pass
    except smtplib.SMTPAuthenticationError:
        logger.error("SMTP 认证失败：请检查用户名和密码")
        return False
    except smtplib.SMTPException as e:
        logger.error(f"SMTP 错误: {str(e)}")
        return False
    except Exception as e:
        logger.error(f"发送邮件时发生未知错误: {str(e)}")
        return False

@asynccontextmanager
async def lifespan(app: FastAPI):
    # 启动时的代码
    await create_tables()
    yield
    await app.state.client.aclose()

app = FastAPI(lifespan=lifespan, debug=is_debug)
app.dependency_overrides[get_session] = get_session

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    if exc.status_code == 404:
        logger.error(f"404 Error: {exc.detail}")
    return JSONResponse(
        status_code=exc.status_code,
        content={"message": exc.detail},
    )

# 注册端点
@app.post("/signup")
async def signup(form_data: OAuth2PasswordRequestForm = Depends(), session: AsyncSession = Depends(get_session)):
    # 检查用户是否已存在
    result = await session.execute(select(User).where(User.username == form_data.username))
    existing_user = result.scalar_one_or_none()

    if existing_user:
        raise HTTPException(status_code=400, detail="用户名已存在")

    # 创建新用户
    hashed_password = pwd_context.hash(form_data.password)
    new_user = User(username=form_data.username, email=form_data.username, hashed_password=hashed_password)
    session.add(new_user)

    try:
        await session.commit()
    except Exception as e:
        await session.rollback()
        raise HTTPException(status_code=500, detail=f"创建用户时发生错误: {str(e)}")

    return {"message": "用户注册成功", "username": form_data.username}

# 登录端点
@app.post("/login")
async def login(form_data: OAuth2PasswordRequestForm = Depends(), session: AsyncSession = Depends(get_session)):
    # 查找用户
    result = await session.execute(select(User).where(User.username == form_data.username))
    user = result.scalar_one_or_none()

    if not user or not pwd_context.verify(form_data.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="用户名或密码错误")

    # 创建访问令牌
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )

    return {"access_token": access_token, "token_type": "bearer"}

# 创建访问令牌的函数
def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

from pydantic import BaseModel, EmailStr
import random
import string

# 在现有路由之前添加新的请求模型
class EmailVerificationRequest(BaseModel):
    email: EmailStr

class VerificationCodeRequest(BaseModel):
    email: EmailStr
    code: str

class SetPasswordRequest(BaseModel):
    email: EmailStr
    password: str
    username: str

# 添加新的路由
@app.post("/request-verification")
async def request_verification(
    request: EmailVerificationRequest,
    session: AsyncSession = Depends(get_session)
):
    # 生成6位验证码
    code = ''.join(random.choices(string.digits, k=6))
    expires_at = datetime.utcnow() + timedelta(minutes=10)

    # 检查是否已存在验证码
    result = await session.execute(
        select(VerificationCode).where(VerificationCode.email == request.email)
    )
    existing_code = result.scalar_one_or_none()

    if existing_code:
        existing_code.code = code
        existing_code.expires_at = expires_at
    else:
        verification = VerificationCode(
            email=request.email,
            code=code,
            expires_at=expires_at
        )
        session.add(verification)

    try:
        await session.commit()
        if await send_verification_email(request.email, code):
            return {"message": "验证码已发送到邮箱"}
        else:
            raise HTTPException(status_code=500, detail="发送邮件失败")
    except Exception as e:
        await session.rollback()
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/verify-code")
async def verify_code(
    request: VerificationCodeRequest,
    session: AsyncSession = Depends(get_session)
):
    result = await session.execute(
        select(VerificationCode).where(VerificationCode.email == request.email)
    )
    verification = result.scalar_one_or_none()

    if not verification:
        raise HTTPException(status_code=400, detail="未找到验证码记录")

    if verification.expires_at < datetime.utcnow():
        await session.delete(verification)
        await session.commit()
        raise HTTPException(status_code=400, detail="验证码已过期")

    if verification.code != request.code:
        raise HTTPException(status_code=400, detail="验证码错误")

    return {"message": "验证成功"}

@app.post("/set-password")
async def set_password(
    request: SetPasswordRequest,
    session: AsyncSession = Depends(get_session)
):
    # 验证邮箱是否通过验证
    result = await session.execute(
        select(VerificationCode).where(VerificationCode.email == request.email)
    )
    verification = result.scalar_one_or_none()

    if not verification:
        raise HTTPException(status_code=400, detail="请先验证邮箱")

    # 检查用户名是否已存在
    user_result = await session.execute(
        select(User).where(User.username == request.username)
    )
    if user_result.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="用户名已存在")

    # 创建新用户
    hashed_password = pwd_context.hash(request.password)
    new_user = User(
        username=request.username,
        email=request.email,
        hashed_password=hashed_password
    )
    session.add(new_user)

    # 删除验证码记录
    await session.delete(verification)

    try:
        await session.commit()
        return {"message": "用户注册成功"}
    except Exception as e:
        await session.rollback()
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == '__main__':
    import uvicorn
    uvicorn.run(
        "__main__:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        # reload_dirs=["./"],
        # reload_includes=["*.py", "api.yaml"],
        ws="none",
        # log_level="warning"
    )