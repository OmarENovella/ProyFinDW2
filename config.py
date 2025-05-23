from fastapi import FastAPI
from pymongo.mongo_client import MongoClient
from pymongo.server_api import ServerApi
import os
from dotenv import load_dotenv
from passlib.context import CryptContext
from fastapi.security import OAuth2PasswordBearer
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from pathlib import Path

load_dotenv()

app = FastAPI()

client = MongoClient(os.getenv("MONGO_URI"), server_api=ServerApi('1'))

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

templates = Jinja2Templates(directory=Path(__file__).parent / "templates")
app.mount("/static", StaticFiles(directory=Path(__file__).parent / "static"), name="static")

db = client.OENA_BDA

'''DATABASE COLLECTIONS'''
users_auth_coll = db["users"]
athletes_coll = db["athletes"]
sports_coll = db["sports"]
coaches_coll = db["coaches"]
sports_chief_coll = db["sports_chief"]
trainings_coll = db["trainings"]
competitions_coll = db["competitions"]
matches_coll = db["matches"]
assistances_coll = db["assistances"]
physical_eval_coll = db["physical_eval"]
sports_storage_coll = db["sports_storage"]
activities_report_coll = db["activities_report"]
chat_coll = db["chat"]
