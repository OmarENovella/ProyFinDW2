from config import app
from fastapi import (
    APIRouter, 
    Form, HTTPException, 
    Depends, Request, 
    WebSocket, WebSocketDisconnect, 
    Cookie, WebSocketException
)
import config
from jose import JWTError, jwt
from typing import (Annotated, List)
from datetime import datetime, timedelta
import os
from fastapi.responses import JSONResponse, RedirectResponse
from bson import ObjectId
from datetime import date

router = APIRouter()

def hash_password(password: str):
    return config.pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str):
    return config.pwd_context.verify(plain_password, hashed_password)

@router.post("/users/register")
async def register_user(
        email: Annotated[str, Form()], 
        password: Annotated[str, Form()], 
        role: Annotated[int, Form()]
    ):

    existing_user = config.users_auth_coll.find_one({"email": email})
    if existing_user:
        return {"message": "User already exists"}

    result = config.users_auth_coll.insert_one({
        "email": email,
        "password": hash_password(password),
        "role": role
    })

    return {
        "message": "User registered successfully", 
        "id": str(result.inserted_id)
    }

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=90))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, os.getenv("SECRET_KEY"), algorithm="HS256")

@router.post("/users/login/form")
async def login_form(
        email: Annotated[str, Form()],
        password: Annotated[str, Form()],
    ):
    
    user = config.users_auth_coll.find_one({"email": email})
    if not user:
        raise WrongLoginDataException("Usuario no encontrado")
    
    if not verify_password(password, user["password"]):
        raise WrongLoginDataException("Contraseña incorrecta")
    
    access_token = create_access_token(data= {"sub": str(user['_id'])})

    response = RedirectResponse("/dashboard", status_code=303)
    response.set_cookie(key="access_token", value=access_token, httponly=True)
    return response

async def error_handle_template(request: Request, message: str, redirect_url: str):
    return config.templates.TemplateResponse(
        "error.html",
        context={
            "request": request,
            "message": message,
            "redirect_url": redirect_url
        }
    )

class WrongLoginDataException(Exception):
    def __init__(self, message: str):
        self.message = message

@app.exception_handler(WrongLoginDataException)
async def wrong_login_exception(request: Request, exc: WrongLoginDataException):
    return await error_handle_template(request, exc.message, "/login")

@router.get("/users/logout/form")
async def logout_form():
    response = RedirectResponse("/login", status_code=303)
    response.delete_cookie(key="access_token")
    return response

async def get_current_user(request: Request):
    token = request.cookies.get("access_token")
    if not token:
        raise HTTPException(
            status_code=401,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        payload = jwt.decode(token, os.getenv("SECRET_KEY"), algorithms=["HS256"])
        user_id: str = payload.get("sub")
        if not user_id:
            raise HTTPException(status_code=401, detail="Invalid token")
    except JWTError:
        raise WrongLoginDataException("Token decode error")

    user = config.users_auth_coll.find_one({"_id": ObjectId(user_id)})
    if not user:
        raise WrongLoginDataException("User not found")

    match user["role"]:
        case 2:
            kind_of_user = config.athletes_coll.find_one({"auth_user_id": user_id})
        case 1:
            kind_of_user = config.coaches_coll.find_one({"auth_user_id": user_id})
        case 0:
            kind_of_user = config.sports_chief_coll.find_one({"auth_user_id": user_id})
        case _:
            raise WrongLoginDataException("Invalid role")
        
    if kind_of_user is None:
        raise IncompleteProfileException(user["_id"], user["role"], user["email"])

    return kind_of_user


class IncompleteProfileException(Exception):
    def __init__(self, auth_user_id: int, user_role: int, email: str):
        self.user_role = user_role
        self.auth_user_id = auth_user_id
        self.email = email

@app.exception_handler(IncompleteProfileException)
async def incomplete_profile_exception_handler(request: Request, exc: IncompleteProfileException):
    forms = {
        0: """
            <form method="post" action="/sports_chiefs/register">
                <input type="hidden" name="auth_user_id" value="{}">
                <label>Nombre:</label><input type="text" name="name" required><br>
                <input type="hidden" name="email" value="{}" required><br>
                <label>Rol:</label><input type="text" name="role" required><br>
                <label>Fecha de admision:</label><input type="date" name="admission_date" required><br>
                <button type="submit">Subir</button>
            </form>
        """.format(exc.auth_user_id, exc.email),
        1: """
            <form action="/coaches/register" method="post">
                <input type="hidden" name="auth_user_id" value="{}">
                <input type="hidden" name="email" value="{}">
                <label>Nombre:</label><input type="text" name="name" required><br>
                <label>Teléfono:</label><input type="text" name="phone" required><br>
                <label>Fecha de contrato:</label><input type="date" name="hiring_date" required><br>
                <button type="submit">Subir</button>
            </form>
        """.format(exc.auth_user_id, exc.email),
        2: """
            <form action="/athletes/register" method="post">
                <input type="hidden" name="auth_user_id" value="{}">
                <label>Nombre:</label><input type="text" name="name" required><br>
                <input type="hidden" name="email" value="{}" required><br>
                <label>Carrera:</label><input type="text" name="major" required>
                <label>Fecha de nacimiento:</label><input type="date" name="birth_day" required><br>
                <label>Fecha de ingreso:</label><input type="date" name="admission_date" required><br>
                <button type="submit">Subir</button>
            </form>
        """.format(exc.auth_user_id, exc.email),
    }
    return config.templates.TemplateResponse(
        "incomplete_profile.html",
        context={
            "request": request,
            "auth_user_id": exc.auth_user_id,
            "email": exc.email,
            "form": forms[exc.user_role]
        }
    )

@router.get("/login")
async def login(request: Request):
    return config.templates.TemplateResponse("login.html", {"request": request})

@router.get("/")
async def index(request: Request):
    return RedirectResponse("/login", status_code=303)

@router.get("/dashboard")
async def dashboard(request: Request, current_user = Depends(get_current_user)):
    auth_user = config.users_auth_coll.find_one({"_id": ObjectId(current_user["auth_user_id"])})
    coaches_list = get_coaches()
    chief_coaches_list = get_sports_chiefs()
    sports = get_sports()
    my_sports_list = get_my_sports(current_user)
    athletes_list = get_athletes()

    return config.templates.TemplateResponse("dashboard.html", {
        "request": request, 
        "current_user": current_user,
        "coaches_list": coaches_list,
        "chief_coaches_list": chief_coaches_list,
        "sports": sports,
        "my_sports_list": my_sports_list,
        "athletes_list": athletes_list,
        "auth_user": {
            'id': str(auth_user["_id"]), 
            "email": auth_user["email"], 
            "role": auth_user["role"]
        }
    })

@router.post("/athletes/register")
async def register_athlete(
    auth_user_id: str = Form(...),
    name: str = Form(...),
    major: str = Form(...),
    birth_day: date = Form(...),
    admission_date: date = Form(...),
    
):
    athlete_data = {
        "auth_user_id": auth_user_id,
        "name": name,
        "major": major,
        "birth_day": birth_day.isoformat(),
        "admission_date": admission_date.isoformat(),
        "disciplines": [],
        "status": "active"
    }
    config.athletes_coll.insert_one(athlete_data)
    return RedirectResponse(
        "/dashboard", 
        status_code=303
    )

@router.post("/coaches/register")
async def register_coach(
    auth_user_id: str = Form(...),
    name: str = Form(...),
    phone: str = Form(...),
    email: str = Form(...),
    hiring_date: date = Form(...),
):
    coach_data = {
        "auth_user_id": auth_user_id,
        "name": name,
        "phone": phone,
        "email": email,
        "hiring_date": hiring_date.isoformat(),
    }
    config.coaches_coll.insert_one(coach_data)
    return RedirectResponse(
        "/dashboard", 
        status_code=303
    )

@router.post("/coaches/update/{coach_id}")
async def update_coach(
    coach_id: str,
    name: str = Form(...),
    phone: str = Form(...),
    email: str = Form(...),
    hiring_date: date = Form(...),
):
    update_data = {
        "name": name,
        "phone": phone,
        "email": email,
        "hiring_date": hiring_date.isoformat(),
    }

    config.coaches_coll.update_one(
        {"_id": ObjectId(coach_id)},
        {"$set": update_data}
    )

    return RedirectResponse("/dashboard", status_code=303)

@router.get("/coaches/delete/{coach_id}")
async def delete_coach(coach_id: str):
    coach = config.coaches_coll.find_one({"_id": ObjectId(coach_id)})
    if not coach:
        raise HTTPException(status_code=404, detail="Entrenador no encontrado")

    config.coaches_coll.delete_one({"_id": ObjectId(coach_id)})

    return RedirectResponse(url="/dashboard", status_code=303)

@router.get("/coaches/edit/{coach_id}")
async def edit_coach_form(request: Request, coach_id: str):
    coach = config.coaches_coll.find_one({"_id": ObjectId(coach_id)})

    if not coach:
        raise HTTPException(status_code=404, detail="Entrenador no encontrado")

    return config.templates.TemplateResponse("edit_trainer.html", {
        "request": request,
        "coach": {
            "id": str(coach["_id"]),
            "auth_user_id": coach["auth_user_id"],
            "name": coach["name"],
            "phone": coach["phone"],
            "email": coach["email"],
            "hiring_date": coach["hiring_date"]
        }
    })

@router.post("/sports_chiefs/register")
async def register_sports_director(
    auth_user_id: str = Form(...),
    name: str = Form(...),
    email: str = Form(...),
    role: str = Form(...),
    admission_date: date = Form(...)
):
    director_data = {
        "auth_user_id": auth_user_id,
        "name": name,
        "email": email,
        "role": role,
        "admission_date": admission_date.isoformat()
    }
    config.sports_chief_coll.insert_one(director_data)
    return RedirectResponse(
        "/dashboard", 
        status_code=303
    )

def get_athletes():
    athletes = config.athletes_coll.find()
    return [
        {
            "id": str(athlete["_id"]),
            "auth_user_id": athlete["auth_user_id"],
            "name": athlete["name"],
            "major": athlete["major"],
            "birth_day": athlete["birth_day"],
            "admission_date": athlete["admission_date"],
            "disciplines": [get_sport(discipline) for discipline in athlete["disciplines"]],
            "status": athlete["status"]
        } for athlete in athletes
    ]

@router.get("/athletes/edit/{athlete_id}")
async def edit_athlete_form(request: Request, athlete_id: str):
    athlete = config.athletes_coll.find_one({"_id": ObjectId(athlete_id)})

    if not athlete:
        raise HTTPException(status_code=404, detail="Atleta no encontrado")

    return config.templates.TemplateResponse("edit_athlete.html", {
        "request": request,
        "athlete": {
            "id": str(athlete["_id"]),
            "name": athlete["name"],
            "major": athlete["major"],
            "birth_day": athlete["birth_day"],
            "admission_date": athlete["admission_date"],
            "disciplines": athlete["disciplines"],
            "status": athlete["status"]
        }
    })

@router.post("/athletes/{athlete_id}/update")
async def update_athlete(
    athlete_id: str,
    name: Annotated[str, Form()],
    major: Annotated[str, Form()],
    birth_day: Annotated[str, Form()],
    admission_date: Annotated[str, Form()],
    status: Annotated[str, Form()],
    request: Request
):
    updated_data = {
        "name": name,
        "major": major,
        "birth_day": birth_day,
        "admission_date": admission_date,
        "status": status
    }

    config.athletes_coll.update_one(
        {"_id": ObjectId(athlete_id)},
        {"$set": updated_data}
    )

    return RedirectResponse(url="/dashboard", status_code=303)

@router.get("/athletes/delete/{athlete_id}")
async def delete_athlete(athlete_id: str):
    athlete = config.athletes_coll.find_one({"_id": ObjectId(athlete_id)})
    if not athlete:
        raise HTTPException(status_code=404, detail="Atleta no encontrado")

    config.athletes_coll.delete_one({"_id": ObjectId(athlete_id)})

    return RedirectResponse(url="/dashboard", status_code=303)


def get_sport(sport_id: str):
    sport = config.sports_coll.find_one({"_id": ObjectId(sport_id)})
    if sport:
        return {
            "id": str(sport["_id"]),
            "name": sport["name"],
            "description": sport["description"],
            "schedule": sport["schedule"],
            "location": sport["location"],
            "coaches": sport["coaches"],
            "athletes_limit": sport["athletes_limit"]
        }
    return None

@router.get("/edit/sport/{sport_id}")
async def edit_sport_form(request: Request, sport_id: str):
    sport = config.sports_coll.find_one({"_id": ObjectId(sport_id)})

    if not sport:
        raise HTTPException(status_code=404, detail="Deporte no encontrado")

    return config.templates.TemplateResponse("edit_sport.html", {
        "request": request,
        "sport": {
            "id": str(sport["_id"]),
            "name": sport["name"],
            "description": sport["description"],
            "schedule": sport["schedule"],
            "location": sport["location"],
            "coaches": sport.get("coaches", []),
            "athletes_limit": sport["athletes_limit"]
        },
        "coaches_list": get_coaches()
    })

@router.post("/edit/sport/{sport_id}")
async def update_sport(
    sport_id: str,
    name: str = Form(...),
    description: str = Form(...),
    location: str = Form(...),
    athletes_limit: int = Form(...),
    coaches: List[str] = Form(...),

):
    result = config.sports_coll.update_one(
        {"_id": ObjectId(sport_id)},
        {
            "$set": {
                "name": name,
                "description": description,
                "location": location,
                "athletes_limit": athletes_limit,
                "coaches": coaches
            }
        }
    )

    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Deporte no encontrado")

    return RedirectResponse(url="/dashboard", status_code=303)


def get_coaches():
    coaches = config.coaches_coll.find()
    return [
        {
            "id": str(coach["_id"]),
            "auth_user_id": coach["auth_user_id"],
            "name": coach["name"],
            "phone": coach["phone"],
            "email": coach["email"],
            "hiring_date": coach["hiring_date"]
        } for coach in coaches
    ]

def get_coach(coach_id: str):
    coach = config.coaches_coll.find_one({"_id": ObjectId(coach_id)})
    if coach:
        return {
            "id": str(coach["_id"]),
            "auth_user_id": coach["auth_user_id"],
            "name": coach["name"],
            "phone": coach["phone"],
            "email": coach["email"],
            "hiring_date": coach["hiring_date"]
        }
    return None

def get_sports_chiefs():
    sports_chiefs = config.sports_chief_coll.find()
    return [
        {
            "id": str(sports_chief["_id"]),
            "auth_user_id": sports_chief["auth_user_id"],
            "name": sports_chief["name"],
            "email": sports_chief["email"],
            "role": sports_chief["role"],
            "admission_date": sports_chief["admission_date"]
        } for sports_chief in sports_chiefs
    ]

@router.post("/register/sport")
async def register_sport(
    name: str = Form(...),
    description: str = Form(...),
    schedule: List[str] = Form(...),
    location: str = Form(...),
    coaches: List[str] = Form(...),
    athletes_limit: int = Form(...)
):
    sport_data = {
        "name": name,
        "description": description,
        "schedule": schedule,
        "location": location,
        "coaches": coaches,
        "athletes_limit": athletes_limit
    }
    config.sports_coll.insert_one(sport_data)
    return RedirectResponse(
        "/dashboard", 
        status_code=303
    )

def get_sports():
    sports = config.sports_coll.find()
    return [
        {
            "id": str(sport["_id"]),
            "name": sport["name"],
            "description": sport["description"],
            "schedule": sport["schedule"],
            "location": sport["location"],
            "coaches": [
                coach_data
                for coach in sport["coaches"]
                if (coach_data := get_coach(coach)) is not None
            ],
            "athletes_limit": sport["athletes_limit"]
        } for sport in sports
    ]

def get_my_sports(current_user):
    my_sports = config.athletes_coll.find_one({"auth_user_id": current_user["auth_user_id"]})
    if my_sports:
        discipline_ids = [ObjectId(id) for id in my_sports["disciplines"]]
        selected_sports = [
            {
                "id": str(sport["_id"]),
                "name": sport["name"],
                "description": sport["description"],
                "schedule": sport["schedule"],
                "location": sport["location"],
                "coaches": [
                coach_data
                    for coach in sport["coaches"]
                    if (coach_data := get_coach(coach)) is not None
                ],
                "athletes_limit": sport["athletes_limit"]
            } for sport in config.sports_coll.find({"_id": {"$in": discipline_ids}})
        ]
        return selected_sports
    return []

@router.get("/sports/signin/{sport_id}")
async def sign_in_sport(
        request: Request,
        sport_id: str,
        current_user = Depends(get_current_user)
    ):

    config.athletes_coll.update_one(
        {"auth_user_id": current_user["auth_user_id"]},
        {"$addToSet": {"disciplines": sport_id}}
    )

    return RedirectResponse(
        "/dashboard", 
        status_code=303
    )

@router.get("/sports/unsign/{sport_id}")
async def unsign_sport(
        request: Request,
        sport_id: str,
        current_user = Depends(get_current_user)
    ):
    
    config.athletes_coll.update_one(
        {"auth_user_id": current_user["auth_user_id"]},
        {"$pull": {"disciplines": sport_id}}
    )

    return RedirectResponse(
        "/dashboard", 
        status_code=303
    )

@router.get("/sports/delete/{sport_id}")
async def delete_sport(
        request: Request,
        sport_id: str,
        current_user = Depends(get_current_user)
    ):
    
    config.sports_coll.delete_one({"_id": ObjectId(sport_id)})

    return RedirectResponse(
        "/dashboard", 
        status_code=303
    )

@router.get("/chat/{user_id}")
async def chat(
    request: Request,
    user_id: str,
    current_user = Depends(get_current_user)
):
    sender_id = str(current_user["auth_user_id"])
    receiver_id = user_id

    chat = await get_or_create_chat(sender_id, receiver_id)
    mensajes = chat.get("messages", [])

    return config.templates.TemplateResponse("chat.html", {
        "request": request,
        "current_user": current_user,
        "user_id": user_id,
        "mensajes": mensajes
    })

def store_message(sender_id: str, receiver_id: str, message: str):
    chat = get_or_create_chat(sender_id, receiver_id)
    chat_id = str(chat["_id"])
    message_data = {
        "sender_id": sender_id,
        "receiver_id": receiver_id,
        "message": message,
        "timestamp": datetime.now().isoformat()
    }
    config.chat_coll.update_one(
        {"_id": ObjectId(chat_id)},
        {"$push": {"messages": message_data}}
    )

async def get_or_create_chat(user1_id: str, user2_id: str):
    chat = config.chat_coll.find_one({
        "users": {"$all": [user1_id, user2_id]}
    })

    if not chat:
        chat_data = {
            "users": [user1_id, user2_id],
            "messages": [],
            "created_at": datetime.utcnow()
        }
        result = config.chat_coll.insert_one(chat_data)
        chat = config.chat_coll.find_one({"_id": result.inserted_id})

    return chat

async def validate_user_session(websocket: WebSocket, access_token: str):
    if not access_token:
        raise WebSocketException(1008, "No se proporcionó token de acceso.")

    try:
        payload = jwt.decode(access_token, os.getenv("SECRET_KEY"), algorithms=["HS256"])
        user_id: str = payload.get("sub")
        if not user_id:
            raise WebSocketException(1008, "Token inválido: falta sub.")
    except JWTError:
        raise WebSocketException(1008, "Error al decodificar el token.")

    user = config.users_auth_coll.find_one({"_id": ObjectId(user_id)})
    if not user:
        raise WebSocketException(1008, "Usuario no encontrado.")

    match user["role"]:
        case 2:
            kind_of_user = config.athletes_coll.find_one({"auth_user_id": user_id})
        case 1:
            kind_of_user = config.coaches_coll.find_one({"auth_user_id": user_id})
        case 0:
            kind_of_user = config.sports_chief_coll.find_one({"auth_user_id": user_id})
        case _:
            raise WebSocketException(1008, "Rol inválido.")

    if kind_of_user is None:
        raise WebSocketException(1008, "Perfil incompleto.")

    return kind_of_user




app.include_router(router)