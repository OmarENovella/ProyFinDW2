import uvicorn

def main():
    uvicorn.run("main:app", reload= True, port= 5000)

if __name__ == "__main__":
    main()