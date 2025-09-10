from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from fastapi import Request

app = FastAPI()

templates = Jinja2Templates(directory="templates")
app.mount("/static", StaticFiles(directory="static"), name="static")

# shared buffer
scrolled_text_data: list[str] = []
# connected clients
connections: list[WebSocket] = []

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse("_stt-index.html", {"request": request})

@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await ws.accept()
    connections.append(ws)
    # send initial contents
    await ws.send_json({"lines": scrolled_text_data})
    try:
        while True:
            msg = await ws.receive_json()
            action = msg.get("action")
            text = msg.get("text", "")
            if action == "append":
                scrolled_text_data.append(text)
            elif action == "clear":
                scrolled_text_data.clear()
            elif action == "remove_last":
                if scrolled_text_data:
                    scrolled_text_data.pop()
            # broadcast to all
            for conn in connections:
                await conn.send_json({"lines": scrolled_text_data})
    except WebSocketDisconnect:
        connections.remove(ws)

if __name__ == "__main__":
    import uvicorn
    import webbrowser
    port = 8080
    webbrowser.open_new(f"http://localhost:{port}")
    uvicorn.run(app, host="0.0.0.0", port=port)