# pip3 install fastapi uvicorn

from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
import requests


app = FastAPI()

API_HEADERS={"x-apikey": '8d6207f17fd3f6635078b3c642461f5194aafb67942c61eb14b0e0a0c3779ed6'}

@app.get('/check_url')
async def check_url(url: str):
    if not url:
        raise HTTPException(status_code=422, detail="Missing required parameter: url", headers={"Access-Control-Allow-Origin": "*"})
    
    # scan URL
    analysis_id = requests.post(
        url = 'https://www.virustotal.com/api/v3/urls',
        headers=API_HEADERS,
        data={"url": url}
    ).json()['data']['id']

    print(analysis_id)

    analysis = requests.get(
        url = f'https://www.virustotal.com/api/v3/analyses/{analysis_id}',
        headers=API_HEADERS
    ).json()

    return JSONResponse(
        content=analysis,
        headers={"access-control-allow-origin": "*"}
    )


if __name__ == '__main__':
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)
