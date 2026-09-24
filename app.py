import asyncio
import time
import httpx
import json
from collections import defaultdict
from functools import wraps
from flask import Flask, request, jsonify
from flask_cors import CORS
from cachetools import TTLCache
from typing import Tuple
from proto import FreeFire_pb2, main_pb2, AccountPersonalShow_pb2
from google.protobuf import json_format, message
from google.protobuf.message import Message
from Crypto.Cipher import AES
import base64
import random
from pathlib import Path
import os

# === Settings ===
MAIN_KEY = base64.b64decode('WWcmdGMlREV1aDYlWmNeOA==')
MAIN_IV = base64.b64decode('Nm95WkRyMjJFM3ljaGpNJQ==')
RELEASEVERSION = "OB55"
USERAGENT = "Dalvik/2.1.0 (Linux; U; Android 13; CPH2095 Build/RKQ1.211119.001)"
SUPPORTED_REGIONS = {"IND", "BR", "US", "SAC", "NA", "SG", "RU", "ID", "TW", "VN", "TH", "ME", "PK", "CIS", "BD", "EUROPE"}
REGION_ALIASES = {"EU": "EUROPE", "EUROPE": "EUROPE", "IN": "IND", "INDIA": "IND", "BRAZIL": "BR", "BANGLADESH": "BD", "PAKISTAN": "PK", "VIETNAM": "VN", "THAILAND": "TH", "INDONESIA": "ID", "SINGAPORE": "SG", "TAIWAN": "TW", "MIDDLEEAST": "ME"}
HTTP_TIMEOUT = httpx.Timeout(30.0, connect=10.0, read=25.0, write=10.0, pool=10.0)
HTTP_RETRIES = 2
# Optional profile API base URL override. Leave unset to use the serverUrl returned by MajorLogin.
# NOTE: client.ind.freefiremobile.com is a client domain and is NOT used automatically as a player-info API.
PROFILE_SERVER_BASE_URL = os.getenv("PROFILE_SERVER_BASE_URL", "").strip().rstrip("/")

# === Flask App Setup ===
app = Flask(__name__)
CORS(app)
cache = TTLCache(maxsize=100, ttl=300)
cached_tokens = defaultdict(dict)

# === Helper Functions ===
def pad(text: bytes) -> bytes:
    padding_length = AES.block_size - (len(text) % AES.block_size)
    return text + bytes([padding_length] * padding_length)

def aes_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    aes = AES.new(key, AES.MODE_CBC, iv)
    return aes.encrypt(pad(plaintext))

def decode_protobuf(encoded_data: bytes, message_type: message.Message) -> message.Message:
    instance = message_type()
    instance.ParseFromString(encoded_data)
    return instance

async def json_to_proto(json_data: str, proto_message: Message) -> bytes:
    json_format.ParseDict(json.loads(json_data), proto_message)
    return proto_message.SerializeToString()

def get_account_credentials(region: str) -> str:
    r = REGION_ALIASES.get(region.upper(), region.upper())
    if r == "IND":
        return "uid=6057084560&password=38E530C925EEC2ED2CE12EFDD050E3ECC4CF0B28B1CBEC77B24DF0EA4C669992"
    elif r in {"BR", "US", "SAC", "NA"}:
        return "uid=3692292847&password=FC22F6812C850FF7D8DB8C5474A106B6FE22CB10C0A6673837216A32675E5649"
    elif r == "VN":
        return "uid=3686689562&password=AD9C4A2B51A749481913F72A36F68A9F231520E9AC29B244DB47A64FD7353A12"
    elif r == "SG":
        return "uid=3692265171&password=A2A5E3C252A35B2BB30698BD1469A759417A68A069CF6980ED959EB01D352E28"
    elif r == "ID":
        return "uid=3692307512&password=4AA06E1DB3F998ABDBDA74578D26B0C84700EC5C079751E7C8F1626048DDBCAE"
    elif r == "TH":
        return "uid=3692333198&password=0ED64C5A89E09B8BE538829B0304FE5F5F7EA3BBE645A341C73ECA49143D2211"
    elif r == "BD":
        return "uid=4300481629&password=08F2965340E6972C2C52716C2046EB858D7ED89EB33BA56D6ACA4473D7834772"
    elif r == "TW":
        return "uid=3692312456&password=1A062FD700DA8F826AF84A37EE2B62121B79516AF71666949C72FFF42D1C554A"
    else:
        try:
            accounts_path = Path(__file__).resolve().parent / "accounts.txt"
            with accounts_path.open("r", encoding="utf-8") as f:
                lines = [line.strip() for line in f if line.strip()]
                if not lines:
                    raise ValueError("File accounts.txt trống.")
                uid, password = random.choice(lines).split()
                return f"uid={uid}&password={password}"
        except Exception as e:
            return f"ERROR: {e}"

# === Token Generation ===
async def http_post(url: str, *, data=None, headers=None, json_data=None):
    last_error = None
    for attempt in range(HTTP_RETRIES + 1):
        try:
            async with httpx.AsyncClient(timeout=HTTP_TIMEOUT, follow_redirects=True) as client:
                resp = await client.post(url, data=data, headers=headers, json=json_data)
                resp.raise_for_status()
                return resp
        except (httpx.TimeoutException, httpx.NetworkError, httpx.RemoteProtocolError) as exc:
            last_error = exc
            if attempt < HTTP_RETRIES:
                await asyncio.sleep(0.8 * (attempt + 1))
            else:
                raise
    raise last_error

async def get_access_token(account: str):
    url = "https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant"
    payload = account + "&response_type=token&client_type=2&client_secret=2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3&client_id=100067"
    headers = {'User-Agent': USERAGENT, 'Connection': "Keep-Alive", 'Accept-Encoding': "gzip", 'Content-Type': "application/x-www-form-urlencoded"}
    resp = await http_post(url, data=payload, headers=headers)
    data = resp.json()
    token = data.get("access_token")
    open_id = data.get("open_id")
    if not token or not open_id:
        raise ValueError("Token service response is missing access_token/open_id")
    return token, open_id

async def create_jwt(region: str):
    region = REGION_ALIASES.get(region.upper(), region.upper())
    account = get_account_credentials(region)
    if account.startswith("ERROR:"):
        raise RuntimeError("No account credentials configured for this region")
    token_val, open_id = await get_access_token(account)
    body = json.dumps({"open_id": open_id, "open_id_type": "4", "login_token": token_val, "orign_platform_type": "4"})
    proto_bytes = await json_to_proto(body, FreeFire_pb2.LoginReq())
    payload = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, proto_bytes)
    url = "https://loginbp.ppmainecoonghj.com/MajorLogin"
    headers = {'User-Agent': USERAGENT, 'Connection': "Keep-Alive", 'Accept-Encoding': "gzip",
               'Content-Type': "application/octet-stream", 'Expect': "100-continue", 'X-Unity-Version': "2018.4.11f1",
               'X-GA': "v1 1", 'ReleaseVersion': RELEASEVERSION}
    resp = await http_post(url, data=payload, headers=headers)
    msg = json.loads(json_format.MessageToJson(decode_protobuf(resp.content, FreeFire_pb2.LoginRes)))
    cached_tokens[region] = {
        'token': f"Bearer {msg.get('token','0')}",
        'region': msg.get('lockRegion','0'),
        'server_url': msg.get('serverUrl','0'),
        'expires_at': time.time() + 25200
    }

async def initialize_tokens():
    results = {}
    tasks = {r: asyncio.create_task(create_jwt(r)) for r in SUPPORTED_REGIONS}
    for region, task in tasks.items():
        try:
            await task
            results[region] = "ok"
        except Exception as exc:
            app.logger.warning("Token initialization failed for %s: %s", region, exc)
            results[region] = "failed"
    return results

async def refresh_tokens_periodically():
    while True:
        await asyncio.sleep(25200)
        await initialize_tokens()

async def get_token_info(region: str) -> Tuple[str,str,str]:
    info = cached_tokens.get(region)
    if info and time.time() < info['expires_at']:
        return info['token'], info['region'], info['server_url']
    await create_jwt(region)
    info = cached_tokens[region]
    return info['token'], info['region'], info['server_url']

async def GetAccountInformation(uid, unk, region, endpoint):
    region = REGION_ALIASES.get(region.upper(), region.upper())
    if region not in SUPPORTED_REGIONS:
        raise ValueError(f"Unsupported region: {region}")
    payload = await json_to_proto(json.dumps({'a': uid, 'b': unk}), main_pb2.GetPlayerPersonalShow())
    data_enc = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, payload)
    token, lock, server = await get_token_info(region)
    headers = {'User-Agent': USERAGENT, 'Connection': "Keep-Alive", 'Accept-Encoding': "gzip",
               'Content-Type': "application/octet-stream", 'Expect': "100-continue",
               'Authorization': token, 'X-Unity-Version': "2018.4.11f1", 'X-GA': "v1 1",
               'ReleaseVersion': RELEASEVERSION}
    base_url = PROFILE_SERVER_BASE_URL or server
    if not base_url or base_url == "0":
        raise RuntimeError("Login response did not include a profile server URL")
    if not base_url.startswith(("http://", "https://")):
        base_url = "https://" + base_url
    request_url = base_url.rstrip("/") + "/" + endpoint.lstrip("/")
    async with httpx.AsyncClient(timeout=HTTP_TIMEOUT) as client:
        resp = await client.post(request_url, data=data_enc, headers=headers)
        if resp.status_code >= 400:
            raise RuntimeError(f"Player-info upstream HTTP {resp.status_code}: {resp.text[:300]}")
        return json.loads(json_format.MessageToJson(decode_protobuf(resp.content, AccountPersonalShow_pb2.AccountPersonalShowInfo)))

# === Caching Decorator ===
def cached_endpoint(ttl=300):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*a, **k):
            key = (request.path, tuple(request.args.items()))
            if key in cache:
                return cache[key]
            res = fn(*a, **k)
            cache[key] = res
            return res
        return wrapper
    return decorator

# === Flask Routes ===
@app.route('/health', methods=['GET'])
def health():
    return jsonify({
        "status": "ok",
        "release_version": RELEASEVERSION,
        "supported_regions": sorted(SUPPORTED_REGIONS),
        "cached_regions": sorted(cached_tokens.keys()),
        "profile_server_override": bool(PROFILE_SERVER_BASE_URL)
    }), 200

@app.route('/player-info')
@cached_endpoint()
def get_account_info():
    region = request.args.get('region')
    uid = request.args.get('uid')

    # Pehle basic validation
    if not uid:
        return jsonify({"error": "Please provide UID."}), 400

    if not region:
        return jsonify({"error": "Please provide REGION."}), 400

    try:
        # API call
        return_data = asyncio.run(GetAccountInformation(uid, "7", region, "/GetPlayerPersonalShow"))

        # Agar data mila toh usko beautify karke bhejo
        formatted_json = json.dumps(return_data, indent=2, ensure_ascii=False)
        return formatted_json, 200, {'Content-Type': 'application/json; charset=utf-8'}

    except Exception as e:
        # Agar koi error aaye toh yeh catch karega
        app.logger.exception("Player-info request failed")
        return jsonify({
            "error": "Player info request failed.",
            "details": str(e),
            "uid": uid,
            "region": region.upper()
        }), 502

@app.route('/refresh', methods=['GET','POST'])
def refresh_tokens_endpoint():
    refresh_secret = os.getenv('REFRESH_SECRET')
    if refresh_secret and request.headers.get('X-Refresh-Secret') != refresh_secret:
        return jsonify({'error': 'Unauthorized'}), 401
    try:
        asyncio.run(initialize_tokens())
        return jsonify({'message':'Tokens refreshed for all regions.'}),200
    except Exception as e:
        return jsonify({'error': f'Refresh failed: {e}'}),500

# === Startup ===
async def startup():
    await initialize_tokens()
    asyncio.create_task(refresh_tokens_periodically())

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.getenv('PORT', '5000')), debug=False)
