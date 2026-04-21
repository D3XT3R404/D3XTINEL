from pathlib import Path
import os
import time
import joblib
import requests

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from urllib.parse import urlparse

from features import extract_features
from bs4 import BeautifulSoup

BASE_DIR = Path(__file__).resolve().parent
MODEL_PATH = BASE_DIR / "model.joblib"

load_dotenv()
VT_API_KEY = os.getenv("VT_API_KEY", "")
model = joblib.load(MODEL_PATH)

app = FastAPI(title="DEXTER Threat Detector")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class URLRequest(BaseModel):
    url: str

SAFE_DOMAINS = [
    "google.com",
    "youtube.com",
    "tiktok.com",
    "facebook.com",
    "instagram.com",
    "github.com",
    "microsoft.com",
    "openai.com",
    "whatsapp.com",
    "x.com",
    "twitter.com"
]


def vt_scan_url(url: str) -> dict:
    if not VT_API_KEY:
        raise HTTPException(status_code=500, detail="VT_API_KEY belum diisi di .env")

    headers = {
        "x-apikey": VT_API_KEY,
        "accept": "application/json",
    }

    r = requests.post(
        "https://www.virustotal.com/api/v3/urls",
        headers=headers,
        data={"url": url},
        timeout=30,
    )

    if r.status_code != 200:
        raise HTTPException(status_code=502, detail=f"VirusTotal submit gagal: {r.text}")

    analysis_id = r.json()["data"]["id"]

    for _ in range(30):
        g = requests.get(
            f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
            headers=headers,
            timeout=30,
        )

        if g.status_code != 200:
            raise HTTPException(status_code=502, detail=f"VirusTotal analisis gagal: {g.text}")

        data = g.json()["data"]
        attrs = data.get("attributes", {})

        if attrs.get("status") == "completed":
            return {
                "analysis_id": analysis_id,
                "status": "completed",
                "stats": attrs.get("stats", {}),
            }

        time.sleep(2)

    return {
        "analysis_id": analysis_id,
        "status": "pending",
        "stats": {},
    }


@app.get("/health")
def health():
    return {"ok": True}


@app.post("/api/check-url")
def check_url(req: URLRequest):

    url = req.url.strip()

    if not url.startswith(("http://","https://")):
        url = "https://" + url

    host = (urlparse(url).hostname or "").lower()


    # =====================
    # SAFE DOMAINS + SUBDOMAIN
    # =====================

    for d in SAFE_DOMAINS:

        if host==d or host.endswith("." + d):

            return {

                "url":url,

                "label":"benign",

                "confidence":0.98,

                "risk_score":0.05,

                "ml_probabilities":{
                    "benign":0.98,
                    "phishing":0.01,
                    "malware":0.00,
                    "potential_risky":0.00
                },

                "vt":{
                    "status":"trusted_domain",
                    "stats":{
                        "harmless":100
                    }
                },

                "reasons":[
                    "Domain masuk daftar terpercaya",
                    "Subdomain terpercaya ikut aman"
                ]
            }


    # =====================
    # MACHINE LEARNING
    # =====================

    feats = extract_features(url)

    probs = model.predict_proba([feats])[0]



    # =====================
    # VIRUSTOTAL
    # =====================

    vt = vt_scan_url(url)

    stats = vt["stats"]

    malicious = int(stats.get("malicious",0))
    suspicious = int(stats.get("suspicious",0))
    harmless = int(stats.get("harmless",0))
    undetected = int(stats.get("undetected",0))

    total = malicious+suspicious+harmless+undetected


    # =====================
    # ML RISK
    # =====================

    ml_risk = (
      probs[1]*0.70 +
      probs[2]*1.00 +
      probs[3]*0.60
    )
    if feats.get("has_homoglyph_brand"):
        ml_risk +=0.09

    if feats.get("has_punycode"):
        ml_risk +=0.10

    if feats.get("is_shortener"):
        ml_risk +=0.05
    
    

    # =====================
    # VT RISK
    # =====================

    vt_risk = 0

    if total>0:
        vt_risk = (
           malicious*1.0 +
           suspicious*0.6
        )/total


    # =====================
    # FUSION
    # 70 ML / 30 VT
    # =====================

    risk = (
      ml_risk*0.85 +
      vt_risk*0.15
    )


    # =====================
    # FINAL VERDICT
    # =====================

    sorted_probs = sorted(probs, reverse=True)
    top1 = float(sorted_probs[0])
    top2 = float(sorted_probs[1])
    gap = top1 - top2

    if top1>0.45 and gap> 0.10:
        label = "suspicious"
    elif probs[2]>0.68:
        label = "malware"
    elif probs[1]>0.64:
        label = "phishing"
    elif probs[3]>0.62:
        label = "potential_risky"
    elif risk>0.44:
        label = "suspicious"
    else:
        label = "benign"

    # =====================
    # CONFIDENCE
    # =====================

    confidence=float(max(probs))

    # =====================
    # REASONS
    # =====================

    reasons=[]

    if feats.get("has_ip"):
       reasons.append(
         "Hostname berupa IP address"
       )

    if feats.get("suspicious_words_count",0)>0:
       reasons.append(
         "Ada kata mencurigakan"
       )

    if malicious>0:
       reasons.append(
         "VirusTotal mendeteksi malicious"
       )

    if suspicious>0:
       reasons.append(
         "VirusTotal mendeteksi suspicious"
       )

    if vt_risk==0 and label=="benign":
       reasons.append(
         "VirusTotal tidak menemukan sinyal berbahaya"
       )


    return {

  "url":url,

  "label":label,

  "confidence":round(confidence,4),

  "risk_score":round(risk,4),

  "ml_probabilities":{
     "benign":float(probs[0]),
     "phishing":float(probs[1]),
     "malware":float(probs[2]),
     "potential_risky":float(probs[3])
  },

  "vt":{
     "analysis_id":vt.get("analysis_id"),
     "status":vt.get("status"),
     "stats":stats
  },

  "reasons":reasons,

  "security_warning":
  "Jangan klik link mencurigakan. Gunakan hasil ini sebagai referensi, bukan keputusan mutlak. Tetap waspada dan gunakan penilaian pribadi Anda. Dan selalu berhati-hati. Jangan memasukkan Informasi Identitas Pribadi (PII) di situs yang tidak terpercaya."

}