import base45
import cbor2
import json
import re
import sqlite3
from datetime import datetime
from typing import Optional
from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature

# ==============================================================================
# 1. CONFIGURAÇÃO DA APLICAÇÃO E BANCO DE DADOS
# ==============================================================================
app = FastAPI(
    title="API de Autenticação Anti-Clonagem - Roko Ikigai",
    description="Serviço REST com verificação criptográfica ECDSA e controle de histórico de leituras.",
    version="2.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

DB_FILE = "validacoes.db"

def init_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS leituras (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            gtin TEXT NOT NULL,
            lote TEXT NOT NULL,
            serial TEXT NOT NULL,
            data_leitura TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()

_CHAVE_PRIVADA = ec.generate_private_key(ec.SECP256R1())
_CHAVE_PUBLICA = _CHAVE_PRIVADA.public_key()

@app.on_event("startup")
def startup_event():
    init_db()

# Configura a pasta static
app.mount("/static", StaticFiles(directory="static"), name="static")

# Redireciona quem acessa o link principal (/) para o HTML
@app.get("/")
def home():
    return FileResponse("static/inspetor_qr.html")

# ==============================================================================
# 2. SCHEMAS E MODELOS
# ==============================================================================
class ValidarQRRequest(BaseModel):
    qr_string: str = Field(..., description="String lida pelo scanner/câmera ou JSON colado")

class DadosLote(BaseModel):
    gtin: str
    lote: str
    serial: str
    data_fabricacao: str
    data_validade: str
    total_leituras: int

class ValidarQRResponse(BaseModel):
    autentico: bool
    status_code: str
    mensagem: str
    dados: Optional[DadosLote] = None

# ==============================================================================
# 3. EXTRAÇÃO E HIGIENIZAÇÃO DE PAYLOAD
# ==============================================================================
def extrair_payload_limpo(texto_bruto: str) -> str:
    texto = texto_bruto.strip()
    if texto.startswith("{") and texto.endswith("}"):
        try:
            dados_json = json.loads(texto)
            if "qr_string" in dados_json:
                texto = dados_json["qr_string"]
        except Exception:
            pass

    match = re.search(r'(LOTE:|SERIE:)[0-9A-Z $%*+\-./:]+', texto.upper())
    if match:
        return match.group(0).strip()

    return texto.replace('"', '').replace("'", "").replace("\n", "").replace("\r", "").strip().upper()

# ==============================================================================
# 4. ENDPOINTS DA API
# ==============================================================================
@app.get("/health", tags=["Infraestrutura"])
def health_check():
    return {"status": "ok", "servico": "validador-qr-anti-clonagem"}

@app.post("/api/v1/validar-qr", response_model=ValidarQRResponse, tags=["Validação"])
def validar_qr_code(body: ValidarQRRequest):
    string_processada = extrair_payload_limpo(body.qr_string)

    if string_processada.startswith("LOTE:"):
        payload_b45 = string_processada[5:].strip()
    elif string_processada.startswith("SERIE:"):
        payload_b45 = string_processada[6:].strip()
    else:
        payload_b45 = string_processada.strip()

    try:
        envelope_bytes = base45.b45decode(payload_b45)
        envelope = cbor2.loads(envelope_bytes)
        dados_lote_raw = envelope[1]
        sig_raw_64 = envelope[2]
        dados_cbor_bytes = cbor2.dumps(dados_lote_raw)
    except Exception as e:
        return ValidarQRResponse(
            autentico=False,
            status_code="FORMATO_INVALIDO",
            mensagem=f"QR Code malformado ou corrompido: {str(e)}",
            dados=None
        )

    try:
        r = int.from_bytes(sig_raw_64[:32], 'big')
        s = int.from_bytes(sig_raw_64[32:], 'big')
        sig_der = utils.encode_dss_signature(r, s)

        _CHAVE_PUBLICA.verify(
            sig_der,
            dados_cbor_bytes,
            ec.ECDSA(hashes.SHA256())
        )
    except InvalidSignature:
        return ValidarQRResponse(
            autentico=False,
            status_code="FRAUDE",
            mensagem="❌ ALERTA DE FRAUDE: Assinatura digital inválida! QR Code alterado.",
            dados=None
        )

    gtin = str(dados_lote_raw.get(1, ""))
    lote = str(dados_lote_raw.get(2, ""))
    data_fab = str(dados_lote_raw.get(3, ""))
    data_val = str(dados_lote_raw.get(4, ""))
    serial = str(dados_lote_raw.get(5, "SEM-SERIAL"))

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    cursor.execute(
        "SELECT COUNT(*) FROM leituras WHERE gtin = ? AND lote = ? AND serial = ?",
        (gtin, lote, serial)
    )
    leituras_anteriores = cursor.fetchone()[0]

    cursor.execute(
        "INSERT INTO leituras (gtin, lote, serial, data_leitura) VALUES (?, ?, ?, ?)",
        (gtin, lote, serial, datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    )
    conn.commit()
    conn.close()

    total_leituras = leituras_anteriores + 1

    if total_leituras == 1:
        return ValidarQRResponse(
            autentico=True,
            status_code="VALIDO",
            mensagem="✅ Produto autêntico! Primeira leitura registrada no sistema.",
            dados=DadosLote(
                gtin=gtin,
                lote=lote,
                serial=serial,
                data_fabricacao=data_fab,
                data_validade=data_val,
                total_leituras=total_leituras
            )
        )
    else:
        return ValidarQRResponse(
            autentico=True,
            status_code="SUSPEITA_CLONAGEM",
            mensagem=f"⚠️ ALERTA DE SUSPEITA DE CLONAGEM: Este produto específico já foi lido {total_leituras} vezes!",
            dados=DadosLote(
                gtin=gtin,
                lote=lote,
                serial=serial,
                data_fabricacao=data_fab,
                data_validade=data_val,
                total_leituras=total_leituras
            )
        )

@app.post("/api/v1/dev/gerar-qr-teste", tags=["Desenvolvimento"])
def gerar_qr_teste(
    gtin: str = "7891234567890",
    lote: str = "LOTE-2026-VAL500",
    serial: str = "SN-00010042"
):
    dados = {
        1: gtin,
        2: lote,
        3: "2026-09-24",
        4: "2028-09-24",
        5: serial
    }
    dados_cbor = cbor2.dumps(dados)

    sig_der = _CHAVE_PRIVADA.sign(dados_cbor, ec.ECDSA(hashes.SHA256()))
    r, s = utils.decode_dss_signature(sig_der)
    sig_64 = r.to_bytes(32, 'big') + s.to_bytes(32, 'big')

    qr_str = "LOTE:" + base45.b45encode(cbor2.dumps({1: dados, 2: sig_64})).decode('utf-8')
    return {"qr_string": qr_str}

@app.get("/api/v1/dev/historico", tags=["Desenvolvimento"])
def ver_historico_leituras():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT id, gtin, lote, serial, data_leitura FROM leituras ORDER BY id DESC")
    linhas = cursor.fetchall()
    conn.close()

    historico = [
        {"id": l[0], "gtin": l[1], "lote": l[2], "serial": l[3], "data_leitura": l[4]}
        for l in linhas
    ]
    return {"total_registros": len(historico), "leituras": historico}

@app.delete("/api/v1/dev/leituras/{leitura_id}", tags=["Desenvolvimento"])
def deletar_leitura_por_id(leitura_id: int):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM leituras WHERE id = ?", (leitura_id,))
    linhas_afetadas = cursor.rowcount
    conn.commit()
    conn.close()

    if linhas_afetadas == 0:
        raise HTTPException(status_code=404, detail="ID não encontrado no banco de dados.")

    return {"mensagem": f"✅ Linha ID {leitura_id} excluída com sucesso!"}

@app.delete("/api/v1/dev/limpar-historico", tags=["Desenvolvimento"])
def limpar_todo_historico():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM leituras")
    conn.commit()
    conn.close()

    return {"mensagem": "🗑️ Todo o histórico de leituras foi apagado com sucesso!"}
