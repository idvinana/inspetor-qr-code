import base45
import cbor2
import os
from typing import Optional
from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature

# ==============================================================================
# 1. CONFIGURAÇÃO DA APLICAÇÃO E CORS
# ==============================================================================
app = FastAPI(
    title="API de Autenticação de QR Code de Lote",
    description="Serviço REST para validação offline/online de assinaturas criptográficas ECDSA P-256.",
    version="1.0.0"
)

# Libera CORS para permitir requisições de leitores Web / PWA / Mobile
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Em produção, restringir para seus domínios
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ==============================================================================
# 2. CARREGAMENTO DA CHAVE PÚBLICA DA FÁBRICA
# ==============================================================================
# Chave pública fictícia para teste em desenvolvimento (substitua pelo seu PEM real)
CHAVE_PUBLIC_PEM_TESTE = """-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE24uR8w2yG... (sua_chave_publica_aqui)
-----END PUBLIC KEY-----"""

# Em produção, você pode carregar de uma variável de ambiente ou arquivo PEM
CHAVE_PUBLICA: Optional[ec.EllipticCurvePublicKey] = None

@app.on_event("startup")
def startup_event():
    global CHAVE_PUBLICA
    # Tenta carregar a chave de uma variável de ambiente se existir
    pem_bytes = os.getenv("FABRICA_PUBLIC_KEY_PEM", "").encode('utf-8')
    if not pem_bytes:
        # Para fins de execução local/demo, se não houver env var, gera uma nova chave
        global _private_key_demo
        _private_key_demo = ec.generate_private_key(ec.SECP256R1())
        CHAVE_PUBLICA = _private_key_demo.public_key()
        print("⚠️ [DEV] Gerada nova Chave Pública temporária para os testes da API.")
    else:
        CHAVE_PUBLICA = serialization.load_pem_public_key(pem_bytes)
        print("✅ Chave Pública da Fábrica carregada com sucesso!")

# ==============================================================================
# 3. SCHEMAS PYDANTIC (MODELOS DE REQUISIÇÃO E RESPOSTA)
# ==============================================================================
class ValidarQRRequest(BaseModel):
    qr_string: str = Field(
        ...,
        description="String lida pelo scanner/câmera",
        example="LOTE:24.G884A3N...PAYLOAD_BASE45..."
    )

class DadosLote(BaseModel):
    gtin: str = Field(..., description="Código do produto (GTIN/EAN-13)")
    lote: str = Field(..., description="Identificador único do lote")
    data_fabricacao: str = Field(..., description="Data de fabricação (YYYY-MM-DD)")
    data_validade: str = Field(..., description="Data de validade (YYYY-MM-DD)")

class ValidarQRResponse(BaseModel):
    autentico: bool = Field(..., description="Indica se a assinatura matemática é válida")
    status_code: str = Field(..., description="Código do resultado (VALIDO, FRAUDE, FORMATO_INVALIDO)")
    mensagem: str = Field(..., description="Mensagem legível para exibição na tela do operador")
    dados: Optional[DadosLote] = Field(None, description="Dados decodificados do lote se o QR for autêntico")

# ==============================================================================
# 4. ENDPOINTS DA API
# ==============================================================================
@app.get("/health", tags=["Infraestrutura"])
def health_check():
    """Endpoint para monitoramento (Load Balancer / Kubernetes)."""
    return {"status": "ok", "servico": "validador-qr-lote"}


@app.post("/api/v1/validar-qr", response_model=ValidarQRResponse, tags=["Validação"])
def validar_qr_code(body: ValidarQRRequest):
    """
    Recebe a string lida do QR Code de Lote, decodifica a estrutura Base45/CBOR
    e verifica matematicamente a assinatura ECDSA P-256 da fábrica.
    """
    if not CHAVE_PUBLICA:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Chave pública da fábrica não foi inicializada no servidor."
        )

    qr_str = body.qr_string.strip()

    # 1. Tratar o prefixo
    if qr_str.startswith("LOTE:"):
        payload_b45 = qr_str[5:]
    else:
        payload_b45 = qr_str

    # 2. Tentar decodificar Base45 -> CBOR
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

    # 3. Converter a assinatura para o formato DER exigido pelo 'cryptography'
    try:
        r = int.from_bytes(sig_raw_64[:32], 'big')
        s = int.from_bytes(sig_raw_64[32:], 'big')
        sig_der = utils.encode_dss_signature(r, s)

        # 4. Verificação Matemática da Assinatura Digital
        CHAVE_PUBLICA.verify(
            sig_der,
            dados_cbor_bytes,
            ec.ECDSA(hashes.SHA256())
        )
        
        # Estruturar os dados no modelo Pydantic
        dados_formatados = DadosLote(
            gtin=str(dados_lote_raw.get(1, "")),
            lote=str(dados_lote_raw.get(2, "")),
            data_fabricacao=str(dados_lote_raw.get(3, "")),
            data_validade=str(dados_lote_raw.get(4, ""))
        )

        return ValidarQRResponse(
            autentico=True,
            status_code="VALIDO",
            mensagem="✅ Produto autêntico e assinado digitalmente pela fábrica.",
            dados=dados_formatados
        )

    except InvalidSignature:
        return ValidarQRResponse(
            autentico=False,
            status_code="FRAUDE",
            mensagem="❌ ALERTA DE FRAUDE: A assinatura digital é inválida! Este QR Code foi alterado ou clonado.",
            dados=None
        )


# Helper endpoint para gerar payloads de teste rápidos via Swagger
@app.post("/api/v1/dev/gerar-qr-teste", tags=["Desenvolvimento"])
def gerar_qr_teste(gtin: str = "7891234567890", lote: str = "LOTE-2026-VAL500"):
    """Gera um QR Code válido assinado com a chave privada de testes do servidor."""
    global _private_key_demo
    dados = {1: gtin, 2: lote, 3: "2026-09-24", 4: "2028-09-24"}
    dados_cbor = cbor2.dumps(dados)
    
    sig_der = _private_key_demo.sign(dados_cbor, ec.ECDSA(hashes.SHA256()))
    r, s = utils.decode_dss_signature(sig_der)
    sig_64 = r.to_bytes(32, 'big') + s.to_bytes(32, 'big')
    
    qr_str = "LOTE:" + base45.b45encode(cbor2.dumps({1: dados, 2: sig_64})).decode('utf-8')
    return {"qr_string": qr_str}