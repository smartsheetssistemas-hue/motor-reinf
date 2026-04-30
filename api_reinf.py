from fastapi import FastAPI
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware
import time

app = FastAPI(title="Motor REINF API - Nuvem")

# Isso permite que o Google Sheets acesse a API sem ser bloqueado por segurança
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# O formato que o Google vai mandar
class LoteReinf(BaseModel):
    cnpj: str
    tipo_evento: str
    xml_bruto: str

# Rota principal de transmissão
@app.post("/transmitir")
def transmitir_xml(lote: LoteReinf):
    # AQUI DEPOIS VAMOS COLOCAR A SUA LÓGICA DE ASSINATURA ICP-BRASIL!
    # Por enquanto, ele apenas simula o sucesso para testarmos a ligação.
    
    return {
        "sucesso": True, 
        "protocolo": "PROT-CLOUD-999", 
        "msg": f"A NUVEM recebeu o {lote.tipo_evento} do CNPJ {lote.cnpj} com Sucesso!"
    }

# Rota de teste para ver se o servidor está vivo
@app.get("/")
def home():
    return {"status": "API REINF está ONLINE na Nuvem e pronta para o trabalho!"}