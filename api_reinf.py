import os
import re
import base64
import hashlib
import requests
from datetime import datetime, timezone
from lxml import etree
from cryptography import x509
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="Motor REINF API - Nuvem")

# Libera o acesso para o Google Sheets
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# O pacote que o Google Sheets vai enviar
class LoteReinf(BaseModel):
    cnpj: str
    tipo_evento: str
    xml_bruto: str
    cert_b64: str  # O arquivo .pfx transformado em texto
    cert_senha: str # A senha do certificado

# 1. FUNÇÃO: LER O CERTIFICADO DA MEMÓRIA RAM (Sem precisar de arquivo salvo)
def preparar_credenciais_memoria(pfx_b64, senha):
    pfx_dados = base64.b64decode(pfx_b64)
    p12 = pkcs12.load_key_and_certificates(pfx_dados, senha.encode())
    chave_privada, certificado, _ = p12
    
    cert_pem = certificado.public_bytes(serialization.Encoding.PEM)
    cert_der = certificado.public_bytes(serialization.Encoding.DER)
    chave_pem = chave_privada.private_bytes(
        serialization.Encoding.PEM, 
        serialization.PrivateFormat.PKCS8, 
        serialization.NoEncryption()
    )
    return chave_privada, cert_der, cert_pem, chave_pem

# 2. FUNÇÃO: ASSINATURA XADES ICP-BRASIL (O seu código genial!)
def assinar_xades_icp_brasil(xml_str, chave_privada, cert_der):
    xml_str = re.sub(r'<ds:Signature.*?</ds:Signature>', '', xml_str, flags=re.DOTALL)
    xml_root_temp = etree.fromstring(xml_str.encode('utf-8'), etree.XMLParser(remove_blank_text=True))
    
    elemento_assinado = None
    id_str = ""
    for elem in xml_root_temp.iter():
        for attr in elem.attrib:
            if attr.lower() == 'id':
                elemento_assinado = elem
                id_str = elem.attrib[attr]
                break
        if elemento_assinado is not None:
            break
    
    if elemento_assinado is None:
        elemento_assinado = xml_root_temp
        
    uri_str = f"#{id_str}" if id_str else ""

    xml_c14n = etree.tostring(elemento_assinado, method="c14n", exclusive=True, with_comments=False)
    digest_xml = base64.b64encode(hashlib.sha256(xml_c14n).digest()).decode('utf-8')

    cert = x509.load_der_x509_certificate(cert_der)
    cert_b64 = base64.b64encode(cert_der).decode('utf-8')
    cert_digest = base64.b64encode(hashlib.sha256(cert_der).digest()).decode('utf-8')
    issuer_attrs = cert.issuer.rfc4514_string()
    serial = cert.serial_number
    agora = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    signature_xml = f'''<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Id="Signature-1">
        <ds:SignedInfo>
            <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
            <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
            <ds:Reference URI="{uri_str}">
                <ds:Transforms>
                    <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
                    <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
                </ds:Transforms>
                <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                <ds:DigestValue>{digest_xml}</ds:DigestValue>
            </ds:Reference>
            <ds:Reference Type="http://uri.etsi.org/01903#SignedProperties" URI="#xades-1">
                <ds:Transforms>
                    <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
                </ds:Transforms>
                <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                <ds:DigestValue>DUMMY_XADES_DIGEST</ds:DigestValue>
            </ds:Reference>
        </ds:SignedInfo>
        <ds:SignatureValue>DUMMY_SIGNATURE_VALUE</ds:SignatureValue>
        <ds:KeyInfo>
            <ds:X509Data>
                <ds:X509Certificate>{cert_b64}</ds:X509Certificate>
            </ds:X509Data>
        </ds:KeyInfo>
        <ds:Object>
            <xades:QualifyingProperties xmlns:xades="http://uri.etsi.org/01903/v1.3.2#" Target="#Signature-1">
                <xades:SignedProperties Id="xades-1">
                    <xades:SignedSignatureProperties>
                        <xades:SigningTime>{agora}</xades:SigningTime>
                        <xades:SigningCertificate>
                            <xades:Cert>
                                <xades:CertDigest>
                                    <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                                    <ds:DigestValue>{cert_digest}</ds:DigestValue>
                                </xades:CertDigest>
                                <xades:IssuerSerial>
                                    <ds:X509IssuerName>{issuer_attrs}</ds:X509IssuerName>
                                    <ds:X509SerialNumber>{serial}</ds:X509SerialNumber>
                                </xades:IssuerSerial>
                            </xades:Cert>
                        </xades:SigningCertificate>
                        <xades:SignaturePolicyIdentifier>
                            <xades:SignaturePolicyId>
                                <xades:SigPolicyId>
                                    <xades:Identifier Qualifier="OIDAsURN">urn:oid:2.16.76.1.7.1.6.2.4</xades:Identifier>
                                </xades:SigPolicyId>
                                <xades:SigPolicyHash>
                                    <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                                    <ds:DigestValue>V1oxev3+Z5tia7oVifHtePiXskTb6LP9K1QE2u1zoV4=</ds:DigestValue>
                                </xades:SigPolicyHash>
                            </xades:SignaturePolicyId>
                        </xades:SignaturePolicyIdentifier>
                    </xades:SignedSignatureProperties>
                </xades:SignedProperties>
            </xades:QualifyingProperties>
        </ds:Object>
    </ds:Signature>'''

    xml_str_com_sig = re.sub(r'(</[^>]*Reinf>)', f'{signature_xml}\\1', xml_str)
    xml_root = etree.fromstring(xml_str_com_sig.encode('utf-8'), etree.XMLParser(remove_blank_text=True))

    signed_props_node = xml_root.find('.//{http://uri.etsi.org/01903/v1.3.2#}SignedProperties')
    xades_c14n = etree.tostring(signed_props_node, method="c14n", exclusive=True, with_comments=False)
    digest_xades = base64.b64encode(hashlib.sha256(xades_c14n).digest()).decode('utf-8')

    xades_ref_node = xml_root.xpath(".//ds:Reference[@URI='#xades-1']/ds:DigestValue", namespaces={'ds': 'http://www.w3.org/2000/09/xmldsig#'})[0]
    xades_ref_node.text = digest_xades

    signed_info_node = xml_root.find('.//{http://www.w3.org/2000/09/xmldsig#}SignedInfo')
    signed_info_c14n = etree.tostring(signed_info_node, method="c14n", exclusive=True, with_comments=False)
    
    signature_bytes = chave_privada.sign(signed_info_c14n, padding.PKCS1v15(), hashes.SHA256())
    signature_b64 = base64.b64encode(signature_bytes).decode('utf-8')

    sig_value_node = xml_root.find('.//{http://www.w3.org/2000/09/xmldsig#}SignatureValue')
    sig_value_node.text = signature_b64

    return xml_root

# 3. A ROTA DE TRANSMISSÃO
@app.post("/transmitir")
def transmitir_xml(lote: LoteReinf):
    try:
        # 1. Tira o certificado do texto Base64
        chave_privada, cert_der, cert_pem, chave_pem = preparar_credenciais_memoria(lote.cert_b64, lote.cert_senha)
        
        # 2. Ajusta as TAGS de Identificação do Governo (seu código)
        xml_str = lote.xml_bruto
        nr_insc_match = re.search(r'<nrInsc>(\d+)</nrInsc>', xml_str)
        nr_insc = nr_insc_match.group(1) if nr_insc_match else lote.cnpj[:8]
        
        old_id_match = re.search(r'(?i)id="(ID\d+)"', xml_str)
        if old_id_match:
            old_id = old_id_match.group(1)
            cnpj_raiz_14 = nr_insc[:8].ljust(14, '0') 
            agora_id = datetime.now().strftime("%Y%m%d%H%M%S")
            id_evento = f"ID1{cnpj_raiz_14}{agora_id}00001"
            xml_str = xml_str.replace(old_id, id_evento)
        else:
            id_evento = "ID_NAO_ENCONTRADO"

        tp_insc_match = re.search(r'<tpInsc>(\d)</tpInsc>', xml_str)
        tp_insc = tp_insc_match.group(1) if tp_insc_match else "1"
        if tp_insc == '1' and len(nr_insc) > 8: nr_insc = nr_insc[:8]

        # 3. Assina Criptograficamente o XML
        evento_assinado = assinar_xades_icp_brasil(xml_str, chave_privada, cert_der)
        evento_assinado_bytes = etree.tostring(evento_assinado, encoding='utf-8', xml_declaration=False)
        evento_assinado_str = evento_assinado_bytes.decode('utf-8')

        # 4. Envelopa para o Lote Assíncrono do e-CAC
        lote_xml_str = f"""<?xml version="1.0" encoding="utf-8"?>
<Reinf xmlns="http://www.reinf.esocial.gov.br/schemas/envioLoteEventosAssincrono/v1_00_00">
  <envioLoteEventos>
    <ideContribuinte>
      <tpInsc>{tp_insc}</tpInsc>
      <nrInsc>{nr_insc}</nrInsc>
    </ideContribuinte>
    <eventos>
      <evento Id="{id_evento}">
        {evento_assinado_str}
      </evento>
    </eventos>
  </envioLoteEventos>
</Reinf>"""
        lote_xml_bytes = lote_xml_str.encode('utf-8')

        # 5. Salva chaves rapidamente só para criar a conexão HTTPS segura
        caminho_cert = f"/tmp/cert_{lote.cnpj}.pem"
        caminho_key = f"/tmp/key_{lote.cnpj}.pem"
        # Se for no windows (para teste local), salva na mesma pasta
        if os.name == 'nt':
            caminho_cert, caminho_key = f"cert_{lote.cnpj}.pem", f"key_{lote.cnpj}.pem"

        with open(caminho_cert, 'wb') as f: f.write(cert_pem)
        with open(caminho_key, 'wb') as f: f.write(chave_pem)

        # 6. ENVIA PARA A RECEITA FEDERAL
        url_reinf = "https://reinf.receita.economia.gov.br/recepcao/lotes"
        res = requests.post(
            url_reinf, 
            data=lote_xml_bytes, 
            headers={'Content-Type': 'application/xml;charset=utf-8'}, 
            cert=(caminho_cert, caminho_key)
        )

        # 7. Apaga as chaves por segurança
        try:
            os.remove(caminho_cert)
            os.remove(caminho_key)
        except:
            pass

        # 8. Devolve a resposta pro Google Sheets
        if res.status_code == 201:
            prot_match = re.search(r'<protocoloEnvio>(.*?)</protocoloEnvio>', res.text)
            protocolo = prot_match.group(1) if prot_match else "Oculto"
            return {"sucesso": True, "protocolo": protocolo, "msg": f"O e-CAC recebeu o {lote.tipo_evento} e gerou o Protocolo: {protocolo}"}
        else:
            return {"sucesso": False, "erro": f"Rejeição do e-CAC:\n{res.text}"}

    except Exception as e:
        return {"sucesso": False, "erro": f"Erro Interno da API: {str(e)}"}
# ---------------------------------------------------------
# NOVA ROTA: CONSULTAR PROTOCOLO NO E-CAC
# ---------------------------------------------------------
class ConsultaReinf(BaseModel):
    cnpj: str
    protocolo: str
    cert_b64: str
    cert_senha: str

@app.post("/consultar")
def consultar_xml(consulta: ConsultaReinf):
    try:
        # 1. Pega o certificado da memória
        chave_privada, cert_der, cert_pem, chave_pem = preparar_credenciais_memoria(consulta.cert_b64, consulta.cert_senha)
        
        # 2. Rota oficial de Consulta do Governo
        url_consulta = f"https://reinf.receita.economia.gov.br/consulta/lotes/{consulta.protocolo}"
        
        # 3. Salva chaves temporárias para a conexão HTTPS
        caminho_cert = f"/tmp/cert_cons_{consulta.cnpj}.pem"
        caminho_key = f"/tmp/key_cons_{consulta.cnpj}.pem"
        if os.name == 'nt':
            caminho_cert, caminho_key = f"cert_cons_{consulta.cnpj}.pem", f"key_cons_{consulta.cnpj}.pem"

        with open(caminho_cert, 'wb') as f: f.write(cert_pem)
        with open(caminho_key, 'wb') as f: f.write(chave_pem)
        
        # 4. Faz a requisição de GET (Consulta)
        res = requests.get(url_consulta, cert=(caminho_cert, caminho_key))
        
        # Apaga os arquivos do certificado
        try:
            os.remove(caminho_cert)
            os.remove(caminho_key)
        except:
            pass
            
        xml_retorno = res.text
        
        # 5. Analisa a Resposta do Governo
        if "<cdResposta>2</cdResposta>" in xml_retorno or "<cdRetorno>0</cdRetorno>" in xml_retorno:
            recibo_match = re.search(r'<nrRecibo>(.*?)</nrRecibo>', xml_retorno)
            if not recibo_match: 
                recibo_match = re.search(r'<nrRecArqBase>(.*?)</nrRecArqBase>', xml_retorno)
            recibo = recibo_match.group(1) if recibo_match else "Recibo Oculto"
            
            return {"sucesso": True, "recibo": recibo, "xml_retorno": xml_retorno}
            
        elif "cdResposta>1<" in xml_retorno:
            return {"sucesso": False, "erro": "Lote ainda em processamento na fila da Receita. Tente novamente em alguns minutos."}
            
        else:
            return {"sucesso": False, "erro": f"Lote Rejeitado pelo e-CAC:\n{xml_retorno}"}
            
    except Exception as e:
        return {"sucesso": False, "erro": f"Erro Interno da API: {str(e)}"}
# ---------------------------------------------------------
# NOVA ROTA: EXTRATOR UNIVERSAL DE NOTAS FISCAIS
# ---------------------------------------------------------
class ConsultaNotas(BaseModel):
    cnpj_tomador: str
    data_ini: str
    data_fim: str
    portal: str # "SP_CAPITAL", "NACIONAL", "GINFES"
    cert_b64: str
    cert_senha: str

@app.post("/buscar_notas")
def buscar_notas(consulta: ConsultaNotas):
    try:
        chave_privada, cert_der, cert_pem, chave_pem = preparar_credenciais_memoria(consulta.cert_b64, consulta.cert_senha)
        notas_encontradas =[]

        # ========================================================
        # MOTOR 1: PREFEITURA DE SÃO PAULO (CAPITAL)
        # ========================================================
        if consulta.portal == "SP_CAPITAL":
            # Aqui entrará a requisição SOAP oficial da Nota Paulistana
            # Que usa o certificado A1 para baixar os XMLs
            
            # (Simulação do formato padronizado que o Python vai devolver)
            notas_encontradas.append({
                "nf": "555",
                "serie": "SN",
                "cnpj_prestador": "10611620000110",
                "nome_prestador": "ASTERSEG ELETRONICA LTDA",
                "emissao": "2026-05-10",
                "vencimento": "",
                "pagamento": "2026-05-10",
                "bruto": 1500.00,
                "base": 1500.00,
                "inss": 165.00,
                "ir": 0.0,
                "pcc": 69.75,
                "natureza": "15044",
                "cod_servico": "100000020"
            })

        # ========================================================
        # MOTOR 2: PORTAL NACIONAL DA NFS-E (MEIs)
        # ========================================================
        elif consulta.portal == "NACIONAL":
            # Aqui entrará a requisição para a API do Serpro/Portal Nacional
            pass

        return {"sucesso": True, "qtd": len(notas_encontradas), "notas": notas_encontradas}

    except Exception as e:
        return {"sucesso": False, "erro": str(e)}
