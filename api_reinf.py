import os
import re
import base64
import hashlib
import requests
import zeep
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

# O pacote que o Google Sheets vai enviar para o e-CAC
class LoteReinf(BaseModel):
    cnpj: str
    tipo_evento: str
    xml_bruto: str
    cert_b64: str  
    cert_senha: str 

# O pacote que o Google Sheets vai enviar para Consultar o e-CAC
class ConsultaReinf(BaseModel):
    cnpj: str
    protocolo: str
    cert_b64: str
    cert_senha: str

# O pacote que o Google Sheets vai enviar para Buscar Notas na Prefeitura
class ConsultaNotas(BaseModel):
    cnpj_tomador: str
    ccm: str
    data_ini: str
    data_fim: str
    portal: str
    cert_b64: str
    cert_senha: str


# =========================================================
# FUNÇÕES DE CERTIFICADO E ASSINATURA E-CAC
# =========================================================
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

# =========================================================
# ASSINADOR ESPECÍFICO PARA A PREFEITURA DE SP (XMLDSig Padrão)
# =========================================================
def assinar_xml_sp(xml_str, chave_privada, cert_der):
    xml_str = xml_str.replace('\n', '').replace('\r', '')
    xml_root = etree.fromstring(xml_str.encode('utf-8'))
    xml_c14n = etree.tostring(xml_root, method="c14n", exclusive=True, with_comments=False)
    digest_xml = base64.b64encode(hashlib.sha1(xml_c14n).digest()).decode('utf-8')

    cert_b64 = base64.b64encode(cert_der).decode('utf-8')

    signature_xml = f'''<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <ds:SignedInfo>
    <ds:CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315" />
    <ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1" />
    <ds:Reference URI="">
      <ds:Transforms>
        <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature" />
        <ds:Transform Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315" />
      </ds:Transforms>
      <ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1" />
      <ds:DigestValue>{digest_xml}</ds:DigestValue>
    </ds:Reference>
  </ds:SignedInfo>
  <ds:SignatureValue>DUMMY_SIGNATURE_VALUE</ds:SignatureValue>
  <ds:KeyInfo>
    <ds:X509Data>
      <ds:X509Certificate>{cert_b64}</ds:X509Certificate>
    </ds:X509Data>
  </ds:KeyInfo>
</ds:Signature>'''

    xml_str_com_sig = xml_str.replace('</p1:PedidoConsultaNFeRecebidas>', f'{signature_xml}</p1:PedidoConsultaNFeRecebidas>')
    xml_root_sig = etree.fromstring(xml_str_com_sig.encode('utf-8'))

    signed_info_node = xml_root_sig.xpath('.//*[local-name()="SignedInfo"]')[0]
    signed_info_c14n = etree.tostring(signed_info_node, method="c14n", exclusive=True, with_comments=False)
    
    signature_bytes = chave_privada.sign(signed_info_c14n, padding.PKCS1v15(), hashes.SHA1())
    signature_b64 = base64.b64encode(signature_bytes).decode('utf-8')

    sig_value_node = xml_root_sig.xpath('.//*[local-name()="SignatureValue"]')[0]
    sig_value_node.text = signature_b64

    return etree.tostring(xml_root_sig, encoding='utf-8').decode('utf-8')


# =========================================================
# ROTAS DO E-CAC (Transmissão e Consulta)
# =========================================================
@app.post("/transmitir")
def transmitir_xml(lote: LoteReinf):
    try:
        chave_privada, cert_der, cert_pem, chave_pem = preparar_credenciais_memoria(lote.cert_b64, lote.cert_senha)
        
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

        evento_assinado = assinar_xades_icp_brasil(xml_str, chave_privada, cert_der)
        evento_assinado_bytes = etree.tostring(evento_assinado, encoding='utf-8', xml_declaration=False)
        evento_assinado_str = evento_assinado_bytes.decode('utf-8')

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

        caminho_cert = f"/tmp/cert_{lote.cnpj}.pem"
        caminho_key = f"/tmp/key_{lote.cnpj}.pem"
        if os.name == 'nt':
            caminho_cert, caminho_key = f"cert_{lote.cnpj}.pem", f"key_{lote.cnpj}.pem"

        with open(caminho_cert, 'wb') as f: f.write(cert_pem)
        with open(caminho_key, 'wb') as f: f.write(chave_pem)

        url_reinf = "https://reinf.receita.economia.gov.br/recepcao/lotes"
        res = requests.post(url_reinf, data=lote_xml_bytes, headers={'Content-Type': 'application/xml;charset=utf-8'}, cert=(caminho_cert, caminho_key))

        try:
            os.remove(caminho_cert)
            os.remove(caminho_key)
        except: pass

        if res.status_code == 201:
            prot_match = re.search(r'<protocoloEnvio>(.*?)</protocoloEnvio>', res.text)
            protocolo = prot_match.group(1) if prot_match else "Oculto"
            return {"sucesso": True, "protocolo": protocolo, "msg": f"O e-CAC recebeu e gerou o Protocolo: {protocolo}"}
        else:
            return {"sucesso": False, "erro": f"Rejeição do e-CAC:\n{res.text}"}

    except Exception as e:
        return {"sucesso": False, "erro": f"Erro Interno da API: {str(e)}"}

@app.post("/consultar")
def consultar_xml(consulta: ConsultaReinf):
    try:
        chave_privada, cert_der, cert_pem, chave_pem = preparar_credenciais_memoria(consulta.cert_b64, consulta.cert_senha)
        
        url_consulta = f"https://reinf.receita.economia.gov.br/consulta/lotes/{consulta.protocolo}"
        
        caminho_cert = f"/tmp/cert_cons_{consulta.cnpj}.pem"
        caminho_key = f"/tmp/key_cons_{consulta.cnpj}.pem"
        if os.name == 'nt':
            caminho_cert, caminho_key = f"cert_cons_{consulta.cnpj}.pem", f"key_cons_{consulta.cnpj}.pem"

        with open(caminho_cert, 'wb') as f: f.write(cert_pem)
        with open(caminho_key, 'wb') as f: f.write(chave_pem)
        
        res = requests.get(url_consulta, cert=(caminho_cert, caminho_key))
        
        try:
            os.remove(caminho_cert)
            os.remove(caminho_key)
        except: pass
            
        xml_retorno = res.text
        
        if "<cdResposta>2</cdResposta>" in xml_retorno or "<cdRetorno>0</cdRetorno>" in xml_retorno:
            recibo_match = re.search(r'<nrRecibo>(.*?)</nrRecibo>', xml_retorno)
            if not recibo_match: recibo_match = re.search(r'<nrRecArqBase>(.*?)</nrRecArqBase>', xml_retorno)
            recibo = recibo_match.group(1) if recibo_match else "Recibo Oculto"
            return {"sucesso": True, "recibo": recibo, "xml_retorno": xml_retorno}
            
        elif "cdResposta>1<" in xml_retorno:
            return {"sucesso": False, "erro": "Lote ainda em processamento na fila da Receita. Tente novamente em alguns minutos."}
        else:
            return {"sucesso": False, "erro": f"Lote Rejeitado pelo e-CAC:\n{xml_retorno}"}
            
    except Exception as e:
        return {"sucesso": False, "erro": f"Erro Interno da API: {str(e)}"}

# =========================================================
# ROTA: EXTRATOR UNIVERSAL DE NOTAS FISCAIS (MODO ESPIÃO SP)
# =========================================================
@app.post("/buscar_notas")
def buscar_notas(consulta: ConsultaNotas):
    try:
        if not consulta.cert_senha: return {"sucesso": False, "erro": "A senha do certificado está vazia na planilha."}
        if not consulta.cert_b64 or len(consulta.cert_b64) < 100: return {"sucesso": False, "erro": "O arquivo .pfx não foi lido corretamente."}

        try:
            chave_privada, cert_der, cert_pem, chave_pem = preparar_credenciais_memoria(consulta.cert_b64, consulta.cert_senha)
        except Exception as err_cert:
            return {"sucesso": False, "erro": f"Certificado ou senha incorretos: {str(err_cert)}"}
        
        lista_de_notas = list()
        
        # ========================================================
        # MOTOR 1: PREFEITURA DE SÃO PAULO (CAPITAL) VIA ZEEP SOAP
        # ========================================================
        if consulta.portal == "SP_CAPITAL":
            if not consulta.ccm:
                return {"sucesso": False, "erro": "CCM obrigatório para Prefeitura de SP."}

            # 1. Salva as chaves para a conexão
            caminho_cert = f"/tmp/cert_busca_{consulta.cnpj_tomador}.pem"
            caminho_key = f"/tmp/key_busca_{consulta.cnpj_tomador}.pem"
            if os.name == 'nt':
                caminho_cert, caminho_key = f"cert_busca_{consulta.cnpj_tomador}.pem", f"key_busca_{consulta.cnpj_tomador}.pem"

            with open(caminho_cert, 'wb') as f: f.write(cert_pem)
            with open(caminho_key, 'wb') as f: f.write(chave_pem)

            # 2. Monta e Assina o Pedido
            pedido_xml = f'''<?xml version="1.0" encoding="UTF-8"?>
<p1:PedidoConsultaNFeRecebidas xmlns:p1="http://www.prefeitura.sp.gov.br/nfe">
  <CPFCNPJ>
    <CNPJ>{consulta.cnpj_tomador.zfill(14)}</CNPJ>
  </CPFCNPJ>
  <Inscricao>{consulta.ccm.zfill(8)}</Inscricao>
  <dtInicio>{consulta.data_ini}</dtInicio>
  <dtFim>{consulta.data_fim}</dtFim>
</p1:PedidoConsultaNFeRecebidas>'''

            pedido_assinado = assinar_xml_sp(pedido_xml, chave_privada, cert_der)
            pedido_assinado_limpo = pedido_assinado.replace('\n', '').replace('\r', '')

            # 3. CONEXÃO SOAP PROFISSIONAL (ZEEP)
            try:
                import urllib3
                from zeep.transports import Transport
                from requests import Session
                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
                
                # Prepara o "carteiro" (Session) com o Certificado Digital A1
                session = Session()
                session.cert = (caminho_cert, caminho_key)
                session.verify = False
                transport = Transport(session=session)
                
                # Lê o Manual (WSDL) direto da Prefeitura
                wsdl_url = "https://nfe.prefeitura.sp.gov.br/ws/lotenfe.asmx?wsdl"
                cliente_soap = zeep.Client(wsdl=wsdl_url, transport=transport)
                
                # Dispara a função ConsultaNFeRecebidas do Governo
                # Passando a "versaoSchema=1" e a "mensagemXML"
                resposta_sp = cliente_soap.service.ConsultaNFeRecebidas(1, pedido_assinado_limpo)
                
            except Exception as ez:
                return {"sucesso": False, "erro": f"Erro no Cliente SOAP: {str(ez)}"}

            finally:
                try:
                    os.remove(caminho_cert)
                    os.remove(caminho_key)
                except: pass

            # 4. TRATA A RESPOSTA (O Zeep já devolve o XML limpo!)
            if not resposta_sp:
                return {"sucesso": False, "erro": "A prefeitura devolveu uma resposta nula."}

            # Como o Zeep já extraiu o XML pra gente, a gente só precisa ler
            xml_retorno = etree.fromstring(resposta_sp.encode('utf-8'))
            
            # --- MODO DE INVESTIGAÇÃO (DEBUG) ---
            # Vamos cuspir o que o Zeep conseguiu ler da Prefeitura!
            return {"sucesso": False, "erro": f"XML DA PREFEITURA VIA ZEEP: {resposta_sp[:800]}"}
            
            if not xml_retorno_str:
                erros_api = soap_resp.xpath('//*[local-name()="Erro"]//*[local-name()="Descricao"]/text()')
                if erros_api: return {"sucesso": False, "erro": f"Erro API SP: {erros_api[0]}"}
                return {"sucesso": True, "qtd": 0, "notas": []} 

            # Descompacta o retorno
            xml_retorno = etree.fromstring(xml_retorno_str[0].encode('utf-8'))
            
            # Checa os Alertas da Prefeitura
            erros_sp = xml_retorno.xpath('//*[local-name()="Alerta"]')
            if erros_sp:
                msg_alerta = erros_sp[0].xpath('.//*[local-name()="Descricao"]/text()')[0]
                if "Nenhuma NFe" in msg_alerta or "Nenhum" in msg_alerta:
                    return {"sucesso": True, "qtd": 0, "notas": []}
                else:
                    return {"sucesso": False, "erro": f"Prefeitura recusou: {msg_alerta}"}

            # Varre as notas recebidas
            nfs = xml_retorno.xpath('//*[local-name()="NFe"]')
            
            for nf in nfs:
                num_nf = nf.xpath('.//*[local-name()="NumeroNFe"]/text()')[0]
                emissao_full = nf.xpath('.//*[local-name()="DataEmissaoNFe"]/text()')[0]
                emissao_dia = emissao_full[:10]
                
                cnpj_p = nf.xpath('.//*[local-name()="InscricaoPrestador"]/text()')
                cnpj_prestador = cnpj_p[0] if cnpj_p else "00000000000000"
                
                nome_p = nf.xpath('.//*[local-name()="RazaoSocialPrestador"]/text()')
                nome_prestador = nome_p[0] if nome_p else "PRESTADOR DESCONHECIDO"
                
                v_bruto = float(nf.xpath('.//*[local-name()="ValorServicos"]/text()')[0])
                
                v_inss = nf.xpath('.//*[local-name()="ValorINSS"]/text()')
                v_inss = float(v_inss[0]) if v_inss else 0.0
                
                v_ir = nf.xpath('.//*[local-name()="ValorIR"]/text()')
                v_ir = float(v_ir[0]) if v_ir else 0.0
                
                v_pis = nf.xpath('.//*[local-name()="ValorPIS"]/text()')
                v_pis = float(v_pis[0]) if v_pis else 0.0
                
                v_cof = nf.xpath('.//*[local-name()="ValorCOFINS"]/text()')
                v_cof = float(v_cof[0]) if v_cof else 0.0
                
                v_csll = nf.xpath('.//*[local-name()="ValorCSLL"]/text()')
                v_csll = float(v_csll[0]) if v_csll else 0.0

                cod = nf.xpath('.//*[local-name()="CodigoServico"]/text()')
                cod_servico = cod[0] if cod else ""

                lista_de_notas.append({
                    "nf": num_nf,
                    "serie": "SN",
                    "cnpj_prestador": cnpj_prestador,
                    "nome_prestador": nome_prestador,
                    "emissao": emissao_dia,
                    "vencimento": emissao_dia, 
                    "pagamento": emissao_dia,
                    "bruto": v_bruto,
                    "base": v_bruto,
                    "inss": v_inss,
                    "ir": v_ir,
                    "pcc": round(v_pis + v_cof + v_csll, 2),
                    "natureza": "15044", 
                    "cod_servico": cod_servico
                })

        elif consulta.portal == "NACIONAL":
            return {"sucesso": False, "erro": "A rota do Portal Nacional ainda está em construção."}

        return {"sucesso": True, "qtd": len(lista_de_notas), "notas": lista_de_notas}

    except Exception as e:
        return {"sucesso": False, "erro": f"Erro fatal no Extrator: {str(e)}"}
