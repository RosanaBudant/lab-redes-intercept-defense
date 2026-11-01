# Fase 3 — Defesa com TLS e Autenticação

Parte 1 do trabalho: versão **protegida** do serviço (servidor + cliente),
usando TLS sobre o socket TCP, autenticação do servidor por certificado e
senhas armazenadas com hash. Neutraliza os ataques das Fases 1 (sniffer) e
2 (proxy MITM).

## Arquivos

| Arquivo | Descrição |
|---------|-----------|
| `server_tls.py` | Servidor do protocolo protegido com TLS (porta 9999) |
| `client_tls.py` | Cliente TLS que valida o certificado do servidor |
| `sniffer_tls.py` | Sniffer adaptado: mostra `[TEXTO]` ou `[CIFRADO]`, para a prova antes/depois |
| `servidor.crt` | Certificado público do servidor (pode ser versionado) |
| `servidor.key` | Chave privada do servidor — **NÃO** vai para o Git (gerada localmente) |

## Requisitos

- Python 3 (biblioteca padrão: `ssl`, `hashlib`, `hmac`, `socket`, `threading`).
- OpenSSL (para gerar o certificado).
- Linux com root para o sniffer (`sudo`).

## 1. Geração do certificado

A chave privada não é versionada, então cada ambiente gera o seu certificado.
Na pasta `fase3-defense`, execute:

```bash
openssl req -x509 -newkey rsa:2048 -keyout servidor.key -out servidor.crt -days 365 -nodes \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
```

Isso cria dois arquivos:

- `servidor.key` — **chave privada** (fica só no servidor; nunca compartilhar).
- `servidor.crt` — **certificado** (chave pública + identidade; o cliente usa para validar).

O `subjectAltName` (SAN) com `localhost` e `127.0.0.1` é obrigatório: o Python
valida o nome do servidor contra o SAN, não contra o CN. Para conferir:

```bash
openssl x509 -in servidor.crt -noout -ext subjectAltName
# deve mostrar: DNS:localhost, IP Address:127.0.0.1
```

## 2. Como executar o serviço protegido

```bash
# Terminal 1 — servidor TLS
cd fase3-defense && python3 server_tls.py

# Terminal 2 — cliente TLS
cd fase3-defense && python3 client_tls.py
```

Ao conectar, o cliente informa a cifra negociada (ex.: `TLS_AES_256_GCM_SHA384
(TLSv1.3)`) e que o servidor foi autenticado. Em seguida, os comandos do
protocolo funcionam normalmente (LOGIN, SET, GET, DEL, QUIT), agora cifrados.

Usuários de teste: `alice` / `senha123` e `bob` / `12345`.

## 3. Mecanismos de defesa implementados

- **Confidencialidade e integridade (TLS):** o canal é cifrado com TLS 1.3. O
  conteúdo (credenciais, comandos, valores) trafega ilegível.
- **Autenticação do servidor (certificado):** o cliente usa
  `create_default_context(Purpose.SERVER_AUTH, cafile="servidor.crt")` e
  `server_hostname`, validando a identidade do servidor. Um servidor que
  apresente outro certificado é recusado — impede o MITM se passar pelo servidor.
- **Senhas com hash:** o servidor nunca guarda senhas em texto. Cada senha é
  armazenada como `(salt, hash)`, usando PBKDF2-HMAC-SHA256 com 200.000
  iterações e salt aleatório por usuário. A verificação usa
  `hmac.compare_digest` (comparação em tempo constante).
- **Robustez:** handshake TLS feito por conexão em thread própria, com timeout
  de handshake e de inatividade, sem derrubar o servidor em caso de falha.

## 4. Demonstração da defesa (provas antes/depois)

### 4.1. O sniffer não lê mais (confidencialidade)

O `sniffer_tls.py` mostra `[TEXTO]` quando o conteúdo é legível e `[CIFRADO]`
(bytes em hexadecimal) quando não é.

**Antes (sem TLS)** — servidor e cliente da Fase 1:
```bash
# T1
cd fase1-sniffer && python3 server.py
# T2
cd fase3-defense && sudo python3 sniffer_tls.py
# T3
cd fase1-sniffer && python3 client.py
```
O sniffer mostra `[TEXTO] 'LOGIN alice senha123'` — conteúdo legível.

**Depois (com TLS)** — servidor e cliente protegidos:
```bash
# T1
cd fase3-defense && python3 server_tls.py
# T2
cd fase3-defense && sudo python3 sniffer_tls.py
# T3
cd fase3-defense && python3 client_tls.py
```
O sniffer mostra `[CIFRADO] 16 03 01 ...` — bytes do TLS, ilegíveis.

### 4.2. O cliente recusa um servidor impostor (autenticação)

Gera-se um certificado diferente (impostor) e sobe-se um servidor com ele. O
cliente, que confia apenas em `servidor.crt`, recusa a conexão com:
```
[!] FALHA NA VALIDACAO DO CERTIFICADO - conexao recusada.
    Motivo: [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed
```
Mesmo com o mesmo CN e SAN, o impostor não tem a identidade confiável — o MITM
é barrado.

### 4.3. O proxy MITM da Fase 2 não consegue mais atacar (integridade)

Com o cliente apontando ao proxy da Fase 2 (porta 8888) e o proxy encaminhando
ao servidor TLS (9999):
```bash
# T1
cd fase3-defense && python3 server_tls.py
# T2
cd fase2-mitm && python3 proxy.py
# T3
cd fase3-defense && python3 client_tls.py --porta 8888
```
O proxy passa a ver apenas bytes cifrados do handshake TLS (não mais
`[INTERCEPTADO] SET cor azul`), e a tentativa de interceptação resulta em falha
de handshake no servidor. O ataque de modificação da Fase 2 deixa de funcionar.

## Observação de segurança

A chave privada `servidor.key` está no `.gitignore` e **não** é enviada ao
repositório. O certificado `servidor.crt` é público e pode ser versionado. Os
arquivos de teste do impostor também são ignorados.
