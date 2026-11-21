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

### 4.3. Tráfego protegido através do proxy da Fase 2

O proxy da Fase 2 foi implementado para interpretar mensagens terminadas por
`\n`. O fluxo TLS é binário, então o modo de alteração por linha não deve ser
usado para concluir que houve erro de validação do certificado: ele pode
esperar pelo delimitador ou encerrar sem estabelecer o túnel.

Para verificar que o proxy não consegue ler os comandos, use o modo transparente,
que repassa os bytes sem tentar interpretar ou alterar mensagens:
```bash
# T1
cd fase3-defense && python3 server_tls.py
# T2
cd fase2-mitm && python3 proxy.py --transparente
# T3
cd fase3-defense && python3 client_tls.py --porta 8888
```
O TLS continua sendo estabelecido entre o cliente e o servidor através do
proxy. O proxy deve observar somente bytes do TLS, sem exibir comandos ou
valores. Esse teste demonstra que o proxy de aplicação não interpreta o
conteúdo protegido. Por ser transparente, ele não tenta adulterá-lo e, portanto,
esta captura não é evidência de uma tentativa ativa de modificação.

O cliente também deve recusar um servidor que apresente certificado não
configurado como confiável (seção 4.2). Registre o erro real do cliente; não
atribua uma falha de encaminhamento do proxy à validação do certificado.

Para observar o comportamento diante de uma tentativa ativa de intermediação com
o proxy em modo alterador (Fase 2), use o proxy sem `--transparente` entre o
cliente TLS e o servidor TLS. O coletor de evidências da Fase 3
(`capturar_evidencias.py` / `capturar_pcap_fase3.sh`) inclui esse cenário: na
execução `evidencias/fase3_20261120_183111/`, o cliente não concluiu o handshake
(timeout), o servidor registrou `HANDSHAKE_FALHOU` e não houve valor adulterado
aceito nem exposição de comandos/credenciais em claro pelo proxy (ver
`RESULTADOS.txt` e `tls_via_proxy_alterador.pcap`).

Para repetir somente as capturas e testes de TLS desta etapa no Ubuntu/WSL:

```bash
cd /mnt/d/lab-redes-intercept-defense/fase3-defense
sudo bash capturar_pcap_fase3.sh
```

Cada execução cria um novo subdiretório em `evidencias/`, gera certificados
temporários fora do repositório e encerra apenas os processos que ela própria
iniciou.

## Observação de segurança

A chave privada `servidor.key` está no `.gitignore` e **não** é enviada ao
repositório. O certificado `servidor.crt` é público e pode ser versionado. Os
arquivos de teste do impostor também são ignorados.
