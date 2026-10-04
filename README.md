# Interceptação e Defesa de um Protocolo de Aplicação

Trabalho da disciplina **Laboratório de Redes de Computadores** — PUCRS, 2026/2.

O projeto explora, em três fases, como um protocolo de aplicação pode ser observado e manipulado na rede, e como defendê-lo: começando pela escuta passiva, passando por um ataque *man-in-the-middle* e terminando com proteção via TLS e mecanismos de detecção.

## Fases

| Fase | Tema | Entrega | Status |
|------|------|---------|--------|
| 1 | Escuta passiva com sniffer em *raw socket* | 05/10/2026 | 🚧 Em andamento |
| 2 | Proxy MITM concorrente | 26/10/2026 | ⏳ Pendente |
| 3 | Defesa com TLS e detecção | 23/11/2026 | ⏳ Pendente |

### Fase 1 — Sniffer em raw socket
Captura passiva de pacotes diretamente de um *raw socket*, com decodificação dos cabeçalhos e extração do conteúdo do protocolo de aplicação.

| Componente | Arquivo | Status |
|------------|---------|--------|
| Servidor | `fase1-sniffer/server.py` | ✅ Implementado |
| Cliente | `fase1-sniffer/client.py` | ✅ Implementado |
| Sniffer | `fase1-sniffer/client.py` | ⏳ Em avaliação |

### Fase 2 — Proxy MITM concorrente
Proxy posicionado entre cliente e servidor, capaz de atender múltiplas conexões simultâneas, interceptando e (opcionalmente) alterando as mensagens trocadas.

### Fase 3 — Defesa com TLS e detecção
Proteção do canal com TLS e implementação de mecanismos para detectar tentativas de interceptação.

## Estrutura do repositório

```
.
├── fase1-sniffer/
│   ├── server.py      # Servidor do protocolo
│   ├── client.py      # Cliente (interativo ou roteiro automático)
│   └── sniffer.py     # Sniffer de pacotes TCP
│
└── README.md
```

As pastas `fase2-proxy/`, `fase3-defesa/` e `docs/` serão criadas conforme as próximas fases forem desenvolvidas.

## Requisitos

- Python 3 (somente biblioteca padrão, sem dependências externas)
- Linux para o sniffer (raw sockets exigem privilégios de root ou a capability `CAP_NET_RAW`); servidor e cliente rodam em qualquer sistema

## Protocolo de aplicação

Protocolo texto claro sobre TCP, porta padrão **`9999/tcp`**. Cada mensagem é uma linha terminada em `\n`, nos dois sentidos.

### Comandos (cliente → servidor)

| Comando | Descrição | Exige login |
|---------|-----------|:-----------:|
| `LOGIN usuario senha` | Autentica a sessão | — |
| `SET chave valor` | Grava um par chave/valor (o valor pode conter espaços) | ✔ |
| `GET chave` | Consulta o valor de uma chave | ✔ |
| `DEL chave` | Remove uma chave | ✔ |
| `QUIT` | Encerra a conexão | ✔ |

Os comandos não diferenciam maiúsculas de minúsculas (`get` = `GET`).

### Respostas (servidor → cliente)

| Resposta | Quando |
|----------|--------|
| `OK` | `LOGIN`, `SET` ou `DEL` executados com sucesso |
| `OK valor` | `GET` encontrou a chave |
| `OK tchauzinho;)` | `QUIT` — o servidor fecha a conexão em seguida |
| `Erro! Login invalido` | Usuário ou senha incorretos |
| `Erro! Nao autenticado` | Comando enviado antes de um `LOGIN` bem-sucedido |
| `Erro! Chave nao encontrada` | `GET` de uma chave inexistente |
| `Erro! Argumentos invalidos` | Número de argumentos errado |
| `Erro! Comando desconhecido` | Comando não reconhecido |

Regra geral: respostas que começam com `OK` indicam sucesso; respostas que começam com `Erro!` indicam falha.

### Comportamento do servidor

- Usuários de teste fixos no código: `alice` / `senha123` e `bob` / `12345`.
- Os dados ficam em memória, compartilhados entre as conexões, e se perdem ao reiniciar o servidor.
- O servidor atende **um cliente por vez**: uma segunda conexão espera até a primeira terminar.
- O log do servidor exibe as credenciais recebidas, o que ajuda a conferir o que o sniffer captura.
- O sniffer captura pacotes do protocolo TCP e apresenta determinados dados da seguinte forma:
PACOTE  N :
IP ORIGEM  |  IP DESTINO |    TEMPO   | DADOS CONTIDOS
xxx.x.x.x  |  xxx.x.x.x  |  HH:MM:SS  |  codificacão UTF-8 de Data

## Como executar

```bash
cd fase1-sniffer

# Terminal 1 — sniffer
sudo python3 sniffer.py

# Terminal 2 — servidor
python3 server.py

# Terminal 3 — cliente interativo
python3 client.py                        # conecta em 127.0.0.1:9999
python3 client.py --host 192.168.0.10    # servidor em outra máquina


# Ou: roteiro automático (LOGIN → SET → GET → DEL → GET → QUIT),
# útil para gerar tráfego previsível para o sniffer
python3 client.py --roteiro
python3 client.py --roteiro --usuario bob --senha 12345 --pausa 1

```

Opções do cliente: `--host`, `--porta`, `--roteiro`, `--usuario`, `--senha`, `--pausa` (segundos entre comandos no roteiro). Use `python3 client.py -h` para ver a ajuda.

## Integrantes

- Rosana Schreiner Budant — [@RosanaBudant](https://github.com/RosanaBudant)
- Luísa Kirsch Silva Zarth — [@LuisaZarth](https://github.com/LuisaZarth)
- Leonardo Nunes Pasa — [@LeoPasa](https://github.com/LeoPasa)

## Aviso

Este projeto tem finalidade exclusivamente acadêmica. As técnicas de interceptação devem ser usadas apenas em ambiente de laboratório controlado, sobre tráfego próprio e com autorização. Interceptar comunicações de terceiros sem consentimento é ilegal.