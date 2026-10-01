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

### Fase 2 — Proxy MITM concorrente
Proxy posicionado entre cliente e servidor, capaz de atender múltiplas conexões simultâneas, interceptando e (opcionalmente) alterando as mensagens trocadas.

### Fase 3 — Defesa com TLS e detecção
Proteção do canal com TLS e implementação de mecanismos para detectar tentativas de interceptação.

## Estrutura do repositório

```
.
├── fase1-sniffer/     # Sniffer em raw socket
├── fase2-proxy/       # Proxy MITM concorrente
├── fase3-defesa/      # TLS e detecção
├── docs/              # Relatórios, capturas e enunciados
└── README.md
```

## Requisitos

- Linux (raw sockets exigem privilégios de root ou a capability `CAP_NET_RAW`)
- <!-- Linguagem e versão, ex.: Python 3.x / gcc -->
- <!-- Dependências, se houver -->

## Protocolo de aplicação

Protocolo texto claro sobre TCP, mensagens terminadas em `\n`.

### Comandos (cliente → servidor)
| Comando               | Descrição                          |
|------------------------|-------------------------------------|
| `LOGIN usuario senha`  | Autentica a sessão                  |
| `SET chave valor`      | Grava um par chave/valor             |
| `GET chave`            | Consulta o valor de uma chave        |
| `DEL chave`            | Remove uma chave                     |
| `QUIT`                 | Encerra a conexão                    |

### Respostas (servidor → cliente)
| Resposta         | Significado                          |
|-------------------|----------------------------------------|
| `OK`              | Comando executado com sucesso          |
| `OK valor`        | Sucesso, retornando o valor (GET)       |
| `ERR mensagem`    | Falha (não autenticado, chave inexistente, etc.) |

### Porta padrão
`9999/tcp`

## Como executar

```bash
# Fase 1
cd fase1-sniffer
sudo <comando para rodar o sniffer>
```

<!-- Completar com as instruções de cada fase conforme forem implementadas -->
# Servidor (fase1-sniffer/server.py ou pasta equivalente)
python3 server.py


## Integrantes

- Rosana Schreiner Budant — [@RosanaBudant](https://github.com/RosanaBudant)
- Luísa Kirsch Silva Zarth - [@LuisaZarth](https://github.com/LuisaZarth)
- <!-- Nome — @usuario -->

## Aviso

Este projeto tem finalidade exclusivamente acadêmica. As técnicas de interceptação devem ser usadas apenas em ambiente de laboratório controlado, sobre tráfego próprio e com autorização. Interceptar comunicações de terceiros sem consentimento é ilegal.
