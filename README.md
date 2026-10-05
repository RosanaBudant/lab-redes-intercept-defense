# Interceptação e Defesa de um Protocolo de Aplicação

Trabalho da disciplina **Laboratório de Redes de Computadores** — PUCRS, 2026/2.

O projeto explora, em três fases, como um protocolo de aplicação em texto claro pode ser observado e manipulado na rede, e como defendê-lo: começando pela escuta passiva (sniffer), passando por um ataque *man-in-the-middle* e terminando com proteção via TLS e detecção do ataque.

## Fases

| Fase | Tema | Entrega | Status |
|------|------|---------|--------|
| 1 | Aplicação alvo + sniffer de tráfego (escuta passiva) | 05/10/2026 | ✅ Concluída |
| 2 | Proxy MITM concorrente | 26/10/2026 | ⏳ Pendente |
| 3 | Defesa (TLS) e detecção | 23/11/2026 | ⏳ Pendente |

## Fase 1 — Aplicação alvo e sniffer

| Componente | Arquivo | Descrição |
|------------|---------|-----------|
| Servidor | `fase1-sniffer/server.py` | Servidor TCP do protocolo (porta 9999) |
| Cliente | `fase1-sniffer/client.py` | Cliente interativo ou roteiro automático |
| Sniffer | `fase1-sniffer/sniffer.py` | Interceptador passivo em *raw socket* |
| Captura (auto) | `fase1-sniffer/capturar.sh` | Roda servidor + sniffer + cliente e grava a saída do sniffer |
| Evidência pcap | `fase1-sniffer/capturar_pcap.sh` | Gera `evidencia.pcap` (via tcpdump) para abrir no Wireshark |

## Topologia de testes

O enunciado pede, no mínimo, três máquinas: cliente, servidor e observador. Conforme combinado com a professora, o grupo montou esse ambiente dentro de um único **GitHub Codespace**, usando **três terminais** em vez de três VMs. Os três processos rodam na mesma máquina e se comunicam pela interface de *loopback* (`lo`, `127.0.0.1`), que é por onde o sniffer captura o tráfego.

```
          GitHub Codespace (um container Linux)
  +-------------------------------------------------+
  |  Terminal 1          Terminal 2      Terminal 3 |
  |  +---------+         +---------+    +---------+  |
  |  | servidor| <-----> | cliente |    | sniffer |  |
  |  |  :9999  |   TCP   |         |    | (raw)   |  |
  |  +----+----+         +----+----+    +----^----+  |
  |       |                   |              |       |
  |       +--- interface loopback (lo) ------+       |
  |              127.0.0.1  -  tudo em texto claro   |
  +-------------------------------------------------+
```

- **Servidor** (papel da VM-servidor): escuta em `0.0.0.0:9999`.
- **Cliente** (papel da VM-cliente): conecta em `127.0.0.1:9999`.
- **Sniffer** (papel da VM-observador): abre um *raw socket* (`AF_PACKET`/`SOCK_RAW`), lê os quadros da `lo`, decodifica os cabeçalhos IP e TCP e exibe o conteúdo da aplicação. Precisa de privilégio de root (`sudo`).

Observação sobre o loopback: cada mensagem aparece **duas vezes** na captura, porque a interface de loopback entrega o mesmo pacote no envio e na recepção. Isso é comportamento normal do `lo`, não duplicação de dados pelo programa.

## Requisitos

- Python 3 (somente biblioteca padrão, sem dependências externas).
- Linux com privilégio de root para o sniffer (*raw socket*). No Codespace, `sudo` já está disponível.
- `tcpdump` para gerar o `.pcap` da evidência (`sudo apt install tcpdump`).
- Wireshark (em qualquer máquina) para abrir o `.pcap`.

## Protocolo de aplicação

Protocolo texto claro sobre TCP, porta **9999/tcp**. Cada mensagem é uma linha terminada em `\n`, nos dois sentidos. É um repositório chave-valor com login simples — duas das sugestões do enunciado combinadas.

### Comandos (cliente -> servidor)

| Comando | Descrição | Exige login |
|---------|-----------|:-----------:|
| `LOGIN usuario senha` | Autentica a sessão | — |
| `SET chave valor` | Grava um par chave/valor (o valor pode conter espaços) | sim |
| `GET chave` | Consulta o valor de uma chave | sim |
| `DEL chave` | Remove uma chave | sim |
| `QUIT` | Encerra a conexão | sim |

Os comandos não diferenciam maiúsculas de minúsculas (`get` = `GET`).

### Respostas (servidor -> cliente)

| Resposta | Quando |
|----------|--------|
| `OK` | `LOGIN`, `SET` ou `DEL` com sucesso |
| `OK valor` | `GET` encontrou a chave |
| `OK tchauzinho;)` | `QUIT` — o servidor fecha a conexão em seguida |
| `Erro! Login invalido` | Usuário ou senha incorretos |
| `Erro! Nao autenticado` | Comando enviado antes de um `LOGIN` |
| `Erro! Chave nao encontrada` | `GET` de chave inexistente |
| `Erro! Argumentos invalidos` | Número de argumentos errado |
| `Erro! Comando desconhecido` | Comando não reconhecido |

Regra geral: respostas que começam com `OK` indicam sucesso; `Erro!` indica falha.

Usuários de teste fixos no código: `alice` / `senha123` e `bob` / `12345`. Os dados ficam em memória e se perdem ao reiniciar o servidor.

## Como executar

### Opção A — manual, com três terminais

```bash
cd fase1-sniffer

# Terminal 1 — servidor
python3 server.py

# Terminal 2 — sniffer (precisa de root)
sudo python3 sniffer.py

# Terminal 3 — cliente
python3 client.py --roteiro      # sequencia automatica LOGIN->SET->GET->DEL->QUIT
# ou:
python3 client.py                # modo interativo
```

Com o sniffer ligado no Terminal 2, ao rodar o cliente no Terminal 3 as credenciais e os valores aparecem em texto claro na tela do sniffer — demonstrando a quebra de confidencialidade.

### Opção B — automático (um terminal)

```bash
cd fase1-sniffer
bash capturar.sh
```

Sobe o servidor, liga o sniffer, roda o cliente e encerra tudo na ordem certa, gravando a saída do sniffer em `captura_sniffer.txt`.

### Gerar a evidência para o Wireshark

```bash
cd fase1-sniffer
bash capturar_pcap.sh
```

Gera `evidencia.pcap`. Baixe o arquivo e abra no Wireshark; aplique o filtro `tcp.port == 9999` e use **Follow -> TCP Stream** para ver a conversa em texto claro.

## Aviso

Projeto com finalidade exclusivamente acadêmica. As técnicas de interceptação devem ser usadas apenas em ambiente de laboratório controlado, sobre tráfego próprio e com autorização. Interceptar comunicações de terceiros sem consentimento é ilegal.

## Integrantes

- Rosana Schreiner Budant — [@RosanaBudant](https://github.com/RosanaBudant)
- Luísa Kirsch Silva Zarth — [@LuisaZarth](https://github.com/LuisaZarth)
- Leonardo Nunes Pasa — [@LeoPasa](https://github.com/LeoPasa)
