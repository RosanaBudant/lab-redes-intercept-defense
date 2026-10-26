# Modelo de Concorrência e Regiões Críticas — Fase 2

Trabalho de Laboratório de Redes de Computadores — PUCRS, 2026/2
Proxy MITM concorrente (Fase 2)

## 1. Objetivo

Este documento descreve como o proxy MITM e o servidor atendem múltiplas conexões
ao mesmo tempo, quais são os pontos em que threads diferentes acessam dados
compartilhados (as regiões críticas), como a robustez é garantida e qual evidência
comprova que a concorrência funciona.

## 2. Modelo de concorrência adotado: thread por conexão

Tanto o proxy quanto o servidor usam o modelo *thread por conexão*
(*thread-per-connection*): o laço principal fica bloqueado em `accept()` esperando
novas conexões e, a cada conexão que chega, cria uma nova thread para atendê-la,
voltando imediatamente a aceitar a próxima. Assim, nenhuma conexão trava as demais.

### 2.1. No servidor (`server.py`)

O laço principal aceita a conexão e dispara uma thread por cliente:

- `accept()` recebe a conexão.
- `threading.Thread(target=atender_cliente, ...)` cria a thread; `start()` a inicia.
- O laço volta na hora ao `accept()`, pronto para o próximo cliente.

Cada cliente é, portanto, atendido por **uma thread**. O estado de autenticação
(`autenticado`) é uma variável **local** de `atender_cliente`, de modo que cada
conexão tem o seu próprio — não há mistura de sessões.

### 2.2. No proxy (`proxy.py`)

O proxy usa threads em dois níveis:

1. Uma thread **por conexão de cliente**: o laço principal, a cada `accept()`,
   dispara `atender()` em uma thread.
2. Dentro de cada conexão, **duas threads de repasse** (uma por sentido):
   - `cliente -> servidor` (onde a modificação é aplicada);
   - `servidor -> cliente`.

As duas threads de repasse são coordenadas por um `threading.Event` (`encerrar`):
quando qualquer um dos sentidos termina (o cliente ou o servidor fecha a conexão),
o evento é sinalizado e a conexão é encerrada de forma ordenada, fechando os dois
sockets uma única vez.

## 3. Regiões críticas

Região crítica é todo trecho em que mais de uma thread acessa um mesmo dado
compartilhado. Foram identificadas as seguintes:

### 3.1. Dicionário `ARMAZENAMENTO` (servidor) — principal região crítica

O repositório chave-valor (`ARMAZENAMENTO`) é **compartilhado por todas as threads
de cliente**. Quando vários clientes executam `SET`, `GET` ou `DEL` ao mesmo tempo,
todos acessam o mesmo dicionário.

Por que o acesso é seguro no estado atual, mesmo sem um *lock* explícito: em CPython,
o *Global Interpreter Lock* (GIL) garante que operações individuais sobre um
dicionário — gravar uma chave (`d[k] = v`), ler (`d.get(k)`), remover (`d.pop(k)`) —
sejam **atômicas**, ou seja, não são interrompidas no meio. Como cada comando do
protocolo corresponde a **uma** dessas operações, não há risco de o dicionário ser
corrompido.

Limitação conhecida: o GIL **não** protege sequências compostas do tipo
ler-modificar-gravar. Se o protocolo ganhasse, por exemplo, um comando de
incremento (ler o valor, somar 1 e gravar), seria necessário proteger esse trecho
com um `threading.Lock`. Além disso, se dois clientes gravarem a **mesma** chave ao
mesmo tempo, vale a última gravação (*last-write-wins*) — isso é comportamento
esperado, não um defeito, mas é uma condição de corrida no sentido de que o
resultado final depende da ordem de escalonamento das threads.

### 3.2. Sockets de uma conexão (proxy)

As duas threads de repasse de uma mesma conexão compartilham os dois sockets
(o do cliente e o do servidor): uma lê de um e escreve no outro, e vice-versa. O
ponto delicado é o **encerramento**: quando uma thread fecha os sockets, a outra
pode estar no meio de um `recv`/`send`, o que gera o erro "Bad file descriptor".
Esse erro é tratado (ver seção 4) e não afeta outras conexões. O `threading.Event`
garante que o fechamento aconteça apenas uma vez.

### 3.3. Saída padrão (`print`)

Todas as threads escrevem no mesmo terminal. Isso pode fazer as linhas de log se
intercalarem, mas **não corrompe dados** — é apenas uma questão de legibilidade do
log, não uma região crítica que exija proteção.

## 4. Robustez

O requisito de robustez — lidar com desconexões e mensagens malformadas sem
derrubar as demais sessões — é atendido por:

- **Isolamento por thread**: cada conexão roda em suas próprias threads, então uma
  falha em uma conexão não afeta as outras.
- **Tratamento de exceções**: tanto `atender_cliente` (servidor) quanto as threads
  de repasse (proxy) estão envolvidos em `try/except OSError`. Uma desconexão
  abrupta ou um socket já fechado gera uma exceção que é capturada, encerrando
  apenas aquela conexão.
- **Mensagens malformadas**: o servidor sempre devolve uma resposta válida
  (`Erro! Comando desconhecido`, `Erro! Argumentos invalidos`) em vez de quebrar, e
  a decodificação tolerante a bytes inválidos evita que dados estranhos derrubem a
  thread.

## 5. Evidência: teste de carga

O script `teste_carga.py` dispara N clientes simultâneos (padrão 20), cada um
executando uma sessão completa (`LOGIN` -> `SET` -> `GET` -> `QUIT`) por chaves
distintas, e conta quantos foram atendidos com sucesso.

Resultado obtido:

```
[*] Clientes disparados : 20
[*] Atendidos com sucesso: 20
[*] Falharam             : 0
[*] Tempo total          : 0.10 s
```

Os logs do servidor e do proxy mostram as conexões **intercaladas** (um cliente é
atendido no meio do atendimento de outro), o que comprova que o atendimento é de
fato simultâneo, e não sequencial.

## 6. Limitações

- O modelo thread-por-conexão é simples e adequado à escala do trabalho, mas cria
  uma thread por conexão; para milhares de conexões simultâneas, um modelo baseado
  em `select`/`asyncio` escalaria melhor.
- Como discutido na seção 3.1, o acesso ao armazenamento é seguro para as operações
  atuais graças ao GIL, mas operações compostas futuras exigiriam um `Lock`.