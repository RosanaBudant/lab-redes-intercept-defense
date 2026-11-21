# Relatório final — Interceptação e defesa de um protocolo de aplicação

**Disciplina:** Laboratório de Redes de Computadores — PUCRS, 2026/2  
**Grupo:** Rosana Schreiner Budant, Luísa Kirsch Silva Zarth e Leonardo Nunes Pasa  
**Versão:** consolida os resultados já validados das Fases 1 e 2 e as evidências
da Fase 3 coletadas em Ubuntu/WSL em 20/11/2026 (execução
`fase3_20261120_183111`).

## Resumo

O trabalho implementa um protocolo TCP de texto claro, demonstra a exposição
de seus dados por escuta passiva, mostra a possibilidade de alteração de
mensagens por um proxy intermediário e apresenta uma versão protegida com TLS.
Na versão protegida, o cliente valida o certificado e o nome do servidor, e o
servidor mantém hashes de senha em memória. As evidências da Fase 3 mostram que
o conteúdo da aplicação não aparece em claro nas capturas TLS, que o cliente
rejeita um certificado não confiável e que, ao forçar o proxy MITM da Fase 2 em
modo alterador sobre a conexão protegida, o handshake TLS não se completa e o
servidor não aceita valor adulterado. A análise também identifica limites que
TLS não resolve, em especial replay de comandos na camada de aplicação,
exposição de metadados e comprometimento dos próprios pontos finais.

As Fases 1 e 2 já foram apresentadas e validadas; não foram reexecutadas para
este relatório. Seus resultados são referenciados pelos relatórios anteriores.
As evidências novas são exclusivas da Fase 3 e estão em
[`evidencias/fase3_20261120_183111/`](evidencias/fase3_20261120_183111/).
As capturas foram analisadas com TShark 4.2.2; a interface gráfica do
Wireshark não está instalada neste ambiente. Imagens comparativas de apoio
(Antes/Depois) estão em [`evidencias/prints/`](evidencias/prints/).

## 1. Objetivo e escopo

O objetivo foi demonstrar, em ambiente controlado, três propriedades:

1. **Fase 1 — confidencialidade:** em TCP sem TLS, observar comandos,
   credenciais e valores da aplicação.
2. **Fase 2 — integridade e autenticação:** posicionar um proxy entre cliente e
   servidor, ler e alterar uma mensagem, e observar que o protocolo original
   não detecta a alteração.
3. **Fase 3 — defesa e detecção:** proteger a conexão com TLS, validar o
   certificado do servidor, verificar o que o intermediário ainda consegue
   observar, registrar sinais úteis para detecção e verificar o comportamento
   diante de certificado não confiável e de tentativa de intermediação ativa.

O serviço é um repositório chave-valor com os comandos `LOGIN`, `SET`, `GET`,
`DEL` e `QUIT`. O protocolo usa mensagens de texto terminadas por nova linha.

## 2. Ambiente e método

As capturas novas foram feitas em Ubuntu/WSL, com cliente, servidor e
observador locais, comunicando-se pela loopback (`127.0.0.1`). Portanto, elas
representam um laboratório local controlado, não uma rede física com três
máquinas. A captura raw da interface `lo` pode mostrar cada pacote duas vezes,
uma na transmissão e outra na recepção. O coletor
[`capturar_evidencias.py`](capturar_evidencias.py) registra somente testes da
Fase 3 e usa TShark para numerar e inspecionar os quadros.

O roteiro comparativo a registrar é:

| Fase | Escopo deste relatório | Evidência |
|---|---|---|
| 1 | Resultado previamente apresentado e validado; não repetido | [Relatório da Fase 1](../Relatorio_Fase1.pdf) |
| 2 | Resultado previamente apresentado e validado; não repetido | [Relatório da Fase 2](../Relatorio_Fase2.pdf) e [documento de concorrência](../fase2-mitm/CONCORRENCIA.md) |
| 3 | TLS direto, rejeição de certificado não confiável, TLS via proxy transparente e tentativa de MITM alterador | PCAPs, logs e [`RESULTADOS.txt`](evidencias/fase3_20261120_183111/RESULTADOS.txt) em `evidencias/fase3_20261120_183111/` |

Os PCAPs novos da Fase 3 são separados por cenário. Não foram geradas novas
capturas das Fases 1 e 2.

## 3. Resultados por fase

### 3.1. Fase 1 — escuta passiva

Conforme o resultado previamente apresentado pelo grupo, o serviço original
aceita TCP sem TLS e o sniffer raw consegue recuperar comandos, credenciais e
valores em texto claro.

**Referências do projeto:** [servidor da Fase 1](../fase1-sniffer/server.py),
[sniffer da Fase 1](../fase1-sniffer/sniffer.py) e
[relatório da Fase 1](../Relatorio_Fase1.pdf).

### 3.2. Fase 2 — interceptação ativa

Conforme o resultado previamente apresentado pelo grupo, o cliente conectou ao
proxy na porta 8888, que encaminhou a sessão ao servidor na porta 9999. O proxy
alterou `SET cor azul` para `SET cor vermelho` e o cliente recebeu
`OK vermelho`.

O documento de concorrência da Fase 2 registra um teste de carga com 20
clientes atendidos e nenhuma falha. Esse resultado deve ser citado como
resultado documentado pelo grupo, junto com a evidência correspondente, e não
como uma nova execução realizada para este relatório.

**Conclusão:** sem uma proteção criptográfica de integridade e autenticação, um
intermediário capaz de alterar o fluxo pode adulterar comandos sem que o
protocolo de aplicação original detecte a mudança.

**Referências do projeto:** [proxy da Fase 2](../fase2-mitm/proxy.py),
[documento de concorrência](../fase2-mitm/CONCORRENCIA.md) e
[relatório da Fase 2](../Relatorio_Fase2.pdf).

### 3.3. Fase 3 — canal protegido e detecção

O cliente usa um contexto TLS com o certificado configurado como confiável e
passa o nome do servidor para validação. O certificado de teste é
autoassinado; ele só é aceito porque foi configurado explicitamente como
confiável pelo cliente. Uma cópia de certificado diferente não deve ser aceita
apenas por ter o mesmo nome.

O servidor usa TLS sobre o socket TCP. As senhas de teste são transformadas em
hash PBKDF2-HMAC-SHA256 com salt aleatório antes de compor o dicionário de
usuários em memória; a verificação usa `hmac.compare_digest`. Isso evita
armazenar as senhas em claro no dicionário em execução, mas as credenciais de
teste continuam escritas no código-fonte que inicializa o serviço. Elas não
devem ser reutilizadas fora do laboratório.

O servidor registra horário, origem e eventos técnicos, sem registrar senha nem
valor de armazenamento. A implementação atual inclui o nome de usuário nos
eventos de `LOGIN_OK`/`LOGIN_FALHOU` e registra apenas o tipo de comando em
`SET`, `GET` e `DEL` (sem a chave ou o valor). Nomes de usuário, quando
registrados, devem ser tratados como metadados potencialmente sensíveis ao
compartilhar logs. Entre os eventos registrados estão `HANDSHAKE_FALHOU`,
`CONEXAO_TLS`, `LOGIN_FALHOU`, `COMANDO_NAO_AUTENTICADO`,
`TIMEOUT_INATIVIDADE` e `ERRO_COMUNICACAO`.

**Resultados observados (execução `fase3_20261120_183111`, conforme [`RESULTADOS.txt`](evidencias/fase3_20261120_183111/RESULTADOS.txt)):**

- **TLS direto:** o cliente autenticou o servidor com
  `TLS_AES_256_GCM_SHA384 (TLSv1.3)`, executou `LOGIN`, `SET`, `GET` e `QUIT`
  com sucesso e obteve `OK azul`. O sniffer registrou 26 pacotes marcados como
  `[CIFRADO]` e nenhum `[TEXTO]`. O PCAP
  [`tls_direto.pcap`](evidencias/fase3_20261120_183111/tls_direto.pcap) contém
  quadros TLS 7, 11, 15, 17, 19, 21, 25, 29, 31, 33, 35, 37 e 39; os
  marcadores `senha123`, `SET cor azul` e `SET cor vermelho` não foram
  encontrados em texto claro.
- **Certificado não confiável:** ao conectar a um servidor de teste com
  certificado autoassinado diferente, o cliente encerrou com
  `CERTIFICATE_VERIFY_FAILED` (`self-signed certificate`), sem estabelecer
  sessão protegida. O servidor impostor recebeu alerta TLS `unknown ca`. O
  PCAP [`certificado_nao_confiavel.pcap`](evidencias/fase3_20261120_183111/certificado_nao_confiavel.pcap)
  contém apenas quadros de handshake (7, 11 e 15), sem marcadores em claro.
- **TLS via proxy transparente:** com o proxy repassando bytes sem interpretar
  mensagens, o TLS foi estabelecido de ponta a ponta entre cliente e servidor e
  o cliente obteve `OK azul` (`TLS_AES_256_GCM_SHA384 (TLSv1.3)`). O log do
  proxy contém bytes do protocolo TLS, sem comandos/credenciais em claro. O PCAP
  [`tls_via_proxy.pcap`](evidencias/fase3_20261120_183111/tls_via_proxy.pcap)
  contém quadros TLS 7, 17, 21, 25, 29, 31, 33, 35, 37, 39, 41, 43, 49, 53, 57,
  59, 61, 63, 65, 67, 69, 71, 73, 75, 77 e 79, sem marcadores em claro. Esse
  teste verifica confidencialidade através do intermediário; por ser
  transparente, não tenta adulterar registros.
- **Tentativa de MITM com proxy alterador (Fase 2, modo não transparente):** ao
  intermediar com o comportamento de alteração do proxy, o cliente não concluiu
  o handshake (timeout; sessão TLS não estabelecida) e o servidor registrou
  `HANDSHAKE_FALHOU` (`TimeoutError`). Não houve valor adulterado aceito pelo
  servidor, e a saída do proxy não exibiu comandos/credenciais da aplicação em
  claro. O PCAP
  [`tls_via_proxy_alterador.pcap`](evidencias/fase3_20261120_183111/tls_via_proxy_alterador.pcap)
  contém quadros 7 e 17, sem marcadores em claro. Esse resultado evidencia que a
  tentativa de intermediação/alteração não produziu uma operação adulterada
  aceita no serviço protegido (a sessão segura não foi concluída).

**Referências do projeto:** [servidor TLS](server_tls.py),
[cliente TLS](client_tls.py), [proxy de apoio da Fase 3](proxy.py),
[documentação da defesa](DEFESA_TLS.md) e [README do projeto](../README.md).

## 4. Análise de ameaças e detecção

| Ameaça ou sinal | O que a defesa oferece | O que observar |
|---|---|---|
| Sniffing do conteúdo da aplicação | TLS cifra os dados da sessão | Cliente/servidor completam TLS; captura/sniffer não revelam comandos nem credenciais (E3, E5) |
| Impostor apresentando outro certificado | O cliente confere cadeia de confiança e nome do servidor | Observado: `CERTIFICATE_VERIFY_FAILED` no cliente e alerta `unknown ca` no servidor impostor (E4) |
| Adulteração/intermediação ativa por proxy | TLS protege integridade autenticada; o proxy alterador não consegue concluir a sessão como intermediário válido | Observado: cliente em timeout, `HANDSHAKE_FALHOU` no servidor, sem valor adulterado aceito e sem comandos em claro no proxy (E6) |
| Falhas e tentativas de conexão incomuns | O servidor registra falha de handshake, origem e horário | Agrupamentos anormais de `HANDSHAKE_FALHOU`, timeouts ou erros |
| Acesso não autenticado | O serviço exige `LOGIN` antes de operações protegidas | Evento `COMANDO_NAO_AUTENTICADO` |
| Replay na camada de aplicação | **Não há defesa explícita** contra repetição de um comando válido em outra sessão | Repetições e resultados devem ser tratados pela aplicação; TLS não substitui nonce, identificador único ou controle de idempotência |

Uma conexão TLS bem-sucedida e a ausência de erros não provam, isoladamente,
que não houve tentativa de ataque. Os eventos devem ser correlacionados com
origem, horário, resultado do cliente e captura de rede. Também é importante
distinguir falha causada por incompatibilidade/comportamento do proxy de uma
falha de validação de certificado.

## 5. Limitações

- **Replay de aplicação:** TLS protege a sessão e a sequência de registros,
  mas o protocolo não implementa nonce, contador ou identificador de operação
  para rejeitar uma requisição válida repetida em outra sessão.
- **Metadados:** endereços IP, portas, horários, duração e volume aproximado
  continuam observáveis. Dados do handshake, como versão/cifra e, conforme a
  configuração, o nome SNI, também podem ser expostos.
- **Autenticação do cliente:** a implementação autentica o servidor pelo
  certificado; não implementa certificado de cliente (mTLS). O login da
  aplicação é separado.
- **Pontos finais e chave privada:** TLS não protege contra comprometimento
  do cliente ou servidor, nem contra exposição da chave privada. A chave deve
  ficar somente no servidor e fora do repositório.
- **Credenciais de demonstração:** os usuários e senhas de teste são
  definidos no código e não são adequados para produção.
- **Disponibilidade:** TLS não impede negação de serviço, saturação de
  conexões ou falhas do host/rede.
- **Ambiente:** loopback em um único Ubuntu/WSL não reproduz todos os efeitos de
  uma rede distribuída e pode duplicar pacotes na captura.
- **Alcance do teste de intermediação ativa:** o proxy alterador tentou
  encaminhar/modificar bytes do handshake/aplicação, mas não completou uma
  sessão TLS válida; o resultado observado foi bloqueio/falha de handshake, não
  uma alteração de registro TLS aceita pelo servidor. O teste demonstra que a
  tentativa não produziu operação adulterada aceita, dentro das condições desta
  coleta.

## 6. Registro de evidências

Os PCAPs abaixo foram gerados pelo coletor
[`capturar_evidencias.py`](capturar_evidencias.py). Os resultados consolidados
(filtros, quadros, códigos de saída e eventos) estão em
[`RESULTADOS.txt`](evidencias/fase3_20261120_183111/RESULTADOS.txt). Os logs
brutos por processo e as imagens comparativas de apoio estão na mesma pasta de
evidências ([`evidencias/fase3_20261120_183111/`](evidencias/fase3_20261120_183111/)
e [`evidencias/prints/`](evidencias/prints/)). O filtro `tcp.port == N`
restringe a conversa à porta correspondente; **Follow TCP Stream** permite
inspecionar os bytes da aplicação no Wireshark.

| ID | Captura / registros | Pacotes e filtro | Resultado |
|---|---|---|---|
| E1 — texto claro, Fase 1 | [Relatório apresentado da Fase 1](../Relatorio_Fase1.pdf) | Evidência original descrita no relatório; não recapturada |
| E2 — MITM em texto claro, Fase 2 | [Relatório apresentado da Fase 2](../Relatorio_Fase2.pdf) e [concorrência](../fase2-mitm/CONCORRENCIA.md) | Evidência original descrita nos documentos; não recapturada |
| E3 — TLS direto | [PCAP](evidencias/fase3_20261120_183111/tls_direto.pcap), [cliente](evidencias/fase3_20261120_183111/tls_cliente.txt), [servidor](evidencias/fase3_20261120_183111/tls_servidor.txt), [sniffer](evidencias/fase3_20261120_183111/tls_sniffer.txt) | Quadros TLS 7, 11, 15, 17, 19, 21, 25, 29, 31, 33, 35, 37 e 39; `tcp.port == 9999`; nenhum marcador em claro | Conexão autenticada (`TLS_AES_256_GCM_SHA384`, TLSv1.3), `GET` retornou `OK azul`; sniffer com 26 `[CIFRADO]` e 0 `[TEXTO]` |
| E4 — certificado não confiável | [PCAP](evidencias/fase3_20261120_183111/certificado_nao_confiavel.pcap), [cliente](evidencias/fase3_20261120_183111/certificado_nao_confiavel_cliente.txt), [impostor](evidencias/fase3_20261120_183111/certificado_impostor_servidor.txt) | Quadros TLS 7, 11 e 15; `tcp.port == 9998`; nenhum marcador em claro | Cliente reportou `CERTIFICATE_VERIFY_FAILED`; servidor impostor recebeu alerta `unknown ca` |
| E5 — TLS via proxy transparente | [PCAP](evidencias/fase3_20261120_183111/tls_via_proxy.pcap), [cliente](evidencias/fase3_20261120_183111/tls_proxy_cliente.txt), [servidor](evidencias/fase3_20261120_183111/tls_proxy_servidor.txt), [proxy](evidencias/fase3_20261120_183111/proxy_transparente.txt) | Quadros TLS 7, 17, 21, 25, 29, 31, 33, 35, 37, 39, 41, 43, 49, 53, 57, 59, 61, 63, 65, 67, 69, 71, 73, 75, 77 e 79; `tcp.port == 8888 || tcp.port == 9999`; nenhum marcador em claro | TLS ponta a ponta autenticado, cliente recebeu `OK azul`; proxy não expôs comandos/credenciais em claro |
| E6 — tentativa via proxy alterador (MITM Fase 2) | [PCAP](evidencias/fase3_20261120_183111/tls_via_proxy_alterador.pcap), [cliente](evidencias/fase3_20261120_183111/tls_proxy_alterador_cliente.txt), [servidor](evidencias/fase3_20261120_183111/tls_proxy_alterador_servidor.txt), [proxy](evidencias/fase3_20261120_183111/proxy_alterador.txt) | Quadros TLS 7 e 17; `tcp.port == 8888 || tcp.port == 9999`; nenhum marcador em claro | Cliente em timeout (sessão TLS não estabelecida), servidor com `HANDSHAKE_FALHOU` (`TimeoutError`), sem valor adulterado aceito e sem marcadores em claro no proxy |

O relatório foi conferido com TShark; como a interface gráfica do Wireshark
não está instalada nesta máquina, a análise desta coleta não inclui capturas
de tela da GUI (há imagens comparativas de apoio em
[`evidencias/prints/`](evidencias/prints/)). Os PCAPs podem ser abertos no
Wireshark com **File → Open** e os filtros indicados.

Para repetir no Ubuntu/WSL, com `openssl` e `tshark` instalados:

```bash
cd /mnt/d/lab-redes-intercept-defense/fase3-defense
sudo bash capturar_pcap_fase3.sh
```

O coletor grava cada execução em um subdiretório novo, gera certificados
temporários fora do repositório e encerra apenas os processos que ele próprio
iniciou.

## 7. Conclusão

Os resultados previamente apresentados documentam a exposição e adulteração
nas Fases 1 e 2. Nesta coleta da Fase 3, a captura TLS não revelou marcadores
da aplicação, o cliente rejeitou um certificado não confiável, o tráfego
atravessou um proxy transparente sem ser interpretado e a tentativa de
intermediação com proxy alterador não completou a sessão TLS nem produziu valor
adulterado aceito pelo servidor. TLS, contudo, não elimina replay na camada de
aplicação, exposição de metadados ou ameaças aos próprios pontos finais.
