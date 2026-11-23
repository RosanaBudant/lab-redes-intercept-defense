#!/usr/bin/env python3
"""Coleta somente as evidencias da Fase 3 em loopback."""

import os
import signal
import socket
import struct
import subprocess
import tempfile
import threading
import time
from datetime import datetime
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
FASE2 = ROOT / "fase2-mitm"
FASE3 = ROOT / "fase3-defense"
EVIDENCIAS = FASE3 / "evidencias"
COMANDOS = "LOGIN alice senha123\nSET cor azul\nGET cor\nQUIT\n"
processos = []


class CapturadorPcap:
    def __init__(self, arquivo, portas):
        self.arquivo = arquivo
        self.portas = set(portas)
        self.parar_evento = threading.Event()
        self.pronto = threading.Event()
        self.erro = None
        self.pacotes = 0
        self.socket = None
        self.thread = threading.Thread(target=self._capturar, daemon=True)

    def iniciar(self):
        self.thread.start()
        if not self.pronto.wait(timeout=5):
            raise RuntimeError("O socket raw nao iniciou a captura")
        if self.erro:
            raise RuntimeError(f"Falha ao iniciar a captura raw: {self.erro}")

    def _capturar(self):
        try:
            self.socket = socket.socket(
                socket.AF_PACKET,
                socket.SOCK_RAW,
                socket.htons(3),
            )
            self.socket.bind(("lo", 0))
            self.socket.settimeout(0.25)
            with open(self.arquivo, "wb") as saida:
                saida.write(
                    struct.pack(
                        "<IHHIIII",
                        0xA1B2C3D4,
                        2,
                        4,
                        0,
                        0,
                        65535,
                        1,
                    )
                )
                self.pronto.set()
                while not self.parar_evento.is_set():
                    try:
                        pacote = self.socket.recvfrom(65535)[0]
                    except socket.timeout:
                        continue
                    if not self._porta_alvo(pacote):
                        continue

                    agora = time.time()
                    segundos = int(agora)
                    microssegundos = int((agora - segundos) * 1_000_000)
                    saida.write(
                        struct.pack(
                            "<IIII",
                            segundos,
                            microssegundos,
                            len(pacote),
                            len(pacote),
                        )
                    )
                    saida.write(pacote)
                    self.pacotes += 1
                saida.flush()
        except Exception as erro:
            self.erro = erro
            self.pronto.set()
        finally:
            if self.socket:
                self.socket.close()

    def _porta_alvo(self, pacote):
        if len(pacote) < 14 or struct.unpack("!H", pacote[12:14])[0] != 0x0800:
            return False
        inicio_ip = 14
        tamanho_ip = (pacote[inicio_ip] & 0x0F) * 4
        if tamanho_ip < 20 or len(pacote) < inicio_ip + tamanho_ip + 20:
            return False
        if pacote[inicio_ip + 9] != 6:
            return False
        inicio_tcp = inicio_ip + tamanho_ip
        origem, destino = struct.unpack("!HH", pacote[inicio_tcp:inicio_tcp + 4])
        return origem in self.portas or destino in self.portas

    def parar(self):
        self.parar_evento.set()
        self.thread.join(timeout=3)
        if self.thread.is_alive():
            raise RuntimeError("A thread de captura raw nao encerrou")
        if self.erro:
            raise RuntimeError(f"Falha durante a captura raw: {self.erro}")
        if self.pacotes == 0:
            raise RuntimeError(f"Nenhum pacote capturado em {self.arquivo}")


def executar(comando, *, cwd=None, entrada=None, timeout=15):
    return subprocess.run(
        comando,
        cwd=cwd,
        input=entrada,
        text=True,
        capture_output=True,
        timeout=timeout,
        check=False,
    )


def portas_em_uso():
    saida = executar(["ss", "-H", "-ltn"]).stdout
    portas = set()
    for linha in saida.splitlines():
        try:
            portas.add(int(linha.split()[3].rsplit(":", 1)[1]))
        except (IndexError, ValueError):
            continue
    return portas


def verificar_portas_livres(portas):
    ocupadas = sorted(porta for porta in portas if porta in portas_em_uso())
    if ocupadas:
        raise RuntimeError(
            "Portas ja em uso: "
            + ", ".join(map(str, ocupadas))
            + ". Nenhum processo existente foi encerrado."
        )


def iniciar(nome, comando, cwd, arquivo_log):
    if arquivo_log is None:
        saida = subprocess.DEVNULL
    else:
        arquivo_log.parent.mkdir(parents=True, exist_ok=True)
        saida = open(arquivo_log, "wb")
    try:
        processo = subprocess.Popen(
            comando,
            cwd=cwd,
            stdout=saida,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
    finally:
        if arquivo_log is not None:
            saida.close()
    processos.append(processo)
    time.sleep(0.25)
    if processo.poll() is not None:
        raise RuntimeError(f"{nome} encerrou ao iniciar; consulte {arquivo_log}")
    return processo


def aguardar_porta(porta, processo):
    limite = time.time() + 8
    while time.time() < limite:
        if processo.poll() is not None:
            raise RuntimeError(f"O processo que deveria escutar na porta {porta} encerrou")
        if porta in portas_em_uso():
            return
        time.sleep(0.1)
    raise RuntimeError(f"Nao foi possivel iniciar o servico na porta {porta}")


def parar(processo, sinal=signal.SIGTERM):
    if processo is None or processo.poll() is not None:
        return
    processo.send_signal(sinal)
    try:
        processo.wait(timeout=5)
    except subprocess.TimeoutExpired:
        processo.kill()
        processo.wait(timeout=3)
    if processo in processos:
        processos.remove(processo)


def iniciar_captura(pasta, nome, portas):
    arquivo = pasta / nome
    capturador = CapturadorPcap(arquivo, portas)
    capturador.iniciar()
    return capturador, arquivo


def parar_captura(capturador, arquivo):
    capturador.parar()
    if not arquivo.exists() or arquivo.stat().st_size <= 24:
        raise RuntimeError(f"A captura ficou vazia: {arquivo}")


def executar_cliente(pasta, nome, comando, cwd, entrada=None):
    resultado = executar(comando, cwd=cwd, entrada=entrada)
    linhas = resultado.stdout.splitlines() + resultado.stderr.splitlines()
    linhas_uteis = [
        linha
        for linha in linhas
        if any(marca in linha for marca in ("[*]", "[OK]", "[ERRO]", "[!]"))
        or linha.startswith("Comandos:")
        or linha.startswith("    Motivo:")
    ]
    texto = "\n".join(linhas_uteis)
    (pasta / nome).write_text(
        f"codigo_de_saida={resultado.returncode}\n{texto}\n",
        encoding="utf-8",
    )
    return resultado, texto


def criar_certificado(pasta, nome):
    certificado = pasta / f"{nome}.crt"
    chave = pasta / f"{nome}.key"
    resultado = subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-keyout",
            str(chave),
            "-out",
            str(certificado),
            "-days",
            "7",
            "-nodes",
            "-subj",
            "/CN=localhost",
            "-addext",
            "subjectAltName=DNS:localhost,IP:127.0.0.1",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if resultado.returncode:
        raise RuntimeError(f"Falha ao gerar certificado: {resultado.stderr}")
    return certificado


def tshark_pacotes(arquivo, filtro):
    resultado = executar(
        [
            "tshark",
            "-r",
            str(arquivo),
            "-Y",
            filtro,
            "-T",
            "fields",
            "-e",
            "frame.number",
        ],
        timeout=30,
    )
    if resultado.returncode:
        raise RuntimeError(f"tshark falhou em {arquivo}: {resultado.stderr}")
    return [linha for linha in resultado.stdout.splitlines() if linha.strip()]


def proxy_exibiu_conteudo(texto):
    """Verifica se o proxy exibiu comando/credencial em claro no que repassou.

    Ignora as linhas de banner do proxy (iniciadas por '[*]'), pois o modo
    demonstracao imprime 'SET cor azul sera alterado para vermelho' apenas para
    explicar a regra de alteracao - isso nao e conteudo interceptado.
    """
    conteudo = "\n".join(
        linha
        for linha in texto.splitlines()
        if not linha.lstrip().startswith("[*]")
    )
    return "LOGIN alice senha123" in conteudo or "SET cor azul" in conteudo


def coletar_fase3(pasta, temporario):
    certificado = criar_certificado(temporario, "servidor")

    verificar_portas_livres([9999])
    servidor = iniciar(
        "servidor TLS",
        ["python3", "-u", str(FASE3 / "server_tls.py")],
        temporario,
        pasta / "tls_servidor.txt",
    )
    aguardar_porta(9999, servidor)
    sniffer = iniciar(
        "sniffer TLS",
        ["python3", "-u", str(FASE3 / "sniffer_tls.py")],
        temporario,
        pasta / "tls_sniffer.txt",
    )
    captura, pcap_direto = iniciar_captura(pasta, "tls_direto.pcap", {9999})
    try:
        _, texto_cliente = executar_cliente(
            pasta,
            "tls_cliente.txt",
            ["python3", str(FASE3 / "client_tls.py"), "--cert", str(certificado)],
            temporario,
            entrada=COMANDOS,
        )
        if "Servidor autenticado." not in texto_cliente or "OK azul" not in texto_cliente:
            raise RuntimeError("A sessao TLS direta nao concluiu o roteiro")
    finally:
        parar(sniffer)
        parar_captura(captura, pcap_direto)
        parar(servidor)

    certificado_impostor = criar_certificado(temporario, "impostor")
    verificar_portas_livres([9998])
    impostor = iniciar(
        "servidor com certificado nao confiavel",
        [
            "openssl",
            "s_server",
            "-4",
            "-accept",
            "9998",
            "-cert",
            str(certificado_impostor),
            "-key",
            str(temporario / "impostor.key"),
            "-quiet",
        ],
        temporario,
        pasta / "certificado_impostor_servidor.txt",
    )
    aguardar_porta(9998, impostor)
    captura, pcap_certificado = iniciar_captura(
        pasta, "certificado_nao_confiavel.pcap", {9998}
    )
    try:
        resultado, texto_cliente = executar_cliente(
            pasta,
            "certificado_nao_confiavel_cliente.txt",
            [
                "python3",
                str(FASE3 / "client_tls.py"),
                "--host",
                "127.0.0.1",
                "--porta",
                "9998",
                "--cert",
                str(certificado),
            ],
            temporario,
        )
        if resultado.returncode == 0 or "CERTIFICATE_VERIFY_FAILED" not in texto_cliente:
            raise RuntimeError("O cliente nao rejeitou o certificado nao confiavel")
    finally:
        parar_captura(captura, pcap_certificado)
        parar(impostor)

    verificar_portas_livres([9999, 8888])
    servidor = iniciar(
        "servidor TLS via proxy",
        ["python3", "-u", str(FASE3 / "server_tls.py")],
        temporario,
        pasta / "tls_proxy_servidor.txt",
    )
    aguardar_porta(9999, servidor)
    proxy = iniciar(
        "proxy transparente",
        ["python3", "-u", "proxy.py", "--transparente"],
        FASE2,
        pasta / "proxy_transparente.txt",
    )
    aguardar_porta(8888, proxy)
    captura, pcap_proxy = iniciar_captura(
        pasta, "tls_via_proxy.pcap", {8888, 9999}
    )
    try:
        _, texto_cliente = executar_cliente(
            pasta,
            "tls_proxy_cliente.txt",
            [
                "python3",
                str(FASE3 / "client_tls.py"),
                "--host",
                "localhost",
                "--porta",
                "8888",
                "--cert",
                str(certificado),
            ],
            temporario,
            entrada=COMANDOS,
        )
        if "Servidor autenticado." not in texto_cliente or "OK azul" not in texto_cliente:
            raise RuntimeError("A sessao TLS via proxy nao concluiu o roteiro")
    finally:
        parar_captura(captura, pcap_proxy)
        parar(proxy)
        parar(servidor)

    log_proxy = (pasta / "proxy_transparente.txt").read_text(
        encoding="utf-8", errors="replace"
    )
    if proxy_exibiu_conteudo(log_proxy):
        raise RuntimeError("O proxy exibiu comandos da aplicacao em texto claro")

    # Cenario 4: proxy MITM da Fase 2 em modo ALTERADOR (sem --transparente).
    # Diferente do transparente, aqui o proxy tenta ler e adulterar o conteudo
    # (SET cor azul -> SET cor vermelho). Contra o servico TLS, a tentativa deve
    # FALHAR: o servidor nao conclui o handshake e registra o evento, e o proxy
    # so enxerga bytes cifrados - nunca os comandos em claro.
    verificar_portas_livres([9999, 8888])
    servidor = iniciar(
        "servidor TLS via proxy alterador",
        ["python3", "-u", str(FASE3 / "server_tls.py")],
        temporario,
        pasta / "tls_proxy_alterador_servidor.txt",
    )
    aguardar_porta(9999, servidor)
    proxy_alt = iniciar(
        "proxy alterador",
        ["python3", "-u", "proxy.py"],
        FASE2,
        pasta / "proxy_alterador.txt",
    )
    aguardar_porta(8888, proxy_alt)
    captura, pcap_proxy_alt = iniciar_captura(
        pasta, "tls_via_proxy_alterador.pcap", {8888, 9999}
    )
    try:
        try:
            resultado, texto_cliente = executar_cliente(
                pasta,
                "tls_proxy_alterador_cliente.txt",
                [
                    "python3",
                    str(FASE3 / "client_tls.py"),
                    "--host",
                    "localhost",
                    "--porta",
                    "8888",
                    "--cert",
                    str(certificado),
                ],
                temporario,
                entrada=COMANDOS,
            )
            sessao_concluida = (
                resultado.returncode == 0 and "OK azul" in texto_cliente
            )
        except subprocess.TimeoutExpired:
            # O cliente travou no handshake contra o proxy alterador: a sessao
            # TLS nao se estabeleceu, o que tambem comprova o ataque falhando.
            sessao_concluida = False
            (pasta / "tls_proxy_alterador_cliente.txt").write_text(
                "codigo_de_saida=timeout\n"
                "[!] cliente nao concluiu o handshake (timeout) - "
                "sessao TLS nao estabelecida via proxy alterador\n",
                encoding="utf-8",
            )
    finally:
        parar_captura(captura, pcap_proxy_alt)
        parar(proxy_alt)
        parar(servidor)

    if sessao_concluida:
        raise RuntimeError(
            "O proxy alterador completou a sessao TLS e obteve 'OK azul' - "
            "a defesa falhou"
        )

    log_proxy_alt = (pasta / "proxy_alterador.txt").read_text(
        encoding="utf-8", errors="replace"
    )
    if proxy_exibiu_conteudo(log_proxy_alt):
        raise RuntimeError(
            "O proxy alterador exibiu comandos da aplicacao em texto claro"
        )

    return pcap_direto, pcap_certificado, pcap_proxy, pcap_proxy_alt


def gravar_resultados(pasta, arquivos):
    filtros = {
        "TLS direto": (arquivos[0], "tls"),
        "Certificado nao confiavel": (arquivos[1], "tls"),
        "TLS via proxy transparente": (arquivos[2], "tls"),
        "TLS via proxy alterador (MITM Fase 2)": (arquivos[3], "tls"),
    }
    linhas = [
        f"Evidencias exclusivas da Fase 3 — execucao {pasta.name}",
        "Interface: lo (AF_PACKET raw socket); quadros numerados com TShark 4.2.2.",
        "Credenciais e valores sao ficticios e usados somente no laboratorio.",
        "",
    ]
    for nome, (arquivo, filtro) in filtros.items():
        numeros = tshark_pacotes(arquivo, filtro)
        linhas.append(f"{nome}: {', '.join(numeros) if numeros else 'nenhum pacote TLS'}")

    marcadores = ('"senha123"', '"SET cor azul"', '"SET cor vermelho"')
    for arquivo in arquivos:
        encontrados = []
        for marcador in marcadores:
            encontrados.extend(tshark_pacotes(arquivo, f"tcp contains {marcador}"))
        linhas.append(
            f"Marcadores em claro em {arquivo.name}: "
            + (", ".join(encontrados) if encontrados else "nenhum")
        )

    def ler_saida(nome):
        return (pasta / nome).read_text(encoding="utf-8", errors="replace")

    def resumir_cliente(nome):
        saida = ler_saida(nome).splitlines()
        codigo = saida[0].partition("=")[2] if saida else "desconhecido"
        linha_cifra = next((linha for linha in saida if "Cifra:" in linha), "")
        cifra = (
            linha_cifra.partition("Cifra:")[2].strip()
            if linha_cifra
            else "cifra nao informada"
        )
        autenticado = any("Servidor autenticado." in linha for linha in saida)
        obteve_valor = any("OK azul" in linha for linha in saida)
        respostas_ok = sum(1 for linha in saida if "[OK]" in linha)
        return (
            f"codigo_de_saida={codigo}; "
            f"servidor_autenticado={'sim' if autenticado else 'nao'}; "
            f"cifra={cifra}; respostas_OK={respostas_ok}; "
            f"GET_OK_azul={'sim' if obteve_valor else 'nao'}"
        )

    def resumir_eventos_servidor(nome):
        eventos_permitidos = {
            "CONEXAO_TLS",
            "LOGIN_OK",
            "LOGIN_FALHOU",
            "RECV",
            "SET",
            "GET",
            "DEL",
            "QUIT",
            "HANDSHAKE_FALHOU",
            "ERRO_COMUNICACAO",
        }
        eventos = []
        for linha in ler_saida(nome).splitlines():
            if "] " not in linha:
                continue
            evento = linha.split("] ", 1)[1].split(" ", 1)[0]
            if evento in eventos_permitidos and evento not in eventos:
                eventos.append(evento)
        return ", ".join(eventos) if eventos else "nenhum evento relevante"

    sniffer = ler_saida("tls_sniffer.txt")
    linhas.extend(
        [
            "",
            "Resultados consolidados:",
            "TLS direto: " + resumir_cliente("tls_cliente.txt"),
            (
                "Sniffer TLS: "
                f"{sniffer.count('   [CIFRADO] ')} registros marcados [CIFRADO]; "
                f"{sniffer.count('   [TEXTO] ')} registros marcados [TEXTO]."
            ),
            (
                "Certificado nao confiavel: "
                "codigo_de_saida="
                + ler_saida("certificado_nao_confiavel_cliente.txt")
                .splitlines()[0]
                .partition("=")[2]
                + "; cliente reportou CERTIFICATE_VERIFY_FAILED."
            ),
            (
                "Servidor impostor: "
                + (
                    "recebeu alerta TLS unknown ca."
                    if "unknown ca" in ler_saida("certificado_impostor_servidor.txt")
                    else "nao foi encontrado alerta unknown ca no registro."
                )
            ),
            "TLS via proxy transparente: "
            + resumir_cliente("tls_proxy_cliente.txt"),
            (
                "Proxy transparente: marcadores de comandos/credenciais em claro "
                "na saida: nenhum."
                if not proxy_exibiu_conteudo(ler_saida("proxy_transparente.txt"))
                else "Proxy transparente: foram encontrados marcadores em claro."
            ),
            "Eventos do servidor (TLS direto): "
            + resumir_eventos_servidor("tls_servidor.txt"),
            "Eventos do servidor (TLS via proxy transparente): "
            + resumir_eventos_servidor("tls_proxy_servidor.txt"),
            "TLS via proxy alterador (MITM Fase 2): "
            + resumir_cliente("tls_proxy_alterador_cliente.txt"),
            (
                "MITM Fase 2 barrado: servidor registrou HANDSHAKE_FALHOU="
                + (
                    "sim"
                    if "HANDSHAKE_FALHOU" in ler_saida("tls_proxy_alterador_servidor.txt")
                    else "nao"
                )
                + "; valor adulterado aceito pelo servidor=nao "
                "(sessao TLS nao concluida)."
            ),
            (
                "Proxy alterador: marcadores de comandos/credenciais em claro "
                "na saida: nenhum."
                if not proxy_exibiu_conteudo(ler_saida("proxy_alterador.txt"))
                else "Proxy alterador: foram encontrados marcadores em claro."
            ),
            "Eventos do servidor (TLS via proxy alterador): "
            + resumir_eventos_servidor("tls_proxy_alterador_servidor.txt"),
            (
                "Nota: o proxy MITM da Fase 2 foi testado nos dois modos - "
                "transparente (repasse, confirma confidencialidade) e alterador "
                "(tentativa de adulteracao, barrada pelo TLS com falha de handshake)."
            ),
        ]
    )

    (pasta / "RESULTADOS.txt").write_text(
        "\n".join(linhas) + "\n",
        encoding="utf-8",
    )


def main():
    if os.geteuid() != 0:
        raise RuntimeError("Execute como root para abrir o socket raw.")
    for comando in ("python3", "openssl", "tshark", "ss"):
        resultado = subprocess.run(
            ["bash", "-lc", f"command -v {comando} >/dev/null 2>&1"],
            check=False,
        )
        if resultado.returncode:
            raise RuntimeError(f"Ferramenta obrigatoria ausente: {comando}")

    EVIDENCIAS.mkdir(parents=True, exist_ok=True)
    pasta = EVIDENCIAS / datetime.now().strftime("fase3_%Y%m%d_%H%M%S")
    pasta.mkdir()
    temporario = tempfile.TemporaryDirectory(prefix="fase3-tls-")
    os.chmod(temporario.name, 0o700)
    try:
        arquivos = coletar_fase3(pasta, Path(temporario.name))
        gravar_resultados(pasta, arquivos)
    finally:
        for processo in reversed(processos):
            parar(processo)
        temporario.cleanup()

    print(f"Evidencias da Fase 3 salvas em: {pasta}")
    for arquivo in sorted(pasta.iterdir()):
        print(f"{arquivo.name}: {arquivo.stat().st_size} bytes")


if __name__ == "__main__":
    main()