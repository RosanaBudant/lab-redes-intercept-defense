# Sniffer adaptado para a Fase 3.
# Diferenca para o sniffer da Fase 1: em vez de descartar pacotes cujo
# conteudo nao e texto legivel, ele mostra os bytes em hexadecimal,
# marcando como [CIFRADO]. Assim fica visivel que, com TLS, o conteudo
# trafega ilegivel (bytes cifrados), enquanto sem TLS aparece em texto claro.

import socket
import struct
import time

PORTA_MONITORADA = 9999   # porta do servidor (TLS ou nao)


def capturar():
    numero = 0
    sniffer = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    print(f"[*] Sniffer ativo, monitorando a porta {PORTA_MONITORADA}.")
    print("[*] Conteudo em texto -> [TEXTO]; conteudo cifrado -> [CIFRADO].\n")

    while True:
        pacote = sniffer.recvfrom(65535)[0]
        tempo = time.strftime("%H:%M:%S")

        if len(pacote) < 14:
            continue

        eth_type = struct.unpack("!H", pacote[12:14])[0]
        if eth_type != 0x0800:  # so IPv4
            continue

        cabecalho_ip = pacote[14:14 + (pacote[14] & 0x0F) * 4]
        ip_origem = socket.inet_ntoa(cabecalho_ip[12:16])
        ip_destino = socket.inet_ntoa(cabecalho_ip[16:20])
        protocolo_ip = cabecalho_ip[9]

        if protocolo_ip != 6:  # so TCP
            continue

        if len(pacote) < 14 + len(cabecalho_ip):
            continue

        inicio_tcp = 14 + len(cabecalho_ip)
        if len(pacote) < inicio_tcp + 12:
            continue

        porta_origem, porta_destino = struct.unpack(
            "!HH", pacote[inicio_tcp:inicio_tcp + 4])

        if porta_origem != PORTA_MONITORADA and porta_destino != PORTA_MONITORADA:
            continue

        data_offset = (pacote[inicio_tcp + 12] >> 4) * 4
        inicio_dados = inicio_tcp + data_offset

        if len(pacote) < inicio_dados:
            continue

        data = pacote[inicio_dados:]
        if not data:
            continue

        numero += 1

        # Tenta ler como texto. Se conseguir, e texto claro; se falhar,
        # e conteudo cifrado (ou binario), e mostramos os bytes em hex.
        try:
            texto = data.decode("utf-8")
            # so trata como texto se for "imprimivel" de verdade
            if texto.isprintable() or "\n" in texto or "\t" in texto:
                marca = "[TEXTO]  "
                conteudo = repr(texto)
            else:
                raise UnicodeDecodeError("utf-8", b"", 0, 1, "nao imprimivel")
        except (UnicodeDecodeError, ValueError):
            marca = "[CIFRADO]"
            # mostra os primeiros bytes em hexadecimal
            previa = data[:32]
            conteudo = previa.hex(" ") + (" ..." if len(data) > 32 else "")

        print(f"PACOTE {numero}  ({tempo})  {ip_origem} -> {ip_destino}")
        print(f"   {marca} {conteudo}\n")


if __name__ == "__main__":
    capturar()