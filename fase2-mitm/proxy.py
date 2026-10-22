"""
Proxy MITM (man-in-the-middle) - Fase 2

Posiciona-se entre o cliente e o servidor:
  cliente  ->  proxy (porta 8888)  ->  servidor (porta 9999)
"""

import argparse
import socket
import sys
import threading
from modificacao import modificar

HOST_ESCUTA = "0.0.0.0"
PORTA_PROXY = 8888
HOST_SERVIDOR = "127.0.0.1"
PORTA_SERVIDOR = 9999

TAMANHO_BUFFER = 4096


def repassar(origem, destino, rotulo, encerrar, alterar=True):
    buffer = b""
    try:
        while True:
            dados = origem.recv(TAMANHO_BUFFER)
            if not dados:
                break

            if rotulo != "cliente -> servidor" or not alterar:
                print(f"    [{rotulo}] {dados!r}", flush=True)
                destino.sendall(dados)
            else:
                buffer += dados
                while b"\n" in buffer:
                    mensagem, buffer = buffer.split(b"\n", 1)
                    mensagem += b"\n"
                    texto = mensagem.decode("utf-8", errors="surrogateescape")
                    alterada = modificar(texto)
                    dados_encaminhados = alterada.encode(
                        "utf-8", errors="surrogateescape"
                    )

                    if alterada != texto:
                        print(f"    [INTERCEPTADO] {texto.rstrip()!r}", flush=True)
                        print(f"    [ALTERADO]     {alterada.rstrip()!r}", flush=True)
                    else:
                        print(f"    [{rotulo}] {mensagem!r}", flush=True)

                    destino.sendall(dados_encaminhados)

        if buffer:
            destino.sendall(buffer)
    except OSError as e:
        print(f"[!] Erro no repasse ({rotulo}): {e}", flush=True)
    finally:
        encerrar.set()


def atender(conexao_cliente, endereco_cliente, host_servidor, porta_servidor, alterar=True):
    print(f"[+] Cliente conectado: {endereco_cliente}", flush=True)

    try:
        conexao_servidor = socket.create_connection(
            (host_servidor, porta_servidor), timeout=5
        )
    except OSError as e:
        print(f"[!] Nao foi possivel conectar ao servidor "
              f"{host_servidor}:{porta_servidor}: {e}")
        conexao_cliente.close()
        return

    conexao_servidor.settimeout(None)

    print(f"[+] Conectado ao servidor {host_servidor}:{porta_servidor}", flush=True)
    print("[*] Tunel aberto - repassando dados nos dois sentidos.", flush=True)

    encerrar = threading.Event()

    t_envio = threading.Thread(
        target=repassar,
        args=(conexao_cliente, conexao_servidor, "cliente -> servidor", encerrar, alterar),
        daemon=True,
    )
    t_resposta = threading.Thread(
        target=repassar,
        args=(conexao_servidor, conexao_cliente, "servidor -> cliente", encerrar),
        daemon=True,
    )

    t_envio.start()
    t_resposta.start()

    encerrar.wait()

    conexao_cliente.close()
    conexao_servidor.close()

    print(f"[-] Conexao encerrada: {endereco_cliente}", flush=True)


def main():
    parser = argparse.ArgumentParser(description="Proxy MITM - Fase 2")
    parser.add_argument("--porta", type=int, default=PORTA_PROXY,
                        help=f"porta de escuta do proxy (padrao: {PORTA_PROXY})")
    parser.add_argument("--host-servidor", default=HOST_SERVIDOR,
                        help=f"host do servidor real (padrao: {HOST_SERVIDOR})")
    parser.add_argument("--porta-servidor", type=int, default=PORTA_SERVIDOR,
                        help=f"porta do servidor real (padrao: {PORTA_SERVIDOR})")
    parser.add_argument("--transparente", action="store_true",
                        help="repassa os bytes sem aplicar a modificacao de demonstracao")
    args = parser.parse_args()

    proxy = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    proxy.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        proxy.bind((HOST_ESCUTA, args.porta))
    except OSError as e:
        print(f"[!] Nao foi possivel escutar na porta {args.porta}: {e}",
              file=sys.stderr)
        sys.exit(1)

    proxy.listen(5)
    print(f"[*] Proxy escutando em {HOST_ESCUTA}:{args.porta}")
    print(f"[*] Encaminhando para o servidor "
          f"{args.host_servidor}:{args.porta_servidor}")
    if args.transparente:
        print("[*] Modo transparente: mensagens nao serao alteradas.")
    else:
        print("[*] Modo demonstracao: SET cor azul sera alterado para vermelho.")
    print("[*] Aguardando conexoes... (Ctrl+C para encerrar)")

    try:
        while True:
            conexao_cliente, endereco_cliente = proxy.accept()
            atender(conexao_cliente,                    
                    endereco_cliente,
                    args.host_servidor, 
                    args.porta_servidor,
                    alterar=not args.transparente)
    except KeyboardInterrupt:
        print("\n[*] Encerrando o proxy.")
    finally:
        proxy.close()


if __name__ == "__main__":
    main()
