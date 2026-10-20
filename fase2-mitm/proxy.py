"""
Proxy MITM (man-in-the-middle) - Fase 2
Bloco A: proxy transparente (tunel).

Posiciona-se entre o cliente e o servidor:
  cliente  ->  proxy (porta 8888)  ->  servidor (porta 9999)
"""

import argparse
import socket
import sys

HOST_ESCUTA = "0.0.0.0"      # o proxy escuta em todas as interfaces
PORTA_PROXY = 8888           # porta onde o cliente vai se conectar
HOST_SERVIDOR = "127.0.0.1"  # onde o servidor real esta
PORTA_SERVIDOR = 9999        # porta do servidor real


def atender(conexao_cliente, endereco_cliente, host_servidor, porta_servidor):
    """Trata uma conexao: recebe o cliente e abre a ligacao com o servidor."""
    print(f"[+] Cliente conectado: {endereco_cliente}")

    try:
        conexao_servidor = socket.create_connection(
            (host_servidor, porta_servidor), timeout=5
        )
    except OSError as e:
        print(f"[!] Nao foi possivel conectar ao servidor "
              f"{host_servidor}:{porta_servidor}: {e}")
        conexao_cliente.close()
        return

    print(f"[+] Conectado ao servidor {host_servidor}:{porta_servidor}")
    print("[*] (Parte 1) Tunel ainda nao repassa dados - sera feito na Parte 2.")

    # Aqui entra o relay de dados nos dois sentidos.
    conexao_servidor.close()
    conexao_cliente.close()
    print(f"[-] Conexao encerrada: {endereco_cliente}")


def main():
    parser = argparse.ArgumentParser(description="Proxy MITM - Fase 2 (Parte 1)")
    parser.add_argument("--porta", type=int, default=PORTA_PROXY,
                        help=f"porta de escuta do proxy (padrao: {PORTA_PROXY})")
    parser.add_argument("--host-servidor", default=HOST_SERVIDOR,
                        help=f"host do servidor real (padrao: {HOST_SERVIDOR})")
    parser.add_argument("--porta-servidor", type=int, default=PORTA_SERVIDOR,
                        help=f"porta do servidor real (padrao: {PORTA_SERVIDOR})")
    args = parser.parse_args()

    # Socket de escuta do proxy
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
    print("[*] Aguardando conexoes... (Ctrl+C para encerrar)")

    try:
        while True:
            conexao_cliente, endereco_cliente = proxy.accept()
            atender(conexao_cliente, endereco_cliente,
                    args.host_servidor, args.porta_servidor)
    except KeyboardInterrupt:
        print("\n[*] Encerrando o proxy.")
    finally:
        proxy.close()


if __name__ == "__main__":
    main()