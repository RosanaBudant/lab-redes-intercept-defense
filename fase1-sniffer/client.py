import argparse
import socket
import sys
import time

HOST_PADRAO = "127.0.0.1"
PORTA_PADRAO = 9999


class Cliente:
    def __init__(self, host, porta, timeout=5.0):
        self.sock = socket.create_connection((host, porta), timeout=timeout)
        self.leitor = self.sock.makefile("r", encoding="utf-8", newline="\n")

    def enviar(self, comando):
        self.sock.sendall((comando + "\n").encode("utf-8"))
        resposta = self.leitor.readline()
        if resposta == "":
            raise ConnectionError("Servidor fechou a conexão")
        return resposta.rstrip("\n")

    def fechar(self):
        try:
            self.leitor.close()
        finally:
            self.sock.close()


def eh_sucesso(resposta):
    return resposta == "OK" or resposta.startswith("OK ")


def mostrar(comando, resposta):
    marca = "[OK] " if eh_sucesso(resposta) else "[ERRO]"
    print(f"> {comando}")
    print(f"{marca} {resposta}")


def modo_interativo(cliente):
    print("Comandos: LOGIN usuario senha | SET chave valor | GET chave | DEL chave | QUIT")
    while True:
        try:
            comando = input("> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            comando = "QUIT"
        if not comando:
            continue
        resposta = cliente.enviar(comando)
        marca = "[OK] " if eh_sucesso(resposta) else "[ERRO]"
        print(f"{marca} {resposta}")
        if comando.upper() == "QUIT":
            break


def modo_roteiro(cliente, usuario, senha, pausa):
    comandos = [
        f"LOGIN {usuario} {senha}",
        "SET cor azul",
        "SET cartao 1234-5678-9012-3456",
        "GET cor",
        "GET cartao",
        "DEL cor",
        "GET cor",  
        "QUIT",
    ]
    for comando in comandos:
        resposta = cliente.enviar(comando)
        mostrar(comando, resposta)
        if pausa > 0:
            time.sleep(pausa)


def main():
    parser = argparse.ArgumentParser(description="Cliente do protocolo LOGIN/SET/GET/DEL/QUIT")
    parser.add_argument("--host", default=HOST_PADRAO, help=f"endereço do servidor (padrão: {HOST_PADRAO})")
    parser.add_argument("--porta", type=int, default=PORTA_PADRAO, help=f"porta TCP (padrão: {PORTA_PADRAO})")
    parser.add_argument("--roteiro", action="store_true", help="executa a sequência automática de comandos")
    parser.add_argument("--usuario", default="alice", help="usuário do roteiro (padrão: alice)")
    parser.add_argument("--senha", default="senha123", help="senha do roteiro (padrão: senha123)")
    parser.add_argument("--pausa", type=float, default=0.5, help="segundos entre comandos no roteiro (padrão: 0.5)")
    args = parser.parse_args()

    try:
        cliente = Cliente(args.host, args.porta)
    except OSError as e:
        print(f"Não foi possível conectar em {args.host}:{args.porta}: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Conectado em {args.host}:{args.porta}")
    try:
        if args.roteiro:
            modo_roteiro(cliente, args.usuario, args.senha, args.pausa)
        else:
            modo_interativo(cliente)
    except (ConnectionError, socket.timeout) as e:
        print(f"[!] {e}", file=sys.stderr)
    finally:
        cliente.fechar()
        print("[*] Conexão encerrada")


if __name__ == "__main__":
    main()