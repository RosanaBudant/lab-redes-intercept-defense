import argparse
import socket
import ssl
import sys

HOST_PADRAO = "localhost"
PORTA_PADRAO = 9999

ARQUIVO_CERTIFICADO = "servidor.crt"


def main():
    parser = argparse.ArgumentParser(description="Cliente TLS - Fase 3")
    parser.add_argument("--host", default=HOST_PADRAO,
                        help=f"endereco do servidor (padrao: {HOST_PADRAO})")
    parser.add_argument("--porta", type=int, default=PORTA_PADRAO,
                        help=f"porta do servidor (padrao: {PORTA_PADRAO})")
    parser.add_argument("--cert", default=ARQUIVO_CERTIFICADO,
                        help=f"certificado confiavel (padrao: {ARQUIVO_CERTIFICADO})")
    args = parser.parse_args()

    # Cria o contexto TLS do cliente, dizendo em QUAL certificado confiar.
    # Purpose.SERVER_AUTH ja liga a verificacao do certificado e do nome
    # do servidor por padrao.
    try:
        contexto = ssl.create_default_context(
            ssl.Purpose.SERVER_AUTH,
            cafile=args.cert,
        )
    except FileNotFoundError:
        print(f"[!] Certificado '{args.cert}' nao encontrado.", file=sys.stderr)
        sys.exit(1)

    # Abre a conexao TCP e envolve na camada TLS. O server_hostname usa o
    # host informado, e o nome e validado contra o SAN do certificado.
    socket_cru = None
    try:
        socket_cru = socket.create_connection((args.host, args.porta))
        conexao = contexto.wrap_socket(socket_cru, server_hostname=args.host)
    except ssl.SSLCertVerificationError as erro:
        print("[!] FALHA NA VALIDACAO DO CERTIFICADO - conexao recusada.")
        print(f"    Motivo: {erro}")
        if socket_cru:
            socket_cru.close()
        sys.exit(1)
    except ssl.SSLError as erro:
        print(f"[!] Erro de TLS: {erro}")
        if socket_cru:
            socket_cru.close()
        sys.exit(1)
    except OSError as erro:
        print(f"[!] Nao foi possivel conectar em {args.host}:{args.porta}: {erro}")
        if socket_cru:
            socket_cru.close()
        sys.exit(1)

    # Se chegou aqui, o TLS foi estabelecido e o servidor foi autenticado.
    cifra = conexao.cipher()
    print(f"[*] Conexao TLS estabelecida com {args.host}:{args.porta}")
    print(f"[*] Servidor autenticado. Cifra: {cifra[0]} ({cifra[1]})")

    leitor = conexao.makefile("r", encoding="utf-8", newline="\n")
    print("Comandos: LOGIN usuario senha | SET chave valor | "
          "GET chave | DEL chave | QUIT")

    try:
        while True:
            try:
                comando = input("> ").strip()
            except (EOFError, KeyboardInterrupt):
                print()
                comando = "QUIT"

            if not comando:
                continue

            conexao.sendall((comando + "\n").encode("utf-8"))
            resposta = leitor.readline()

            if resposta == "":
                print("[!] Servidor fechou a conexao")
                break

            resposta = resposta.rstrip("\n")
            marca = "[OK] " if resposta.startswith("OK") else "[ERRO]"
            print(f"{marca} {resposta}")

            if comando.upper() == "QUIT":
                break

    except OSError as erro:
        print(f"[!] Erro de comunicacao: {erro}")
    finally:
        conexao.close()
        print("[*] Conexao encerrada")


if __name__ == "__main__":
    main()