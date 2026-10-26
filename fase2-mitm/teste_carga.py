import argparse
import socket
import threading
import time

HOST = "127.0.0.1"
PORTA = 8888

resultados = []
trava = threading.Lock()


def um_cliente(numero):
    chave = f"cor{numero}"
    try:
        conexao = socket.create_connection((HOST, PORTA), timeout=10)
        conexao.settimeout(10)
        leitor = conexao.makefile("r", encoding="utf-8", newline="\n")

        def enviar(comando):
            conexao.sendall((comando + "\n").encode("utf-8"))
            return leitor.readline().strip()

        r_login = enviar("LOGIN alice senha123")
        r_set = enviar(f"SET {chave} valor{numero}")
        r_get = enviar(f"GET {chave}")
        enviar("QUIT")
        conexao.close()

        ok = (
            r_login.startswith("OK")
            and r_set.startswith("OK")
            and r_get.startswith("OK")
        )
        with trava:
            resultados.append((numero, ok, r_get))
    except OSError as e:
        with trava:
            resultados.append((numero, False, f"ERRO: {e}"))


def main():
    parser = argparse.ArgumentParser(description="Teste de carga do proxy MITM")
    parser.add_argument("--clientes", type=int, default=20,
                        help="quantos clientes simultaneos (padrao: 20)")
    args = parser.parse_args()

    print(f"[*] Disparando {args.clientes} clientes simultaneos contra {HOST}:{PORTA}...")
    inicio = time.time()

    threads = []
    for i in range(args.clientes):
        t = threading.Thread(target=um_cliente, args=(i,))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    duracao = time.time() - inicio

    sucessos = sum(1 for _, ok, _ in resultados if ok)
    falhas = len(resultados) - sucessos

    print("")
    print("=" * 50)
    print(f"[*] Clientes disparados : {args.clientes}")
    print(f"[*] Atendidos com sucesso: {sucessos}")
    print(f"[*] Falharam             : {falhas}")
    print(f"[*] Tempo total          : {duracao:.2f} s")
    print("=" * 50)

    if falhas:
        print("\n[!] Detalhe das falhas:")
        for numero, ok, info in sorted(resultados):
            if not ok:
                print(f"    cliente {numero}: {info}")


if __name__ == "__main__":
    main()