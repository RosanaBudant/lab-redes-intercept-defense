import socket
import threading

HOST = "0.0.0.0"
PORTA = 9999

USUARIOS = {"alice": "senha123", "bob": "12345"}
ARMAZENAMENTO = {}

def processar_comando(linha, autenticado):
    partes = linha.split(maxsplit=2)
    comando = partes[0].upper()
    
    if comando == "LOGIN":
        if len(partes) != 3:
            return "Erro! Argumentos invalidos\n", autenticado
            
        usuario, senha = partes[1], partes[2]

        if USUARIOS.get(usuario) == senha:
            print(f"[LOGIN OK] usuario={usuario} senha={senha}")
            return "OK\n", True
        else:
            print(f"[LOGIN FALHOU] usuario={usuario} senha={senha}")
            return "Erro! Login invalido\n", False

    if not autenticado:
        return "Erro! Nao autenticado\n", autenticado

    if comando == "SET":
        if len(partes) != 3:
            return "Erro! Argumentos invalidos\n", autenticado
        chave, valor = partes[1], partes[2]
        ARMAZENAMENTO[chave] = valor
        print(f"[SET] {chave} = {valor}")
        return "OK\n", autenticado

    if comando == "GET":
        if len(partes) < 2:
            return "Erro! Argumentos invalidos\n", autenticado
        chave = partes[1]
        valor = ARMAZENAMENTO.get(chave)
        print(f"[GET] {chave} -> {valor}")
        if valor is None:
            return "Erro! Chave nao encontrada\n", autenticado
        return f"OK {valor}\n", autenticado

    if comando == "DEL":
        if len(partes) < 2:
            return "Erro! Argumentos invalidos\n", autenticado
        chave = partes[1]
        ARMAZENAMENTO.pop(chave, None)
        print(f"[DEL] {chave}")
        return "OK\n", autenticado

    if comando == "QUIT":
        return "OK tchauzinho;)\n", autenticado

    return "Erro! Comando desconhecido\n", autenticado

def atender_cliente(conexao, endereco):
    TAMANHO_MAXIMO_MENSAGEM = 4096

    print(f"[+] Conexao de {endereco}")
    autenticado = False
    buffer = bytearray()

    with conexao:
        try:
            while True:
                dados = conexao.recv(1024)

                if not dados:
                    if buffer:
                        print(
                            f"[ERRO] Mensagem incompleta ao desconectar: "
                            f"{endereco}"
                        )
                    break

                buffer.extend(dados)

                while b"\n" in buffer:
                    posicao = buffer.index(b"\n")

                    if posicao > TAMANHO_MAXIMO_MENSAGEM:
                        print(f"[ERRO] Mensagem muito grande de {endereco}")
                        return

                    mensagem = bytes(buffer[:posicao])
                    del buffer[:posicao + 1]

                    try:
                        linha = mensagem.decode("utf-8").strip()
                    except UnicodeDecodeError:
                        print(
                            f"[ERRO] Mensagem com codificacao invalida "
                            f"de {endereco}"
                        )
                        return

                    if not linha:
                        continue

                    print(f"[RECV {endereco}] {linha}")

                    resposta, autenticado = processar_comando(
                        linha, autenticado
                    )
                    conexao.sendall(resposta.encode("utf-8"))

                    if linha.upper() == "QUIT":
                        print(f"[-] Cliente solicitou encerramento: {endereco}")
                        return

                if len(buffer) > TAMANHO_MAXIMO_MENSAGEM:
                    print(
                        f"[ERRO] Mensagem incompleta muito grande "
                        f"de {endereco}"
                    )
                    return

        except OSError as erro:
            print(
                f"[ERRO] Falha de comunicacao com {endereco}: {erro}"
            )

    print(f"[-] Conexao encerrada: {endereco}")   


def main():
    socket_servidor = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socket_servidor.setsockopt(
        socket.SOL_SOCKET,
        socket.SO_REUSEADDR,
        1
    )

    socket_servidor.bind((HOST, PORTA))
    socket_servidor.listen(5)

    print(f"[*] Servidor escutando em {HOST}:{PORTA}")

    try:
        while True:
            conexao, endereco = socket_servidor.accept()

            thread_cliente = threading.Thread( # conexão de servidor também precisa ser thread
                target=atender_cliente,
                args=(conexao, endereco),
                daemon=True
            )

            thread_cliente.start()

    except KeyboardInterrupt:
        print("\n[*] Encerrando servidor.")

    finally:
        socket_servidor.close()


if __name__ == "__main__":
    main()