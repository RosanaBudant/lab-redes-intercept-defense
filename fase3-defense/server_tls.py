import hashlib
import os
import socket
import ssl
import threading
import hmac

HOST = "0.0.0.0"
PORTA = 9999

ARQUIVO_CERTIFICADO = "servidor.crt"
ARQUIVO_CHAVE = "servidor.key"

TIMEOUT_HANDSHAKE = 10   # segundos para concluir o handshake TLS
TIMEOUT_LEITURA = 60     # segundos de inatividade permitidos na conversa

# Parametros do hash de senha (PBKDF2)
ITERACOES_HASH = 200_000
TAMANHO_SALT = 16


def gerar_hash(senha, salt):
    """Calcula o hash PBKDF2-HMAC-SHA256 de uma senha com o salt dado."""
    return hashlib.pbkdf2_hmac(
        "sha256",
        senha.encode("utf-8"),
        salt,
        ITERACOES_HASH,
    )


def criar_usuarios(senhas_em_texto):
    """
    Recebe {usuario: senha_texto} e devolve {usuario: (salt, hash)}.
    As senhas em texto sao usadas apenas para gerar os hashes na
    inicializacao e nao ficam guardadas em lugar nenhum. Num sistema
    real, os hashes ja viriam prontos de um banco de dados.
    """
    usuarios = {}
    for usuario, senha in senhas_em_texto.items():
        salt = os.urandom(TAMANHO_SALT)
        usuarios[usuario] = (salt, gerar_hash(senha, salt))
    return usuarios


# Senhas de teste (apenas para gerar os hashes na inicializacao)
USUARIOS = criar_usuarios({"alice": "senha123", "bob": "12345"})

ARMAZENAMENTO = {}


def senha_confere(usuario, senha):
    """Confere a senha recalculando o hash com o salt guardado do usuario."""
    registro = USUARIOS.get(usuario)
    if registro is None:
        return False
    salt, hash_guardado = registro
    hash_tentativa = gerar_hash(senha, salt)
    # compare_digest evita ataques de tempo (timing attack)
    return hmac.compare_digest(hash_tentativa, hash_guardado)


def processar_comando(linha, autenticado):
    partes = linha.split(maxsplit=2)
    comando = partes[0].upper()

    if comando == "LOGIN":
        if len(partes) != 3:
            return "Erro! Argumentos invalidos\n", autenticado

        usuario, senha = partes[1], partes[2]

        if senha_confere(usuario, senha):
            print(f"[LOGIN OK] usuario={usuario}")
            return "OK\n", True
        else:
            print(f"[LOGIN FALHOU] usuario={usuario}")
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


def atender_cliente(conexao_crua, endereco, contexto):
    TAMANHO_MAXIMO_MENSAGEM = 4096

    # Handshake TLS feito dentro da thread, para nao bloquear o laco
    # principal. Timeout para que uma conexao que nao conclui o handshake
    # nao prenda a thread.
    try:
        conexao_crua.settimeout(TIMEOUT_HANDSHAKE)
        conexao = contexto.wrap_socket(conexao_crua, server_side=True)
    except (ssl.SSLError, socket.timeout, OSError) as erro:
        print(f"[ERRO] Falha no handshake TLS com {endereco}: {erro}")
        conexao_crua.close()
        return

    # Depois do handshake, aplica um timeout de inatividade na leitura.
    conexao.settimeout(TIMEOUT_LEITURA)

    print(f"[+] Conexao TLS de {endereco}")
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

        except socket.timeout:
            print(f"[ERRO] Cliente {endereco} inativo por muito tempo (timeout)")
        except OSError as erro:
            print(f"[ERRO] Falha de comunicacao com {endereco}: {erro}")

    print(f"[-] Conexao encerrada: {endereco}")


def main():
    contexto = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    contexto.load_cert_chain(certfile=ARQUIVO_CERTIFICADO, keyfile=ARQUIVO_CHAVE)

    socket_servidor = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socket_servidor.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    socket_servidor.bind((HOST, PORTA))
    socket_servidor.listen(5)

    print(f"[*] Servidor TLS escutando em {HOST}:{PORTA}")

    try:
        while True:
            conexao_crua, endereco = socket_servidor.accept()

            thread_cliente = threading.Thread(
                target=atender_cliente,
                args=(conexao_crua, endereco, contexto),
                daemon=True
            )
            thread_cliente.start()

    except KeyboardInterrupt:
        print("\n[*] Encerrando servidor.")

    finally:
        socket_servidor.close()


if __name__ == "__main__":
    main()