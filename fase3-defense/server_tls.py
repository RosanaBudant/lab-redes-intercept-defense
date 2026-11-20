import hashlib
import hmac
import os
import socket
import ssl
import threading
import time

HOST = "0.0.0.0"
PORTA = 9999

ARQUIVO_CERTIFICADO = "servidor.crt"
ARQUIVO_CHAVE = "servidor.key"

TIMEOUT_HANDSHAKE = 10   # segundos para concluir o handshake TLS
TIMEOUT_LEITURA = 60     # segundos de inatividade permitidos na conversa

# Parametros do hash de senha (PBKDF2)
ITERACOES_HASH = 200_000
TAMANHO_SALT = 16


def agora():
    """Horario atual legivel, para os registros de seguranca."""
    return time.strftime("%Y-%m-%d %H:%M:%S")


def log(evento, endereco=None, detalhe=""):
    """
    Registro de seguranca padronizado.
    Nunca inclui conteudo da aplicacao (senhas, valores) - apenas o tipo de
    evento, a origem, o horario e dados tecnicos nao sensiveis (ex.: cifra TLS).
    """
    origem = f" origem={endereco[0]}:{endereco[1]}" if endereco else ""
    extra = f" {detalhe}" if detalhe else ""
    print(f"[{agora()}] {evento}{origem}{extra}")


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
    inicializacao e nao ficam guardadas em lugar nenhum.
    """
    usuarios = {}
    for usuario, senha in senhas_em_texto.items():
        salt = os.urandom(TAMANHO_SALT)
        usuarios[usuario] = (salt, gerar_hash(senha, salt))
    return usuarios


USUARIOS = criar_usuarios({"alice": "senha123", "bob": "12345"})

ARMAZENAMENTO = {}


def senha_confere(usuario, senha):
    """Confere a senha recalculando o hash com o salt guardado do usuario."""
    registro = USUARIOS.get(usuario)
    if registro is None:
        return False
    salt, hash_guardado = registro
    hash_tentativa = gerar_hash(senha, salt)
    return hmac.compare_digest(hash_tentativa, hash_guardado)


def processar_comando(linha, autenticado, endereco):
    partes = linha.split(maxsplit=2)
    comando = partes[0].upper()

    if comando == "LOGIN":
        if len(partes) != 3:
            return "Erro! Argumentos invalidos\n", autenticado

        usuario, senha = partes[1], partes[2]

        if senha_confere(usuario, senha):
            log("LOGIN_OK", endereco, f"usuario={usuario}")
            return "OK\n", True
        else:
            log("LOGIN_FALHOU", endereco, f"usuario={usuario}")
            return "Erro! Login invalido\n", False

    if not autenticado:
        log("COMANDO_NAO_AUTENTICADO", endereco, f"comando={comando}")
        return "Erro! Nao autenticado\n", autenticado

    if comando == "SET":
        if len(partes) != 3:
            return "Erro! Argumentos invalidos\n", autenticado
        chave, valor = partes[1], partes[2]
        ARMAZENAMENTO[chave] = valor
        log("SET", endereco, f"chave={chave}")
        return "OK\n", autenticado

    if comando == "GET":
        if len(partes) < 2:
            return "Erro! Argumentos invalidos\n", autenticado
        chave = partes[1]
        valor = ARMAZENAMENTO.get(chave)
        log("GET", endereco, f"chave={chave}")
        if valor is None:
            return "Erro! Chave nao encontrada\n", autenticado
        return f"OK {valor}\n", autenticado

    if comando == "DEL":
        if len(partes) < 2:
            return "Erro! Argumentos invalidos\n", autenticado
        chave = partes[1]
        ARMAZENAMENTO.pop(chave, None)
        log("DEL", endereco, f"chave={chave}")
        return "OK\n", autenticado

    if comando == "QUIT":
        return "OK tchauzinho;)\n", autenticado

    log("COMANDO_DESCONHECIDO", endereco, f"comando={comando}")
    return "Erro! Comando desconhecido\n", autenticado


def atender_cliente(conexao_crua, endereco, contexto):
    TAMANHO_MAXIMO_MENSAGEM = 4096

    # Handshake TLS dentro da thread, com timeout, para nao bloquear o laco
    # principal nem prender a thread em uma conexao que nao conclui o handshake.
    try:
        conexao_crua.settimeout(TIMEOUT_HANDSHAKE)
        conexao = contexto.wrap_socket(conexao_crua, server_side=True)
    except (ssl.SSLError, socket.timeout, OSError) as erro:
        # Evento de seguranca: handshake falhou (cliente sem TLS, erro de
        # certificado, ou tentativa de interceptacao). Util para deteccao.
        log("HANDSHAKE_FALHOU", endereco, f"motivo={type(erro).__name__}")
        conexao_crua.close()
        return

    conexao.settimeout(TIMEOUT_LEITURA)

    # Handshake concluido: registra a cifra e a versao TLS negociadas.
    cifra = conexao.cipher()
    if cifra:
        log("CONEXAO_TLS", endereco, f"versao={cifra[1]} cifra={cifra[0]}")
    else:
        log("CONEXAO_TLS", endereco)

    autenticado = False
    buffer = bytearray()

    with conexao:
        try:
            while True:
                dados = conexao.recv(1024)

                if not dados:
                    if buffer:
                        log("MENSAGEM_INCOMPLETA", endereco)
                    break

                buffer.extend(dados)

                while b"\n" in buffer:
                    posicao = buffer.index(b"\n")

                    if posicao > TAMANHO_MAXIMO_MENSAGEM:
                        log("MENSAGEM_MUITO_GRANDE", endereco)
                        return

                    mensagem = bytes(buffer[:posicao])
                    del buffer[:posicao + 1]

                    try:
                        linha = mensagem.decode("utf-8").strip()
                    except UnicodeDecodeError:
                        log("CODIFICACAO_INVALIDA", endereco)
                        return

                    if not linha:
                        continue

                    # Registro do comando recebido SEM os argumentos, para nao
                    # expor conteudo sensivel (senhas, valores) nos logs.
                    comando = linha.split(maxsplit=1)[0].upper()
                    log("RECV", endereco, f"comando={comando}")

                    resposta, autenticado = processar_comando(
                        linha, autenticado, endereco
                    )
                    conexao.sendall(resposta.encode("utf-8"))

                    if linha.upper() == "QUIT":
                        log("QUIT", endereco)
                        return

                if len(buffer) > TAMANHO_MAXIMO_MENSAGEM:
                    log("MENSAGEM_INCOMPLETA_GRANDE", endereco)
                    return

        except socket.timeout:
            log("TIMEOUT_INATIVIDADE", endereco)
        except OSError as erro:
            log("ERRO_COMUNICACAO", endereco, f"motivo={type(erro).__name__}")

    log("CONEXAO_ENCERRADA", endereco)


def main():
    contexto = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    contexto.load_cert_chain(certfile=ARQUIVO_CERTIFICADO, keyfile=ARQUIVO_CHAVE)

    socket_servidor = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socket_servidor.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    socket_servidor.bind((HOST, PORTA))
    socket_servidor.listen(5)

    log("SERVIDOR_INICIADO", detalhe=f"porta={PORTA}")

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
        log("SERVIDOR_ENCERRANDO")

    finally:
        socket_servidor.close()


if __name__ == "__main__":
    main()
