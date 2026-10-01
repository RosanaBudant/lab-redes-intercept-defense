import socket

HOST = "0.0.0.0"
PORTA = 9999

USUARIOS = {"alice": "senha123", "bob": "12345"}
ARMAZENAMENTO = {}

def processar_comando(linha, autenticado):
    partes = linha.split(" ", 2)
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
    print(f"[+] Conexao de {endereco}")
    autenticado = False
    buffer = ""
    with conexao:
        while True:
            dados = conexao.recv(1024)
            if not dados:
                break
            buffer += dados.decode(errors="ignore")
            while "\n" in buffer:
                linha, buffer = buffer.split("\n", 1)
                linha = linha.strip()
                if not linha:
                    continue
                print(f"[RECV {endereco}] {linha}")
                resposta, autenticado = processar_comando(linha, autenticado)
                conexao.sendall(resposta.encode())
                if linha.upper() == "QUIT":
                    print(f"[-] Encerrando conexao {endereco}")
                    return


def main():
    socket_servidor = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socket_servidor.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    socket_servidor.bind((HOST, PORTA))
    socket_servidor.listen(5)
    print(f"[*] Servidor escutando em {HOST}:{PORTA}")

    while True:
        conexao, endereco = socket_servidor.accept()
        atender_cliente(conexao, endereco)


if __name__ == "__main__":
    main()