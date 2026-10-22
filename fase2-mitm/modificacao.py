def modificar(mensagem):
    linha = mensagem.rstrip("\r\n")
    partes = linha.split(" ", 2)

    if (
        len(partes) == 3
        and partes[0].upper() == "SET"
        and partes[1] == "cor"
        and partes[2] == "azul"
    ):
        final_de_linha = mensagem[len(linha):]
        return f"SET cor vermelho{final_de_linha}"

    return mensagem
