#Oi.
#Vou colocar uns comentários para facilitar a compreensão do meu grupo.
import socket #aqui é bem auto-explicativo
import struct #é usado para interpretar os bytes. Aqui vai ser para a leitura dos pacotes.
import time
def capturar():
    numero = 0
    sniffer = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3)) #cria um socket RAW que recebe os pacodes de dados da interface de rede

    while True:
        pacote = sniffer.recvfrom(65535)[0] #aqui está pegando os pacotes (cuja funcão retorna como uma tupla, ao que entendi).
        
        tempo = time.strftime("%H:%M:%S")

        if len(pacote) < 14:
            continue
        
        eth_type = struct.unpack("!H",pacote[12:14])[0]

        if eth_type != 0x0800: #verifica se é protocolo ipv4
            continue

        cabecalho_ip = pacote[14:14 + (pacote[14] & 0x0F )*4]
        ip_origem = socket.inet_ntoa(cabecalho_ip[12:16])
        ip_destino = socket.inet_ntoa(cabecalho_ip[16:20])
        protocolo_ip = cabecalho_ip[9]

        if protocolo_ip == 6: #verifica se é TCP
            if len(pacote) < 14 + len(cabecalho_ip):
                continue

            inicio_tcp = 14 + len(cabecalho_ip)
            
            if len(pacote) < inicio_tcp + 12:
                continue

            porta_origem, porta_destino = struct.unpack(
                "!HH",
                pacote[inicio_tcp:inicio_tcp + 4])

            if porta_origem != 9999 and porta_destino != 9999:
                continue


            data_offset = (pacote[inicio_tcp + 12] >> 4) * 4

            inicio_dados = inicio_tcp + data_offset

            if len(pacote) < inicio_dados:
                continue

            data = pacote[inicio_dados:]

            if not data:
                continue

            try:
                data = data.decode("utf-8")
            except UnicodeDecodeError:
                continue

            numero = numero + 1
            #imprime os dados obtidos
            print("PACOTE ", numero)
            print("IP ORIGEM  |  IP DESTINO |    TEMPO   |    DADOS CONTIDOS")
            print(ip_origem," | ",ip_destino," | ",tempo," | ",data)


if __name__ == "__main__":
    capturar()