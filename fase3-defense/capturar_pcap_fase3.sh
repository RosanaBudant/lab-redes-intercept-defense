#!/bin/bash
echo "[*] Limpando processos antigos..."
sudo pkill -f tcpdump 2>/dev/null
sudo pkill -f sniffer_tls.py 2>/dev/null
pkill -f server_tls.py 2>/dev/null
pkill -f proxy.py 2>/dev/null
sleep 1

echo "[*] Subindo o servidor..."
python3 server_tls.py > /tmp/srv_f3.log 2>&1 &
sleep 1

echo "[*] Ligando o sniffer (grava em captura_sniffer.txt)..."
sudo python3 -u sniffer_tls.py > captura_sniffer.txt 2>&1 &
sleep 1

echo "[*] Subindo o proxy..."
python3 proxy.py > /tmp/proxy_f3.log 2>&1 &
sleep 1

echo "[*] Ligando o tcpdump (portas 8888 e 9999)..."
sudo tcpdump -i lo -w evidencia_fase3.pcap 'tcp port 8888 or tcp port 9999' &
sleep 2

echo "[*] Rodando o cliente (roteiro)..."
python3 client_tls.py --roteiro

echo "[*] Rodando o cliente (LOGIN, SET cor azul, GET cor, QUIT)..."
printf 'LOGIN alice senha123\nSET cor azul\nGET cor\nQUIT\n' | python3 client.py --porta 8888

echo "[*] Encerrando..."
sudo pkill -f sniffer_tls.py 2>/dev/null
sudo pkill -f tcpdump 2>/dev/null
pkill -f server_tls.py 2>/dev/null
pkill -f proxy.py 2>/dev/null
sleep 1

echo ""
echo "=== arquivo gerado ==="
ls -lh evidencia_fase3.pcap
echo ""
sudo tcpdump -r evidencia_fase3.pcap -A 2>/dev/null | grep -E "SET cor"
