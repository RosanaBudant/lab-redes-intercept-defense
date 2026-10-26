#!/bin/bash
echo "[*] Limpando processos antigos..."
sudo pkill -f tcpdump 2>/dev/null
pkill -f server.py 2>/dev/null
pkill -f proxy.py 2>/dev/null
sleep 1

echo "[*] Subindo o servidor..."
(cd ../fase1-sniffer && python3 server.py > /tmp/srv_f2.log 2>&1 &)
sleep 1

echo "[*] Subindo o proxy..."
python3 proxy.py > /tmp/proxy_f2.log 2>&1 &
sleep 1

echo "[*] Ligando o tcpdump (portas 8888 e 9999)..."
sudo tcpdump -i lo -w evidencia_fase2.pcap 'tcp port 8888 or tcp port 9999' &
sleep 2

echo "[*] Rodando o cliente (LOGIN, SET cor azul, GET cor, QUIT)..."
cd ../fase1-sniffer
printf 'LOGIN alice senha123\nSET cor azul\nGET cor\nQUIT\n' | python3 client.py --porta 8888
cd ../fase2-mitm

echo "[*] Encerrando..."
sleep 1
sudo pkill -f tcpdump 2>/dev/null
pkill -f server.py 2>/dev/null
pkill -f proxy.py 2>/dev/null
sleep 1

echo ""
echo "=== arquivo gerado ==="
ls -lh evidencia_fase2.pcap
echo ""
echo "=== conferencia (deve aparecer 'SET cor azul' E 'SET cor vermelho') ==="
sudo tcpdump -r evidencia_fase2.pcap -A 2>/dev/null | grep -E "SET cor"
