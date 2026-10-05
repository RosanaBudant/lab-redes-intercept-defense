#!/bin/bash
echo "[*] Limpando processos antigos..."
sudo pkill -f tcpdump 2>/dev/null
pkill -f server.py 2>/dev/null
sleep 1

echo "[*] Subindo o servidor..."
python3 server.py > server.log 2>&1 &
sleep 1

echo "[*] Ligando o tcpdump (grava em evidencia.pcap)..."
sudo tcpdump -i lo -w evidencia.pcap port 9999 &
sleep 2

echo "[*] Rodando o cliente (roteiro)..."
python3 client.py --roteiro

echo "[*] Encerrando tcpdump e servidor..."
sleep 1
sudo pkill -f tcpdump 2>/dev/null
pkill -f server.py 2>/dev/null
sleep 1

echo ""
echo "=== arquivo gerado ==="
ls -lh evidencia.pcap
echo ""
echo "=== conferencia rapida (deve aparecer LOGIN e SET cartao) ==="
sudo tcpdump -r evidencia.pcap -A 2>/dev/null | grep -E "LOGIN|SET cartao"
