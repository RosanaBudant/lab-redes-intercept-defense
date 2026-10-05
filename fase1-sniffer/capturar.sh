#!/bin/bash
echo "[*] Limpando processos antigos..."
sudo pkill -f sniffer.py 2>/dev/null
pkill -f server.py 2>/dev/null
sleep 1

echo "[*] Subindo o servidor..."
python3 server.py > server.log 2>&1 &
sleep 1

echo "[*] Ligando o sniffer (grava em captura_sniffer.txt)..."
sudo python3 -u sniffer.py > captura_sniffer.txt 2>&1 &
sleep 2

echo "[*] Rodando o cliente (roteiro)..."
python3 client.py --roteiro

echo "[*] Encerrando sniffer e servidor..."
sleep 1
sudo pkill -f sniffer.py 2>/dev/null
pkill -f server.py 2>/dev/null
sleep 1

echo ""
echo "=== linhas capturadas ==="
wc -l captura_sniffer.txt
echo ""
echo "=== evidencia (credenciais e dados sensiveis em texto claro) ==="
grep -E "LOGIN|SET cartao" captura_sniffer.txt
