#!/bin/bash

echo "[*] Limpando processos antigos..."
sudo pkill -f tcpdump 2>/dev/null
pkill -f proxy.py 2>/dev/null
pkill -f server.py 2>/dev/null
pkill -f client.py 2>/dev/null
sleep 1

echo "[*] Iniciando o servidor..."
python3 ../fase1-sniffer/server.py > server.log 2>&1 &
PID_SERVIDOR=$!
sleep 1

echo "[*] Iniciando o proxy..."
python3 proxy.py > proxy.log 2>&1 &
PID_PROXY=$!
sleep 1

NUM_CLIENTES=3
echo "[*] Iniciando $NUM_CLIENTES clientes concorrentes..."

declare -a PIDS_CLIENTES=()

for i in $(seq 1 $NUM_CLIENTES); do
    echo "[*] Iniciando cliente $i..."
    python3 -u ../fase1-sniffer/client.py --porta 8888 --roteiro > client_$i.log 2>&1 &
    PIDS_CLIENTES+=($!)
done

echo "[*] Esperando os clientes se encerrarem..."
for pid in "${PIDS_CLIENTES[@]}"; do
    wait "$pid" 2>/dev/null
done

echo "[*] Todos os clientes terminaram!"

echo "[*] Encerrando servidor e proxy..."
kill $PID_SERVIDOR 2>/dev/null
kill $PID_PROXY 2>/dev/null
pkill -f server.py 2>/dev/null
pkill -f proxy.py 2>/dev/null
sleep 1

echo "=== Teste concluido! ==="
echo "=== Arquivos de log criados ==="
echo "   - server.log"
echo "   - proxy.log"
for i in $(seq 1 $NUM_CLIENTES); do
    echo "   - client_$i.log"
done