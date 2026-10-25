#!/bin/bash

echo "[*] Limpando processos antigos..."
sudo pkill -f tcpdump 2>/dev/null
pkill -f proxy.py 2>/dev/null
pkill -f server.py 2>/dev/null
pkill -f client.py 2>/dev/null
sleep 1

echo "[*] Iniciando o servidor..."
python3 server.py > server.log 2>&1 &
PID_SERVIDOR=$!
sleep 1

echo "[*] Iniciando o proxy..."
python3 proxy.py > proxy.log 2>&1 &
PID_PROXY=$!
sleep 1

NUM_CLIENTES=3
echo "[*] Iniciando $NUM_CLIENTES clientes concorrentes..."

# Array para armazenar os PIDs apenas dos clientes
declare -a PIDS_CLIENTES=()

for i in $(seq 1 $NUM_CLIENTES); do
    echo "[*] Iniciando cliente $i..."
    # Usamos o '-u' para evitar problemas de buffer no log
    python3 -u client.py --porta 8888 --roteiro > client_$i.log 2>&1 &
    # Guarda o PID exato deste cliente no array
    PIDS_CLIENTES+=($!)
done

echo "[*] Esperando os clientes se encerrarem..."
# Aguarda estritamente apenas os PIDs dos clientes (ignora servidor e proxy)
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

echo "=== Teste concluído com sucesso! ==="
sleep 1
echo "=== Arquivos criados ==="
echo "   - server.log"
echo "   - server.log"


for i in $(seq 1 $NUM_CLIENTES); do
    echo "   - client_$i.log"
done