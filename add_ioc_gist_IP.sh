#!/usr/bin/env bash
set -euo pipefail

# ---------------------------------------------
# Objetivo: Adicionar novos IPs (single, subnet, range)
#           ao Gist GitHub configurado abaixo,
#           sem remover os existentes.
# ---------------------------------------------

# 🔧 CONFIGURAÇÕES FIXAS
GITHUB_TOKEN=""             # <- coloque seu token GitHub
GIST_ID=""                    # <- ID do Gist
FILE_NAME=""                   # <- nome do arquivo dentro do Gist
INPUT_FILE=""                    # <- arquivo local com IPs novos
VERBOSE="--verbose"                           # <- mude para "" se não quiser logs detalhados
# ---------------------------------------------

API="https://api.github.com/gists/$GIST_ID"
CURL_OPTS=(-sS -H "Authorization: token $GITHUB_TOKEN" -H "Accept: application/vnd.github+json")

# 🧪 Verifica se o arquivo local existe
if [[ ! -f "$INPUT_FILE" ]]; then
  echo "❌ Arquivo $INPUT_FILE não encontrado."
  exit 2
fi

# 🧪 Testa acesso ao gist
echo "🔍 Verificando acesso ao Gist..."
status=$(curl -s -o /dev/null -w "%{http_code}" "${CURL_OPTS[@]}" "$API")
if [[ "$status" == "401" ]]; then
  echo "❌ Token inválido ou sem permissão para acessar o Gist."
  exit 1
elif [[ "$status" != "200" ]]; then
  echo "❌ Falha ao acessar o Gist (HTTP $status)."
  exit 1
fi
echo "✅ Conexão OK."

# 📥 Baixa conteúdo atual
raw_gist_json=$(curl "${CURL_OPTS[@]}" "$API")

# Extrai o conteúdo
if command -v jq >/dev/null 2>&1; then
  old_content=$(echo "$raw_gist_json" | jq -r --arg f "$FILE_NAME" '.files[$f].content // ""')
else
  old_content=$(python3 - <<PY
import sys, json
j=json.load(sys.stdin)
print(j.get("files", {}).get("$FILE_NAME", {}).get("content",""))
PY
<<<"$raw_gist_json")
fi

# ⚠️ Abort se o arquivo remoto estiver vazio (proteção contra sobrescrita)
if [[ -z "$old_content" ]]; then
  echo "⚠️ O conteúdo remoto está vazio — abortando para evitar sobrescrita acidental."
  exit 1
fi

# 💾 Backup do conteúdo remoto
backup_file="gist_${GIST_ID}_${FILE_NAME}_$(date +%Y%m%d%H%M%S).backup"
echo "$old_content" > "$backup_file"
echo "💾 Backup salvo em: $backup_file"

# 📄 Ler novos IPs
new_lines=$(cat "$INPUT_FILE" | sed 's/\r$//')

# 🧮 Combinar e validar via Python
export OLD_CONTENT="$old_content"
export NEW_LINES="$new_lines"

validation_json=$(python3 <<'PY'
import os, ipaddress, json

old = os.environ.get("OLD_CONTENT", "").splitlines()
new = os.environ.get("NEW_LINES", "").splitlines()

def normalize(line):
    line = line.split('#',1)[0].strip()
    if not line:
        return None
    if '-' in line and '/' not in line:
        try:
            a_str, b_str = [x.strip() for x in line.split('-',1)]
            a = ipaddress.IPv4Address(a_str)
            b = ipaddress.IPv4Address(b_str)
            if int(a) > int(b):
                return None
            return f"{a.compressed}-{b.compressed}"
        except Exception:
            return None
    elif '/' in line:
        try:
            net = ipaddress.IPv4Network(line, strict=True)
            return f"{net.network_address.compressed}/{net.prefixlen}"
        except Exception:
            if line.endswith('/32'):
                try:
                    addr = ipaddress.IPv4Address(line.split('/')[0])
                    return addr.compressed
                except Exception:
                    return None
            return None
    else:
        try:
            addr = ipaddress.IPv4Address(line)
            return addr.compressed
        except Exception:
            return None

old_clean = [normalize(x) for x in old if normalize(x)]
new_clean = [normalize(x) for x in new if normalize(x)]

seen = set(old_clean)
result = list(old_clean)
added, ignored, invalid = [], [], []

for raw in new:
    norm = normalize(raw)
    if not norm:
        invalid.append(raw.strip())
    elif norm in seen:
        ignored.append(norm)
    else:
        result.append(norm)
        seen.add(norm)
        added.append(norm)

out = {
    "final": result,
    "added": added,
    "ignored": ignored,
    "invalid": invalid
}
print(json.dumps(out))
PY
)

final_content=$(echo "$validation_json" | python3 -c 'import sys, json; print("\n".join(json.load(sys.stdin)["final"]))')
added_count=$(echo "$validation_json" | python3 -c 'import sys, json; print(len(json.load(sys.stdin)["added"]))')
ignored_count=$(echo "$validation_json" | python3 -c 'import sys, json; print(len(json.load(sys.stdin)["ignored"]))')
invalid_count=$(echo "$validation_json" | python3 -c 'import sys, json; print(len(json.load(sys.stdin)["invalid"]))')

if [[ "$added_count" -eq 0 ]]; then
  echo "Nenhum IP novo foi adicionado (todos já existem ou inválidos)."
  exit 0
fi

# 📤 Atualiza o gist
export FINAL_CONTENT="$final_content"
payload=$(python3 <<PY
import json, os
print(json.dumps({"files": {"$FILE_NAME": {"content": os.environ["FINAL_CONTENT"]}}}))
PY
)

resp=$(echo "$payload" | curl -sS -X PATCH "${CURL_OPTS[@]}" -d @- "$API")

if echo "$resp" | grep -q '"url":'; then
  echo "✅ Gist atualizado com sucesso (modo append)."
  echo "📄 Arquivo: $FILE_NAME"
  if [[ "$VERBOSE" == "--verbose" ]]; then
    echo
    echo "📈 IPs adicionados ($added_count):"
    echo "$validation_json" | python3 -c 'import sys, json; [print("  " + x) for x in json.load(sys.stdin)["added"]]'
    if [[ "$ignored_count" -gt 0 ]]; then
      echo
      echo "🔁 Ignorados (duplicados):"
      echo "$validation_json" | python3 -c 'import sys, json; [print("  " + x) for x in json.load(sys.stdin)["ignored"]]'
    fi
    if [[ "$invalid_count" -gt 0 ]]; then
      echo
      echo "⚠️ Inválidos (formato incorreto):"
      echo "$validation_json" | python3 -c 'import sys, json; [print("  " + x) for x in json.load(sys.stdin)["invalid"]]'
    fi
    echo
    total_count=$(echo "$validation_json" | python3 -c 'import sys, json; print(len(json.load(sys.stdin)["final"]))')
    echo "📊 Total de IPs agora no Gist: $total_count"
  fi
else
  echo "❌ Erro ao atualizar gist:"
  echo "$resp"
  echo "⚠️ Conteúdo anterior salvo em: $backup_file"
  exit 1
fi
