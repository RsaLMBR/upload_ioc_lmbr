#!/usr/bin/env bash
set -euo pipefail

# ---------------------------------------------
# Script: update-repo-ips.sh
# Objetivo: Adicionar novos IPs (single/subnet/range)
#           a um arquivo dentro de um repositório GitHub.
# ---------------------------------------------

# 🔧 CONFIGURAÇÕES FIXAS
GITHUB_TOKEN="ghp_SEU_TOKEN_AQUI"          # <- coloque seu token GitHub (com escopo "repo")
REPO_OWNER="seu_usuario_ou_org"            # <- exemplo:
REPO_NAME="threat-feed"                    # <- nome do repositório
TARGET_FILE="feed/threat-ips.txt"          # <- caminho do arquivo dentro do repo
BRANCH="main"                              # <- branch que será atualizado
INPUT_FILE="novos_ips.txt"                 # <- arquivo local com novos IPs
COMMIT_MESSAGE="Atualiza lista de IPs automaticamente"
VERBOSE="--verbose"                        # mude para "" se quiser menos logs
# ---------------------------------------------

API="https://api.github.com/repos/$REPO_OWNER/$REPO_NAME/contents/$TARGET_FILE"
CURL_OPTS=(-sS -H "Authorization: token $GITHUB_TOKEN" -H "Accept: application/vnd.github+json")

if [[ ! -f "$INPUT_FILE" ]]; then
  echo "❌ Arquivo $INPUT_FILE não encontrado."
  exit 2
fi

# 🧪 Teste de conexão e permissão
echo "🔍 Verificando acesso ao repositório..."
status=$(curl -s -o /dev/null -w "%{http_code}" -H "Authorization: token $GITHUB_TOKEN" "https://api.github.com/repos/$REPO_OWNER/$REPO_NAME")
if [[ "$status" != "200" ]]; then
  echo "❌ Falha ao acessar o repositório (HTTP $status). Verifique o token e nome do repositório."
  exit 1
fi
echo "✅ Acesso OK."

# 📥 Buscar conteúdo atual do arquivo
echo "📥 Obtendo conteúdo atual do arquivo $TARGET_FILE..."
resp=$(curl "${CURL_OPTS[@]}" "$API?ref=$BRANCH")

if echo "$resp" | grep -q '"message": "Not Found"'; then
  echo "⚠️ Arquivo não encontrado no repositório — será criado do zero."
  old_content=""
  sha=""
else
  old_content=$(echo "$resp" | jq -r '.content' | base64 --decode || true)
  sha=$(echo "$resp" | jq -r '.sha')
fi

# 💾 Backup local
backup_file="repo_${REPO_NAME}_$(basename $TARGET_FILE)_$(date +%Y%m%d%H%M%S).backup"
echo "$old_content" > "$backup_file"
echo "💾 Backup salvo em: $backup_file"

# 📄 Ler novos IPs
new_lines=$(cat "$INPUT_FILE" | sed 's/\r$//')

# 🧮 Combinar e validar
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

# 🔄 Enviar commit via API
encoded_content=$(echo "$final_content" | base64 | tr -d '\n')
payload=$(jq -n \
  --arg msg "$COMMIT_MESSAGE" \
  --arg content "$encoded_content" \
  --arg branch "$BRANCH" \
  --argjson sha "\"$sha\"" \
  '{message: $msg, content: $content, branch: $branch, sha: ($sha | select(. != "\"\""))}')

echo "📤 Enviando commit para $REPO_OWNER/$REPO_NAME..."
resp=$(echo "$payload" | curl -sS -X PUT "${CURL_OPTS[@]}" -d @- "$API")

if echo "$resp" | grep -q '"commit":'; then
  echo "✅ Repositório atualizado com sucesso."
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
    total_count=$(echo "$validation_json" | python3 -c 'import sys, json; print(len(json.load(sys.stdin)["final"]))')
    echo
    echo "📊 Total de IPs agora no arquivo: $total_count"
  fi
else
  echo "❌ Erro ao atualizar arquivo:"
  echo "$resp"
  exit 1
fi
