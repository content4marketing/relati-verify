# relati-verify

Verificador **independente** de evidências de consentimento do Relati.

Este repositório existe para uma única garantia: **as provas de consentimento
podem ser verificadas por qualquer pessoa, em qualquer máquina, para sempre,
mesmo que o Relati deixe de existir.** O código é público, pequeno e sem
dependência de servidores do Relati.

## O que ele verifica

Cada consentimento (formulário, QR ou vídeo) gera um **pacote de evidência**:
um JSON com os fatos do consentimento (quem, quando, quais finalidades, hash
do termo lido, metadados da sessão), contendo apenas dados **mascarados**
(ex.: últimos 4 dígitos do CPF, e-mail mascarado).

1. O pacote é canonicalizado pelo padrão **RFC 8785 (JCS)** e resumido com
   **SHA-256**: esse é o `evidence_hash`.
2. O hash é **ancorado na blockchain Polygon**: uma transação pública carrega
   o hash no campo `input`. O carimbo de tempo do bloco prova a existência da
   evidência naquela data.
3. Uma cópia do pacote fica **selada** (AES-256-GCM) no banco do Relati.

Qualquer alteração de um caractere no pacote muda o hash, e o hash gravado na
blockchain é imutável.

## Onde consigo o arquivo?

No painel do Relati, no detalhe do consentimento de um relato, o gestor
(cliente_admin) baixa o **pacote de prova**: botão "Baixar pacote de prova
(.json)". O arquivo já vem com tudo: o pacote canônico de cada evidência e a
prova (hash registrado, transação Polygon, rede, data da âncora). Um arquivo
por relato; guarde onde quiser: ele não depende do Relati pra valer.

```bash
python3 relati_verify.py verify relati-prova-XXXXXXXX.json
```

O verificador confere cada evidência do arquivo: recalcula o hash canônico,
compara com o registrado e confirma na blockchain (quando ancorada).

## Verificar não exige chave nenhuma

Também dá pra verificar um pacote avulso, com o hash da transação em mãos:

```bash
python3 relati_verify.py verify pacote.json --tx 0xTRANSACAO
```

Saída esperada:

```
hash canônico (SHA-256): c79848f4…
transação: https://polygonscan.com/tx/0x…
hash gravado na blockchain confere: SIM ✓
ancorado em (UTC): 2026-07-06T21:14:02+00:00  (bloco 61234567)

VEREDITO: o pacote de evidência é exatamente o que foi ancorado. ✓
```

Só o Python 3.8+ é necessário. A consulta usa um RPC público da Polygon
(troque com `--rpc` se quiser usar o seu).

## As chaves de decifragem

A cópia **selada** do pacote (formato `v1:iv:tag:ciphertext`) é cifrada com
uma chave AES-256. Existem cópias da chave sob custódias separadas: a do
Relati (operação) e a cópia de segurança guardada offline pelo responsável.
Com qualquer uma delas:

```bash
pip install cryptography   # só para este comando
python3 relati_verify.py decrypt copia-selada.txt --key arquivo-da-chave.txt -o pacote.json
python3 relati_verify.py verify pacote.json --tx 0xTRANSACAO
```

O `decrypt` só autentica e abre o conteúdo; a prova de integridade continua
sendo a âncora pública, que não depende de chave.

## Outros comandos

```bash
# Só o hash canônico de um pacote (e comparação opcional)
python3 relati_verify.py hash pacote.json --expected c79848f4…

# Só a âncora, sem o pacote (você tem o hash anotado)
python3 relati_verify.py check-tx --tx 0xTRANSACAO --hash c79848f4…

# SHA-256 de um arquivo: confira o vídeo de consentimento ou uma foto
# contra o hash carimbado na evidência (video_sha256 / sha256 do original)
python3 relati_verify.py filehash Consentimento-Video-REL-XXXX.mp4
```

Rede de teste: acrescente `--network amoy` (evidências de clínicas em modo
teste não são ancoradas; não têm validade probatória).

## Instalação

```bash
git clone https://github.com/content4marketing/relati-verify.git
cd relati-verify
python3 relati_verify.py --help
```

Ou baixe apenas o arquivo `relati_verify.py`: ele é autocontido.

## Contrato de formato (imutável)

- Canonicalização: RFC 8785 (JCS). Hash: SHA-256, hex minúsculo.
- Âncora: transação Polygon com `input = 0x<evidence_hash>`.
- Cópia selada: `v{n}:{iv_b64}:{tag_b64}:{ct_b64}`, AES-256-GCM, chave de
  32 bytes (64 hex ou base64), IV de 12 bytes, tag de 16 bytes.

Mudanças futuras de formato entrarão como novas versões, sem alterar a
verificação dos pacotes já ancorados.
