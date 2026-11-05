# ciberpt

Ferramenta de auditoria e seguranca defensiva em linha de comando (CLI), focada em analise de configuracoes, infraestrutura web e inspecao de codigo-fonte.

---

## 1. Visão Geral

O ciberpt e concebido como um utilitario modular de analise de seguranca defensiva. O objetivo central e permitir a programadores, analistas de seguranca e administradores de sistemas a avaliacao automatizada da superficie de exposicao e conformidade de servicos e repositorios.

---

## 2. Pilares de Auditoria

```
                 +--------------------------------+
                 |       ciberpt CLI Engine       |
                 +---------------+----------------+
                                 |
        +------------------------+------------------------+
        |                                                 |
+-------v-------+       +----------------+       +--------v------+
|   Web & Net   |       |  Code & Deps   |       | Hardening & OS|
|   Auditing    |       |   (AppSec)     |       | (SysAdmin)    |
+---------------+       +----------------+       +---------------+
| . HTTP Headers|       | . Leaks & Keys |       | . Open Ports  |
| . SSL/TLS     |       | . SCA / CVEs   |       | . Permissoes  |
| . DNS & CORS  |       | . .env checks  |       | . Configs     |
| . Cookies     |       | . php2shell    |       |               |
+---------------+       +----------------+       +---------------+
                                 |
                                 v
                 +--------------------------------+
                 |    Relatorios & Exportacao     |
                 |  (Terminal, JSON, HTML, SARIF) |
                 +--------------------------------+
```

### 2.1 Superficie Web e Rede (`web`)
* Inspecao de cabecalhos de seguranca HTTP (`HSTS`, `CSP`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`).
* Validacao de certificados SSL/TLS (validade temporal, versao minima de protocolo, suites criptograficas).
* Analise de registos DNS defensivos (SPF e DMARC) via DNS-over-HTTPS.
* Auditoria de politicas de Cross-Origin Resource Sharing (CORS).
* Inspecao de diretivas de seguranca em cookies HTTP (`Secure`, `HttpOnly`, `SameSite`).

### 2.2 Higiene de Codigo e AppSec (`appsec`)
* Analise estatica (SAST) de vulnerabilidades de upload arbitrario de ficheiros e vetores de execucao remota (*php2shell*).
* Detecao de listas negras ineficazes, manipulacao direta de nomes de ficheiros enviados por clientes e confianca indevida em cabecalhos de MIME.

### 2.3 Relatorios e Integracao (`reporters`)
* Formatacao para terminal com tabela semantica e calculo de Indice de Postura (Security Score de 0 a 100).
* Exportacao em formato JSON estruturado para consumo programatico.
* Geracao de relatorios visuais autonomos em HTML, totalmente desacoplados e sem dependencias de CDNs externas.

---

## 3. Instalacao

### 3.1 Requisitos de Sistema
* Python 3.10 ou superior.
* Gestor de pacotes `pip` e utilitario `git`.

### 3.2 Procedimento de Instalacao

1. Clonar o repositorio:
```bash
git clone https://github.com/ATUAPRIMA123/ciberpt.git
cd ciberpt
```

2. Instalar o pacote no ambiente Python:
```bash
pip install .
```

*Nota: Para desenvolvimento e modificacao em tempo real do codigo-fonte, utilize a flag editavel:*
```bash
pip install -e .
```

Apos a instalacao, o comando global `ciberpt` ficara disponivel diretamente no terminal. Em alternativa, pode executar o modulo sem instalacao global via `python -m ciberpt.cli`.

---

## 4. Guia de Utilizacao

### 4.1 Auditoria Web e de Servicos Remotos

```bash
# Executar a suite web completa (Headers, TLS, DNS, CORS e Cookies)
ciberpt scan example.com

# Inspecionar exclusivamente os cabecalhos de seguranca HTTP
ciberpt scan example.com -m web.headers

# Auditar registos DNS defensivos (SPF e DMARC)
ciberpt scan example.com -m web.dns

# Auditar politicas de CORS ou diretivas de cookies
ciberpt scan example.com -m web.cors
ciberpt scan example.com -m web.cookies
```

### 4.2 Analise Estatica de Codigo (AppSec / SAST)

```bash
# Auditar um repositorio ou diretorio local a procura de vulnerabilidades de upload (php2shell)
ciberpt scan ./caminho/para/projeto_php

# Analisar um ficheiro especifico
ciberpt scan ./caminho/para/upload.php -m appsec.php_upload
```

### 4.3 Exportacao de Relatorios

```bash
# Gerar um relatorio visual autonomo em HTML
ciberpt scan example.com --html relatorio.html

# Abrir o relatorio diretamente no browser (Windows)
start relatorio.html

# Exportar resultados em formato JSON estruturado
ciberpt scan example.com --json -o resultado.json

# Filtrar a apresentacao por severidade minima (ex: apenas HIGH e CRITICAL)
ciberpt scan example.com --min-severity HIGH
```

### 4.4 Integracao em Pipelines DevSecOps / CI/CD

```bash
# Bloquear pipeline (exit code 1) se existirem vulnerabilidades criticas
ciberpt scan example.com --fail-on CRITICAL

# Bloquear pipeline caso existam vulnerabilidades de severidade media ou superior
ciberpt scan ./src --fail-on MEDIUM
```

---

## 5. Estrutura da Documentacao

* [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) - Principios de arquitetura, fluxo de execucao e interfaces.
* [docs/ROADMAP.md](docs/ROADMAP.md) - Fases de planeamento e marcos de entrega.
* [docs/MODULES_SPEC.md](docs/MODULES_SPEC.md) - Especificacao tecnica dos modulos e analise de viabilidade de linguagens.

---

## 6. Licenca

Distribuido sob a licenca MIT. Consulte o ficheiro [LICENSE](LICENSE) para detalhes integrais.
