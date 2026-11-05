# Roadmap de Desenvolvimento - ciberpt

Este documento estabelece os objetivos tecnicos e os marcos cronologicos para o desenvolvimento do ciberpt.

---

## Fase 0: Planeamento e Especificacao de Arquitetura (Atual)

* [x] Inicializacao do repositorio e definicao de escopo.
* [x] Definicao dos principios de seguranca defensiva e isolamento de modulos.
* [x] Especificacao tecnica dos contratos de dados (ScanResult e Finding).
* [ ] Selecao formal da linguagem base do motor da CLI.
* [ ] Configuracao de padroes de testes unitarios e integracao continua.

---

## Fase 1: MVP - Motor CLI e Modulo de Auditoria Web (Concluida)

Objetivo: Disponibilizar um comando funcional para analise de conformidade de servicos HTTP/HTTPS.

### Itens de Entrega:
* [x] Parser de comandos CLI e suporte a argumentos globais (ciberpt.cli).
* [x] Scanner de cabecalhos de seguranca HTTP (ciberpt.modules.web.headers):
  * Strict-Transport-Security (HSTS)
  * Content-Security-Policy (CSP)
  * X-Frame-Options
  * X-Content-Type-Options
  * Referrer-Policy
  * Permissions-Policy
  * Deteccao de vazamento em Server e X-Powered-By
* [x] Validador de certificados e negociacao SSL/TLS (ciberpt.modules.web.tls):
  * Verificacao de expiracao e dias remanescentes.
  * Detecao de protocolos obsoletos.
  * Integracao com bundle de CA certificado.
* [x] Mecanismo de saida:
  * Renderizacao tabular para terminal (ciberpt.reporters.console).
  * Serializacao para ficheiro JSON (ciberpt.reporters.json_reporter).
* [x] Cobertura de testes unitarios (tests/test_headers.py, tests/test_models.py).

---

## Fase 2: Auditoria Estatica de Segredos e Repositorios Locais (Em Desenvolvimento)

Objetivo: Analise de superficie interna de codigo para prevencao de vazamento de credenciais e vulnerabilidades criticas de RCE.

### Itens de Entrega:
* [x] Analise estatica de uploads arbitrarios e vetores php2shell (ciberpt.modules.appsec.php_upload).
* [ ] Motor de deteccao de segredos via expressoes regulares com ancoragem e analise de entropia de Shannon.
* [ ] Deteccao de padroes criticos (tokens de fornecedores de cloud, credenciais estruturadas, certificados privados).
* [ ] Suporte a arquivo de exclusao (.ciberptignore) para mitigacao de falsos positivos.

---

## Fase 3: Analise de Composicao de Software (SCA) e Hardening (Em Desenvolvimento)

Objetivo: Identificacao de dependencias vulneraveis, mapeamento de CVEs/CVSS e configuracoes inseguras.

### Itens de Entrega:
* [x] Leitor e analisador de manifests de dependencias (requirements.txt, package.json, package-lock.json, composer.json).
* [x] Integracao com bases publicas de dados de vulnerabilidades conhecidas (OSV API).
* [x] Extracao de identificadores CVE e calculo de pontuacoes base CVSS v3.1 (ciberpt.core.cvss).
* [ ] Linter estatico para Dockerfiles (detecao de execucao com privilegios de root, tags mutaveis e portas restritas).

---

## Fase 4: Integracao CI/CD, SARIF e Relatorios Visuais

Objetivo: Automacao completa em pipelines corporativas e geracao de relatorios visuais.

### Itens de Entrega:
* [x] Exportacao para Relatorio HTML Estatico Autonomo (ciberpt.reporters.html_reporter).
* [ ] Implementacao do padrao de saida SARIF v2.1.0 para integracao nativa com GitHub Code Scanning.
* [x] Algoritmo de ponderacao de risco para calculo de indice de postura de seguranca (Security Score).
* [ ] Configuracao de GitHub Action reutilizavel.
