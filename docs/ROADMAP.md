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

## Fase 1: MVP - Motor CLI e Modulo de Auditoria Web

Objetivo: Disponibilizar um comando funcional para analise de conformidade de servicos HTTP/HTTPS.

### Itens de Entrega:
* [ ] Parser de comandos CLI e suporte a argumentos globais.
* [ ] Scanner de cabecalhos de seguranca HTTP:
  * Strict-Transport-Security (HSTS)
  * Content-Security-Policy (CSP)
  * X-Frame-Options
  * X-Content-Type-Options
  * Referrer-Policy
  * Permissions-Policy
* [ ] Validador de certificados e negociacao SSL/TLS:
  * Verificacao de expiracao e cadeia de certificacao.
  * Detecao de protocolos obsoletos (SSLv3, TLS 1.0, TLS 1.1).
* [ ] Analisador basico de configuracao CORS.
* [ ] Mecanismo de saida:
  * Renderizacao tabular para terminal (stdout).
  * Serializacao para ficheiro JSON.

---

## Fase 2: Auditoria Estatica de Segredos e Repositorios Locais

Objetivo: Analise de superficie interna de codigo para prevencao de vazamento de credenciais.

### Itens de Entrega:
* [ ] Motor de deteccao de segredos via expressoes regulares com ancoragem e analise de entropia de Shannon.
* [ ] Deteccao de padroes criticos (tokens de fornecedores de cloud, credenciais estruturadas, certificados privados).
* [ ] Suporte a arquivo de exclusao (.ciberptignore) para mitigacao de falsos positivos.

---

## Fase 3: Analise de Composicao de Software (SCA) e Hardening

Objetivo: Identificacao de dependencias vulneraveis e configuracoes inseguras de contentorizacao.

### Itens de Entrega:
* [ ] Leitor e analisador de manifests de dependencias (requirements.txt, package-lock.json, go.sum).
* [ ] Integracao com bases publicas de dados de vulnerabilidades conhecidas (OSV API).
* [ ] Linter estatico para Dockerfiles (detecao de execucao com privilegios de root, tags mutaveis e portas restritas).

---

## Fase 4: Integracao CI/CD, SARIF e Motor de Pontuacao

Objetivo: Automação completa em pipelines corporativas e pontuação de postura de segurança.

### Itens de Entrega:
* [ ] Implementacao do padrao de saida SARIF v2.1.0 para integracao nativa com GitHub Code Scanning.
* [ ] Algoritmo de ponderacao de risco para calculo de indice de postura de seguranca (Security Score).
* [ ] Configuracao de GitHub Action reutilizavel.
