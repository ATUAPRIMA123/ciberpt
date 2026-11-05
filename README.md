# ciberpt

Ferramenta de auditoria e seguranca defensiva em linha de comando (CLI), focada em analise de configuracoes, infraestrutura web e inspecao de codigo-fonte.

---

## 1. Visao Geral

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
+---------------+       +----------------+       +---------------+
                                 |
                                 v
                 +--------------------------------+
                 |    Relatorios & Exportacao     |
                 |   (Terminal, JSON, SARIF, MD)  |
                 +--------------------------------+
```

### 2.1 Superficie Web e Rede
* Inspecao de cabecalhos de seguranca HTTP (Content-Security-Policy, Strict-Transport-Security, X-Content-Type-Options, Referrer-Policy, Permissions-Policy).
* Validacao de certificados SSL/TLS (validade temporal, versao minima de protocolo, suites criptograficas).
* Analise de registos DNS (SPF, DKIM, DMARC) para prevencao de spoofing de dominio.

### 2.2 Higiene de Codigo e Dependencias (AppSec)
* Detecao estatica de credenciais e segredos em repositorios locais (chaves de API, ficheiros .env, chaves privadas).
* Inspecao de vulnerabilidades conhecidas em manifests de dependencias (Software Composition Analysis - SCA).

### 2.3 Hardening e Conformidade de Infraestrutura
* Verificacao de ficheiros de configuracao (permissao de utilizador em Dockerfiles, exposicao de portas locais).
* Analise de boas praticas de configuracao em servidores web.

### 2.4 Relatorios e Integracao
* Formatacao para terminal com codigo de retorno adequado para automacao.
* Exportacao em formatos estruturados: JSON e SARIF (Static Analysis Results Interchange Format) para pipelines CI/CD.

---

## 3. Estrutura da Documentacao

* [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) - Principios de arquitetura, fluxo de execucao e interfaces.
* [docs/ROADMAP.md](docs/ROADMAP.md) - Fases de planeamento e marcos de entrega.
* [docs/MODULES_SPEC.md](docs/MODULES_SPEC.md) - Especificacao tecnica dos modulos e analise de viabilidade de linguagens.

---

## 4. Licenca

Distribuido sob a licenca MIT. Consulte o ficheiro [LICENSE](LICENSE) para detalhes integrais.
