# Especificacao Tecnica dos Modulos - ciberpt

Este documento define os requisitos tecnicos de cada modulo funcional, bem como a analise comparativa de linguagens para implementacao do motor da CLI.

---

## 1. Especificacao Funcional dos Modulos

### 1.1 Core Engine (`ciberpt.core`)
Modulo responsavel pelo ciclo de vida da execucao, parsing de argumentos, carregamento dinamico de modulos e agregacao de achados.

* **Entrada:** Argumentos de linha de comando, opcoes de filtro por severidade e formato de saida.
* **Saida:** Estrutura de dados normalizada contendo o resultado da sessao de auditoria.

```json
{
  "scan_id": "ciberpt-20261105-001",
  "target": "https://exemplo.pt",
  "timestamp": "2026-11-05T13:30:00Z",
  "score": 85,
  "findings": [
    {
      "id": "SEC-HDR-001",
      "module": "web",
      "severity": "HIGH",
      "title": "Strict-Transport-Security (HSTS) ausente",
      "description": "O cabecalho HSTS nao foi detetado na resposta HTTP.",
      "remediation": "Adicionar o cabecalho 'Strict-Transport-Security: max-age=31536000; includeSubDomains'."
    }
  ]
}
```

### 1.2 Modulo Web (`ciberpt.modules.web`)
Executa verificacoes remotas nao-intrusivas sobre servicos web e infraestrutura de suporte:
* **web.headers:** Inspecao de cabecalhos de seguranca conforme recomendacoes da OWASP (HSTS, CSP, XFO, XCTO, Referrer-Policy, Permissions-Policy) e vazamento de informacao (Server, X-Powered-By).
* **web.tls:** Validacao de certificados digitais X.509, contagem de dias remanescentes para expiracao e detecao de protocolos TLS obsoletos.
* **web.dns:** Inspecao de registos defensivos contra spoofing de e-mail (SPF e DMARC) via DNS-over-HTTPS.
* **web.cors:** Auditoria de politicas de Cross-Origin Resource Sharing, detecao de reflexao de origens arbitrarias com credenciais e aceitacao da origem 'null'.
* **web.cookies:** Verificacao de diretivas de seguranca em cookies HTTP (Secure, HttpOnly, SameSite).

### 1.3 Modulo de Seguranca de Aplicacoes (`ciberpt.modules.appsec`)
Realiza analise estatica de codigo (SAST) em repositorios locais:
* **appsec.php_upload:** Detecao de vulnerabilidades de upload arbitrario de ficheiros e vetores de execucao remota (php2shell):
  * **Listas Negras Fracas:** Deteccao de verificacoes que tentam filtrar apenas '.php', permitindo variantes como `.php2`, `.php3`, `.phtml`, `.phar`.
  * **Destino Derivado de Input do Cliente:** Deteccao de chamadas a `move_uploaded_file()` utilizando `$_FILES['...']['name']` sem renomeacao criptografica aleatoria.
  * **MIME-Type Vulneravel:** Alerta sobre validacao baseada exclusivamente em `$_FILES['...']['type']` controlado pelo atacante.
  * **Invocacao de Comandos em Uploads:** Identificacao de funcoes de execucao do sistema (`system`, `exec`, `shell_exec`) em modulos de upload.

### 1.4 Modulo de Deteccao de Segredos (`ciberpt.modules.secrets`)
Realiza analise estatica do sistema de ficheiros local:
* **Assinaturas Regex:** Identificacao de formatos conhecidos de chaves criptograficas e tokens de autenticacao.
* **Analise de Entropia:** Deteccao de cadeias de caracteres com elevada entropia de Shannon.
* **Validacao de Ficheiros Criticos:** Sinalizacao de ficheiros de configuracao sensiveis no indice do repositorio.

### 1.5 Modulo de Relatorios (`ciberpt.reporters`)
* **Terminal:** Renderizacao tabular com codificacao de cores por severidade e exit codes padronizados (0 para sucesso sem achados criticos, >0 para presenca de vulnerabilidades conforme threshold definido).
* **JSON:** Exportacao estruturada para consumo programatico e pipelines de automacao.
* **HTML:** Relatorio estatico autonomo com design responsivo, resumo executivo, contadores de severidade e instrucoes detalhadas de mitigacao, sem dependencias de CDNs externas.
* **SARIF:** Conformidade com a norma OASIS SARIF v2.1.0 para integracao direta com ferramentas de gestao de vulnerabilidades.

---

## 2. Analise Comparativa de Linguagens de Implementacao

| Criterio | Python (ex: Typer) | Go (ex: Cobra) | Rust (ex: Clap) |
| :--- | :--- | :--- | :--- |
| **Velocidade de Prototipagem** | Elevada | Moderada / Elevada | Moderada |
| **Distribuicao Binaria** | Depende de runtime ou empacotador | Binario estatico autonomo | Binario estatico compilado |
| **Bibliotecas de Seguranca/Rede** | Amplo ecossistema | Robusto e integrado na biblioteca padrao | Ecossistema moderno e seguro em memoria |
| **Eficiencia de Recursos / I/O** | Moderada | Elevada (Goroutines nativas) | Maxima |

### Avaliacao Tecnica:
* **Python:** Reduz o tempo de desenvolvimento inicial do MVP e simplifica a implementacao de regras complexas de analise estatica.
* **Go:** Minimiza problemas de ambiente de execucao no utilizador final devido a geracao de executaveis estaticos sem dependencias externas.
