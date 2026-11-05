# Principios de Arquitetura - ciberpt

Este documento define os principios de engenharia, modelo de execucao e padroes de extensibilidade adotados no ciberpt.

---

## 1. Principios de Design

### 1.1 Postura Estritamente Defensiva
O ciberpt opera exclusivamente no dominio da seguranca defensiva e auditoria de conformidade. Todas as operacoes remotas limitam-se a consultas padronizadas de metadados, analise de cabecalhos publicos e conexoes de protocolo regulares, sem emissao de cargas destrutivas ou exploracao ativa.

### 1.2 Arquitetura Modular Desacoplada
Cada vetor de analise e implementado como um modulo isolado e independente. O motor central e agnostico em relacao as regras especificas de cada scanner, atuando exclusivamente como orquestrador de ciclo de vida e coletor de achados.

### 1.3 Normalizacao de Dados
Independentemente da origem do achado (web, codigo-fonte, manifesto de pacotes ou infraestrutura), todos os dados sao convertidos para uma estrutura comum de contrato (`Finding`).

---

## 2. Fluxo de Execucao do Sistema

```
[CLI Invocation]
       |
       v
+--------------------------+
|  Command Line Interface  |  (Parsing de flags e argumentos)
+--------------+-----------+
               |
               v
+--------------------------+
|    Engine Orchestrator   |  (Instanciacao dos modulos configurados)
+--------------+-----------+
               |
        +------+------+
        |             |
        v             v
+---------------+ +---------------+
| Module: Web   | | Module: AppSec|
+-------+-------+ +-------+-------+
        |                 |
        +--------+--------+
                 |
                 v
+--------------------------+
|    Findings Collector    |  (Agregacao, deduplicacao e calculo de score)
+--------------+-----------+
               |
               v
+--------------------------+
|     Report Generator     |  (Formatacao: Console / JSON / SARIF)
+--------------------------+
```

---

## 3. Contrato de Dados dos Achados

Cada vulnerabilidade, inconsistencia ou aviso identificado por qualquer modulo devera aderir a seguinte definicao de campos:

* **id** (`string`): Identificador unico do tipo de achado (ex: `SEC-HDR-001`).
* **module** (`string`): Modulo originador (ex: `web`, `secrets`, `sca`, `hardening`).
* **severity** (`enum`): Nivel de criticidade categorizado estritamente em `INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`.
* **title** (`string`): Descricao sucinta e tecnica da anomalia identificada.
* **description** (`string`): Detalhamento tecnico do impacto e risco operacional associado.
* **remediation** (`string`): Procedimento normativo e passos de mitigacao recomendados.
* **evidence** (`object` / `string`): Valor factual ou extrato de configuracao que fundamentou o registo do achado.
