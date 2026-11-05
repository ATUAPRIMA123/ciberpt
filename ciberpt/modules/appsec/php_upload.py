import os
import re
from pathlib import Path
from typing import List, Optional

from ciberpt.core.models import Finding, Severity
from ciberpt.modules.base import BaseScanner


class PHPUploadScanner(BaseScanner):
    DANGEROUS_EXTENSIONS = [
        "php", "php2", "php3", "php4", "php5", "php7", "phtml", "pht", "phar", "inc", "pgif"
    ]

    # Padroes indicativos de listas negras frageis (e.g., verificar se == 'php', in_array('php'), etc.)
    RE_BLACKLIST_FILTER = re.compile(
        r"""(?:in_array|strpos|preg_match)\s*\([^)]*['"](?:\.?)php(?:[0-9]|html)?['"]|(?:==|!=|===|!==)\s*['"](?:\.?)php(?:[0-9]|html)?['"]""",
        re.IGNORECASE
    )

    # Padroes de move_uploaded_file em conjunto com o nome original do ficheiro
    RE_MOVE_UPLOAD = re.compile(
        r"""move_uploaded_file\s*\(""",
        re.IGNORECASE
    )

    RE_ORIGINAL_FILENAME = re.compile(
        r"""\$_FILES\s*\[[^\]]+\]\s*\[['"]name['"]\]""",
        re.IGNORECASE
    )

    # Padroes que confiam cegamente em $_FILES['...']['type']
    RE_CLIENT_MIME = re.compile(
        r"""\$_FILES\s*\[[^\]]+\]\s*\[['"]type['"]\]""",
        re.IGNORECASE
    )

    # Padroes de execucao direta de comandos do sistema associados a PHP
    RE_COMMAND_EXEC = re.compile(
        r"""\b(system|exec|shell_exec|passthru|popen|proc_open|eval)\s*\(""",
        re.IGNORECASE
    )

    @property
    def name(self) -> str:
        return "appsec.php_upload"

    @property
    def description(self) -> str:
        return "Analise estatica de vulnerabilidades de upload arbitrario de ficheiros e RCE em PHP (php2shell)"

    def scan(self, target: str, **kwargs) -> List[Finding]:
        target_path = Path(target)
        findings: List[Finding] = []

        if not target_path.exists():
            return findings

        if target_path.is_file():
            if target_path.suffix.lower() in [".php", ".phtml", ".inc", ".php5"]:
                findings.extend(self.audit_file(target_path))
        elif target_path.is_dir():
            for root, _, files in os.walk(target_path):
                # Ignorar diretorios comuns de dependencias
                if any(ignored in root.replace("\\", "/").split("/") for ignored in ["vendor", "node_modules", ".git"]):
                    continue
                for file in files:
                    file_path = Path(root) / file
                    if file_path.suffix.lower() in [".php", ".phtml", ".inc", ".php5"]:
                        findings.extend(self.audit_file(file_path))

        return findings

    def audit_file(self, file_path: Path) -> List[Finding]:
        findings: List[Finding] = []
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return findings

        lines = content.splitlines()

        # 1. Analise de move_uploaded_file sem renomeacao
        if self.RE_MOVE_UPLOAD.search(content) and self.RE_ORIGINAL_FILENAME.search(content):
            if not self._has_safe_renaming(content):
                line_no = self._find_line_number(lines, self.RE_MOVE_UPLOAD)
                findings.append(Finding(
                    id="SEC-APPSEC-PHP-UNRESTRICTED-UPLOAD",
                    module=self.name,
                    severity=Severity.CRITICAL,
                    title="Upload arbitrario: destino derivado diretamente de $_FILES['name']",
                    description=(
                        f"O ficheiro {file_path.name}:{line_no} move ficheiros utilizando o nome original "
                        "fornecido pelo cliente ($_FILES['...']['name']) sem renomeacao aleatoria ou hash criptografico. "
                        "Isto permite a atacantes enviar ficheiros executaveis com extensoes como .php, .php2 ou .phtml, "
                        "resultando em execucao remota de comandos (Webshell)."
                    ),
                    remediation=(
                        "Nunca utilizar o nome original do ficheiro para gravar no disco. Gerar um identificador criptografico "
                        "aleatorio (e.g., bin2hex(random_bytes(16))) e associar uma extensao rigorosamente validada por whitelist."
                    ),
                    evidence={"file": str(file_path), "line": line_no},
                ))

        # 2. Analise de listas negras ineficazes
        if self.RE_BLACKLIST_FILTER.search(content) and not self._has_whitelist(content):
            line_no = self._find_line_number(lines, self.RE_BLACKLIST_FILTER)
            findings.append(Finding(
                id="SEC-APPSEC-PHP-BLACKLIST-FILTER",
                module=self.name,
                severity=Severity.HIGH,
                title="Filtro de extensao baseado em lista negra (Bypass de php2shell)",
                description=(
                    f"Identificada validacao baseada na exclusao de '.php' em {file_path.name}:{line_no}. "
                    "Listas negras sao ineficazes, pois interpretadores e servidores web frequentemente executam extensoes "
                    "alternativas como .php2, .php3, .php4, .php5, .phtml, .pht ou .phar."
                ),
                remediation=(
                    "Substituir listas negras por uma lista branca (whitelist) restrita de extensoes explicitamente permitidas "
                    "(e.g., ['jpg', 'png', 'pdf']) e rejeitar qualquer outra extensao."
                ),
                evidence={"file": str(file_path), "line": line_no},
            ))

        # 3. Confianca indevida em $_FILES['...']['type']
        if self.RE_CLIENT_MIME.search(content) and ("move_uploaded_file" in content or "file_put_contents" in content):
            line_no = self._find_line_number(lines, self.RE_CLIENT_MIME)
            findings.append(Finding(
                id="SEC-APPSEC-PHP-TRUST-CLIENT-MIME",
                module=self.name,
                severity=Severity.MEDIUM,
                title="Validacao de tipo de ficheiro baseada em MIME controlado pelo cliente",
                description=(
                    f"O codigo em {file_path.name}:{line_no} referencia $_FILES['...']['type']. "
                    "Este valor e derivado diretamente do cabecalho HTTP Content-Type enviado pelo utilizador e pode "
                    "ser facilmente manipulado (ex: enviar script PHP com 'image/png')."
                ),
                remediation=(
                    "Inspecionar o conteudo real do ficheiro no servidor utilizando finfo_file(finfo_open(FILEINFO_MIME_TYPE), $tmp) "
                    "ou a funcao mime_content_type()."
                ),
                evidence={"file": str(file_path), "line": line_no},
            ))

        # 4. Funcoes de execucao de sistema em ficheiros com rotinas de upload
        if ("move_uploaded_file" in content or "file_put_contents" in content) and self.RE_COMMAND_EXEC.search(content):
            line_no = self._find_line_number(lines, self.RE_COMMAND_EXEC)
            findings.append(Finding(
                id="SEC-APPSEC-PHP-COMMAND-EXECUTION",
                module=self.name,
                severity=Severity.HIGH,
                title="Invocacao de funcoes de execucao de comandos em modulo de manipulacao de ficheiros",
                description=(
                    f"Detetada utilizacao de funcoes de execucao de comandos do sistema operativo em {file_path.name}:{line_no}. "
                    "Se argumentos externos alcancarem estas rotinas apos o upload, ocorre escalada direta para RCE."
                ),
                remediation="Evitar chamadas a funcoes como system(), exec() ou shell_exec(). Caso estritamente necessario, utilizar escapeshellarg().",
                evidence={"file": str(file_path), "line": line_no},
            ))

        return findings

    def _has_whitelist(self, content: str) -> bool:
        whitelist_indicators = ["allowed_extensions", "allowed_ext", "whitelist", "permitted_ext"]
        return any(ind in content.lower() for ind in whitelist_indicators)

    def _has_safe_renaming(self, content: str) -> bool:
        renaming_indicators = [
            "random_bytes", "bin2hex", "uniqid", "md5(", "sha1(", "hash(", "uuid", "random_int"
        ]
        return any(ind in content.lower() for ind in renaming_indicators)

    def _find_line_number(self, lines: List[str], regex: re.Pattern) -> int:
        for idx, line in enumerate(lines, 1):
            if regex.search(line):
                return idx
        return 1
