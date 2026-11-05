import argparse
import sys
from typing import Optional

from ciberpt import __version__
from ciberpt.core.engine import AuditEngine
from ciberpt.core.models import Severity
from ciberpt.reporters.console import ConsoleReporter
from ciberpt.reporters.json_reporter import JSONReporter


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ciberpt",
        description="ciberpt - Utilitario modular de auditoria e seguranca defensiva em linha de comando",
    )
    parser.add_argument(
        "-v", "--version",
        action="version",
        version=f"ciberpt {__version__}",
    )

    subparsers = parser.add_subparsers(dest="command", help="Comandos disponiveis")

    # Comando 'scan'
    scan_parser = subparsers.add_parser("scan", help="Executar auditoria de seguranca")
    scan_parser.add_argument(
        "target",
        help="Alvo a auditar (URL, endereco de host ou dominio)",
    )
    scan_parser.add_argument(
        "-m", "--module",
        choices=["all", "web", "web.headers", "web.tls"],
        default="all",
        help="Modulo especifico a executar (default: all)",
    )
    scan_parser.add_argument(
        "--json",
        action="store_true",
        help="Emitir saida exclusivamente em formato JSON para o stdout",
    )
    scan_parser.add_argument(
        "-o", "--output",
        help="Caminho do ficheiro para persistir o relatorio JSON",
    )
    scan_parser.add_argument(
        "--min-severity",
        choices=["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"],
        default="INFO",
        help="Filtrar achados com severidade igual ou superior a indicada",
    )
    scan_parser.add_argument(
        "--fail-on",
        choices=["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"],
        default=None,
        help="Encerrar com exit code 1 caso existam achados iguais ou superiores a severidade indicada (util para pipelines CI/CD)",
    )
    scan_parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        help="Tempo limite em segundos para cada operacao de rede (default: 10)",
    )

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 0

    if args.command == "scan":
        min_sev = Severity(args.min_severity) if args.min_severity else Severity.INFO
        engine = AuditEngine(modules=[args.module], timeout=args.timeout)

        try:
            result = engine.run(args.target)
        except Exception as e:
            sys.stderr.write(f"Erro operacional durante execucao do motor: {str(e)}\n")
            return 2

        if args.output:
            JSONReporter.save(result, args.output)

        if args.json:
            sys.stdout.write(JSONReporter.render(result) + "\n")
        else:
            ConsoleReporter.render(result, min_severity=min_sev)

        if args.fail_on:
            threshold = Severity(args.fail_on).rank
            has_blocking = any(f.severity.rank >= threshold for f in result.findings)
            if has_blocking:
                return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
