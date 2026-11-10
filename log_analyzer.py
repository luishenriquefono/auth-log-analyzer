"""
Analisador de Logs e Detecção de Falhas de Autenticação.
Lê logs no formato: DATA HORA STATUS IP USUARIO
Exemplo: 2026-11-10 10:14:02 FAIL 192.168.1.50 admin
"""

from collections import Counter
from datetime import datetime

DADOS_EXEMPLO = """2026-11-10 08:12:01 SUCCESS 192.168.1.10 user1
2026-11-10 08:14:22 FAIL 203.0.113.195 admin
2026-11-10 08:14:25 FAIL 203.0.113.195 root
2026-11-10 08:14:28 FAIL 203.0.113.195 admin
2026-11-10 08:15:02 FAIL 203.0.113.195 support
2026-11-10 08:20:11 SUCCESS 192.168.1.15 dev_luis
2026-11-10 08:33:40 FAIL 198.51.100.4 guest
2026-11-10 08:35:10 FAIL 203.0.113.195 test
"""


def analisar_logs(linhas_log: list[str], limite_alerta: int = 3) -> dict:
    ips_falha = Counter()
    usuarios_alvo = Counter()
    total_sucessos = 0
    total_falhas = 0

    for linha in linhas_log:
        linha = linha.strip()
        if not linha:
            continue

        partes = linha.split()
        if len(partes) < 5:
            continue

        data, hora, status, ip, usuario = partes[:5]

        if status == "FAIL":
            total_falhas += 1
            ips_falha[ip] += 1
            usuarios_alvo[usuario] += 1
        elif status == "SUCCESS":
            total_sucessos += 1

    ips_suspeitos = {
        ip: contagem
        for ip, contagem in ips_falha.items()
        if contagem >= limite_alerta
    }

    return {
        "total_sucessos": total_sucessos,
        "total_falhas": total_falhas,
        "ips_suspeitos": ips_suspeitos,
        "usuarios_mais_visados": usuarios_alvo.most_common(3),
    }


def gerar_relatorio(metricas: dict) -> None:
    print("=" * 45)
    print(" 🛡️  RELATÓRIO DE MONITORAMENTO DE ACESSOS")
    print("=" * 45)
    print(f"Logins com sucesso: {metricas['total_sucessos']}")
    print(f"Logins com falha:   {metricas['total_falhas']}")
    print("-" * 45)

    print("⚠️  Alertas de Força Bruta (Possíveis Ameaças):")
    if metricas["ips_suspeitos"]:
        for ip, qtd in metricas["ips_suspeitos"].items():
            print(f"  - IP: {ip:<15} | Falhas consecutivas: {qtd}")
    else:
        print("  - Nenhuma anomalia detectada.")

    print("-" * 45)
    print("🎯 Alvos Mais Frequentes:")
    for usuario, qtd in metricas["usuarios_mais_visados"]:
        print(f"  - Usuário '{usuario}': {qtd} tentativa(s)")
    print("=" * 45)


if __name__ == "__main__":
    linhas = DADOS_EXEMPLO.strip().split("\n")
    metricas = analisar_logs(linhas, limite_alerta=3)
    gerar_relatorio(metricas)
