# auth-log-analyzer
Script CLI em Python puro para parseamento de arquivos de log, contabilização de falhas de autenticação e mitigação de tentativas de força bruta via detecção por limiar de requisições.
# 🛡️ Auth Log Analyzer

Um script CLI leve e modular desenvolvido em Python puro para análise de logs de autenticação, identificação de acessos suspeitos e detecção de ataques de força bruta (*brute-force*).

---

### 📌 Sobre o Projeto

Em ambientes de infraestrutura e segurança da informação, a análise rápida de registros de autenticação é fundamental para identificar comportamentos anômalos antes que uma invasão ocorra. 

Este projeto processa arquivos ou fluxos de log de autenticação, extrai métricas operacionais e aplica regras baseadas em limiares configuráveis para alertar sobre IPs que excedem limites seguros de falhas consecutivas.

---

### ⚙️ Funcionalidades

- **Processamento de Linhas de Log:** Extração de *timestamp*, status do evento (`SUCCESS` / `FAIL`), endereço IP de origem e nome de usuário.
- **Detecção de Força Bruta:** Identificação automática de endereços IP que excedem um limite definido de tentativas inválidas.
- **Mapeamento de Alvos:** Ranqueamento dos nomes de usuários mais visados durante tentativas de invasão.
- **Resumo Estruturado no Terminal:** Saída limpa e formatada para visualização direta no console.
- **Zero Dependências Externas:** Desenvolvido exclusivamente com bibliotecas nativas do Python (`collections`, `datetime`).

---

### 📁 Formato de Log Suportado

O analisador processa entradas de texto estruturadas com a seguinte ordem posicional:

```text
YYYY-MM-DD HH:MM:SS <STATUS> <IP_ORIGEM> <USUARIO>
