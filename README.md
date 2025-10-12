<div align="center">
  <img src="assets/logo-aresprobe.png" alt="AresProbe Logo" width="400"/>
  
  # AresProbe
  ### Advanced Web Security Testing Framework
  
  [![GitHub](https://img.shields.io/badge/GitHub-g0dux%2FAresProbe-blue?logo=github)](https://github.com/g0dux/AresProbe)
  [![Python](https://img.shields.io/badge/Python-3.8%2B-blue?logo=python)](https://www.python.org/)
  [![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
  
  **Mais poderoso que Burp Suite + SQLMap combinados**
  
  ---
</div>

## 📋 Sobre o Projeto

AresProbe é uma ferramenta de teste de segurança web avançada que combina as funcionalidades do Burp Suite e SQLMap, mas com maior eficiência e uma interface de terminal poderosa. Desenvolvida para profissionais de segurança que precisam de uma ferramenta completa e modular.

## 🚀 Características Principais

### 🔍 Testes de Segurança Avançados
- **SQL Injection**: Múltiplas técnicas (Boolean-based, Time-based, Union-based, Error-based, Stacked queries)
- **XSS (Cross-Site Scripting)**: Detecção de vulnerabilidades XSS com payloads avançados
- **Directory Traversal**: Teste de vulnerabilidades de travessia de diretório
- **Command Injection**: Detecção de injeção de comandos do sistema
- **XXE (XML External Entity)**: Teste de vulnerabilidades XXE
- **SSRF (Server-Side Request Forgery)**: Detecção de vulnerabilidades SSRF

### 🌐 Proxy HTTP/HTTPS
- Interceptação de tráfego em tempo real
- Suporte completo a HTTPS com tunneling
- Análise de requisições e respostas
- Modificação de tráfego em tempo real

### 📊 Relatórios Detalhados
- Relatórios em múltiplos formatos (JSON, HTML, TXT)
- Análise detalhada de vulnerabilidades
- Métricas de performance e tempo de resposta
- Exportação de dados para análise posterior

### 🔧 Interface Modular
- CLI interativa e intuitiva
- Sistema de plugins extensível
- Gerenciamento de sessões avançado
- Logging detalhado com níveis configuráveis

## 📦 Instalação

### Pré-requisitos
- Python 3.8 ou superior
- pip (gerenciador de pacotes Python)

### Instalação Rápida

#### Windows (Recomendado)
```bash
# Clone o repositório
git clone https://github.com/g0dux/AresProbe.git
cd AresProbe

# Crie um ambiente virtual
python -m venv venv

# Ative o ambiente virtual
venv\Scripts\activate

# Instalação automática para Windows
python install_windows.py

# Ou instalação manual
pip install -r requirements-windows.txt

# Execute o AresProbe
python main.py
```

#### Linux/Mac
```bash
# Clone o repositório
git clone https://github.com/g0dux/AresProbe.git
cd AresProbe

# Crie um ambiente virtual
python -m venv venv

# Ative o ambiente virtual
source venv/bin/activate

# Instale as dependências
pip install -r requirements.txt

# Execute o AresProbe
python main.py
```

### Solução de Problemas Windows

Se você encontrar problemas com `uvloop` no Windows:
- Use `requirements-windows.txt` em vez de `requirements.txt`
- Execute `python install_windows.py` para instalação automática
- O `uvloop` não é compatível com Windows, mas o AresProbe funciona perfeitamente sem ele

## 🎯 Uso Rápido

### Modo Interativo
```bash
python main.py
```

### Scan Rápido
```bash
python main.py --scan http://example.com
```

### Proxy Server
```bash
python main.py --proxy 8080
```

## 📖 Comandos Principais

### Scan de Segurança
```bash
# Scan completo
scan http://example.com --type comprehensive

# Scan específico de SQL Injection
scan http://example.com --type sql

# Scan com proxy habilitado
scan http://example.com --proxy --threads 20
```

### Gerenciamento de Proxy
```bash
# Iniciar proxy
proxy start 8080

# Verificar status
proxy status

# Ver requisições interceptadas
proxy requests

# Limpar dados interceptados
proxy clear
```

### Relatórios
```bash
# Gerar relatório
report generate

# Mostrar últimos resultados
report show

# Exportar em diferentes formatos
report export json
report export html
```

## 🔧 Configuração Avançada

### Variáveis de Ambiente
```bash
# Configurar nível de log
export ARESPROBE_LOG_LEVEL=DEBUG

# Configurar timeout padrão
export ARESPROBE_TIMEOUT=60

# Configurar número de threads
export ARESPROBE_THREADS=20
```

### Arquivo de Configuração
Crie um arquivo `config.json` na raiz do projeto:
```json
{
    "default_timeout": 30,
    "default_threads": 10,
    "proxy_port": 8080,
    "log_level": "INFO",
    "user_agent": "AresProbe/1.0",
    "verify_ssl": false
}
```

## 🛡️ Recursos de Segurança

### Proteções Implementadas
- Validação rigorosa de entrada
- Sanitização de payloads maliciosos
- Rate limiting para evitar sobrecarga
- Logging de todas as operações
- Verificação de permissões

### Boas Práticas
- Use apenas em ambientes autorizados
- Mantenha logs de todas as operações
- Atualize regularmente as dependências
- Monitore o uso de recursos

## 📚 Documentação

### Estrutura do Projeto
```
aresprobe/
├── core/           # Módulos principais
│   ├── engine.py   # Motor principal
│   ├── proxy.py    # Servidor proxy
│   ├── scanner.py  # Scanner de vulnerabilidades
│   ├── sql_injector.py  # Engine de SQL injection
│   ├── session.py  # Gerenciador de sessões
│   └── logger.py   # Sistema de logging
├── cli/            # Interface de linha de comando
│   ├── interface.py # CLI principal
│   └── commands.py  # Implementação de comandos
└── plugins/        # Sistema de plugins
```

### API de Desenvolvimento
```python
from aresprobe import AresEngine, ScanConfig, ScanType

# Inicializar engine
engine = AresEngine()
engine.initialize()

# Configurar scan
config = ScanConfig(
    target_url="http://example.com",
    scan_types=[ScanType.SQL_INJECTION, ScanType.XSS],
    threads=10,
    timeout=30
)

# Executar scan
results = engine.run_scan(config)

# Gerar relatório
report = engine.generate_report("report.html")
```

## 🤝 Contribuição

Contribuições são bem-vindas! Por favor:

1. Fork o projeto
2. Crie uma branch para sua feature (`git checkout -b feature/AmazingFeature`)
3. Commit suas mudanças (`git commit -m 'Add some AmazingFeature'`)
4. Push para a branch (`git push origin feature/AmazingFeature`)
5. Abra um Pull Request

## 📄 Licença

Este projeto está licenciado sob a Licença MIT - veja o arquivo [LICENSE](LICENSE) para detalhes.

## ⚠️ Aviso Legal

Esta ferramenta é destinada apenas para testes de segurança autorizados. O uso não autorizado é estritamente proibido e pode violar leis locais e internacionais. Os desenvolvedores não se responsabilizam pelo uso indevido desta ferramenta.

## 📞 Suporte

- **Issues**: [GitHub Issues](https://github.com/g0dux/AresProbe/issues)
- **Documentação**: [Wiki](https://github.com/g0dux/AresProbe/wiki)
- **Discord**: [Servidor da Comunidade](https://discord.gg/aresprobe)

## 🏆 Reconhecimentos

- Inspirado no Burp Suite e SQLMap
- Comunidade de segurança open source
- Contribuidores e testadores

---

**AresProbe** - Mais poderoso que Burp Suite + SQLMap, com a eficiência que você precisa.
