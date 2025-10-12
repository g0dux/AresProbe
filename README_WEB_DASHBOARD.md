# AresProbe Web Dashboard & API

## 🚀 **VISÃO GERAL**

O AresProbe agora inclui um **Web Dashboard completo** e uma **API REST robusta** para automação e integração. Esta implementação oferece uma interface web profissional e uma API para automação de testes de segurança.

## 🌐 **WEB DASHBOARD**

### **Características Principais:**

- **Interface Web Moderna** - Design cyber/hacker com tema escuro
- **Dashboard em Tempo Real** - Métricas e monitoramento ao vivo
- **Gráficos Interativos** - Visualização de dados com Chart.js
- **Gerenciamento de Scans** - Interface para criar, monitorar e gerenciar scans
- **Análise de Vulnerabilidades** - Visualização e análise de resultados
- **Monitoramento de Performance** - Métricas de sistema em tempo real
- **WebSockets** - Atualizações em tempo real sem refresh

### **Funcionalidades:**

1. **Dashboard Principal**
   - Estatísticas gerais (total de scans, scans ativos, vulnerabilidades)
   - Gráficos de atividade de scans
   - Distribuição de severidade de vulnerabilidades
   - Métricas de performance do sistema

2. **Gerenciamento de Scans**
   - Criação de novos scans via interface web
   - Monitoramento de progresso em tempo real
   - Cancelamento de scans ativos
   - Histórico de scans

3. **Análise de Vulnerabilidades**
   - Listagem de vulnerabilidades encontradas
   - Filtros por severidade
   - Detalhes de cada vulnerabilidade
   - Recomendações de correção

4. **Monitoramento de Sistema**
   - Uso de CPU e memória
   - Throughput de rede
   - Tempo de resposta
   - Status dos engines

## 🔌 **API REST**

### **Características Principais:**

- **API REST Completa** - Endpoints para todas as funcionalidades
- **Autenticação JWT** - Sistema de autenticação seguro
- **Chaves de API** - Automação com chaves de API
- **Documentação Interativa** - Swagger UI integrado
- **Webhooks** - Notificações em tempo real
- **Rate Limiting** - Proteção contra abuso
- **Validação de Dados** - Pydantic para validação

### **Endpoints Principais:**

#### **Autenticação:**
- `POST /api/v1/auth/login` - Login de usuário
- `POST /api/v1/auth/refresh` - Renovar token
- `POST /api/v1/auth/api-keys` - Criar chave de API

#### **Scans:**
- `POST /api/v1/scans` - Criar novo scan
- `GET /api/v1/scans` - Listar scans
- `GET /api/v1/scans/{id}` - Status do scan
- `DELETE /api/v1/scans/{id}` - Cancelar scan

#### **Vulnerabilidades:**
- `GET /api/v1/scans/{id}/vulnerabilities` - Vulnerabilidades do scan
- `GET /api/v1/vulnerabilities` - Listar todas as vulnerabilidades

#### **Relatórios:**
- `POST /api/v1/reports` - Gerar relatório
- `GET /api/v1/reports/{id}/download` - Download do relatório

#### **Performance:**
- `GET /api/v1/performance` - Métricas de performance
- `GET /api/v1/system` - Informações do sistema

#### **AI/ML:**
- `POST /api/v1/ai/analyze` - Análise com IA
- `GET /api/v1/ai/stats` - Estatísticas dos modelos

#### **Evasion:**
- `POST /api/v1/evasion/test` - Teste de evasão

## 🚀 **COMO USAR**

### **1. Iniciar o Web Dashboard:**

```bash
# Ativar ambiente virtual
# Windows
venv\Scripts\activate
# Linux/Mac
source venv/bin/activate

# Iniciar dashboard web completo
python start_web_dashboard.py
```

**Acesse:** http://localhost:8080

### **2. Iniciar apenas a API:**

```bash
# Iniciar apenas o servidor API
python start_api_server.py
```

**API:** http://localhost:8000  
**Documentação:** http://localhost:8000/docs

### **3. Usar a API via cURL:**

```bash
# Login
curl -X POST "http://localhost:8000/api/v1/auth/login" \
     -H "Content-Type: application/json" \
     -d '{"username": "admin", "password": "admin"}'

# Criar scan
curl -X POST "http://localhost:8000/api/v1/scans" \
     -H "Authorization: Bearer YOUR_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"target": "https://example.com", "scan_types": ["comprehensive"]}'

# Verificar status do scan
curl -X GET "http://localhost:8000/api/v1/scans/SCAN_ID" \
     -H "Authorization: Bearer YOUR_TOKEN"
```

### **4. Usar com Chave de API:**

```bash
# Criar chave de API (requer admin)
curl -X POST "http://localhost:8000/api/v1/auth/api-keys" \
     -H "Authorization: Bearer ADMIN_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"name": "My API Key", "permissions": ["scan:create", "scan:read"]}'

# Usar chave de API
curl -X GET "http://localhost:8000/api/v1/scans" \
     -H "Authorization: ares_YOUR_API_KEY"
```

## 🔐 **AUTENTICAÇÃO**

### **Usuário Padrão:**
- **Username:** `admin`
- **Password:** `admin`

### **Tipos de Autenticação:**

1. **JWT Tokens** - Para interface web e acesso temporário
2. **API Keys** - Para automação e integração

### **Permissões:**

- `scan:create` - Criar scans
- `scan:read` - Ler scans
- `scan:delete` - Cancelar scans
- `vulnerability:read` - Ler vulnerabilidades
- `report:create` - Gerar relatórios
- `report:read` - Ler relatórios
- `ai:analyze` - Usar análise de IA
- `evasion:test` - Testar evasão
- `system:read` - Ler informações do sistema
- `dashboard:read` - Acessar dashboard
- `*` - Todas as permissões (admin)

## 📊 **DASHBOARD FEATURES**

### **Interface Moderna:**
- Tema cyber/hacker com cores verdes e pretas
- Design responsivo para desktop e mobile
- Animações e transições suaves
- Indicadores visuais de status

### **Tempo Real:**
- WebSockets para atualizações instantâneas
- Gráficos que se atualizam automaticamente
- Progresso de scans em tempo real
- Métricas de sistema ao vivo

### **Funcionalidades Avançadas:**
- Filtros e busca
- Exportação de dados
- Notificações toast
- Modais interativos
- Tooltips informativos

## 🔧 **CONFIGURAÇÃO**

### **Variáveis de Ambiente:**

```bash
# Configurações do servidor
ARESPROBE_ENV=web                    # Modo de execução
ARESPROBE_PLATFORM=windows           # Plataforma (windows/unix)
PYTHONPATH=/path/to/aresprobe        # Caminho do Python

# Configurações da API
API_HOST=0.0.0.0                    # Host da API
API_PORT=8000                       # Porta da API
WEB_PORT=8080                       # Porta do Web Dashboard

# Configurações de segurança
JWT_SECRET_KEY=your_secret_key       # Chave secreta JWT
API_KEY_PREFIX=ares_                 # Prefixo das chaves de API
```

### **Personalização:**

1. **Tema:** Edite `aresprobe/web/templates/base.html`
2. **API:** Modifique `aresprobe/api/routes.py`
3. **Dashboard:** Edite `aresprobe/web/static/dashboard.js`

## 🛠️ **DESENVOLVIMENTO**

### **Estrutura de Arquivos:**

```
aresprobe/
├── api/                    # API REST
│   ├── __init__.py
│   ├── main.py            # Aplicação FastAPI principal
│   ├── routes.py          # Endpoints da API
│   ├── auth.py            # Autenticação e autorização
│   └── models.py          # Modelos Pydantic
├── web/                   # Web Dashboard
│   ├── __init__.py
│   ├── main.py            # Aplicação web principal
│   ├── routes.py          # Rotas web
│   ├── templates/         # Templates HTML
│   │   ├── base.html      # Template base
│   │   └── dashboard.html # Dashboard principal
│   └── static/            # Arquivos estáticos
│       └── dashboard.js   # JavaScript do dashboard
├── start_web_dashboard.py # Launcher do dashboard
└── start_api_server.py    # Launcher da API
```

### **Adicionar Novos Endpoints:**

1. **API:** Adicione em `aresprobe/api/routes.py`
2. **Web:** Adicione em `aresprobe/web/routes.py`
3. **Modelos:** Defina em `aresprobe/api/models.py`

### **Adicionar Novas Páginas Web:**

1. Crie template em `aresprobe/web/templates/`
2. Adicione rota em `aresprobe/web/routes.py`
3. Adicione JavaScript se necessário

## 🚨 **TROUBLESHOOTING**

### **Problemas Comuns:**

1. **Porta em uso:**
   ```bash
   # Verificar portas em uso
   netstat -an | grep :8080
   netstat -an | grep :8000
   ```

2. **Dependências faltando:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Erro de importação:**
   ```bash
   export PYTHONPATH=/path/to/aresprobe
   ```

4. **WebSocket não conecta:**
   - Verifique se o firewall permite conexões WebSocket
   - Confirme se o servidor está rodando

### **Logs:**

- **API:** Logs aparecem no console
- **Web:** Logs aparecem no console
- **Erros:** Verifique o console do navegador (F12)

## 📈 **PRÓXIMOS PASSOS**

### **Melhorias Planejadas:**

1. **Autenticação Avançada:**
   - OAuth2 integration
   - Multi-factor authentication
   - LDAP/AD integration

2. **Dashboard Avançado:**
   - Mais tipos de gráficos
   - Filtros avançados
   - Relatórios personalizados

3. **API Avançada:**
   - GraphQL endpoint
   - Webhook management
   - API versioning

4. **Integrações:**
   - SIEM integration
   - Ticketing systems
   - CI/CD pipelines

## 🎯 **CONCLUSÃO**

O AresProbe agora oferece uma **interface web profissional** e uma **API REST completa** para automação. Isso torna a ferramenta adequada tanto para uso manual via interface web quanto para integração em pipelines de automação.

**Recursos Implementados:**
- ✅ Web Dashboard completo
- ✅ API REST robusta
- ✅ Autenticação JWT e API Keys
- ✅ WebSockets para tempo real
- ✅ Documentação interativa
- ✅ Interface moderna e responsiva

A ferramenta está pronta para uso em ambientes de produção! 🚀
