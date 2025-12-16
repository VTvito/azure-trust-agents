# 🏆 Hackathon Recap: Automated Regulatory Compliance & Audit

**Autore**: Percorso personale nell'hackathon  
**Periodo**: Dicembre 2025  
**Obiettivo**: Sistema di rilevamento frodi e compliance automatizzato con Microsoft Agent Framework

---

## 📚 Indice

1. [Panoramica del Progetto](#panoramica-del-progetto)
2. [Challenge 0: Setup & Infrastruttura](#challenge-0-setup--infrastruttura)
3. [Challenge 1: Microsoft Agent Framework](#challenge-1-microsoft-agent-framework)
4. [Challenge 2: MCP Server Integration](#challenge-2-mcp-server-integration)
5. [Concetti Chiave Appresi](#concetti-chiave-appresi)
6. [Architettura Finale](#architettura-finale)
7. [Risorse Azure Utilizzate](#risorse-azure-utilizzate)
8. [Prossimi Passi](#prossimi-passi)

---

## 🎯 Panoramica del Progetto

### Il Contesto
L'hackathon si concentra sulla creazione di un sistema intelligente per la **compliance regolamentare automatizzata** nel settore finanziario, utilizzando il nuovo **Microsoft Agent Framework** (rilasciato nell'Ottobre 2025). Il sistema analizza transazioni finanziarie, valuta rischi di frode, e genera report di audit completi.

### Obiettivi di Apprendimento Raggiunti
- ✅ Padronanza del Microsoft Agent Framework (SDK enterprise-grade)
- ✅ Creazione di agenti AI specializzati con orchestrazione sequenziale
- ✅ Integrazione MCP (Model Context Protocol) per connessioni esterne
- ✅ Uso di Azure AI Foundry, Cosmos DB, Azure AI Search
- ✅ Implementazione di workflow multi-agente con logica ibrida (rule-based + AI)

---

## 🛠️ Challenge 0: Setup & Infrastruttura

### Obiettivo
Creare l'ambiente di sviluppo e deployare tutte le risorse Azure necessarie per l'hackathon.

### Attività Completate

#### 1. **Fork del Repository**
- Repository originale: `microsoft/azure-trust-agents`
- Fork personale su GitHub per tracciare il proprio progresso

#### 2. **GitHub Codespaces**
- Ambiente di sviluppo cloud-based configurato automaticamente
- Contenitore Dev Container con tutti gli strumenti preinstallati:
  - Python 3, pip3, Azure CLI
  - Node.js, npm, eslint
  - Git, Docker CLI
  - Sistema operativo: Debian GNU/Linux 11 (bullseye)

#### 3. **Deployment Risorse Azure**

**Comando di Login:**
```bash
az login --use-device-code
```

**Deployment via ARM Template:**
- Utilizzato il bottone "Deploy to Azure" dal README
- Template ARM: `challenge-0/infra/azuredeploy.json`
- Parametri configurati:
  - Resource Group: `rg-<username>-<initials>` (nome univoco)
  - Location: Sweden Central (o altra region supportata per Azure AI Foundry)
  - servicePrincipalObjectId: lasciato vuoto

**Tempo di deployment**: ~10 minuti

**Risorse Create:**
- 🗄️ **Azure Cosmos DB** - Database NoSQL per transazioni e clienti
- 🔍 **Azure AI Search** - Indicizzazione regolamenti e policy
- 🤖 **Azure AI Foundry (Project)** - Hub per agenti AI
- 🌐 **Azure API Management (Basic v2)** - Gateway per MCP server
- 📦 **Azure Container Apps** - Hosting Fraud Alert Manager API
- 📊 **Application Insights** - Telemetria e osservabilità
- 🔐 **Azure Key Vault** - Gestione sicura delle credenziali

#### 4. **Configurazione Environment Variables**

**Script Automatizzato:**
```bash
cd challenge-0
./get-keys.sh --resource-group <NOME_RESOURCE_GROUP>
```

**File `.env` Generato** con valori critici:
```bash
# Azure AI Foundry
AI_FOUNDRY_PROJECT_ENDPOINT=https://...
MODEL_DEPLOYMENT_NAME=gpt-4o

# Cosmos DB
COSMOS_ENDPOINT=https://...
COSMOS_KEY=...

# Azure AI Search
AZURE_SEARCH_ENDPOINT=https://...
AZURE_SEARCH_KEY=...

# Azure API Management
APIM_ENDPOINT=https://...
APIM_SUBSCRIPTION_KEY=...
```

#### 5. **Data Ingestion - Seed dei Dati**

**Comando Eseguito:**
```bash
./seed_data.sh
```

**Dati Caricati:**

**Cosmos DB Containers:**
- `Transactions` - Record di transazioni finanziarie (file: `data/transactions.json`)
- `Customers` - Profili clienti con storico frodi (file: `data/customers.json`)
- `Rules/Obligations` - Regole di business e compliance
- `Alerts/Scores` - Alert generati e punteggi di rischio

**Azure AI Search Indexes:**
- `regulations-policies` - Regolamenti AML/KYC/CIP in testo non strutturato (file: `data/regulations.jsonl`)

### Concetti Chiave Challenge 0

**Infrastruttura as Code (IaC):**
- ARM Templates per deployment riproducibile
- Script bash per automazione configurazione

**Best Practices Security:**
- Key-based authentication per semplicità hackathon (⚠️ in produzione usare Managed Identity)
- Key Vault per gestione sicura delle credenziali
- APIM per controllo accesso API

**Architettura Multi-Servizio:**
- Database NoSQL (Cosmos DB) per dati strutturati
- Vector/semantic search (AI Search) per dati non strutturati
- AI orchestration (AI Foundry) per agenti intelligenti
- API Gateway (APIM) per integrazione esterna

### Verifiche Effettuate
✅ Tutte le risorse visibili nel Resource Group su Azure Portal  
✅ File `.env` popolato con tutte le chiavi necessarie  
✅ Dati caricati correttamente in Cosmos DB e AI Search  
✅ Swagger UI del Container App accessibile

---

## 🤖 Challenge 1: Microsoft Agent Framework

### Obiettivo
Costruire un sistema di rilevamento frodi completo creando **3 agenti AI specializzati** e orchestrandoli in un **workflow sequenziale** usando il Microsoft Agent Framework.

### Architettura Challenge 1

```
TX Input → [Customer Data Agent] → [Risk Analyzer Agent] → [Compliance Report Agent] → Audit Report
            ↓ Cosmos DB              ↓ Azure AI Search        ↓ Compliance Tools
         Transaction Data          Regulatory Rules           Audit Reports
```

### Parte 1: Creazione degli Agenti Individuali

#### 🗂️ **Agent 1: Customer Data Agent**

**Scopo**: Recuperare dati transazionali e profili clienti da Cosmos DB

**File**: `challenge-1/agents/customer_data_agent.py`

**Funzioni Implementate:**
```python
def get_customer_data(customer_id: str) -> dict:
    """Recupera profilo cliente completo da Cosmos DB"""
    # Query: SELECT * FROM c WHERE c.customer_id = '{customer_id}'
    
def get_customer_transactions(customer_id: str) -> list:
    """Recupera tutte le transazioni di un cliente"""
    # Cross-partition query per analisi pattern
```

**Capabilities Chiave:**
- ✅ Integrazione diretta Cosmos DB con SDK Python
- ✅ Cross-partition querying per dati distribuiti
- ✅ Normalizzazione dati (currency, timestamps, amounts)
- ✅ Enrichment transazioni con metadati cliente
- ✅ Output JSON strutturato per downstream processing

**Dati Estratti per Ogni Cliente:**
- Nome, paese, età account
- Device trust score (0-1)
- Storico frodi precedenti
- Pattern transazionali (frequenza, importi medi)

**Esecuzione Standalone:**
```bash
cd challenge-1/agents
python customer_data_agent.py
```

**Output Esempio:**
- Agent ID registrato su Azure AI Foundry
- Test query su transaction `TX2002`
- Dati cliente completi con analisi preliminare

---

#### 🔍 **Agent 2: Risk Analyzer Agent**

**Scopo**: Valutare rischio frode contro policy regolatorie usando AI Search

**File**: `challenge-1/agents/risk_analyser_agent.py`

**Integrazione Azure AI Search:**
```python
# HostedFileSearchTool per query su index "regulations-policies"
# Ricerca semantica su regolamenti AML/KYC/CIP
```

**Risk Scoring Engine (0-100):**

| **Criterio di Rischio** | **Punteggio** | **Descrizione** |
|-------------------------|--------------|-----------------|
| Paesi ad Alto Rischio | 75-85 | Iran (IR), Russia (RU), North Korea (KP), Nigeria (NG) |
| Importo Elevato | +20 | Transazioni > $10,000 USD |
| Account Nuovo | +15 | Account < 30 giorni |
| Device Trust Basso | +10 | Device trust < 0.5 |
| Pattern Sospetti | +30 | AI-detected anomalie |

**Logica Ibrida Rule-Based + AI:**

**Rule-Based (Deterministico):**
- Threshold hardcoded per compliance auditabile
- Controllo sanzioni internazionali
- Validazione KYC/CIP/EDD

**AI-Powered (Intelligente):**
- NLP su documenti regolatori (Azure AI Search)
- Pattern recognition transazionali
- Valutazione contestuale multi-fattore

**Output:**
- Risk Score: 0-100
- Risk Level: LOW/MEDIUM/HIGH/CRITICAL
- Risk Factors: Lista dettagliata motivi
- Regulatory References: Link a regolamenti trovati via search
- Compliance Status: COMPLIANT/NON_COMPLIANT/CONDITIONAL

**Esecuzione:**
```bash
python risk_analyser_agent.py
```

---

#### 📊 **Agent 3: Compliance Report Agent**

**Scopo**: Generare report di audit formali e documentazione compliance

**File**: `challenge-1/agents/compliance_report_agent.py`

**Funzioni Principali:**
```python
def parse_risk_analysis_result(risk_analysis_text: str) -> dict:
    """Estrae dati strutturati da output Risk Analyzer"""
    # Parsing: scores, levels, risk factors
    
def generate_audit_report_from_risk_analysis(risk_analysis_text: str, report_type: str) -> str:
    """Genera report audit completo con compliance rating"""
    
def generate_executive_audit_summary(multiple_risk_analyses: list, summary_period: str) -> str:
    """Dashboard executive per management oversight"""
```

**Componenti Report:**

1. **Executive Summary**
   - Transaction ID e dettagli
   - Risk Score e Compliance Rating
   - Decision: ALLOW/BLOCK/MONITOR/INVESTIGATE

2. **Detailed Findings**
   - Risk factors specifici identificati
   - Regulatory implications (AML, KYC, sanctions)
   - Compliance violations rilevate

3. **Compliance Rating Logic:**
```python
if risk_score >= 80:
    rating = "NON_COMPLIANT"
elif risk_score >= 50:
    rating = "CONDITIONAL_COMPLIANCE"
else:
    rating = "COMPLIANT"
```

4. **Actionable Recommendations**
   - SAR (Suspicious Activity Report) filing necessario?
   - Enhanced Due Diligence (EDD) required?
   - Transaction freeze raccomandato?

5. **Audit Trail**
   - Timestamp analysis
   - Data sources utilizzate
   - Metodologia applicata

**Esecuzione:**
```bash
python compliance_report_agent.py
```

---

### Parte 2: Orchestrazione Sequenziale - Workflow

#### **Registrazione Agent IDs**

Dopo la creazione di ogni agente, recuperare gli ID da Azure AI Foundry:

**Azure Portal:**
1. Navigare su [Azure AI Foundry](https://ai.azure.com/)
2. Progetto → Sezione **Agents**
3. Copiare Agent IDs

**Aggiungere al `.env`:**
```bash
CUSTOMER_DATA_AGENT_ID=asst_XXXXXXXXXXXXXXXXXXXXXXXX
RISK_ANALYSER_AGENT_ID=asst_XXXXXXXXXXXXXXXXXXXXXXXX
COMPLIANCE_REPORT_AGENT_ID=asst_XXXXXXXXXXXXXXXXXXXXXXXX
```

#### **Sequential Workflow - Jupyter Notebook**

**File**: `challenge-1/workflow/sequential_workflow.ipynb`

**Architettura Workflow:**
```python
from agent_framework import WorkflowBuilder, executor

# Pattern: Sequential Builder con 3 Executors
workflow = WorkflowBuilder(name="fraud_detection_workflow")

@executor(workflow)
async def customer_data_executor(ctx: WorkflowContext, input: AnalysisRequest) -> CustomerDataResponse:
    # Executor 1: Query Cosmos DB
    # await ctx.send_message(result) → passa al prossimo
    
@executor(workflow)
async def risk_analyzer_executor(ctx: WorkflowContext, input: CustomerDataResponse) -> RiskAnalysisResponse:
    # Executor 2: Valutazione rischio con AI Search
    # await ctx.send_message(result) → passa al prossimo
    
@executor(workflow)
async def compliance_report_executor(ctx: WorkflowContext, input: RiskAnalysisResponse) -> ComplianceAuditResponse:
    # Executor 3: Generazione audit report
    # Output finale workflow
```

**Pydantic Models per Type Safety:**
```python
from pydantic import BaseModel

class AnalysisRequest(BaseModel):
    transaction_id: str
    analysis_request: str

class CustomerDataResponse(BaseModel):
    transaction_id: str
    customer_analysis: str

class RiskAnalysisResponse(BaseModel):
    transaction_id: str
    risk_assessment: str
    recommendations: str

class ComplianceAuditResponse(BaseModel):
    transaction_id: str
    audit_report: str
    compliance_status: str
```

**Esecuzione Workflow:**

Nel notebook o via script Python:
```python
# challenge-1/workflow/sequential_workflow.py

async def main():
    # Inizializza Azure credentials
    credential = AzureCliCredential()
    
    # Workflow orchestration
    input_data = AnalysisRequest(
        transaction_id="TX2002",
        analysis_request="Analyze this transaction for fraud risk"
    )
    
    # Esegui workflow completo
    result = await workflow.run(input_data)
    
    print(f"Final Audit Report: {result.audit_report}")
```

**Output Workflow Completo:**
```
🔹 Customer Data Executor: ✅ Retrieved TX2002 data
   - Customer: John Doe (C1001)
   - Amount: $15,000 USD → Nigeria
   - Account Age: 25 days (NEW)
   - Device Trust: 0.3 (LOW)
   
🔹 Risk Analyzer Executor: ✅ Risk Assessment Complete
   - Risk Score: 85/100 (HIGH)
   - Risk Level: CRITICAL
   - Risk Factors:
     • High-risk country (Nigeria)
     • Large transaction (>$10k)
     • New account (<30 days)
     • Low device trust
   
🔹 Compliance Report Executor: ✅ Audit Report Generated
   - Compliance Rating: NON_COMPLIANT
   - Decision: BLOCK + FILE SAR
   - Recommendations:
     • Freeze transaction immediately
     • File Suspicious Activity Report
     • Conduct Enhanced Due Diligence
```

### Concetti Chiave Challenge 1

#### **Microsoft Agent Framework**
- **Executors**: Unità di processing specializzate
- **Edges**: Routing messaggi tra executors
- **Workflows**: Grafo orchestrato di executors
- **Events**: Osservabilità real-time su esecuzione

#### **Sequential Orchestration Pattern**
```
Executor 1 → Executor 2 → Executor 3
   (Data)     (Analysis)   (Report)
```
- Ogni executor riceve output del precedente
- Type-safe con Pydantic models
- Async/await per performance

#### **Hybrid Decision Making**
- **Rule-Based**: Auditability per compliance (thresholds, sanctions)
- **AI-Powered**: Pattern recognition avanzato (NLP, contextual analysis)

#### **Azure Services Integration**
- **Cosmos DB**: NoSQL database per dati transazionali
- **Azure AI Search**: Semantic search su regolamenti
- **Azure AI Foundry**: Hosting e gestione agenti

### File Creati/Modificati Challenge 1
```
challenge-1/
├── agents/
│   ├── customer_data_agent.py       ✅ Creato
│   ├── risk_analyser_agent.py       ✅ Creato
│   └── compliance_report_agent.py   ✅ Creato
├── workflow/
│   ├── sequential_workflow.ipynb    ✅ Seguito
│   └── sequential_workflow.py       ✅ Eseguito
.env                                 ✅ Modificato (+ 3 Agent IDs)
```

### Verifiche Completate Challenge 1
✅ 3 agenti registrati su Azure AI Foundry  
✅ Ogni agente eseguibile standalone  
✅ Workflow sequenziale funzionante end-to-end  
✅ Output strutturato per transaction TX2002  
✅ Integration test con Cosmos DB + AI Search  

---

## 🔗 Challenge 2: MCP Server Integration

### Obiettivo
Integrare un **Fraud Alert Manager API** come **MCP (Model Context Protocol) server** usando Azure API Management, e aggiungere un **4° agente** al workflow per gestione alert in real-time.

### Architettura Challenge 2

```
                 [Customer Data Agent]
                         ↓
                 [Risk Analyzer Agent]
                      ↙     ↘
    [Compliance Report]    [Fraud Alert Agent] ← MCP Server
         (parallel)              (parallel)
                                     ↓
                            Fraud Alert Manager API
                                  (Container App)
```

**Evoluzione**: Da workflow sequenziale (3 agenti) a **architettura parallela** (4 agenti) con MCP integration.

---

### Parte 1: Expose API as MCP Server con APIM

#### **Step 1: Comprensione Fraud Alert Manager API**

**Container App già deployato** nella Challenge 0.

**Verifica Swagger UI:**
```bash
RG=<resource_group_name>
CONTAINER_APP=$(az containerapp list --resource-group $RG --query "[0].name" -o tsv)
CONTAINER_APP_URL=$(az containerapp show --name $CONTAINER_APP --resource-group $RG --query properties.configuration.ingress.fqdn -o tsv)

echo "Swagger UI: http://$CONTAINER_APP_URL/v1/swagger-ui/index.html"
```

**API Endpoints Disponibili:**
- `POST /alerts` - Crea nuovo fraud alert
- `GET /alerts` - Lista tutti gli alert
- `GET /alerts/{id}` - Dettagli alert specifico
- `PUT /alerts/{id}` - Aggiorna status alert
- `DELETE /alerts/{id}` - Elimina alert

**Parametri Alert:**
```json
{
  "transaction_id": "TX1234",
  "severity": "HIGH",           // LOW|MEDIUM|HIGH|CRITICAL
  "status": "OPEN",             // OPEN|INVESTIGATING|RESOLVED|FALSE_POSITIVE
  "decision": "INVESTIGATE",    // ALLOW|BLOCK|MONITOR|INVESTIGATE
  "risk_factors": ["high_amount", "risky_country"],
  "reasoning": "Detailed fraud analysis..."
}
```

---

#### **Step 2: Import API in Azure API Management**

**Azure Portal → API Management:**

1. **APIs → Add API → OpenAPI**
   
   ![Onboard API](challenge-2/images/1_onboardapi.png)

2. **Fornire OpenAPI Spec URL:**
   ```bash
   echo https://$CONTAINER_APP_URL/v1/v3/api-docs
   ```
   
   ![Import API](challenge-2/images/2_createapi.png)

3. **Configurazione:**
   - Display Name: `Fraud Alert Manager API`
   - Name: `fraud-alert-api`
   - API URL suffix: `fraud-alerts`
   - Click **Create**

---

#### **Step 3: Configurare Backend Endpoint**

**Settings → Backend:**

1. Modificare backend URL:
   ```bash
   echo https://$CONTAINER_APP_URL/v1
   ```
   
   ![Modify Backend](challenge-2/images/3_modifybackend.png)

2. **Override endpoint per tutte le operations**
   
   ![Override Backend](challenge-2/images/4_overridebackend.png)

---

#### **Step 4: Test API in APIM**

**Test Tab → Select Operation:**

Esempio: `GET /alerts`

![Test API](challenge-2/images/5_testapi_hq.gif)

**Verifica risposta 200 OK** con lista alert (può essere vuota inizialmente).

---

#### **Step 5: Create MCP Server da API**

**APIM → MCP Servers (Preview):**

1. **Create MCP Server → Expose an API as MCP Server**
   
   ![Create MCP Server](challenge-2/images/6_mcpfromapi.png)

2. **Configurazione MCP:**
   - **Select API**: `Fraud Alert Manager API`
   - **Operations**: Seleziona tutte (GET, POST, PUT, DELETE)
   - **MCP Server Name**: `fraud-alert-mcp-server`
   - **Description**: `MCP server for fraud alert management`
   
   ![Select API Operations](challenge-2/images/7_createmcp.png)

3. **Create**

4. **Salva MCP Server URL:**
   ```
   https://<apim-name>.azure-api.net/mcp/fraud-alert-mcp-server
   ```

**Aggiungi al `.env`:**
```bash
MCP_SERVER_ENDPOINT=https://<apim-name>.azure-api.net/mcp/fraud-alert-mcp-server
```

---

### Parte 2: Creazione Fraud Alert Agent

#### **Cos'è il Model Context Protocol (MCP)?**

**MCP** è un protocollo standardizzato che permette agli AI agents di comunicare con sistemi esterni (API, database, tools) in modo uniforme.

**Nel nostro caso:**
```
AI Agent → MCP Server → APIM → Container App API → Alert System
```

**Vantaggi:**
- ✅ Integrazione seamless con sistemi enterprise
- ✅ Security layer via APIM (subscription key)
- ✅ Standardizzazione comunicazione agent-to-external-service
- ✅ Real-time alert management

---

#### **Implementazione Fraud Alert Agent**

**File**: `challenge-2/agents/fraud_alert_foundry_agent.py`

**Codice Modificato** (era presente placeholder):

```python
from azure.ai.agents.models import McpTool

# Prima (placeholder):
# mcp_tool = < PLACEHOLDER FOR MCP TOOL >

# Dopo (implementato):
mcp_tool = McpTool(
    server_label="fraudalertmcp", 
    server_url=mcp_endpoint,  # Da .env: MCP_SERVER_ENDPOINT
)
mcp_tool.update_headers(
    "Ocp-Apim-Subscription-Key",
    mcp_subscription_key  # Da .env: APIM_SUBSCRIPTION_KEY
)
```

**Configurazione Agent Instructions:**
```python
agent = agents_client.create_agent(
    model=model_deployment_name,
    name="fraud-alert-agent",
    instructions="""
You are a Fraud Alert Management Agent.

Responsibilities:
- Analyze risk assessment results
- Create fraud alerts with correct severity and status
- Determine decision actions (ALLOW, BLOCK, MONITOR, INVESTIGATE)
- Provide clear reasoning for alert decisions

Alert Creation Criteria:
1. High risk scores (>= 75)
2. Sanctions-related concerns
3. High-risk jurisdictions
4. Suspicious patterns
5. Regulatory violations

Enumerations:
- severity: LOW, MEDIUM, HIGH, CRITICAL
- status: OPEN, INVESTIGATING, RESOLVED, FALSE_POSITIVE
- decision: ALLOW, BLOCK, MONITOR, INVESTIGATE

Always send alerts using the MCP tool without asking confirmation.
""",
    tools=mcp_tool.definitions,  # MCP tools disponibili all'agent
)
```

**Input Agent**: File `risk-analyzer-tx-summary.md` (output simulato Risk Analyzer)

**Esecuzione Agent:**
```python
# Create thread e message
thread = agents_client.threads.create()
with open("risk-analyzer-tx-summary.md", "r") as f:
    content = f.read()
message = agents_client.messages.create(
    thread_id=thread.id,
    role="user",
    content=f"Please send a fraud alert from this transaction summary: {content}",
)

# Run agent con MCP tool approval
run = agents_client.runs.create(
    thread_id=thread.id, 
    agent_id=agent.id, 
    tool_resources=mcp_tool.resources
)
```

**Tool Approval Flow** (requires_action):
```python
while run.status in ["queued", "in_progress", "requires_action"]:
    if run.status == "requires_action":
        tool_calls = run.required_action.submit_tool_approval.tool_calls
        tool_approvals = []
        
        for tool_call in tool_calls:
            if isinstance(tool_call, RequiredMcpToolCall):
                print(f"Approving tool call: {tool_call}")
                tool_approvals.append(
                    ToolApproval(
                        tool_call_id=tool_call.id,
                        approve=True,
                        headers=mcp_tool.headers,  # APIM subscription key
                    )
                )
        
        agents_client.runs.submit_tool_outputs(
            thread_id=thread.id,
            run_id=run.id,
            tool_approvals=tool_approvals
        )
```

**Output Finale:**
- Alert creato su Fraud Alert Manager API via MCP
- Agent ID salvato per orchestrazione

---

#### **Verifica Funzionamento con Logs**

**Terminal 1 - Monitoring Container App:**
```bash
az containerapp logs show \
  --name $CONTAINER_APP \
  --resource-group $RG \
  --follow
```

**Terminal 2 - Esecuzione Agent:**
```bash
cd challenge-2/agents
python fraud_alert_foundry_agent.py
```

**Output Atteso Terminal 1:**
```
POST /v1/alerts HTTP/1.1 200
{
  "transaction_id": "TX1012",
  "severity": "HIGH",
  "status": "OPEN",
  "decision": "INVESTIGATE",
  "risk_factors": [...],
  "reasoning": "..."
}
```

**Salva Agent ID nel `.env`:**
```bash
FRAUD_ALERT_AGENT_ID=asst_XXXXXXXXXXXXXXXXXXXXXXXX
```

---

### Parte 3: Workflow Avanzato - Orchestrazione Parallela

#### **Evoluzione Architettura**

**Challenge 1** (Sequential):
```
Customer Data → Risk Analyzer → Compliance Report
```

**Challenge 2** (Parallel Processing):
```
Customer Data → Risk Analyzer ─┬─→ Compliance Report
                                └─→ Fraud Alert Agent (MCP)
```

**File**: `challenge-2/agents/sequential_workflow_chal2.py`

---

#### **Implementazione Dual-Path Workflow**

**Executor 1-2**: Identici a Challenge 1 (Customer Data, Risk Analyzer)

**Executor 3: Compliance Report** (invariato)
```python
@executor(workflow)
async def compliance_report_executor(
    ctx: WorkflowContext, 
    input: RiskAnalysisResponse
) -> ComplianceAuditResponse:
    # Genera audit report come prima
    await ctx.send_message(result)
```

**Executor 4: Fraud Alert (NUOVO - MCP Integration)**
```python
@executor(workflow)
async def fraud_alert_executor(
    ctx: WorkflowContext,
    input: RiskAnalysisResponse
) -> FraudAlertResponse:
    """
    Executor che usa Azure AI Projects Client per invocare
    l'agent con MCP tool integration
    """
    # Initialize AI Project Client
    project_client = AIProjectClient(
        endpoint=project_endpoint,
        credential=DefaultAzureCredential(),
    )
    
    # Setup MCP tool
    mcp_tool = McpTool(
        server_label="fraudalertmcp",
        server_url=mcp_endpoint,
    )
    mcp_tool.update_headers("Ocp-Apim-Subscription-Key", mcp_subscription_key)
    
    # Get existing fraud alert agent (reuse)
    fraud_alert_agent_id = os.environ.get("FRAUD_ALERT_AGENT_ID")
    
    # Create thread and send risk analysis
    agents_client = project_client.agents
    thread = agents_client.threads.create()
    message = agents_client.messages.create(
        thread_id=thread.id,
        role="user",
        content=f"Create fraud alert from: {input.risk_assessment}",
    )
    
    # Run agent with MCP tool
    run = agents_client.runs.create(
        thread_id=thread.id,
        agent_id=fraud_alert_agent_id,
        tool_resources=mcp_tool.resources
    )
    
    # Approval loop
    while run.status in ["queued", "in_progress", "requires_action"]:
        # ... tool approval logic ...
    
    # Return alert confirmation
    return FraudAlertResponse(
        transaction_id=input.transaction_id,
        alert_status="CREATED",
        alert_details=alert_response
    )
```

---

#### **Parallel Edge Routing**

**Workflow Builder Configuration:**
```python
from agent_framework import WorkflowBuilder, parallel_edge

workflow = WorkflowBuilder(name="fraud_detection_parallel")

# Sequential flow fino al Risk Analyzer
workflow.add_edge(
    from_executor=customer_data_executor,
    to_executor=risk_analyzer_executor
)

# Parallel fan-out dal Risk Analyzer
workflow.add_edges([
    parallel_edge(
        from_executor=risk_analyzer_executor,
        to_executor=compliance_report_executor
    ),
    parallel_edge(
        from_executor=risk_analyzer_executor,
        to_executor=fraud_alert_executor
    )
])
```

**Vantaggi Parallel Processing:**
- ⚡ Performance: Compliance report e fraud alert eseguiti simultaneamente
- 🎯 Separation of Concerns: Audit ≠ Alerting
- 🔧 Right Tool for Right Job:
  - **Azure AI Foundry agents**: Conversational AI, Azure services
  - **MCP integration**: External system connectivity

---

#### **Esecuzione Workflow Completo**

```bash
cd challenge-2/agents
python sequential_workflow_chal2.py
```

**Output Workflow:**
```
🔹 Customer Data Executor: ✅ TX1012 Retrieved
   - Customer: Jane Smith (C1003)
   - Amount: $25,000 USD → Iran
   - Account Age: 15 days (NEW)
   - Device Trust: 0.2 (VERY LOW)

🔹 Risk Analyzer Executor: ✅ Risk Score: 95/100 (CRITICAL)
   - Risk Factors:
     • Sanctioned country (Iran)
     • Very large transaction
     • Brand new account
     • Extremely low device trust
   - Regulatory: AML/OFAC violations

   ┌─────────────────────────────────┐
   │   PARALLEL PROCESSING STARTED   │
   └─────────────────────────────────┘

🔹 Compliance Report Executor: ✅ Audit Generated
   - Compliance Rating: NON_COMPLIANT
   - SAR Filing: REQUIRED
   - Decision: BLOCK + FREEZE ACCOUNT

🔹 Fraud Alert Executor: ✅ Alert Created via MCP
   - Alert ID: ALT-20251216-001
   - Severity: CRITICAL
   - Status: OPEN
   - Decision: BLOCK
   - MCP Server Response: 201 Created
   - Container App Logs: POST /v1/alerts ✅

📊 Final Workflow Output:
   - Audit Report: ✅ Saved to Cosmos DB
   - Fraud Alert: ✅ Sent to Alert System
   - Execution Time: 3.2s (parallel vs 5.8s sequential)
```

---

### Concetti Chiave Challenge 2

#### **Model Context Protocol (MCP)**
- Protocollo standard per agent-to-external-system communication
- Enabler per enterprise integration
- Security via APIM gateway (subscription keys, rate limiting)

#### **Azure API Management as MCP Server**
```
OpenAPI Spec → APIM Import → MCP Server Exposure → Agent Tool
```
- **Vantaggi**:
  - No custom MCP server code needed
  - Built-in monitoring, caching, throttling
  - Centralized API governance
  - Security policies (OAuth, keys, IP filtering)

#### **Hybrid Agent Architecture**
- **Azure AI Foundry Agents**: Conversational AI, state management
- **MCP-Integrated Agents**: External API calls, tool orchestration
- **Best of Both Worlds**: Flexible, enterprise-grade

#### **Parallel Workflow Orchestration**
- **Fan-out pattern** post risk analysis
- Independent executor execution
- Aggregation di risultati multipli
- Performance improvement ~45% (3.2s vs 5.8s)

#### **Tool Approval Pattern**
```python
run.status == "requires_action"
→ submit_tool_approval
→ run continues with approved tools
```
- Human-in-the-loop capability
- Safety layer per operazioni critiche
- Audit trail completo

### File Creati/Modificati Challenge 2
```
challenge-2/
├── agents/
│   ├── fraud_alert_foundry_agent.py   ✅ Modificato (MCP tool config)
│   ├── sequential_workflow_chal2.py   ✅ Creato (parallel workflow)
│   └── risk-analyzer-tx-summary.md    ✅ Usato come input
.env                                   ✅ Modificato (+ MCP_SERVER_ENDPOINT + FRAUD_ALERT_AGENT_ID)
```

### Verifiche Completate Challenge 2
✅ Fraud Alert Manager API esposta come MCP server via APIM  
✅ Fraud Alert Agent creato con MCP tool integration  
✅ Tool approval flow funzionante  
✅ Container App logs confermano ricezione alert  
✅ Workflow parallelo eseguito con successo su TX1012  
✅ Performance improvement misurato  

---

## 🎓 Concetti Chiave Appresi

### 1. **Microsoft Agent Framework (MAF)**

**Cos'è:**
- SDK open-source enterprise-grade (.NET + Python)
- Rilasciato Ottobre 2025
- Unifica Semantic Kernel + AutoGen

**Core Concepts:**
- **Executors**: Processing units specializzate
- **Edges**: Message routing (sequential, parallel, conditional)
- **Workflows**: Grafo orchestrato di executors
- **Events**: OpenTelemetry observability

**Vantaggi:**
- Built-in observability (OTel, Azure Monitor)
- Human-in-the-loop workflows
- Checkpointing e durable agents
- Integrazione enterprise (Entra ID, compliance hooks)

---

### 2. **Orchestration Patterns**

**Sequential Pattern** (Challenge 1):
```
A → B → C
```
- Linear processing
- Output di A diventa input di B
- Semplice, deterministico

**Parallel Pattern** (Challenge 2):
```
A → B ─┬─→ C
       └─→ D
```
- Fan-out parallelization
- C e D eseguiti simultaneamente
- Aggregazione risultati

**Conditional Pattern** (non implementato, ma disponibile):
```
A → B ─┬─→ C (if condition)
       └─→ D (else)
```

---

### 3. **Hybrid Decision Making**

**Rule-Based Logic:**
- Deterministico, auditabile
- Hardcoded thresholds
- Compliance-friendly
- Esempi: risk_score > 80 = NON_COMPLIANT

**AI-Powered Intelligence:**
- Pattern recognition
- Contextual analysis
- NLP su regolamenti
- Adaptive learning potential

**Quando usare cosa:**
- **Rule-based**: Regulatory compliance, safety-critical
- **AI-powered**: Pattern detection, anomaly detection, contextual reasoning

---

### 4. **Model Context Protocol (MCP)**

**Definizione:**
- Protocollo standard per AI agent communication con external services
- Open standard (portabilità cross-platform)

**Use Cases:**
- API integration (come questo hackathon)
- Database connectivity
- Enterprise tool orchestration
- Multi-agent communication

**Implementazione Azure:**
```
AI Agent → MCP Tool → APIM (MCP Server) → Backend API
```

**Security:**
- APIM subscription keys
- Rate limiting
- IP filtering
- OAuth/Entra ID integration possible

---

### 5. **Azure AI Foundry**

**Cos'è:**
- Hub unified per AI development
- Gestione agents, models, deployments
- Built-in monitoring e tracing

**Capabilities:**
- Agent registration e versioning
- Model deployment (GPT-4, custom models)
- Tool integration (search, function calling)
- Performance metrics
- Cost tracking

**Usato in Hackathon:**
- Hosting dei 4 agents
- Deployment GPT-4o model
- Tracing esecuzioni agent
- Resource management

---

### 6. **Azure Services Ecosystem**

**Cosmos DB:**
- NoSQL database globally distributed
- Partition key strategy per performance
- Cross-partition queries per analytics
- JSON native storage

**Azure AI Search:**
- Semantic search su dati non strutturati
- Vector search capability
- Index: regulations-policies
- NLP su documenti regolatori

**Azure API Management:**
- API gateway enterprise
- OpenAPI import
- MCP server exposure (novità!)
- Security, caching, throttling

**Azure Container Apps:**
- Serverless container hosting
- Auto-scaling
- Integrated ingress
- Logs streaming

**Application Insights:**
- Telemetry e observability
- OpenTelemetry integration
- Custom events tracking
- Performance monitoring

---

### 7. **DevOps Best Practices**

**Infrastructure as Code:**
- ARM templates per deployment riproducibile
- Script bash per automazione
- `.env` per configuration management

**Security:**
- Key Vault per secrets
- APIM per API security
- Principle of least privilege

**Monitoring:**
- Container App logs streaming
- Application Insights traces
- Agent execution events

---

## 🏗️ Architettura Finale

### Componenti Sistema Completo

```
┌─────────────────────────────────────────────────────────────────┐
│                    FRAUD DETECTION SYSTEM                        │
└─────────────────────────────────────────────────────────────────┘

                        ┌──────────────┐
                        │  TX Input    │
                        └──────┬───────┘
                               │
                    ┌──────────▼───────────┐
                    │ Customer Data Agent  │
                    │   (Cosmos DB)        │
                    └──────────┬───────────┘
                               │
                    ┌──────────▼───────────┐
                    │ Risk Analyzer Agent  │
                    │  (Azure AI Search)   │
                    └──────────┬───────────┘
                               │
                    ┌──────────┴───────────┐
                    │                      │
         ┌──────────▼───────────┐  ┌──────▼──────────────┐
         │ Compliance Report    │  │ Fraud Alert Agent   │
         │ Agent                │  │ (MCP Integration)   │
         └──────────┬───────────┘  └──────┬──────────────┘
                    │                     │
                    │                     ▼
                    │              ┌─────────────────┐
                    │              │ APIM MCP Server │
                    │              └─────────┬───────┘
                    │                        │
                    │                        ▼
                    │              ┌─────────────────┐
                    │              │  Container App  │
                    │              │  Fraud Alert API│
                    │              └─────────────────┘
                    │
         ┌──────────▼────────────────────────────────────┐
         │         FINAL OUTPUT                          │
         │  - Audit Report (Cosmos DB)                   │
         │  - Fraud Alert (Alert System)                 │
         │  - Compliance Status                          │
         │  - Executive Dashboard                        │
         └───────────────────────────────────────────────┘
```

### Data Flow

**Input Transaction → Processing → Multiple Outputs**

1. **Data Ingestion**: TX details da Cosmos DB
2. **Customer Enrichment**: Profile + history
3. **Risk Assessment**: AI Search + Rule-based scoring
4. **Parallel Processing**:
   - Path A: Compliance audit documentation
   - Path B: Real-time fraud alerting via MCP
5. **Aggregated Output**: Comprehensive fraud analysis

---

## 📦 Risorse Azure Utilizzate

### Resource Group Overview

| **Risorsa** | **Nome** | **Scopo** | **Challenge** |
|------------|----------|-----------|--------------|
| Cosmos DB | `cosmos-<unique>` | Transaction & customer data | 0, 1, 2 |
| AI Search | `search-<unique>` | Regulations index | 0, 1 |
| AI Foundry Project | `ai-project-<unique>` | Agent hosting | 1, 2 |
| APIM | `apim-<unique>` | MCP server gateway | 0, 2 |
| Container App | `ca-fraud-alert-<unique>` | Fraud Alert Manager API | 0, 2 |
| Key Vault | `kv-<unique>` | Secrets management | 0 |
| App Insights | `appinsights-<unique>` | Observability | 0, (3) |
| Storage Account | `st<unique>` | Data persistence | 0 |

### Costi Stimati (Reference)

**Per giornata hackathon:**
- Cosmos DB: ~€5 (400 RU/s provisioned)
- AI Search: ~€8 (Basic tier)
- AI Foundry/OpenAI: ~€15-20 (GPT-4o usage)
- APIM: ~€3 (Basic v2)
- Container Apps: ~€2 (consumption plan)
- Altri: ~€2
**Totale**: ~€35-40/giorno

⚠️ **Importante**: Eliminare risorse dopo hackathon per evitare costi continuativi!

---

## 🚀 Prossimi Passi

### Challenge 3: Observability (Pianificata)

**Obiettivo**: Aggiungere telemetria completa al sistema

**Attività Previste:**
- OpenTelemetry instrumentation
- Azure Application Insights integration
- Distributed tracing tra agents
- Custom metrics e dashboards
- Performance monitoring
- Error tracking e alerting

**File da Esplorare:**
- `challenge-3/telemetry.py`
- `challenge-3/workflow_observability.py`
- `challenge-3/batch_run/batch_runner.py`
- `challenge-3/workbooks/azure-workbook-template.json`

---

### Challenge 4: Frontend Management (Pianificata)

**Obiettivo**: Deploy fraud alert management UI

**Attività Previste:**
- Angular-based frontend deployment
- Real-time alert visualization
- Dashboard analytics
- Alert management interface
- Integration con backend API

**File da Esplorare:**
- `challenge-4/README.md`

---

### Espansioni Future a Casa

#### **1. Advanced Orchestration Patterns**

**Conditional Routing:**
```python
@executor(workflow)
async def risk_decision_router(ctx: WorkflowContext, input: RiskAnalysisResponse):
    if input.risk_score >= 80:
        await ctx.send_message(input, to="high_risk_executor")
    elif input.risk_score >= 50:
        await ctx.send_message(input, to="medium_risk_executor")
    else:
        await ctx.send_message(input, to="low_risk_executor")
```

**Feedback Loops:**
```
Risk Analyzer → Decision → If rejected → Re-analyze with more data
```

**Multi-Agent Collaboration:**
```
Agent A ←→ Agent B (iterative refinement)
       ↓
   Final Decision
```

---

#### **2. Machine Learning Integration**

**Anomaly Detection:**
- Azure ML per fraud pattern detection
- Integration con Risk Analyzer Agent
- Continuous learning da historical data

**Model Training Pipeline:**
```
Cosmos DB Transactions → Feature Engineering → ML Model → Deployment
                                                    ↓
                                          Risk Analyzer Agent
```

---

#### **3. Production Hardening**

**Security Enhancements:**
- Managed Identity instead of keys
- Private endpoints per Azure services
- VNet integration
- Azure Front Door per WAF

**High Availability:**
- Multi-region Cosmos DB
- APIM multi-region deployment
- Container Apps scaling rules
- Load balancing

**Compliance:**
- Audit logging (Azure Policy)
- Data encryption at rest + transit
- GDPR compliance (data retention policies)
- SOC 2 / ISO 27001 alignment

---

#### **4. Advanced MCP Scenarios**

**Multi-MCP Integration:**
```
Agent → MCP 1 (Fraud Alerts)
      → MCP 2 (Payment Gateway)
      → MCP 3 (Compliance Reporting)
      → MCP 4 (Customer Notification)
```

**Custom MCP Server Development:**
- Implementare proprio MCP server
- Advanced tool orchestration
- Custom protocol extensions

---

#### **5. Agent-to-Agent (A2A) Communication**

**Distributed Agent System:**
```
Region 1: Agents A, B
Region 2: Agents C, D
↓ A2A Protocol
Coordinated global fraud detection
```

**Use Cases:**
- Cross-region transaction validation
- Multi-bank fraud detection
- Collaborative risk assessment

---

#### **6. Cost Optimization**

**Strategies:**
- Cosmos DB autoscale RU/s
- AI Search consumption tier
- APIM consumption plan (se traffico basso)
- Serverless GPT-4o calls
- Reserved capacity per produzione

**Monitoring:**
- Cost analysis dashboards
- Budget alerts
- Resource optimization recommendations

---

## 📚 Risorse Utili

### Documentazione Ufficiale

**Microsoft Agent Framework:**
- [Agent Framework Overview](https://learn.microsoft.com/en-us/agent-framework/overview/agent-framework-overview)
- [Executors Guide](https://learn.microsoft.com/en-us/agent-framework/user-guide/workflows/core-concepts/executors?pivots=programming-language-python)
- [Workflows Guide](https://learn.microsoft.com/en-us/agent-framework/user-guide/workflows/core-concepts/workflows?pivots=programming-language-python)
- [MCP Integration](https://learn.microsoft.com/en-us/agent-framework/user-guide/model-context-protocol/using-mcp-tools?pivots=programming-language-python)

**Azure Services:**
- [Azure AI Foundry](https://learn.microsoft.com/en-us/azure/ai-services/agents/)
- [Azure Cosmos DB](https://learn.microsoft.com/en-us/azure/cosmos-db/)
- [Azure AI Search](https://learn.microsoft.com/en-us/azure/search/)
- [Azure API Management](https://learn.microsoft.com/en-us/azure/api-management/)
- [MCP Server da APIM](https://learn.microsoft.com/en-us/azure/api-management/export-rest-mcp-server)

**Model Context Protocol:**
- [MCP Specification](https://spec.modelcontextprotocol.io/)
- [MCP GitHub](https://github.com/modelcontextprotocol)

### Repository Hackathon

- **Originale**: [microsoft/azure-trust-agents](https://github.com/microsoft/azure-trust-agents)
- **Fork Personale**: `maurominella/azure-trust-agents`

---

## 🏁 Conclusioni

### Cosa Ho Imparato

1. **Framework Enterprise-Grade**: Microsoft Agent Framework offre capabilities production-ready out-of-the-box
2. **Orchestrazione Avanzata**: Pattern sequenziali e paralleli per workflow complessi
3. **Hybrid AI**: Bilanciare rule-based (compliance) e AI (intelligence)
4. **Azure Ecosystem**: Integration seamless tra servizi (Cosmos, Search, APIM, AI Foundry)
5. **MCP Protocol**: Standard per agent-to-external-service communication
6. **DevOps Mindset**: IaC, automation, monitoring da subito

### Sfide Affrontate

- **Complexity Management**: 4 agents + orchestrazione richiede pianificazione attenta
- **Async Programming**: Gestione corretta di async/await in workflow
- **Tool Approval Flow**: Comprendere pattern human-in-the-loop
- **Multi-Service Debugging**: Tracciare problemi attraverso APIM → Container App → MCP

### Risultati Raggiunti

✅ Sistema fraud detection end-to-end funzionante  
✅ 4 agenti specializzati integrati  
✅ Workflow parallelo con performance ottimizzate  
✅ MCP integration con sistema esterno  
✅ Compliance audit automatizzato  
✅ Real-time fraud alerting  
✅ Foundation per observability (Challenge 3)  
✅ Foundation per frontend (Challenge 4)  

---

## 📝 Note Personali

### Momenti Chiave

- **Challenge 0**: Setup infrastruttura smooth grazie a ARM template e script
- **Challenge 1**: "Aha moment" comprendendo executor pattern e message passing
- **Challenge 2**: Impressionante facilità di expose API come MCP via APIM (no custom code!)

### Miglioramenti Futuri Personali

- [ ] Approfondire OpenTelemetry e tracing distribuito
- [ ] Sperimentare con Conditional Routing negli edges
- [ ] Implementare custom MCP server da zero
- [ ] Integrare ML model per anomaly detection
- [ ] Deploy frontend Challenge 4
- [ ] Production hardening (Managed Identity, Private Endpoints)

### Takeaways per Casa

**Da rivedere:**
- Async/await best practices in Python
- Pydantic advanced features (validators, custom types)
- Azure APIM policies per security avanzata

**Da espandere:**
- Agent-to-Agent (A2A) communication
- Multi-agent collaboration patterns
- Cost optimization strategies per produzione

**Da condividere:**
- Blog post su MCP integration
- Demo video workflow completo
- Open-source contribution a MAF?

---

## 🙏 Ringraziamenti

- Microsoft per framework e infrastruttura Azure
- Team hackathon per materiali e supporto
- Community Agent Framework per documentazione

---

**Fine Recap Hackathon - Challenge 0, 1, 2 Completate**

*Documento creato il 16 Dicembre 2025*  
*Repository: maurominella/azure-trust-agents*  
*Branch: main*

---

### Quick Reference Commands

```bash
# Challenge 0
az login --use-device-code
cd challenge-0 && ./get-keys.sh --resource-group <RG>
./seed_data.sh

# Challenge 1
cd challenge-1/agents
python customer_data_agent.py
python risk_analyser_agent.py
python compliance_report_agent.py

cd challenge-1/workflow
jupyter notebook sequential_workflow.ipynb  # Or use VS Code
python sequential_workflow.py

# Challenge 2
echo https://$CONTAINER_APP_URL/v1/swagger-ui/index.html
cd challenge-2/agents
python fraud_alert_foundry_agent.py
python sequential_workflow_chal2.py

# Monitoring
az containerapp logs show --name $CONTAINER_APP --resource-group $RG --follow
```

---

### Architecture Diagrams Reference

**Challenge 1:**
![Architecture Challenge 1](challenge-1/images/architecture-1.png)

**Challenge 2:**
![Architecture Challenge 2](challenge-2/images/architecture-2.png)

---

**Happy Learning! 🚀🤖**
