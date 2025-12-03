# 🚀 Azure Trust Agents – Hackathon Environment
Benvenuti! Questo repository è stato preparato con un Dev Container e con i Prebuilds di GitHub Codespaces per offrirvi un ambiente pronto all’uso. In pochi click avrete un workspace completo, senza installazioni locali.

## 📦 Cos’è un Codespace?
Un Codespace è un workspace personale basato su una VM in cloud.

Ogni studente crea il proprio Codespace: è isolato, privato e legato al suo account GitHub.

Nessuno usa il Codespace di un altro, e nessuno consuma le risorse di Mauro o di Microsoft: ognuno usa le proprie ore gratuite di GitHub.

## ⚡ Cos’è un Prebuild?
Un Prebuild è l’equivalente di un’immagine Docker già pronta e pubblicata.

La prima volta Mauro ha impiegato ~20 minuti per costruirla, ma ora è disponibile per tutti.

Quando aprite un Codespace su main, GitHub userà automaticamente il prebuild → apertura in meno di un minuto.

Non vedrete un messaggio esplicito “stai usando il prebuild”: l’unico segnale è la velocità di avvio.

## 📝 Istruzioni passo‑passo
Accedete a GitHub con il vostro account personale.

Aprite il repo: https://github.com/maurominella/azure-trust-agents.

Cliccate sul pulsante verde Code.

Selezionate la tab Codespaces.

Cliccate su Create codespace on main.

Attendere pochi secondi: si aprirà VS Code nel browser con l’ambiente già configurato.

## 🔍 Verifica rapida dell’ambiente
Dopo l’apertura, provate questi comandi nel terminale:
```
bash
az --version        # Controlla che Azure CLI sia installato
python --version    # Controlla la versione di Python
pip list            # Mostra i pacchetti installati
```
Se funzionano, significa che il prebuild è stato usato correttamente.

## 🛑 Gestione delle risorse
Stop: se finite di lavorare, fermate il Codespace. Rimane salvato e potete riaprirlo.

Delete: se non vi serve più, cancellatelo. Attenzione: perderete le modifiche non pushate su GitHub.

Push su GitHub: per rendere permanenti le modifiche, fate sempre git commit e git push.

## 📂 Cosa rimane / cosa si perde

| Tipo di modifica                  | Dopo Stop | Dopo Delete | Dopo Push |
|-----------------------------------|-----------|-------------|-----------|
| File creati/modificati            | ✅         | ❌           | ✅         |
| Pacchetti installati manualmente  | ✅         | ❌           | ❌ (serve aggiornarli nel devcontainer) |
| Commit locali non pushati         | ✅         | ❌           | ✅         |
| Configurazioni nel `.devcontainer.json` | ✅ (solo in quel Codespace) | ❌ | ✅ (se pushate nel repo) |



## 🎯 Best practice per l’hackathon
Create il Codespace su main.

Non lasciatelo acceso tutta la notte: fermatelo o cancellatelo.

Fate sempre git push per salvare il vostro lavoro.

Non serve fare login su Microsoft Open Source: lavorate solo sul fork di Mauro.

-----------

# 👉 Con questo setup, ognuno di voi avrà un ambiente identico, pronto in pochi secondi, e potrà lavorare in autonomia senza installazioni locali.
