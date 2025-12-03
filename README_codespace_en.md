# 🚀 Azure Trust Agents – Hackathon Environment
Welcome! This repository has been prepared with a Dev Container and GitHub Codespaces Prebuilds to provide you with a ready-to-use environment. With just a few clicks you will have a complete workspace, without local installations.

## 📦 What is a Codespace?
A Codespace is a personal workspace based on a VM in the cloud.

Each student creates their own Codespace: it is isolated, private, and linked to their GitHub account.

No one uses another person’s Codespace, and no one consumes Mauro’s or Microsoft’s resources: everyone uses their own free GitHub hours.

## ⚡ What is a Prebuild?
A Prebuild is the equivalent of a Docker image already built and published.

The first time Mauro spent ~20 minutes building it, but now it is available to everyone.

When you open a Codespace on main, GitHub will automatically use the prebuild → startup in less than a minute.

You will not see an explicit message “you are using the prebuild”: the only signal is the fast startup.

## 📝 Step‑by‑step instructions
- Log in to GitHub with your personal account.
- Open the repo: https://github.com/maurominella/azure-trust-agents.
- Click the green Code button.
- Select the Codespaces tab.
- Click Create codespace on main.
- Wait a few seconds: VS Code will open in the browser with the environment already configured.

## 🔍 Quick environment check
After opening, try these commands in the terminal:
```bash
az --version        # Check that Azure CLI is installed
python --version    # Check the Python version
pip list            # Show installed packages
```
If they work, it means the prebuild was used correctly.

## 🛑 Resource management
- **Stop**: if you finish working, stop the Codespace. It remains saved and you can reopen it.
- **Delete**: if you no longer need it, delete it. ⚠️ You will lose any changes not pushed to GitHub.
- **Push to GitHub**: to make changes permanent, always run git commit and git push.

## 📂 What remains / what is lost
| Tipo of change                    | AFter Stop | After Delete | After Push |
|-----------------------------------|-----------|-------------|-----------|
| Created/modified files           | ✅         | ❌           | ✅         |
| Manually installed packages  | ✅         | ❌           | ❌ (must be updated in devcontainer) |
| Local commits not pushed        | ✅         | ❌           | ✅         |
| Configurations in `.devcontainer.json` | ✅ (only in that Codespace) | ❌ | ✅ (se pushed to the repo) |


## 🎯 Best practice for the hackathon
- Create the Codespace on main.
- Do not leave it running overnight: stop or delete it.
- Always run git push to save your work.
- No need to log in to Microsoft Open Source: work only on Mauro’s fork.

----------

👉 With this setup, each of you will have an identical environment, ready in a few seconds, and will be able to work independently without local installations.
