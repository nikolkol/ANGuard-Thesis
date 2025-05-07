## ⚙ Technologies Used
- *OpenCTI* — Threat Intelligence Platform
- *PyCTI* — Python API for OpenCTI
- *Python* — Data parsing and automation scripts
- *ModSecurity* — Open Source Web Application Firewall
- *NGINX* — Web server and reverse proxy
- *Telegram Bot API* — For alert notifications
- *Docker* — For service orchestration

## 🛠 Configuration

### 1. Clone this repository
bash
git clone https://github.com/nikolkol/ANGuard-Thesis.git
cd ANGuard-Thesis

### 2. Edit .env file inside both folder

### 3. Deploy OpenCTI locally
bash
cd opencti
docker-compose up -d


### 4. Start WAF Environment (NGINX + ModSecurity + CRS)
bash
cd DVWA-nginx-ModSecurity
docker-compose up -d


### 5. Run ANGuard Parser
bash
cd DVWA-nginx-ModSecurity/script
python import_logging.py

### 6. Run ANGuard Parser
bash
python import_logging.py


