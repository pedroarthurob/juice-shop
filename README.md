# 🍹 Análise Comparativa de Segurança

## OWASP Juice Shop — Ferramentas Tradicionais vs LLM

Projeto desenvolvido na disciplina de **Segurança de Sistemas** com o objetivo de comparar ferramentas tradicionais de detecção de vulnerabilidades com uma análise manual assistida por LLM, utilizando como alvo a aplicação vulnerável **OWASP Juice Shop**.

---

## 📄 Relatório Completo

O relatório técnico detalhado contendo:

* Metodologia completa
* Prompt utilizado na análise com LLM
* Comparação técnica aprofundada
* Discussão e limitações
* Conclusão final

Está disponível [aqui](https://docs.google.com/document/d/1pYtsARmDzzym986M2wgpwNlNXHppjO_ddeY1XCm7mFo/edit?usp=sharing).

---

## 📚 Sobre a aplicação analisada

Este repositório é um fork do projeto oficial:

**OWASP Juice Shop**

Repositório oficial:
[https://github.com/juice-shop/juice-shop](https://github.com/juice-shop/juice-shop)

Página oficial:
[https://owasp-juice.shop](https://owasp-juice.shop)

O Juice Shop é uma aplicação web propositalmente vulnerável, utilizada para:

* Treinamentos de segurança
* Testes de ferramentas (SAST, SCA, DAST)
* CTFs
* Demonstrações de vulnerabilidades reais

⚠️ Este fork foi utilizado exclusivamente para fins acadêmicos.

---

# 🎯 Objetivo do Projeto

Comparar duas abordagens distintas de análise de segurança:

## 🔎 1. Ferramentas Tradicionais

* SCA (Software Composition Analysis)
* SAST (Static Application Security Testing)
* DAST (Dynamic Application Security Testing)
* Análise de secrets
* Misconfiguration scanning

Ferramentas utilizadas:

* Trivy
* Grype
* Semgrep
* OWASP ZAP

---

## 🤖 2. Análise Assistida por LLM

* Revisão manual completa do código-fonte
* Prompt estruturado simulando um engenheiro de Application Security sênior
* Geração de relatório técnico consolidado

Modelo utilizado: GPT-5.2 (Agent Mode)

---

# 🧪 Metodologia

1. Fork do repositório oficial
2. Execução das ferramentas no código-fonte
3. Armazenamento dos artefatos na pasta `results/`
4. Execução de análise manual assistida por LLM
5. Comparação qualitativa e quantitativa dos resultados

---

# 📂 Estrutura dos Resultados

Todos os artefatos gerados durante o experimento estão organizados em `results/`.

```
results/
├── gpt 5.2/
│   └── LLM_Security_Report.md
├── grype/
│   └── full-scan.txt
├── semgrep/
│   └── report.txt
├── trivy/
│   ├── dependency-tree.txt
│   ├── full-scan.txt
│   ├── misconfig.txt
│   ├── report.sarif
│   ├── secrets.txt
│   └── vulnerabilities.txt
└── zap/
    ├── ZAP-Report.html
    ├── normalize/
    │   └── normalize.css
    ├── themes/
    │   └── original/
    │       ├── colors.css
    │       └── main.css
    └── zap32x32.png
```

---

# 🛠 Ferramentas Utilizadas

## 🔍 Trivy

Site oficial: [https://trivy.dev/](https://trivy.dev/)

Utilizado para:

* Vulnerabilidades (SCA)
* Secrets
* Misconfigurações
* Exportação SARIF

### Execução

```bash
trivy fs . | tee results/trivy/full-scan.txt
trivy fs --scanners vuln . | tee results/trivy/vulnerabilities.txt
trivy fs --scanners secret . | tee results/trivy/secrets.txt
trivy fs --scanners misconfig . | tee results/trivy/misconfig.txt
trivy fs --format sarif -o results/trivy/report.sarif .
```

---

## 🧩 Grype

Repositório oficial: [https://github.com/anchore/grype](https://github.com/anchore/grype)

Foco em detecção de CVEs via análise de dependências (SCA).

```bash
grype . | tee results/grype/full-scan.txt
```

---

## 🧠 Semgrep

Site oficial: [https://semgrep.dev/](https://semgrep.dev/)

Ferramenta de SAST baseada em padrões.

```bash
semgrep --config=p/security-audit . | tee results/semgrep/report.txt
```

---

## 🌐 OWASP ZAP (DAST)

Ferramenta de análise dinâmica de segurança desenvolvida pelo projeto
OWASP.

A aplicação foi executada localmente em:

```
http://localhost:3000
```

Foram realizados:

* Spider Scan
* Active Scan

O processo de execução do scan seguiu como referência
[este tutorial](https://www.youtube.com/watch?v=Dl-srkru6Ak).

Relatório gerado:

```
results/zap/ZAP-Report.html
```

Observação: o relatório HTML depende dos arquivos de estilo presentes na mesma pasta (`normalize/`, `themes/`).

---

# 🤖 Análise Assistida por LLM

A análise foi realizada utilizando um prompt estruturado que simula uma revisão manual completa de segurança do código-fonte.

O modelo foi instruído explicitamente a:

* Ignorar completamente a pasta `results/`
* Analisar apenas o código da aplicação
* Reportar apenas vulnerabilidades com impacto real de segurança

Critérios analisados:

* Injection (SQL, Command, Template)
* XSS
* Authentication e Authorization flaws
* Hardcoded secrets
* Cryptography misuse
* CSRF
* Open redirect
* Sensitive data exposure
* Business logic flaws
* Session handling

### 📜 Prompt Utilizado

O prompt completo utilizado na análise encontra-se documentado no relatório técnico.

Ele inclui:

* Contexto fornecido ao modelo
* Objetivos explícitos
* Restrições
* Formato esperado de saída

Relatório final:

```
results/gpt 5.2/LLM_Security_Report.md
```

---

# ▶️ Como Reproduzir o Experimento

## 1️⃣ Clonar o repositório

```bash
git clone https://github.com/pedroarthurob/juice-shop.git
cd juice-shop
```

## 2️⃣ Instalar dependências

```bash
npm install
```

## 3️⃣ Executar ferramentas

Certifique-se de ter instalado:

* Trivy
* Grype
* Semgrep
* OWASP ZAP

Execute os comandos descritos nas seções anteriores para gerar os artefatos dentro de `results/`.

---

# 🌐 Executar a Aplicação (Opcional)

Para rodar via Docker:

```bash
docker pull bkimminich/juice-shop
docker run --rm -p 3000:3000 bkimminich/juice-shop
```

Acesse:

[http://localhost:3000](http://localhost:3000)

Para instruções completas (Node, Vagrant, distribuições empacotadas etc.), consulte o repositório oficial do projeto.

---

# 📊 Conclusão do Experimento

Com base na análise realizada, observou-se que:

* Ferramentas tradicionais demonstraram alta velocidade e eficiência na detecção de vulnerabilidades conhecidas.
* O LLM foi capaz de identificar essencialmente as mesmas vulnerabilidades detectadas pelas ferramentas.
* O LLM também identificou vulnerabilidades contextuais e falhas de lógica de negócio não claramente detectadas pelas ferramentas automatizadas.

Entretanto:

* Ferramentas tradicionais são superiores em velocidade, custo e escalabilidade.
* A análise com LLM apresentou maior profundidade explicativa, porém com maior tempo de execução e custo computacional.

Conclusão principal:

LLMs não substituem ferramentas tradicionais, mas representam um complemento poderoso em auditorias de segurança mais aprofundadas.

A combinação entre ferramentas automatizadas e análise assistida por LLM mostrou-se a abordagem mais completa para análise de segurança.

Do ponto de vista prático, ferramentas automatizadas permanecem essenciais para integração contínua e pipelines DevSecOps, enquanto LLMs mostram maior valor em auditorias exploratórias e revisões aprofundadas.

---

# 👥 Integrantes

* Pedro Arthur de Oliveira Barreto
* Rayane Bezerra da Silva

Disciplina: **Segurança de Sistemas**

---

# 📌 Considerações Finais

Este projeto possui caráter exclusivamente acadêmico e experimental.

O experimento buscou avaliar empiricamente:

* Capacidade real de detecção
* Cobertura comparativa
* Limitações práticas
* Reprodutibilidade
* Impacto da análise contextual

O resultado demonstra que a integração entre ferramentas tradicionais e LLMs pode representar uma evolução relevante no processo de revisão de segurança.

---
