---
layout: default
---

<div class="hero" markdown="1">

<p class="prompt">whoami</p>

# Crônicas de Hacknagem

Sou o **Fernando Bortotti**, operador de **red team** e pesquisador de segurança ofensiva. Este é o meu caderno público de pesquisa: aqui compartilho artigos, *write-ups* e vulnerabilidades com o propósito de difundir conhecimento na área de segurança da informação.

Os temas vão de **red team** e análise de vulnerabilidades a **bug bounty**, análise de malware e CTFs. <span class="blink">_</span>

[~/sobre](sobre.md) &middot; [~/cves](articles/cves/cves-pgadmin.md) &middot; [github](https://github.com/fernandobortotti) &middot; [linkedin](https://www.linkedin.com/in/fbortotti/)

</div>

<div class="callout cves" markdown="1">

### CVEs publicadas

Vulnerabilidades que reportei de forma responsável e que receberam identificadores **CVE** oficiais — todas no **pgAdmin 4** (ferramenta de administração do PostgreSQL):

<span class="badge crit">9.3 Stored XSS</span> <span class="badge crit">9.0 RCE</span> <span class="badge high">8.1 Path Traversal</span> <span class="badge high">7.0 RCE</span> <span class="badge med">6.5 Auth Bypass</span> <span class="badge low">3.5 HTML Injection</span>

→ [Leia a análise técnica completa das 6 CVEs](articles/cves/cves-pgadmin.md)

</div>

<div class="post-list" markdown="1">

## CVEs

1. [Visão geral — As 6 CVEs que encontrei no pgAdmin 4](articles/cves/cves-pgadmin.md)
    - Resumo das seis vulnerabilidades que reportei de forma responsável no pgAdmin 4 e que foram publicadas oficialmente no cve.org, com impacto, versões afetadas e correção de cada uma.

2. [CVE-2026-12048 — Stored XSS via `html-react-parser`](articles/cves/cve-2026-12048-stored-xss-html-react-parser.md) <span class="badge crit">9.3 CRÍTICA</span>
    - Um servidor PostgreSQL malicioso (ou um objeto com nome forjado) injeta HTML arbitrário no DOM do pgAdmin, permitindo phishing dentro da própria interface.

3. [CVE-2026-12046 — RCE pré-autenticado no SQL Editor](articles/cves/cve-2026-12046-rce-sqleditor-sem-auth.md) <span class="badge crit">9.0 CRÍTICA</span>
    - Duas rotas sem `@pga_login_required` alcançam um `pickle.loads` sobre dados de sessão, abrindo caminho para execução remota de código.

4. [CVE-2026-7819 — Escrita arbitrária via symlink no File Manager](articles/cves/cve-2026-7819-path-traversal-symlink.md) <span class="badge high">8.1 ALTA</span>
    - O uso de `abspath` em vez de `realpath` permite escapar do diretório de armazenamento por link simbólico e escrever em qualquer caminho acessível ao processo.

5. [CVE-2026-7818 — RCE via desserialização insegura de sessões](articles/cves/cve-2026-7818-desserializacao-sessao.md) <span class="badge high">7.0 ALTA</span>
    - O gerenciador de sessões desserializava arquivos com `pickle` antes de qualquer verificação de integridade HMAC.

6. [CVE-2026-7820 — Bypass do bloqueio de conta](articles/cves/cve-2026-7820-bypass-lockout.md) <span class="badge med">6.5 MÉDIA</span>
    - A rota `/login` padrão do Flask-Security ignorava a coluna `locked`, derrotando a proteção contra força bruta.

7. [CVE-2026-12047 — HTML injection no módulo Cloud Deployment](articles/cves/cve-2026-12047-html-injection-cloud.md) <span class="badge low">3.5 BAIXA</span>
    - Texto de exceções dos SDKs de nuvem era refletido sem escape no Cloud Wizard, permitindo injeção de HTML.

## Análise estática de Malware

1. [Análise estática de uma variante do Agent Tesla](articles/analise-malware/analise_estatica_agenttesla.md)
    - A análise estática é fundamental para compreender o funcionamento de um malware sem executá-lo, permitindo examinar sua estrutura, fluxo de controle e artefatos embutidos. Aqui essa metodologia foi aplicada para dissecar o Agent Tesla, revelando suas camadas de ofuscação e cadeia de carregamento.

## Ensaios e análises

1. [Ensaio sobre Campanha de Phishing Direcionada a Pessoa Jurídica (PJ) no Brasil - Parte I](articles/ensaio-sobre-campanha-phishing-contra-pj/ensaio.md)
    - Mapeamento de uma campanha de phishing no Brasil direcionada a PJ, que se inicia com e-mails falsos de órgãos municipais, induzindo à instalação de extensões maliciosas no Chrome para roubo de credenciais e dados.

## Bug Bounty

1. [Possível Vulnerabilidade no Steam Remote](articles/steam/steamRemote.md)
    - Uma análise aprofundada de uma possível vulnerabilidade no Steam Remote Play: como a falha pode ser explorada e as medidas recomendadas para mitigação.

2. [SQL Injection Time-Based Blind](articles/bughunt/SQLiTimeBasedBlind.md)
    - Exploração de uma vulnerabilidade de SQL Injection Time-Based Blind encontrada na API de um programa privado de bug bounty.

## CTF

1. [Resolução da máquina Different CTF](articles/tryhackme/DifferentCTF.md)
    - Solução da máquina do TryHackMe explorando a vulnerabilidade do PwnKit para escalação de privilégio.

## Dicas

1. [Explorando Técnicas de Redirecionamento de Tráfego para o Burp Suite!](articles/burp/redirectBurp.md)
    - Técnica para redirecionar o tráfego de uma interface diretamente para o Burp Suite, permitindo analisar requisições feitas por ferramentas de pentest ou scripts personalizados que normalmente passariam despercebidas.

</div>
