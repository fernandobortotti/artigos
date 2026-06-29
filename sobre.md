---
layout: default
title: Sobre
description: Fernando Bortotti — operador de red team e pesquisador de segurança ofensiva
---

# Sobre mim

<div class="hero" markdown="1">

<p class="prompt">whoami</p>

Olá! Sou o **Fernando Bortotti**, operador de **red team** e pesquisador de segurança ofensiva. Atuo simulando adversários reais para encontrar, explorar e — principalmente — ajudar a corrigir falhas antes que elas sejam abusadas.

Este blog é o meu caderno público: aqui eu documento pesquisas, técnicas, *write-ups* e vulnerabilidades que encontro, com o propósito de compartilhar conhecimento com a comunidade de segurança.

</div>

## O que eu faço

- **Red Team & Adversary Simulation** — emulação de ameaças, pós-exploração e movimentação lateral com foco em objetivos de negócio.
- **Pesquisa de vulnerabilidades** — análise de código, *fuzzing* e revisão manual de aplicações em busca de falhas exploráveis.
- **Bug Bounty & Web Hacking** — caça a vulnerabilidades em aplicações e APIs (SQLi, XSS, desserialização, *path traversal*, falhas de autenticação, etc.).
- **Análise de malware** — análise estática e dinâmica para entender cadeias de carregamento e ofuscação.

## CVEs publicadas

Algumas das vulnerabilidades que reportei de forma responsável e que foram reconhecidas oficialmente com identificadores CVE. Todas no **pgAdmin 4** (a ferramenta de administração do PostgreSQL), creditadas via CNA do projeto PostgreSQL:

<div class="post-list" markdown="1">

| CVE | Tipo | Severidade | Análise |
|-----|------|------------|---------|
| [CVE-2026-12048](https://www.cve.org/CVERecord?id=CVE-2026-12048) | Stored XSS | <span class="badge crit">9.3 CRÍTICA</span> | [ler](articles/cves/cve-2026-12048-stored-xss-html-react-parser.md) |
| [CVE-2026-12046](https://www.cve.org/CVERecord?id=CVE-2026-12046) | Auth ausente + RCE (pickle) | <span class="badge crit">9.0 CRÍTICA</span> | [ler](articles/cves/cve-2026-12046-rce-sqleditor-sem-auth.md) |
| [CVE-2026-7819](https://www.cve.org/CVERecord?id=CVE-2026-7819) | Path traversal via symlink | <span class="badge high">8.1 ALTA</span> | [ler](articles/cves/cve-2026-7819-path-traversal-symlink.md) |
| [CVE-2026-7818](https://www.cve.org/CVERecord?id=CVE-2026-7818) | Desserialização insegura (RCE) | <span class="badge high">7.0 ALTA</span> | [ler](articles/cves/cve-2026-7818-desserializacao-sessao.md) |
| [CVE-2026-7820](https://www.cve.org/CVERecord?id=CVE-2026-7820) | Bypass de bloqueio de conta | <span class="badge med">6.5 MÉDIA</span> | [ler](articles/cves/cve-2026-7820-bypass-lockout.md) |
| [CVE-2026-12047](https://www.cve.org/CVERecord?id=CVE-2026-12047) | HTML injection | <span class="badge low">3.5 BAIXA</span> | [ler](articles/cves/cve-2026-12047-html-injection-cloud.md) |

</div>

Veja também a [visão geral consolidada das 6 CVEs](articles/cves/cves-pgadmin.md).

> Busca oficial: [cve.org → "bortotti"](https://www.cve.org/CVERecord/SearchResults?query=bortotti)

## Contato

<div class="callout" markdown="1">

- **GitHub:** [github.com/fernandobortotti](https://github.com/fernandobortotti)
- **LinkedIn:** [linkedin.com/in/fbortotti](https://www.linkedin.com/in/fbortotti/)
- **E-mail:** [fernando.bortotti@bsd.com.br](mailto:fernando.bortotti@bsd.com.br)

</div>

> **Aviso:** todo o conteúdo deste blog tem finalidade exclusivamente educacional. Não me responsabilizo pelo uso indevido das informações aqui apresentadas — aplique esse conhecimento de forma ética e dentro da lei.
