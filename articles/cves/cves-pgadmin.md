# CVEs no pgAdmin 4

## Introdução

Este artigo reúne um conjunto de vulnerabilidades que reportei de forma responsável (*coordinated disclosure*) no [pgAdmin 4](https://www.pgadmin.org/), a ferramenta de administração e desenvolvimento mais utilizada para o banco de dados PostgreSQL. As falhas foram triadas e corrigidas pela CNA do projeto PostgreSQL e publicadas oficialmente no [cve.org](https://www.cve.org/CVERecord/SearchResults?query=bortotti).

O objetivo aqui é documentar, em português, a natureza técnica de cada vulnerabilidade, o impacto, as versões afetadas e como cada uma foi corrigida. Acredito que mostrar o raciocínio por trás de cada falha ajuda outros pesquisadores a desenvolverem o olhar para esse tipo de problema — em especial os clássicos de aplicações web em Python: desserialização insegura, *path traversal*, autenticação ausente e *cross-site scripting*.

> **Aviso:** todo o conteúdo tem finalidade exclusivamente educacional. As falhas já foram corrigidas nas versões indicadas. Atualize sua instalação do pgAdmin 4 para a versão mais recente.

## Sobre o pgAdmin 4

O pgAdmin 4 é uma aplicação web (escrita em Python/Flask no backend e React no frontend) que pode rodar em dois modos:

- **Desktop mode**: roda localmente para um único usuário.
- **Server mode**: roda como um serviço multiusuário, acessível pela rede — é nesse modo que várias dessas falhas têm impacto real.

Por concentrar credenciais e acesso a bancos de dados, qualquer falha no pgAdmin tende a ter impacto elevado.

## Resumo das vulnerabilidades

| CVE | Tipo (CWE) | Severidade (CVSS 3.1) | Versões afetadas |
|-----|------------|------------------------|------------------|
| [CVE-2026-12048](https://www.cve.org/CVERecord?id=CVE-2026-12048) | Stored XSS (CWE-79 / CWE-116) | **9.3 — Crítica** | 6.0 até < 9.16 |
| [CVE-2026-12046](https://www.cve.org/CVERecord?id=CVE-2026-12046) | Auth ausente + desserialização (CWE-306 / CWE-502) | **9.0 — Crítica** | 6.9 até < 9.16 |
| [CVE-2026-7819](https://www.cve.org/CVERecord?id=CVE-2026-7819) | *Path traversal* via symlink (CWE-61 / CWE-22) | **8.1 — Alta** | < 9.15 |
| [CVE-2026-7818](https://www.cve.org/CVERecord?id=CVE-2026-7818) | Desserialização insegura (CWE-502) | **7.0 — Alta** | < 9.15 |
| [CVE-2026-7820](https://www.cve.org/CVERecord?id=CVE-2026-7820) | Bypass de bloqueio de conta (CWE-307) | **6.5 — Média** | < 9.15 |
| [CVE-2026-12047](https://www.cve.org/CVERecord?id=CVE-2026-12047) | HTML injection (CWE-79 / CWE-116) | **3.5 — Baixa** | 6.6 até < 9.16 |

A seguir, o detalhamento de cada uma.

---

## CVE-2026-12048 — Stored XSS via texto de erro renderizado pelo `html-react-parser`

- **Tipo:** Cross-Site Scripting armazenado (CWE-79 / CWE-116)
- **CVSS 3.1:** 9.3 (Crítica) — `AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N`
- **Versões afetadas:** pgAdmin 4 da 6.0 até antes da 9.16

Esta é a mais grave do conjunto. O frontend do pgAdmin passava textos retornados pelo servidor PostgreSQL (mensagens de `ErrorResponse`, nomes de objetos citados em erros do tipo *relation does not exist*, e campos de planos `EXPLAIN` como *Recheck Cond* e *Exact Heap Blocks*) diretamente pelo `html-react-parser` em praticamente todos os pontos de exibição: *toasts* do notificador, áreas de ajuda e erro de formulários, modais de confirmação, o visualizador de planos do *Explain*, e os diálogos do editor SQL.

O problema: esse texto não é confiável. Um servidor PostgreSQL controlado pelo atacante — ou mesmo qualquer servidor onde um usuário de baixo privilégio consiga criar uma tabela ou coluna com nome malicioso — podia injetar HTML arbitrário (incluindo `<iframe>`) no DOM do pgAdmin no momento em que a vítima se conectasse a esse servidor ou visualizasse um plano de execução referenciando o objeto criado.

O `srcdoc` do `<iframe>` injetado podia buscar JavaScript hospedado pelo atacante e, escrevendo em `parent.location`, redirecionar a aba principal do pgAdmin da vítima para uma URL maliciosa. Como a injeção parte de dentro da própria interface do pgAdmin, controles clássicos contra *clickjacking* (`X-Frame-Options`, `Content-Security-Policy: frame-ancestors`) **não mitigam** o ataque. Uma página de phishing renderizada dentro da janela legítima do pgAdmin é praticamente indistinguível de um diálogo genuíno.

**Correção:** três camadas complementares — (1) sanitização com **DOMPurify** ao redor de cada chamada do `html-react-parser`; (2) um novo contrato de renderização em texto puro (`SafeMessage` / `SafeHtmlMessage` e os helpers `Notifier.errorText`/`alertText`/etc.), migrando cerca de cinquenta *callers*; e (3) *escape* de HTML no backend (`execute_post_connection_sql`) para que consumidores de JSON (logs de auditoria, clientes de API) também nunca recebam o markup cru.

Referência: [pgadmin4#10068](https://github.com/pgadmin-org/pgadmin4/issues/10068)

---

## CVE-2026-12046 — Desserialização de pickle sem autenticação no SQL Editor (RCE)

- **Tipo:** Falta de autenticação em função crítica (CWE-306) + Desserialização de dados não confiáveis (CWE-502)
- **CVSS 3.1:** 9.0 (Crítica) — `AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H`
- **Versões afetadas:** pgAdmin 4 da 6.9 até antes da 9.16

Dois *endpoints* do *blueprint* do SQL Editor — `DELETE /sqleditor/close/<trans_id>` e `POST /sqleditor/initialize/sqleditor/update_connection/<sgid>/<sid>/<did>` — eram as **únicas** rotas do módulo que não tinham o *decorator* `@pga_login_required`. Ambas alcançam um *sink* de `pickle.loads` sobre `session['gridData'][<trans_id>]['command_obj']`. Em *server mode*, esses *endpoints* eram acessíveis sem qualquer sessão autenticada.

A falha em si é um clássico de *missing authentication on critical function* protegendo um *sink* de desserialização insegura. Para transformá-la em execução remota de código, o atacante ainda precisa forjar um arquivo de sessão no servidor contendo um *payload* malicioso de pickle, o que exige: (a) conhecimento da `SECRET_KEY` do Flask do pgAdmin e (b) acesso de escrita ao diretório `sessions/`. Nenhuma das pré-condições é concedida pela falha sozinha — daí a complexidade de ataque "alta" (`AC:H`). Mas quando essas condições já existem (deploy mal configurado, comprometimento prévio, configuração vazada), a ausência do gate de autenticação é o último salto que transforma um comprometimento parcial em execução de código não autenticada no processo do pgAdmin — e, por extensão, no host, sob a conta que executa o serviço.

A falha é exclusiva do *server mode*: em *desktop mode*, um *hook* `before_request` reautentica o `DESKTOP_USER` a cada requisição.

**Correção:** uma linha — adicionar o *decorator* `@pga_login_required` em cada um dos dois *endpoints*, igualando-os a todas as outras rotas do módulo. A cadeia `is_authenticated` / MFA passa a rodar antes de o `trans_id` ser dereferenciado.

Referência: [pgadmin4#10072](https://github.com/pgadmin-org/pgadmin4/issues/10072)

---

## CVE-2026-7819 — *Path traversal* via link simbólico no File Manager (escrita arbitrária)

- **Tipo:** *Symlink following* / *path traversal* (CWE-61 / CWE-22)
- **CVSS 3.1:** 8.1 (Alta) — `AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H`
- **Versões afetadas:** pgAdmin 4 antes da 9.15

A função `check_access_permission` do File Manager usava `os.path.abspath`, que resolve `..` mas **não** resolve links simbólicos — enquanto a escrita subsequente no kernel **segue** symlinks. Esse descompasso é a vulnerabilidade.

Um usuário autenticado podia plantar um link simbólico dentro do seu próprio diretório de armazenamento apontando para fora dele e, com isso, induzir o pgAdmin a escrever em qualquer caminho alcançável pelo processo. Dependendo de como o pgAdmin está implantado (qual usuário o executa, quais arquivos são acessíveis), isso pode levar a escalonamento de privilégios no host.

**Correção:** a verificação de acesso passou a usar `os.path.realpath` (que resolve symlinks) tanto na origem quanto no destino, além de um helper `_open_upload_target` que abre o alvo com a flag `O_NOFOLLOW` (modo `0o600`), fechando a janela de TOCTOU no componente final do caminho. O modo do arquivo foi endurecido de `0o644` para `0o600`.

Referência: [pgadmin4#9902](https://github.com/pgadmin-org/pgadmin4/issues/9902)

---

## CVE-2026-7818 — Desserialização insegura no gerenciador de sessões em arquivo (RCE)

- **Tipo:** Desserialização de dados não confiáveis (CWE-502)
- **CVSS 3.1:** 7.0 (Alta) — `AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H`
- **Versões afetadas:** pgAdmin 4 antes da 9.15

O `FileBackedSessionManager` desserializava o conteúdo dos arquivos de sessão (usando o módulo padrão de serialização do Python, o `pickle`) **antes** de qualquer verificação de integridade HMAC. Ou seja: qualquer arquivo colocado no diretório de sessões era desserializado incondicionalmente.

Um usuário autenticado com acesso de escrita ao diretório de sessões (por má configuração ou em combinação com outra falha de *path traversal* — como a CVE-2026-7819 acima) podia plantar um *payload* serializado e malicioso para obter execução de código no nível do sistema operacional, sob a identidade do processo do pgAdmin.

**Correção:** passou-se a prefixar um HMAC SHA-256 (64 bytes em hex) calculado sobre o corpo da sessão com a `SECRET_KEY`, verificado com `hmac.compare_digest` **antes** de qualquer desserialização. A verificação é levantada como exceção (e não via `assert`) quando a `SECRET_KEY` está vazia, para não ser removida sob a flag `-O` do Python.

Referência: [pgadmin4#9901](https://github.com/pgadmin-org/pgadmin4/issues/9901)

---

## CVE-2026-7820 — Bypass do bloqueio de conta pela rota `/login` padrão do Flask-Security

- **Tipo:** Restrição inadequada de tentativas de autenticação (CWE-307)
- **CVSS 3.1:** 6.5 (Média) — `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N`
- **Versões afetadas:** pgAdmin 4 antes da 9.15

O pgAdmin aplicava o `MAX_LOGIN_ATTEMPTS` (proteção contra força bruta) **apenas** dentro da sua *view* customizada `/authenticate/login`. Porém, a *view* padrão `/login` do **Flask-Security**, registrada automaticamente por `security.init_app()` e acessível em todo servidor, nunca consultava o campo `User.locked`: o modelo do pgAdmin dependia do `UserMixin.is_locked()` do Flask-Security (que sempre retorna "não bloqueado") e do `is_active` do Flask-Login (que só checa a coluna `active`, não `locked`).

Resultado: um atacante que tivesse disparado o bloqueio de uma conta via `/authenticate/login` ainda conseguia obter uma sessão reenviando credenciais válidas diretamente para `/login`, derrotando a proteção contra força bruta para contas com fonte de autenticação `INTERNAL`. O mesmo bypass significa que as tentativas via `/login` nunca eram limitadas, permitindo um ataque de adivinhação de senha *online* ilimitado.

Contas LDAP, OAuth2, Kerberos e Webserver não são afetadas, pois não têm senha local e são rejeitadas pela validação do `LoginForm` antes da checagem de bloqueio.

**Correção:** sobrescrita de `User.is_active` e `User.is_locked()` para que a coluna `locked` seja respeitada em **todos** os caminhos de autenticação.

Referência: [pgadmin4#9904](https://github.com/pgadmin-org/pgadmin4/issues/9904)

---

## CVE-2026-12047 — HTML injection no módulo de *cloud deployment*

- **Tipo:** HTML injection (CWE-79 / CWE-116)
- **CVSS 3.1:** 3.5 (Baixa) — `AV:N/AC:L/PR:L/UI:R/S:U/C:N/I:L/A:N`
- **Versões afetadas:** pgAdmin 4 da 6.6 até antes da 9.16

Os *endpoints* do módulo de implantação em nuvem (`verify_credentials`, `deploy`, `regions`, `update-server`, sob `/rds/`, `/azure/`, `/google/` e o *blueprint* `/cloud/`) propagavam o texto de exceções dos SDKs da AWS / Azure / Google para o corpo da resposta JSON (campos `info` e `errormsg`) **sem** codificar o HTML. O Cloud Wizard, no frontend, renderizava essas *strings* via `html-react-parser`.

O ponto de entrada reportado foi o `/rds/verify_credentials/`: um usuário autenticado submetia uma `access_key` contendo um *payload* `<iframe/src=...>`; a AWS STS rejeitava a credencial com uma exceção `IncompleteSignature` que **cita a `access_key` literalmente**; o backend do pgAdmin repassava esse texto para o campo `info`; e o Cloud Wizard o interpretava como HTML. A partir daí, o mesmo vetor de redirecionamento de aba via `<iframe>` da CVE-2026-12048 se aplica.

O impacto base é auto-direcionado (o próprio usuário que enviou o *payload* vê a injeção); escalonar para outros usuários exigiria um *primitive* de CSRF adicional. Por isso a severidade baixa. O mesmo padrão de "erro não sanitizado dentro de JSON" estava presente em vários *endpoints* irmãos do Azure e do Google.

**Correção:** *escape* de HTML em toda *string* de exceção externa/SDK no *sink* do *endpoint*, via um novo helper compartilhado `sanitize_external_text` (em `web/pgadmin/utils/text_sanitize.py`). Adicionalmente, o Cloud Wizard passou a renderizar o `FormFooterMessage` em modo texto puro para *strings* vindas do backend.

Referência: [pgadmin4#10069](https://github.com/pgadmin-org/pgadmin4/issues/10069)

---

## Conclusão

Esse conjunto de falhas no pgAdmin 4 ilustra bem como vulnerabilidades clássicas continuam vivas em aplicações modernas:

- **Confie sempre na fonte certa.** Vários problemas (XSS, HTML injection) nasceram de tratar como confiável um texto que, na prática, vinha de um servidor de banco ou de uma mensagem de SDK influenciável pelo atacante.
- **Desserialização é perigosa.** Tanto a CVE-2026-7818 quanto a CVE-2026-12046 giram em torno de `pickle.loads` sobre dados que o atacante pode influenciar — verificar integridade (HMAC) **antes** de desserializar é essencial.
- **`abspath` não é `realpath`.** A diferença entre resolver `..` e resolver *symlinks* foi o suficiente para uma escrita arbitrária de arquivos.
- **Controles de segurança precisam cobrir todos os caminhos.** O bypass de bloqueio de conta existia porque a proteção estava em uma *view*, mas outra *view* equivalente ficava exposta.

Recomendação prática: **mantenha o pgAdmin 4 sempre atualizado** (>= 9.16) e, em *server mode*, garanta que a `SECRET_KEY`, o diretório de sessões e as permissões de arquivo estejam devidamente protegidos.

## Referências

1. [Resultado da busca por "bortotti" no cve.org](https://www.cve.org/CVERecord/SearchResults?query=bortotti)
2. [CWE-502: Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html)
3. [CWE-79: Cross-site Scripting](https://cwe.mitre.org/data/definitions/79.html)
4. [CWE-22: Path Traversal](https://cwe.mitre.org/data/definitions/22.html)
5. [CWE-306: Missing Authentication for Critical Function](https://cwe.mitre.org/data/definitions/306.html)
6. [CWE-307: Improper Restriction of Excessive Authentication Attempts](https://cwe.mitre.org/data/definitions/307.html)
7. [Repositório do pgAdmin 4](https://github.com/pgadmin-org/pgadmin4)
