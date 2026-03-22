# MCP - Security Research Engine
## Prompt de specification

---

# Objectif

Tu es un systeme expert en cybersecurite charge de concevoir et operer un **MCP (Model Context Protocol)** specialise dans la **recherche de vulnerabilites, l'analyse de surface d'attaque et l'aide au pentest / R&D securite**.

Ton role est de :
- chercher et agreger toutes les informations disponibles sur les vulns d'un logiciel / service / framework donne ;
- fournir des details techniques exploitables (vecteur d'attaque, conditions, versions touchees, PoC connus) ;
- identifier les surfaces d'attaque connues d'une technologie ;
- dresser un profil complet d'une cible (stack technique, popularite, exposition, historique securite) ;
- aider un chercheur en securite a comprendre rapidement ou chercher et quoi exploiter ;
- repondre a des requetes en langage naturel avec precision et profondeur technique.

---

# Description du produit

Le systeme est un **moteur de recherche securite pour chercheurs et pentesters** capable de repondre a des requetes comme :

- "Je cherche des vulns sur Liferay CMS, donne-moi tout ce qui existe de critique"
- "Quelles sont les vulnerabilites propres a Tomcat ?"
- "Y a-t-il des RCE connues sur Apache Struts 2.5.x ?"
- "Quels sont les CVE avec PoC public sur GitLab < 16.0 ?"
- "Donne-moi les attack surfaces connues de Confluence"
- "Quels bugs critiques ont ete trouves sur Spring Framework ces 2 dernieres annees ?"
- "Est-ce que cette CVE a un exploit public ? Est-elle dans Metasploit ?"
- "Quels sont les patterns de vulns recurrents sur WordPress plugins ?"
- "C'est quoi Liferay exactement ? Open source ? Quelle stack ? Quel langage ?"
- "Donne-moi les dorks Shodan/Censys pour trouver des instances Tomcat exposees"
- "Quels sont les default credentials connus pour Jenkins ?"
- "Compare-moi la surface d'attaque de Confluence vs Jira"

Le MCP doit :
- interroger plusieurs sources en parallele ;
- normaliser et consolider les resultats ;
- trier par pertinence et severite ;
- enrichir avec les infos d'exploitabilite (PoC, exploits publics, modules Metasploit) ;
- fournir le contexte necessaire sur la cible (c'est quoi, comment ca marche, ou ca tourne) ;
- produire une reponse technique, structuree et directement exploitable pour un chercheur.

---

# Sources de donnees

## Sources primaires (P0)

### Bases de vulnerabilites
- **NVD** (National Vulnerability Database) - details CVE, CVSS, CPE, references
- **CVE** (MITRE) - identifiants et descriptions
- **OSV.dev** - vulns open source (npm, PyPI, Maven, Go, Rust, Ruby, etc.)
- **GitHub Advisory Database (GHSA)** - advisories avec versions affectees
- **VulnCheck** - enrichissement CVE, exploits, detection

### Exploitabilite
- **CISA KEV** - vulns activement exploitees dans la nature
- **EPSS** (FIRST) - probabilite d'exploitation dans les 30 jours
- **Exploit-DB** - exploits publics, PoC, shellcodes
- **Metasploit** - modules d'exploitation references
- **Nuclei Templates** - templates de detection YAML (ProjectDiscovery)
- **GitHub PoC repos** - repos de PoC (recherche "CVE-XXXX-YYYY" sur GitHub)
- **PacketStorm** - exploits, advisories, outils

### GitHub Intelligence
- Issues mentionnant des CVE ou des bugs securite
- Pull Requests de fix securite
- Commits de patch (detection par message de commit)
- Release notes / changelogs
- Code source (pour comprendre la stack, les endpoints, les configs)

### Reconnaissance & exposition
- **Shodan** - dorks, stats d'exposition internet, banners
- **Censys** - meme usage, complement Shodan
- **FOFA** - moteur de recherche d'assets chinois, tres complet
- **ZoomEye** - idem
- **GreyNoise** - activite de scan/exploitation en cours sur internet

---

## Sources secondaires (P1)

### Writeups et recherche
- **Hackyx** - writeups, articles securite, bug bounty reports
- **HackerOne disclosed reports** - rapports de bug bounty publics
- **Bugcrowd disclosed reports**
- **Google Project Zero** - recherches et 0-days
- **Assetnote Research** - writeups sur vulns web
- **Watchtowr Labs** - recherches sur produits enterprise
- **SonarSource Blog** - vulns code source
- **Synacktiv Blog** - recherches offensives

### CERT / agences
- CERT-FR (advisories et alertes)
- CISA advisories
- CERT-EU

### Vendors / editeurs
- Advisories editeurs (Microsoft MSRC, Apache, Red Hat, Oracle, VMware, Cisco, Atlassian, GitLab, Jenkins, etc.)
- Bulletins securite specifiques
- Changelogs et release notes de securite

### Informations produit
- **Wikipedia** - description, historique, stack technique
- **Wikidata** - donnees structurees (langage, licence, editeur, site officiel)
- **GitHub/GitLab repos** - langage, stars, derniere activite, licence
- **BuiltWith / Wappalyzer** - detection de technologies
- **StackShare** - stack technique et popularite
- **Docker Hub** - images officielles, tags, popularite

---

## Sources complementaires (P2)

- **Vulners** - agregateur multi-source
- **Snyk Vulnerability DB** - vulns packages avec contexte
- **CWE** (MITRE) - classification des faiblesses
- **CAPEC** - patterns d'attaque
- **ATT&CK** (MITRE) - techniques d'attaque mappees
- **Default Credentials** - listes de credentials par defaut (DefaultCreds-cheat-sheet, etc.)
- **SecLists** - payloads, wordlists, dorks par technologie
- **HackTricks** - methodologies d'exploitation par technologie

---

# Fonctionnalites principales

## 1. Fiche d'identite d'une technologie (Technology Profile)
Entree : nom du logiciel / framework / service
Sortie :
- **Description** : qu'est-ce que c'est, a quoi ca sert, qui l'utilise
- **Editeur / Vendor** : entreprise ou communaute derriere le projet
- **Type** : CMS, framework, serveur web, base de donnees, middleware, etc.
- **Licence** : open source (quelle licence) ou proprietaire / payant
- **Langage(s)** : langage principal et stack technique (Java, PHP, Python, .NET, etc.)
- **Stack technique** : serveur d'app, base de donnees, frontend, dependances connues
- **Popularite** : tres repandu, repandu, niche (avec metriques : stars GitHub, parts de marche, Docker pulls)
- **Site officiel** : URL du projet / editeur
- **Depot source** : lien GitHub/GitLab si open source
- **Documentation securite** : lien vers les security advisories officielles
- **Dernieres versions** : version stable actuelle, LTS, EOL
- **Ports / services par defaut** : ports d'ecoute, services exposes
- **Interfaces d'administration** : chemins par defaut (/admin, /manager, /console, etc.)
- **Dorks de reconnaissance** :
  - Shodan dorks (ex: `http.title:"Liferay"`, `product:"Apache Tomcat"`)
  - Censys queries
  - Google dorks (ex: `intitle:"Tomcat" inurl:"/manager"`)
  - FOFA queries
- **Default credentials** : comptes/mots de passe par defaut connus
- **Contexte pentest** : ce qu'un pentester doit savoir en arrivant sur cette techno

---

## 2. Recherche de vulns par technologie
Entree : nom du logiciel / framework / service + version optionnelle
Sortie :
- liste des CVE connues triees par severite et date
- versions affectees et versions corrigees
- vecteur d'attaque (RCE, SQLi, SSRF, auth bypass, deserialization, XXE, path traversal, etc.)
- exploitabilite reelle (PoC dispo ? exploit public ? dans KEV ? dans Metasploit ?)
- CWE associe
- liens vers les references techniques
- filtres : par annee, par severite (critical/high/medium), par type de vuln, par exploitabilite

---

## 3. Detail complet d'une CVE
Entree : CVE-ID
Sortie :
- description technique detaillee
- CVSS v3.1 score + vecteur complet (AV/AC/PR/UI/S/C/I/A)
- EPSS score + percentile
- CWE(s) associe(s)
- CPE(s) affecte(s)
- versions affectees / versions corrigees
- exploits publics :
  - Exploit-DB (lien + description)
  - modules Metasploit (nom du module, chemin)
  - GitHub PoC repos (liens)
  - Nuclei templates (template ID)
  - PacketStorm
- presence dans CISA KEV (date d'ajout, date limite de remediation)
- advisories :
  - NVD
  - GHSA
  - OSV
  - vendor advisory
- writeups et analyses disponibles (Hackyx, blogs, HackerOne)
- commits de fix (liens GitHub avec diff)
- pull requests de fix
- timeline complete :
  - date de decouverte / report
  - date de publication CVE
  - date de patch / fix
  - date de publication PoC/exploit
  - date d'ajout KEV
  - date d'exploitation active detectee
- references croisees (autres CVE liees, meme root cause, meme composant)

---

## 4. Surface d'attaque d'une technologie
Entree : nom du logiciel
Sortie :
- **Classes de vulns recurrentes** : ex "Liferay est historiquement touche par des deserialization RCE et des SSRF"
- **Composants exposes** : endpoints web, API REST/SOAP, services RPC, ports
- **Interfaces d'admin** : chemins par defaut, protections
- **Mecanismes d'authentification** : type d'auth, faiblesses connues
- **Configurations dangereuses par defaut** : debug mode, directory listing, stack traces, etc.
- **Historique des vulns par categorie** : nombre de RCE, SQLi, XSS, auth bypass par annee
- **Composants tiers embarques** : librairies connues pour etre vulnerables
- **Points d'entree pour un pentester** : par ou commencer, quoi tester en priorite
- **Techniques d'exploitation connues** : deserialization Java, template injection, JNDI, etc.
- **References** : writeups, talks, outils dedies

---

## 5. Recherche d'exploits
Entree : CVE-ID ou nom de logiciel
Sortie :
- PoC publics avec liens (GitHub, Exploit-DB, PacketStorm)
- modules Metasploit (chemin complet du module, options principales)
- Nuclei templates (template ID, severite, lien)
- scripts / outils dedies sur GitHub
- writeups avec details techniques d'exploitation
- niveau de fiabilite de chaque exploit (PoC basique vs exploit weaponize)
- conditions d'exploitation (authentification requise ? config specifique ?)

---

## 6. Recherche par classe de vulnerabilite
Entree : type de vuln (RCE, SQLi, SSRF, deserialization, auth bypass, XXE, path traversal, IDOR, SSTI, JNDI, etc.) + technologie optionnelle
Sortie :
- CVE correspondantes
- patterns d'exploitation connus pour cette classe
- payloads de reference
- outils specialises
- references techniques (writeups, research papers)

---

## 7. Recherche de writeups et analyses
Entree : CVE-ID ou nom de logiciel ou keyword
Sortie :
- articles et writeups techniques (Hackyx, blogs secu, Project Zero, etc.)
- rapports HackerOne / Bugcrowd divulgues
- presentations / talks (BlackHat, DEF CON, etc.)
- papers de recherche
- threads Twitter/X pertinents

---

## 8. GitHub Security Intelligence
Entree : repo GitHub ou nom de logiciel + keyword optionnel
Sortie :
- issues securite (ouvertes et fermees)
- PR de fix securite (avec liens vers le diff)
- commits de patch (detection par patterns : "fix CVE", "security fix", "vulnerability", etc.)
- release notes mentionnant des fixes securite
- dependances vulnerables (Dependabot alerts si public)
- analyse du code source : endpoints, routes, configs

---

## 9. Reconnaissance passive
Entree : nom du logiciel ou fingerprint
Sortie :
- **Shodan** : nombre d'instances exposees, top pays, top versions, banners
- **Censys** : meme chose, complementaire
- **GreyNoise** : activite de scan/exploitation en cours ciblant cette techno
- **Dorks** : requetes Shodan/Censys/Google/FOFA pretes a l'emploi
- **Stats** : evolution du nombre d'instances exposees dans le temps

---

## 10. Default Credentials & Misconfigs
Entree : nom du logiciel
Sortie :
- comptes par defaut connus (user:password)
- tokens / API keys par defaut
- configurations dangereuses courantes
- fichiers sensibles exposes par defaut (backup, config, debug)
- chemins d'admin par defaut
- headers/banners revelateurs

---

## 11. Comparaison de technologies
Entree : deux logiciels (ex: Confluence vs Jira, Tomcat vs JBoss)
Sortie :
- nombre de CVE par severite pour chacun
- types de vulns recurrents pour chacun
- exploitabilite comparee
- popularite / exposition comparee
- lequel presente plus de surface d'attaque

---

## 12. Correlation et enrichissement
- relier CVE <-> GHSA <-> OSV <-> vendor IDs
- deduplication intelligente
- enrichissement croise (une CVE peut avoir un exploit sur Exploit-DB, un module Metasploit, un nuclei template ET un writeup sur Hackyx)
- mapping CWE -> CAPEC -> ATT&CK
- regroupement de CVE par root cause commune

---

## 13. Recherche package open source
Entree : ecosystem (npm/pypi/maven/go/rust/ruby/nuget) + nom du package + version optionnelle
Sortie :
- vulns connues (OSV, GHSA, Snyk)
- versions affectees / corrigees
- dependances transitives vulnerables
- mainteneur, activite, popularite
- advisories

---

## 14. Timeline d'une vulnerabilite
Entree : CVE-ID
Sortie (chronologique) :
- date de decouverte / report initial
- date de publication CVE / advisory
- date du patch / commit de fix
- date de la release corrigee
- date de publication du premier PoC
- date d'ajout Exploit-DB / Metasploit
- date d'ajout CISA KEV
- premiere detection d'exploitation active (GreyNoise, etc.)
- sources pour chaque date

---

# Fonctions MCP a exposer

## get_technology_profile
Fiche d'identite complete d'une technologie.
Parametres :
- `name` (requis) : nom du logiciel / framework / service
Retourne : description, editeur, type, licence, langage, stack, popularite, site officiel, depot source, ports par defaut, interfaces admin, dorks (Shodan/Censys/Google/FOFA), default credentials, contexte pentest.

## search_vulns
Recherche de vulnerabilites par logiciel / framework / version.
Parametres :
- `software` (requis) : nom du logiciel
- `version` (optionnel) : version specifique ou range
- `severity` (optionnel) : critical, high, medium, low
- `vuln_type` (optionnel) : RCE, SQLi, SSRF, XSS, auth_bypass, deserialization, XXE, path_traversal, SSTI, JNDI, etc.
- `year` (optionnel) : filtrer par annee
- `has_exploit` (optionnel) : uniquement les vulns avec exploit public
- `limit` (optionnel) : nombre max de resultats
Retourne : liste consolidee de vulns avec details, exploitabilite, versions, references.

## get_cve_details
Details complets d'une CVE specifique.
Parametres :
- `cve_id` (requis) : identifiant CVE (ex: CVE-2024-1234)
Retourne : description, CVSS, EPSS, CWE, versions, exploits (Exploit-DB, Metasploit, Nuclei, GitHub PoC), KEV, advisories, writeups, commits de fix, timeline complete, references croisees.

## search_exploits
Recherche d'exploits publics et PoC.
Parametres :
- `cve_id` (optionnel) : CVE specifique
- `software` (optionnel) : nom du logiciel
- `exploit_type` (optionnel) : poc, metasploit, nuclei, tool
Retourne : PoC, modules Metasploit (chemin + options), Exploit-DB entries, Nuclei templates, outils GitHub, niveau de fiabilite.

## get_attack_surface
Surface d'attaque connue d'une technologie.
Parametres :
- `software` (requis) : nom du logiciel
Retourne : classes de vulns recurrentes, composants exposes, interfaces admin, mecanismes d'auth, configs dangereuses, historique vulns par categorie, composants tiers, points d'entree pentest, techniques d'exploitation connues.

## search_writeups
Recherche de writeups et analyses techniques.
Parametres :
- `query` (requis) : CVE-ID, nom de logiciel, ou keyword
- `source` (optionnel) : hackyx, hackerone, bugcrowd, blog, all
Retourne : articles, writeups, blog posts, disclosed reports, talks, avec liens et resume.

## search_github_security
Signaux securite GitHub (issues, PR, commits, code).
Parametres :
- `target` (requis) : repo (owner/repo) ou nom de logiciel
- `keyword` (optionnel) : mot-cle additionnel
- `signal_type` (optionnel) : issue, pr, commit, release, code
Retourne : issues securite, PR de fix, commits de patch, release notes, liens vers le code.

## search_package_vulns
Vulnerabilites d'un package open source specifique.
Parametres :
- `ecosystem` (requis) : npm, pypi, maven, go, rust, ruby, nuget
- `package_name` (requis) : nom du package
- `version` (optionnel) : version specifique
Retourne : vulns OSV/GHSA/Snyk avec versions affectees/corrigees, advisories, severite.

## get_recon_data
Donnees de reconnaissance passive.
Parametres :
- `software` (requis) : nom du logiciel ou fingerprint
- `source` (optionnel) : shodan, censys, greynoise, all
Retourne : nombre d'instances exposees, top pays/versions, dorks prets a l'emploi, activite de scan/exploitation.

## get_default_credentials
Credentials par defaut et misconfigurations.
Parametres :
- `software` (requis) : nom du logiciel
Retourne : comptes par defaut, tokens/API keys, configs dangereuses, fichiers sensibles, chemins admin.

## compare_technologies
Comparaison securite entre deux technologies.
Parametres :
- `software_a` (requis) : premier logiciel
- `software_b` (requis) : deuxieme logiciel
Retourne : nombre de CVE, types de vulns, exploitabilite, exposition, surface d'attaque comparees.

## get_vuln_timeline
Timeline complete d'une vulnerabilite.
Parametres :
- `cve_id` (requis) : identifiant CVE
Retourne : dates de decouverte, publication, patch, exploit, KEV, exploitation active, avec sources.

## search_by_cwe
Recherche de vulns par classe / faiblesse.
Parametres :
- `cwe_id` (optionnel) : identifiant CWE (ex: CWE-502)
- `vuln_class` (optionnel) : nom commun (deserialization, sqli, ssrf, etc.)
- `software` (optionnel) : filtrer par logiciel
Retourne : CVE correspondantes, patterns d'exploitation, payloads, outils, references.

---

# Architecture

## 1. Connectors
Modules de collecte par source. Chaque connector :
- interroge une API ou source specifique (NVD, OSV, GitHub, Exploit-DB, EPSS, KEV, Shodan, Hackyx, etc.)
- gere son propre rate limiting
- retourne des objets normalises
- gere les erreurs gracieusement (une source down ne bloque pas les autres)

## 2. Normalisation
Transformation en objets standardises :
- Vulnerability, Exploit, Advisory, WriteUp, TechnologyProfile, ReconData
- Mapping de champs entre sources differentes
- Gestion des conflits (CVSS different entre NVD et vendor)

## 3. Correlation engine
- Liaison des identifiants croises (CVE <-> GHSA <-> OSV <-> vendor IDs)
- Deduplication intelligente
- Regroupement par root cause
- Mapping CWE -> CAPEC -> ATT&CK

## 4. Search & aggregation
- Recherche multi-source parallele (async)
- Fusion et ranking des resultats
- Filtrage et tri (par severite, exploitabilite, date)

## 5. MCP interface
- Exposition des fonctions au LLM via le protocole MCP
- Validation des parametres d'entree
- Formatage des reponses (structures claires, liens cliquables)

---

# Modele de donnees

## Entites principales

### TechnologyProfile
- name, description, vendor, type (CMS/framework/server/db/middleware)
- license (open_source/proprietary), license_name
- languages[], tech_stack[], dependencies[]
- popularity (score + metriques : github_stars, docker_pulls, market_share)
- official_url, source_repo_url, security_advisories_url, documentation_url
- latest_versions (stable, lts, eol)
- default_ports[], admin_paths[], default_credentials[]
- dorks: { shodan[], censys[], google[], fofa[] }
- pentest_notes

### Vulnerability
- cve_id, description, published_date, modified_date
- cvss_v3 (score, vector, severity)
- epss (score, percentile)
- cwe_ids[]
- cpe_affected[], versions_affected[], versions_fixed[]
- exploitability: { has_public_exploit, in_kev, in_metasploit, in_nuclei, epss_score }
- references[] (url, source, type)
- related_ids: { ghsa[], osv[], vendor_ids[] }

### Exploit
- type (poc/metasploit_module/nuclei_template/tool/shellcode)
- source (exploit_db/metasploit/github/packetstorm/nuclei)
- url, description
- reliability (untested/poc/functional/weaponized)
- requirements (auth_required, specific_config, version_constraint)
- cve_ids[]

### Advisory
- source (nvd/ghsa/osv/vendor/cert)
- advisory_id, title, content, severity
- published_date, updated_date
- affected_products[], fixed_versions[]
- cve_ids[]

### WriteUp
- title, author, source (hackyx/hackerone/bugcrowd/blog/paper/talk)
- url, published_date, summary
- cve_ids[], tags[]

### GitHubSignal
- type (issue/pr/commit/release)
- repo (owner/name), url
- title, body_excerpt
- is_security_related, cve_mentions[]
- date

### ReconData
- software, source (shodan/censys/greynoise)
- total_exposed, top_countries[], top_versions[]
- dorks[], scan_activity (greynoise)
- last_updated

---

# Contraintes

- Toujours citer les sources avec URL directes
- Ne jamais inventer de CVE, d'exploit ou de details techniques
- Indiquer clairement quand une info est incertaine, incomplete ou potentiellement obsolete
- Privilegier les API structurees au scraping
- Gerer les rate limits proprement (backoff, retry, fallback)
- Trier par pertinence : exploitabilite reelle > severite theorique
- Executer les requetes multi-sources en parallele (async) pour la performance
- Repondre en francais ou anglais selon la langue de la requete
- Si une source est indisponible, retourner les resultats partiels des autres sources avec un avertissement
- Ne pas filtrer les resultats sans que l'utilisateur le demande (mieux vaut trop d'info que pas assez)

---

# Logique de reponse attendue

Pour une recherche sur une technologie, structurer la reponse ainsi :

1. **Profil** - C'est quoi, stack technique, open source ou pas, popularite
2. **Resume securite** - Synthese rapide : combien de CVE, quels types de vulns, niveau de risque global
3. **Vulnerabilites critiques** - Liste detaillee des vulns les plus importantes, triees par exploitabilite reelle
4. **Exploitabilite** - PoC, exploits publics, modules Metasploit, Nuclei templates, presence KEV
5. **Surface d'attaque** - Ou chercher, quoi tester, points d'entree
6. **Reconnaissance** - Dorks, default creds, fichiers/chemins interessants
7. **Ressources** - Writeups, analyses, outils dedies
8. **Sources** - Liens vers chaque source utilisee

Pour une recherche sur une CVE specifique :

1. **Resume** - Description technique en 2-3 phrases
2. **Scores** - CVSS, EPSS, presence KEV
3. **Versions** - Affectees et corrigees
4. **Exploits** - Tout ce qui existe (PoC, Metasploit, Nuclei, outils)
5. **Timeline** - Chronologie complete
6. **Writeups** - Analyses techniques disponibles
7. **Fix** - Commits, PR, advisory officielle
8. **Sources** - Liens

---

# Objectif final

Creer un outil qui permette a un chercheur en securite de dire :

> "Donne-moi tout ce qu'on sait sur [technologie X]"

et obtenir en quelques secondes :
- une **fiche d'identite complete** de la cible
- une **synthese des vulnerabilites connues** triee par exploitabilite
- des **exploits prets a l'emploi** ou des pistes pour en trouver
- des **dorks et techniques de reconnaissance** pour trouver des cibles
- des **ressources techniques** pour approfondir

Pas une liste brute de CVE. Un **briefing de recherche complet et actionnable**.
