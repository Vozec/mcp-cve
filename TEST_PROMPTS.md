# MCP-CVE — Test Prompts (Exhaustive)

Colle ces prompts un par un dans Claude Code après avoir redémarré la session.
Chaque bloc teste un ou plusieurs outils avec différentes combinaisons de paramètres.
Les résultats attendus sont indiqués pour valider que le tool ne plante pas.

---

## 1. `get_technology_profile`

```
Donne-moi le profil complet de la technologie "Liferay CMS"
```
```
Profil de sécurité de "Apache Tomcat"
```
```
get_technology_profile pour "Jenkins"
```

**Attend :** `nvd_sample`, `kev_entries`, `shodan`, `github_repo`, `hacktricks_pages`, `hackyx_articles`, `vulners_exploits`

---

## 2. `search_vulns`

### Params minimaux
```
Cherche les vulnérabilités de "WordPress"
```

### Avec version
```
Vulnérabilités de "Apache Struts" version "2.5"
```

### Avec severity
```
CVEs CRITICAL de "Confluence"
```

### Avec vuln_type
```
Vulnérabilités RCE sur "Joomla"
```

### Avec year
```
Vulnérabilités de "Drupal" en 2023
```

### has_exploit = true
```
Cherche des vulns exploitées publiquement sur "Liferay", uniquement celles avec un exploit connu
```

### Combo max
```
Vulnérabilités CRITICAL de "Apache Tomcat" version "9.0", type RCE, en 2024, uniquement avec exploit public
```

**Attend :** liste triée KEV > EPSS > CVSS, champs `in_kev`, `has_nuclei_poc`, `epss`

---

## 3. `get_cve_details`

### CVE récent et connu
```
Donne-moi tous les détails sur CVE-2021-44228
```

### CVE Liferay
```
Détails complets de CVE-2020-7961
```

### CVE avec Metasploit
```
CVE-2017-5638 — donne-moi les exploits, writeups, timeline complète
```

### CVE inexistant (test d'erreur gracieuse)
```
get_cve_details sur CVE-9999-99999
```

**Attend :** `nvd`, `epss`, `kev`, `exploits` (github_poc, exploit_db_and_searchsploit, nuclei_templates_github, metasploit_modules, vulners), `writeups`, `fix_commits`

---

## 4. `search_exploits`

### Par CVE
```
Cherche tous les exploits pour CVE-2021-44228
```

### Par software
```
Exploits publics pour "Apache Log4j"
```

### Par software + exploit_type nuclei
```
Templates Nuclei pour "Confluence"
```

### Par software + exploit_type metasploit
```
Modules Metasploit pour "Apache Struts"
```

### Par software + exploit_type exploitdb
```
Entrées Exploit-DB pour "Joomla"
```

### Par software + exploit_type poc
```
PoC GitHub pour "Spring Framework"
```

### Par software + exploit_type vulners
```
Exploits Vulners pour "Jenkins"
```

### Par CVE + exploit_type searchsploit
```
SearchSploit pour CVE-2017-5638
```

**Attend :** `total_found`, les clés correspondant aux sources demandées

---

## 5. `get_attack_surface`

```
Analyse la surface d'attaque de "Confluence"
```
```
Surface d'attaque de "Adobe ColdFusion"
```
```
Surface d'attaque de "SharePoint"
```

**Attend :** `severity_distribution`, `top_cwes`, `yearly_distribution`, `cves_with_exploits`, `kev_entries`, `hacktricks_pages`, `related_writeups`

---

## 6. `search_writeups`

### Params minimaux
```
Cherche des writeups sur "Liferay RCE"
```

### Avec source
```
Writeups sur "deserialization Java" depuis "medium"
```

### Avec source hackerone
```
Bug bounty reports sur "SSRF" depuis "hackerone"
```

### Pagination
```
Writeups sur "Apache" page 2, 20 résultats par page
```

### Par CVE
```
Writeups et analyses sur CVE-2021-44228
```

**Attend :** `total`, `articles` avec titre, url, source, tags

---

## 7. `search_github_security`

### GitHub — repo spécifique
```
Cherche les issues de sécurité dans le repo GitHub "liferay/liferay-portal"
```

### GitHub — keyword
```
Issues GitHub sur "Tomcat" avec le mot-clé "deserialization"
```

### GitHub — avec labels
```
Issues GitHub de "apache/struts" avec les labels "security,vulnerability"
```

### GitHub — signal_type issue
```
Issues de sécurité GitHub pour "Jenkins", type issue uniquement
```

### GitHub — signal_type commit
```
Commits de sécurité sur "Spring Framework" sur GitHub
```

### GitHub — signal_type advisory
```
Advisories GitHub pour "Drupal"
```

### GitLab — repo spécifique
```
Issues de sécurité sur le projet GitLab "gitlab-org/gitlab"
```

### GitLab — platform explicite
```
Cherche les MR de sécurité sur "Liferay" sur GitLab (platform: gitlab)
```

### GitLab — URL complète
```
Security signals sur https://gitlab.com/gitlab-org/gitlab avec keyword "RCE"
```

### Les deux plateformes
```
Cherche des signaux de sécurité sur "Jira" sur GitHub et GitLab
```

**Attend :** les clés des sources actives selon platform + signal_type

---

## 8. `search_package_vulns`

### npm
```
Vulnérabilités du package npm "lodash"
```

### PyPI avec version
```
Vulnérabilités de "django" (PyPI) version "3.2.0"
```

### Maven
```
Vulnérabilités Maven pour "org.apache.struts:struts2-core"
```

### Go
```
Package Go "golang.org/x/net" — vulnérabilités connues
```

### crates.io
```
Vulnérabilités du crate Rust "serde"
```

### RubyGems
```
Package RubyGems "rails" — toutes les vulns connues
```

### NuGet
```
Vulnérabilités NuGet pour "Newtonsoft.Json"
```

**Attend :** `osv_vulnerabilities`, `github_advisories`, `total_found`

---

## 9. `get_recon_data`

```
Données de reconnaissance Shodan pour "Liferay"
```
```
Recon data pour "Apache Tomcat"
```
```
get_recon_data pour 'http.title:"Grafana"'
```

**Attend :** `shodan.by_product`, `shodan.by_title`, `dorks` (shodan, censys, google, fofa)

---

## 10. `get_default_credentials`

```
Credentials par défaut de "Jenkins"
```
```
Credentials par défaut et mauvaises configs de "Apache Tomcat"
```
```
Credentials par défaut de "Grafana"
```
```
Accès par défaut pour "Liferay CMS"
```

**Attend :** `defaultcreds_cheatsheet`, `related_articles`

---

## 11. `compare_technologies`

```
Compare la sécurité de "Confluence" vs "Jira"
```
```
Quel est le plus risqué entre "WordPress" et "Drupal" ?
```
```
Compare "Apache Tomcat" et "JBoss"
```

**Attend :** les deux logiciels avec `cve_analysis` (total, severity, top_cwes, with_exploits), `kev_count`, `shodan_exposed`

---

## 12. `get_vuln_timeline`

### CVE actif dans KEV
```
Timeline complète de CVE-2021-44228
```

### CVE sans KEV
```
Timeline de CVE-2020-7961
```

### CVE récent
```
Timeline de CVE-2024-21413
```

**Attend :** `timeline` (liste ordonnée), `epss_current`, `kev_details`, `nuclei_status`, `nvd_references`

---

## 13. `search_by_cwe`

### Par CWE ID direct
```
CVEs avec CWE-502 (deserialization)
```

### Par vuln_class
```
Toutes les vulns de type "ssrf" dans la NVD
```

### Par vuln_class + software
```
Vulnérabilités "sqli" dans "WordPress"
```

### Classes supportées à tester
```
CVEs de type "xss" sur "Liferay"
```
```
CVEs de type "auth_bypass" sur "Jenkins"
```
```
CVEs de type "path_traversal" sur "Apache"
```
```
CVEs de type "rce" dans la NVD (sans filtre software)
```
```
CVEs de type "xxe" dans "Spring"
```
```
search_by_cwe vuln_class="deserialization" software="Liferay"
```

### Vuln_class invalide (test d'erreur gracieuse)
```
search_by_cwe vuln_class="foobar"
```

**Attend :** `cwe_id` résolu, `total_found`, liste de CVEs

---

## 14. `searchsploit_search`

### Params minimaux
```
Searchsploit pour "Liferay"
```

### Avec platform
```
Exploits searchsploit pour "Apache Tomcat" sur plateforme "java"
```

### Avec exploit_type
```
Remote exploits dans searchsploit pour "WordPress"
```

### Combo
```
Exploits "webapps" sur "php" pour "Joomla" dans searchsploit
```

### Platform windows
```
Exploits Windows dans searchsploit pour "IIS"
```

**Attend :** `total_found`, liste `exploits` avec edb_id, title, date, type, platform

---

## 15. `get_security_resources`

### Params minimaux
```
Ressources de sécurité pour "Java deserialization"
```

### resource_type writeup
```
Writeups et articles sur "SSRF", type writeup
```

### resource_type cheatsheet
```
Cheatsheets HackTricks pour "Active Directory"
```

### resource_type exploit
```
Exploits disponibles pour "Apache Struts", type exploit
```

### resource_type article
```
Articles sur "Log4Shell"
```

### Combo all
```
Toutes les ressources de sécurité pour "Liferay" — writeups, cheatsheets, exploits, articles
```

**Attend :** `total_resources`, les clés selon resource_type (hackyx_writeups, vulners_articles, hacktricks, searchsploit, vulners_exploits)

---

## 16. `search_vulners`

### Query simple
```
Cherche dans Vulners "Apache Tomcat RCE"
```

### Query Lucene avancée
```
Vulners query: title:*liferay* bulletinFamily:exploit
```

### Query CVE
```
Vulners CVE-2021-44228
```

### Query temporelle
```
Vulners: bulletinFamily:exploit published:[2024-01-01 TO 2024-12-31]
```

### Query logicielle avancée
```
Cherche dans Vulners "Spring deserialization" avec limit 30
```

**Attend :** `total`, `results` avec titre, url, score, source

---

## 17. `search_nuclei_pocs`

### Par keyword
```
CVEs avec PoC Nuclei pour "Apache"
```

### Par CVE
```
Template Nuclei pour CVE-2021-44228
```

### only_with_template=true
```
CVEs de "WordPress" avec template Nuclei uniquement
```

### Avec severity
```
CVEs CRITICAL de "Confluence" avec PoC Nuclei
```

### Combo max
```
CVEs "high" de "Liferay" avec PoC ET template Nuclei
```

### Sans résultat probable (test gracieux)
```
search_nuclei_pocs keyword="ZabbixUnknownSoftwareXYZ123"
```

### Erreur : ni keyword ni cve_id
```
search_nuclei_pocs sans paramètre
```

**Attend :** `total`, `cves` avec is_poc, is_template, poc_urls

---

## 18. `search_advisories`

### Par keyword simple
```
Advisories GitHub pour "Liferay"
```

### Par CVE
```
Advisory GitHub pour CVE-2021-44228
```

### Type reviewed
```
Advisories GitHub vérifiés (reviewed) pour "Spring"
```

### Type unreviewed
```
Advisories GitHub non vérifiés (unreviewed) pour "WordPress"
```

### Type malware
```
Advisories GitHub de type malware pour "npm"
```

### Avec ecosystem
```
Advisories Maven pour "log4j"
```

### Avec severity
```
Advisories critical sur PyPI
```

### Avec CWEs
```
Advisories filtrés sur CWE-79,CWE-89 pour "PHP"
```

### include_unreviewed=true (défaut)
```
Advisories pour "Apache" reviewed ET unreviewed
```

### include_unreviewed=false
```
Advisories reviewed uniquement pour "Jenkins"
```

**Attend :** soit `advisories` (si type spécifié), soit `reviewed`+`unreviewed`+`malware` (si include_unreviewed=true)

---

## 19. `search_gitlab_security`

### Params minimaux (project connu)
```
Cherche les issues de sécurité dans le projet GitLab "gitlab-org/gitlab"
```

### Avec keyword
```
Issues GitLab de "gitlab-org/gitlab" avec keyword "RCE"
```

### Avec labels custom
```
Issues GitLab de "gitlab-org/gitlab" avec labels "security::vulnerability,type::bug"
```

### signal_type issue
```
Issues GitLab de "gitlab-org/gitlab", type issue uniquement
```

### signal_type mr
```
MR de sécurité dans "gitlab-org/gitlab", type mr
```

### signal_type commit
```
Commits de sécurité dans "gitlab-org/gitlab", type commit
```

### URL complète
```
Security signals pour https://gitlab.com/gitlab-org/gitlab avec keyword "CVE"
```

### Projet inexistant (test erreur gracieuse)
```
search_gitlab_security project="foo/bar-nonexistent-project-xyz"
```

**Attend :** `issues`, `merge_requests`, `commits` (déduplicés), selon signal_type

---

## Tests transversaux (combinaisons multi-outils)

### Recherche complète sur une techno
```
Je prépare un pentest sur une instance Liferay Portal 7.4.
Donne-moi :
1. Le profil de la techno (get_technology_profile)
2. Les vulns critiques et high (search_vulns severity=CRITICAL et HIGH)
3. Les exploits publics disponibles (search_exploits)
4. La surface d'attaque (get_attack_surface)
5. Les credentials par défaut (get_default_credentials)
6. Les ressources HackTricks et writeups (get_security_resources)
```

### Workflow CVE complet
```
CVE-2020-7961 (Liferay RCE) :
1. Détails complets (get_cve_details)
2. Timeline (get_vuln_timeline)
3. Exploits dispo (search_exploits)
4. Writeups (search_writeups)
5. Advisories GitHub (search_advisories)
```

### Comparaison + recommandations
```
Compare WordPress vs Drupal en termes de sécurité.
Utilise compare_technologies, puis search_by_cwe type="sqli" pour chacun,
et search_nuclei_pocs pour chacun.
```

### Recon complet
```
Recon passif sur "Grafana" :
1. get_recon_data
2. get_technology_profile
3. search_vulns severity=CRITICAL has_exploit=true
4. get_default_credentials
```
