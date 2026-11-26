# Étude de marché — pentest autonome par IA (2026-11)

Sources consultées le 2026-11-26 (API GitHub + lecture des README/code). Les données
viennent d'agents de recherche ; elles reflètent l'état des dépôts à cette date.
Issue de suivi : #3.

## Critères de l'opérateur
1. Gestion multi-agents — 2. Skill/plugin/MCP par agent — 3. Orchestrateur —
4. Parler à l'orchestrateur — 5. Interface web — 6. Rapports et graphiques.

## Tableau comparatif

| Projet | Licence | ★ | Multi-agent | MCP/skill par agent | Orchestrateur | Parler à l'orch. | Web UI | Rapports/graphes | Vivant |
|---|---|---|---|---|---|---|---|---|---|
| **ARTEX** | AGPL-3.0 | — | Oui (planner/worker) | **Oui (MCP hot-swap, ouvert)** | Oui | Oui | **Oui (Next.js)** | **Oui (graphes ouverts)** | Oui |
| PentAGI (vxcontrol) | MIT (open-core) | 35k | Oui (~13 rôles, agent-as-tool) | **Enterprise only** | Oui | Oui | Oui (React SPA) | Rapports oui ; **attack-graph = Enterprise** | Oui |
| Strix (usestrix) | Apache-2.0 | 77k | Oui (graph of agents) | Oui (MCP externes) | Oui | Partiel (TUI + instruction) | Oui (viewer + cloud) | Oui (compliance) | Oui (très actif) |
| HexStrike | MIT | 14k | Partiel (modules, pas agents) | Serveur MCP 150+ outils | Partiel (decision engine) | Via client externe | Partiel (dashboards) | Oui (vuln cards) | Stagnant ~3,5 mois |
| CAI (aliasrobotics) | MIT+proprio | 10k | Oui (15+ agents, handoffs) | Oui (MCP natif) | Oui | Oui (REPL+HITL) | Non (REPL+API) | Partiel (reporter + /graph) | **Archivé** |
| PentestGPT (GreyDGL) | MIT | 17k | Partiel (2–3 rôles) | Non | Partiel (Supervisor) | Partiel (legacy HITL) | Non (CLI) | Partiel (pas de graphe) | Oui |
| PentestAGI (SzymonPaczos) | MIT | 2 | = PentestGPT | Non | Partiel | Partiel | Non | Partiel | Fork verbatim, nul |
| agent-pentest-assistant | MIT | 4 | Non (wrapper Strix) | Non | Non | Non | Config/audit only | Partiel (logs) | Quasi mort |
| PentestMCP (YoussefSahnoun) | MIT | 7 | Non (serveur MCP) | 26 outils AD | Non | — | Non | Partiel | — |
| pentestMCP (ramkansal) | MIT | 120 | Non (serveur MCP) | 35+ outils, async | Non | — | Non | Non | 2026 |
| ptai / Pentest-AI (0xSteph) | MIT | ~1.3-1.9k | 18 agents (fichiers) | 52 outils MCP | Non | — | Non | SARIF | Oui |

## Verdict : garder ARTEX et l'étendre
Aucun projet ne surclasse ARTEX sur les 6 critères réunis. ARTEX est le seul avec
console web + MCP hot-swap + graphes de findings **tous en cœur ouvert et vivant**.
- Strix est le plus mûr (77k★) mais orienté AppSec/web, pilotage de l'orchestrateur limité.
- PentAGI est le concurrent architectural le plus proche, mais **open-core** : ses
  meilleures briques (MCP, profils d'agents, plugins, rapports clients, graphe d'attaque
  temps réel) sont **payantes**. ARTEX a déjà en ouvert ce que PentAGI fait payer.
- CAI est riche mais **archivé** (produit fermé). PentestGPT = idées, pas de base.
- PentestAGI (le fork que l'opérateur avait cité) = fork verbatim de PentestGPT, apport nul.

## À importer (idées d'archi, issues créées)
- #33 **Sandbox Docker + tool terminal générique** préchargé par type d'engagement (PentAGI). Idée n°1 : débloque le pentest général et la vérification non-HTTP.
- #35 **Triade de supervision** adviser/planner/reflector (PentAGI) : fiabilité, surtout modèles locaux.
- #34 **Mémoire à deux étages** pgvector + graphe de connaissances (PentAGI).
- #36 **Scope-gateway d'egress + audit haché** (agent-pentest-assistant).
- #8 **Vérification par PoC/sortie d'outil exacte** (Strix "le modèle ne peut pas accorder verified" ; ptai idem). Déjà filée.
- Catalogue d'adaptateurs d'outils de **HexStrike** (150+, surtout reverse 25+, recon réseau 25+, cloud, OSINT) à piller pour #15–24 ; mais HexStrike n'a **ni wifi, ni C2, et AD partiel** → à compléter.
- Gros serveurs MCP Kali existants (**Bolt** 100+, **HexStrike** 150+, **mcp-vanguard** 89, **Darkmoon** 80+) : option = brancher un serveur massif plutôt qu'un wrapper par outil.

## Déjà présent dans ARTEX (vérifié dans le code, pas à réimporter)
- Messaging worker en direct + contrôle d'intention : `sendWorkerMessage`, `controlIntent`,
  `addGoal`/`addConstraint` (le « parler à l'orchestrateur » et le patch sont là).
- Failover multi-provider + rotation : `llmpool/` (`ErrExhausted`, round-robin par priorité).
- MCP hot-swap (stdio/http/sse) : `server/mcpdiscover.go`.
- Exécution de commandes sous privilèges réduits + isolation : `server/execpriv_unix.go`, `server/isolation.go`.
- Graphes de findings en cœur ouvert.

## Absent dans ARTEX (vrais manques → les issues ci-dessus)
- Conteneur d'outils jetable préchargé par mission (#33).
- Mémoire vectorielle / graphe de connaissances (#34) : aucune trace de pgvector dans le code.
- Détecteur de boucle / mentor / reflector dédiés (#35).
- Vérification de finding non-HTTP (#8).
- Confinement d'egress au point de sortie + audit haché (#36).
