# Report Intelligence Dataset

## Objectif

Cette couche se place après Silver/Gold et produit des faits structurés pour le
reporting. Aucun calcul métier n’est attendu dans le futur template HTML.

    Silver + Gold -> intelligence modules -> Parquet intelligence
                                  \-------> report_context/HOSTNAME.json

## Mapping réel

| Information | Source | Colonne / transformation |
|---|---|---|
| Asset, FQDN, IP, OS | Silver assets | hostname, ipAddress, assetOsPrimary |
| Relation asset/finding | Silver asset_findings | assetId, findingId |
| Finding courant | Silver findings | score, CVE, sévérité, dates, recommandation |
| Détail enrichi | Silver finding_details | CVSS, KEV, EPSS, preuves, URL historique |
| Versions | Silver finding_versions / détail JSON | detectedVersion, expectedVersion |
| Remédiation | Gold remediation + finding courant | regroupement exact recommandation/version |

## Commandes et sorties

    python scripts/build_report_dataset.py --hostname BYCVSRV069 --pretty-json
    python scripts/validate_report_dataset.py output/intelligence/report_context/BYCVSRV069.json

output/intelligence contient assets.parquet, findings.parquet,
vulnerabilities.parquet, scan_history.parquet, finding_history.parquet,
asset_risk_history.parquet, remediation.parquet, sources.parquet et les JSON
sous report_context/. Le JSON versionné contient metadata, asset, posture,
historique, findings, CVE, risque, remédiation, validation, sources et qualité.

## Historique

Le dataset actuel ne contient pas une série exhaustive de scans. firstSeen et
lastSeen sont traités comme des bornes d’observation, jamais comme une
chronologie inventée. scan_history indique reconstructed_observation_bounds.

- NEW : première observation explicitement identifiée.
- PERSISTENT : détecté sur plusieurs observations successives.
- RESOLVED : détecté puis explicitement non détecté.
- REOPENED : non détecté après détection, puis détecté à nouveau.
- REGRESSION : réservé à une dégradation prouvable.
- UNKNOWN : données insuffisantes.

## Priorité, corrélation et remédiation

La classification existante est conservée : P1 pour KEV/TRS supérieur ou égal
à 900/CVSS supérieur ou égal à 9, P2 pour TRS supérieur ou égal à 700/CVSS
supérieur ou égal à 7, P3 sinon.

Une CVE est multi_source_confirmed seulement si deux scanners normalisés
distincts la confirment. Les campagnes regroupent exclusivement une
recommandation exacte et une version cible exacte. Chaque action comporte
owner, preuves, critères de sortie et références findings/CVE. Local IT est
une politique de routage, pas une donnée CMDB.

## Limites

- L’enrichissement détaillé local ne couvre que 11 findings.
- De nombreux findings courants n’exposent ni scanner, ni CVSS, ni titre.
- L’historique exhaustif nécessite des snapshots ou un endpoint d’observations.
- NVD, EPSS publiques, CISA et CMDB ne sont pas simulées.
- Les absences restent nulles ou UNKNOWN et sont quantifiées dans data_quality.
