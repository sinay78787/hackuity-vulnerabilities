# Référentiel fonctionnel du dashboard

## Sources

| Domaine | Source locale | Usage |
|---|---|---|
| Assets | `output/*/gold/asset_summary.parquet` | Inventaire, scores et volumes |
| Findings critiques | `output/*/gold/critical_findings.parquet` | Investigation par serveur |
| CVE | `output/*/gold/cve_summary.parquet` | Vue vulnérabilités |
| Remédiations | `output/*/gold/remediation_summary.parquet` | Priorisation des actions |
| Périmètres et providers | `hackuity_all_open_findings.json` en streaming | Filtres transverses |

Le fichier `scripts/export_dashboard_data.py` agrège ces sources dans
`webapp/data/dashboard-data.js`. L’application HTML n’accède jamais directement
à l’API Hackuity.

## Règles de calcul

- Critique : TRS supérieur ou égal à 900.
- Élevé : TRS compris entre 700 et 899.
- Modéré : TRS compris entre 400 et 699.
- Faible : TRS inférieur à 400.
- CISA KEV : nombre de findings dont le champ brut `cisaKev` vaut `true`.
- Provider : union de `providerIds` et `assetProviderIds` observés.
- Périmètre : union des `perimeterIds` observés sur les findings de l’asset.
- Scope global : intersection des filtres périmètre, provider, risque et KEV.
- CVE dans un scope filtré : CVE reliées aux findings critiques disponibles
  pour les assets du scope.

## Priorisation et recommandations

Chaque finding, CVE et plan de remédiation reçoit une priorité calculée de
manière reproductible :

| Priorité | Déclencheurs | Délai cible |
|---|---|---:|
| P1 | CISA KEV, TRS ≥ 900 ou CVSS ≥ 9 | 7 jours |
| P2 | TRS ≥ 700, CVSS ≥ 7 ou exposition ≥ 180 jours | 30 jours |
| P3 | Autres cas | 90 jours |

Le score de priorité sur 100 combine le TRS (50 %), le CVSS (30 %),
l’ancienneté du finding (10 %) et un bonus CISA KEV (10 %). La raison affichée
sur chaque action conserve les signaux utilisés : TRS, CVSS, ancienneté, KEV et
version cible lorsqu’elle existe.

Une recommandation fournie par Hackuity ou le provider est marquée « source ».
Lorsqu’elle est absente, le dashboard affiche une action prudente marquée
« dérivée », construite dans cet ordre : mise à jour vers la version attendue,
correctif éditeur de la CVE, traitement du service exposé, puis analyse de la
preuve provider et scan de validation. Une donnée absente telle que le CVSS
reste affichée « Non renseigné » et n’est jamais remplacée par zéro.

## Historique serveur

- L’ancienneté correspond au nombre de jours depuis firstSeen.
- La fraîcheur correspond au nombre de jours depuis lastSeen.
- Les actions d’un serveur sont rapprochées de ses findings et triées par
  priorité, TRS, CVSS et signaux KEV.
- Après correction, un nouveau scan est systématiquement demandé pour vérifier
  la disparition du finding.

## Limites explicites

- L’échantillon actuel contient dix assets seulement.
- Les périmètres sont affichés par identifiant car l’export ne contient pas
  leurs libellés. Un mapping ID/nom pourra être ajouté ultérieurement.
- Une valeur absente est affichée comme non renseignée et n’est jamais inventée.
- Les recommandations sont des priorités opérationnelles dérivées des scores,
  de l’ancienneté et de CISA KEV ; elles ne remplacent pas une décision de risque.
- Les remédiations associées à un serveur utilisent d’abord une correspondance
  textuelle avec ses findings, puis les priorités globales comme fallback.

## Actualisation

```powershell
python scripts/export_dashboard_data.py --gold-dir output/gold
```

Après actualisation, recharger `webapp/index.html` avec `Ctrl+F5`.
