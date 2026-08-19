# Import Power BI

Importer les tables Silver `assets.parquet`, `findings.parquet`,
`asset_findings.parquet`, `cves.parquet`, `finding_cves.parquet`, puis les vues
Gold selon les besoins. Les fichiers sont plats, compressés en Snappy et ne
contiennent pas de types Arrow complexes.

Relations recommandées :

- `assets[assetId]` (1) vers `asset_findings[assetId]` (*)
- `findings[findingId]` (1) vers `asset_findings[findingId]` (*)
- `findings[findingId]` (1) vers `finding_cves[findingId]` (*)
- `cves[cveId]` (1) vers `finding_cves[cveId]` (*)

Conserver un filtrage à sens unique depuis les dimensions. Masquer les clés
techniques dans la vue rapport et utiliser les tables Gold pour les pages de
synthèse.

Exemple Power Query :

```powerquery
let
    Source = Parquet.Document(File.Contents("C:\data\gold\asset_summary.parquet"))
in
    Source
```

Mesures DAX :

```dax
Assets = DISTINCTCOUNT(asset_findings[assetId])
Open Findings = COUNTROWS(asset_findings)
Critical Assets =
CALCULATE(DISTINCTCOUNT(critical_findings[assetId]))
Max TRS = MAX(findings[hyScoreV2])
```

Pour les gros volumes, désactiver la détection automatique des relations,
charger uniquement les colonnes utiles, utiliser l’actualisation incrémentielle
après publication et éviter les relations bidirectionnelles.
