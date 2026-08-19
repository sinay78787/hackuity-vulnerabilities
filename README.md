# Pipeline Hackuity

Pipeline Python 3.11+ en couches Bronze, Silver et Gold, conçu pour traiter
l’export JSON en streaming et produire des Parquet plats compatibles Power BI.

## Report Intelligence Dataset

La couche output/intelligence transforme les tables Silver/Gold existantes en
faits structurés et en un report_context autonome pour chaque asset.

    python scripts/build_report_dataset.py --hostname BYCVSRV069 --pretty-json
    python scripts/validate_report_dataset.py output/intelligence/report_context/BYCVSRV069.json

Les schémas, règles historiques, sources et limites sont documentés dans
docs/REPORT_DATASET.md. Les données absentes restent nulles ou UNKNOWN.

### Preuves techniques et événements

La couche Intelligence extrait également les composants, occurrences de
chemins, références scanner et événements d’audit présents dans les caches de
détail Hackuity. Elle produit components.parquet,
component_occurrences.parquet et finding_events.parquet.

    python scripts/enrich_finding_details.py --diagnostic --resume
    python scripts/enrich_finding_details.py --all --resume
    python scripts/build_report_dataset.py --all

Le diagnostic est limité à cinq findings. L’extraction complète conserve le
cache et la reprise existants. Voir docs/TECHNICAL_EVIDENCE.md pour les champs
réellement observés et les limites de corrélation.

## Sécurité et installation

L’ancienne clé exposée doit être révoquée immédiatement dans Hackuity. Ne la
réutilisez pas. Copiez `.env.example` vers `.env`, renseignez une nouvelle clé
et gardez `.env` hors Git.

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
Copy-Item .env.example .env
```

## Démarrage sur un petit échantillon

Ces commandes sont entièrement locales et n’appellent pas l’API :

```powershell
python scripts/inspect_hackuity_export.py --assets 5
python scripts/convert_existing_export.py --max-assets 10 --batch-size 1000
python scripts/extract_finding_ids.py --max-assets 10 --batch-size 1000
python scripts/build_silver_model.py
python scripts/build_gold_model.py
python scripts/validate_outputs.py
pytest
```

Après validation, supprimer ou déplacer uniquement les sorties de test, puis
relancer la conversion sans `--max-assets`. Le JSON source n’est jamais modifié.

## Exécution complète locale

```powershell
python scripts/convert_existing_export.py --batch-size 50000
python scripts/extract_finding_ids.py --batch-size 100000
python scripts/build_silver_model.py
python scripts/build_gold_model.py
python scripts/validate_outputs.py
```

## Enrichissement API

Une nouvelle clé est obligatoire. Toujours commencer par une limite :

```powershell
python scripts/enrich_finding_details.py --min-trs 900 --limit 100 --resume
python scripts/enrich_finding_details.py --min-trs 900 --limit 10000 --resume
```

Ne lancez l’enrichissement complet qu’après validation du rapport de
diagnostic, du mapping du détail et du volume d’appels.

Nouvelle extraction incrémentale de test :

```powershell
python scripts/extract_hackuity.py --hostname TESTHOST --max-assets 1 --resume
```

L’extracteur écrit des fichiers JSON compressés par asset, un manifeste et des
checkpoints. La reprise ignore les assets terminés. L’option
`--include-details` ne déclenche volontairement pas d’enrichissement massif :
utilisez le script dédié avec `--limit`.

## Orchestration

```powershell
python scripts/run_pipeline.py --skip-enrich
python scripts/run_pipeline.py --step inspect
python scripts/run_pipeline.py --step enrich
```

Arborescence :

```text
output/
  bronze/finding_details/
  bronze/incremental/
  silver/assets/
  silver/asset_findings/
  silver/finding_details/
  silver/*.parquet
  gold/*.parquet
  diagnostics/*.json
logs/hackuity_pipeline.log
```

Le mapping utilise des fallbacks documentés dans `hackuity_pipeline/core.py`.
La présence réelle de CVE, IP, CVSS et remédiation doit être confirmée dans
`output/diagnostics/export_schema_report.json`, puis avec un petit échantillon
de réponses de détail avant généralisation. Voir
`docs/powerbi_import.md` pour le modèle Power BI.

## Enrichissement détaillé et remédiation

L’enrichissement appelle l’endpoint suivant avec les quatre options de détail :

```text
GET /api/v1/namespaces/{namespace}/findings/{findingId}
withActiveProviderInfos=true
withSearchInfo=true
withAssessmentInfos=true
withTagsClearValues=true
```

Chaque réponse est enveloppée et conservée dans
`output/bronze/finding_details/{findingId}.json`. Un cache présent et valide est
ignoré ; `--force` impose un nouvel appel. Un cache invalide est retéléchargé.
Les erreurs structurées sont écrites dans
`logs/enrich_finding_details_errors.jsonl`.

Premier test recommandé :

```powershell
python scripts/enrich_finding_details.py --finding-id 1xhQYnqaueQC --force
python scripts/build_finding_details_silver.py
python scripts/build_remediation_gold.py
python scripts/validate_outputs.py --allow-missing
```

Échantillon prioritaire :

```powershell
python scripts/enrich_finding_details.py --status OPEN --min-hyscore 400 --limit 100 --resume
```

Options : `--limit`, `--offset`, `--min-hyscore`, `--status`,
`--only-cisa-kev`, `--finding-id`, `--force`, `--resume`, `--sleep`,
`--max-retries`, `--timeout`, `--input` et `--output-dir`. `--all-findings`
désactive volontairement la sélection prioritaire et nécessite une validation
explicite du volume.

Tables produites :

```text
output/silver/finding_details.parquet
output/silver/finding_cves.parquet
output/silver/finding_references.parquet
output/silver/finding_evidence_paths.parquet
output/silver/finding_versions.parquet
output/gold/remediation_findings.parquet
output/gold/remediation_summary.parquet
```

`remediation_findings.parquet` a pour granularité une combinaison
finding + CVE + chemin + composant/version. La table agrégée utilise la
remédiation explicite lorsqu’elle existe. À défaut, la clé est un regroupement
technique fondé sur provider, finding, composant et version attendue : il ne
s’agit pas d’une recommandation officielle.

Les preuves i18n brutes restent dans `providerEvidenceRaw`. Les chemins et
versions structurés sont des extractions tolérantes, initialement optimisées
pour Qualys. Une absence de donnée reste nulle et n’est jamais inventée.

L’orchestration n’appelle pas l’API de détail par défaut :

```powershell
python scripts/run_pipeline.py --skip-enrich
python scripts/run_pipeline.py --enrich-finding-details
```

Avec `--enrich-finding-details`, l’étape API est limitée par défaut à 100
findings prioritaires.
