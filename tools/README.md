# Inspection des Parquet

L’inspecteur est indépendant et ne modifie aucun dataset :

    python tools/inspect_parquets.py
    python tools/inspect_parquets.py --dataset findings
    python tools/inspect_parquets.py --hostname BYCVSRV069
    python tools/inspect_parquets.py --cve CVE-2019-17531
    python tools/inspect_parquets.py --finding 7x9iSLX3X2Jy

Les fichiers de smoke tests sont exclus par défaut. Les options --include-tests
et --json permettent respectivement de les inclure ou d’obtenir un rapport JSON.

# Export Excel autonome

Cet utilitaire est indépendant du pipeline Bronze/Silver/Gold. Il lit les
Parquet sans les modifier et écrit uniquement le classeur demandé.

```powershell
python -m pip install -r tools/requirements-excel.txt
python tools/export_parquet_to_excel.py
```

Pour Silver et Gold :

```powershell
python tools/export_parquet_to_excel.py output/gold output/silver --output exports/hackuity_complet.xlsx
```

Ajoutez `--overwrite` pour remplacer volontairement un classeur existant.
Les tables dépassant 1 048 575 lignes sont réparties sur plusieurs onglets.
