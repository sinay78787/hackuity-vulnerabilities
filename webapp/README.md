# Démo locale Hackuity

Ouvrir `index.html` dans un navigateur. L’application est entièrement statique
et n’effectue aucun appel réseau.

Pour actualiser les données après reconstruction des tables Gold :

```powershell
python scripts/export_dashboard_data.py --gold-dir output/gold
```

Les définitions métier, sources et limites sont documentées dans
`METHODOLOGY.md`.
