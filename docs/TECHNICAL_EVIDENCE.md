# Hackuity Technical Evidence

## Endpoint confirmé

Le cache existant prouve l’utilisation de :

    GET /api/v1/namespaces/{namespace}/findings/{findingId}
      ?withActiveProviderInfos=true
      &withSearchInfo=true
      &withAssessmentInfos=true
      &withTagsClearValues=true

Cette réponse contient les informations des providers actifs, les attributs
scanner, QID, logiciels vulnérables, chemins, scores, MITRE ATT&CK et
findingAuditHistory. Le chemin applicatif finissant par /history est une URL
d’interface construite par le projet. Aucun endpoint API distinct pour cette
page n’a été prouvé localement.

## Données réellement observées

- assessmentsRelated.activeFindingProviderInfos : providerId, assessmentId,
  firstDetection, score initial et attributs étendus ;
- extendedAttributesList : QID, descriptions, solutions et CVE selon scanner ;
- vulnerableFilePaths : chemins techniques fournis par le scanner ;
- vulnerableSoftwares : vendor/product affectés ;
- searchFinding.mitreAttackTtps : identifiants MITRE tels que T1059 ;
- findingAuditHistory.info.atomInfos : auditId, at, trigger, providerId,
  assessmentType, statut déclaré, acteur et scores ;
- providerFindingHistory : état livré par les providers.

Les réponses locales ne contiennent pas toutes des versions installées/cibles
structurées. Elles restent nulles quand le texte ou le JSON ne les fournit pas.

## Parsing et provenance

La priorité est donnée aux objets JSON contenant package/component/product,
versions et chemin. Les tableaux scanner puis le texte labellisé sont utilisés
ensuite. Le texte n’est jamais fusionné de manière fuzzy.

Chaque composant ou occurrence conserve le finding, le scanner, les références,
le chemin du cache, son hash SHA-256 et la date de récupération. Lorsque
plusieurs composants et plusieurs chemins existent sans relation explicite, les
chemins sont conservés avec component_id nul plutôt que faussement attribués.

## Extraction à grande échelle

Le script existant prend désormais --all comme alias de --all-findings :

    python scripts/enrich_finding_details.py --all --resume

Le cache output/bronze/finding_details évite les rappels. Les options limit,
offset, sleep, max-retries et timeout restent disponibles. Le client existant
gère retry/backoff et les erreurs 429 sont tracées. Avant un volume complet :

    python scripts/enrich_finding_details.py --diagnostic --resume

Ce mode limite à cinq findings et affiche composants, versions, chemins,
références scanner et événements trouvés.
