# Skill: sync-all

Synchronise tous les repositories liés au projet secureCodeBox.

## Repositories

1. `/home/rvv/secureCodeBox` - Starter kit secureCodeBox
2. `/home/rvv/vuejs.secureCodeBox.Dashboard` - Dashboard Vue.js (frontend + backend)
3. `/home/rvv/go-wpscan-wpvuln-enricher` - Enrichisseur Go WPVuln
4. `/home/rvv/python-wpscan-wpvuln-enricher` - Enrichisseur Python WPVuln

## Instructions

Quand l'utilisateur invoque `/sync-all [message]`, effectue les actions suivantes :

### 1. Vérifier l'état de chaque repo

Pour chaque repository, exécute `git status --short` pour voir s'il y a des modifications.

### 2. Afficher un résumé

Affiche un tableau récapitulatif :
- Nom du repo
- Nombre de fichiers modifiés
- Fichiers non trackés

### 3. Demander confirmation

Montre à l'utilisateur les changements et demande confirmation avant de procéder.

### 4. Commit et push

Pour chaque repo avec des modifications :

```bash
cd <repo_path>
git add -A
git commit -m "<message>

Co-Authored-By: Claude <noreply@anthropic.com>"
git push
```

### 5. Rapport final

Affiche un résumé des commits effectués avec les SHA courts.

## Arguments

- `message` (optionnel) : Message de commit commun. Si non fourni, demander à l'utilisateur.

## Exemple d'utilisation

```
/sync-all "Ajout fonctionnalité templates de scan"
```

## Notes

- Ne jamais faire de force push
- Toujours demander confirmation avant de push
- Si un repo n'a pas de modifications, l'ignorer
- En cas d'erreur sur un repo, continuer avec les autres et signaler l'erreur à la fin
