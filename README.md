# GESTION PDV CI — version isolée compatible avec la conservation de systeme-d1

## Important : conservation des données
Cette version utilise la **même base D1 systeme-d1** mais crée des tables **pdv_*** distinctes. Les tables historiques (`users`, `sessions`, mouvements, etc.) ne sont **ni modifiées ni supprimées**. Les anciens comptes ne sont pas automatiquement transférés dans l’application PDV : ils restent disponibles dans leur application d’origine.

Le compte `mega@services.local` déjà présent dans `users` n'est pas automatiquement authentifié dans `pdv_users` : son ancien hash peut utiliser un algorithme incompatible. Il faut initialiser un compte Super Admin PDV distinct avec un nouveau mot de passe sécurisé.

## Déploiement (GitHub + Cloudflare Pages)
1. Sauvegarder/exporter la base D1 existante.
2. Publier les fichiers du ZIP dans un dépôt GitHub privé.
3. Associer Cloudflare Pages au dépôt ; dossier de sortie `public`.
4. Configurer les liaisons `SYSTEME_DB` (D1 systeme-d1) et `SYSTEME_KV` (KV existant).
5. Dans la console D1 **de systeme-d1**, exécuter **une seule fois et dans l'ordre** `migrations/0001_init.sql`, puis `0002_extended.sql`, puis `0003_controls.sql`. Ne pas rejouer les ALTER TABLE des migrations 0002/0003 sur une installation déjà initialisée.
6. Configurer en secrets Cloudflare `SUPERADMIN_EMAIL=mega@services.local`, `SUPERADMIN_INITIAL_PASSWORD` (nouveau mot de passe fort), `SESSION_PEPPER` (valeur aléatoire), `SETUP_TOKEN` (valeur aléatoire distincte). Configurer `ENABLE_INITIAL_SETUP=true` temporairement.
7. Faire un POST `/api/setup` avec l'en-tête `x-setup-token: <SETUP_TOKEN>` ; ne jamais publier ce jeton. Après succès, retirer `ENABLE_INITIAL_SETUP` et `SETUP_TOKEN`, puis redéployer.
8. Se connecter avec le nouveau mot de passe Super Admin PDV.

## Limitations et sécurité
- Cette version isole le système PDV de la base historique ; elle **ne migre pas** les comptes, opérations ou utilisateurs de l'ancien système. Une migration de données exige une cartographie complète des deux schémas.
- La présence des tables préfixées doit être vérifiée avant mise en service.
- Le projet reste un MVP et ne doit pas être utilisé en production pour des fonds réels sans audit de sécurité, tests d'intégration Cloudflare et sauvegardes.
- Ne jamais mettre de mots de passe ni secrets dans GitHub.
