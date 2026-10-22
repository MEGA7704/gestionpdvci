# MEGA TRÉSORERIE PRO — prototype technique GitHub / Cloudflare Pages

**Statut : socle MVP incomplet, non prêt pour une exploitation financière réelle.**

Inclus : inscription entreprise, connexion serveur avec cookie HttpOnly, sessions, rôles de base, PDV, services, portefeuilles, dépôts/retraits avec écriture double, historique paginé et première interface responsive.

**Non inclus** : initialisation de fonds, création/affectation des agents, correction avec approbation, contrôle de caisse, clôture, PDF, abonnements et paiements, demandes de fermeture, migration d'anciens comptes, récupération de mot de passe, restriction d'historique par agent, audit complet, verrouillage par IP séparé et robustesse production. Ne pas déployer en exploitation avant ces ajouts et un audit de sécurité.

## Déploiement
1. Décompresser puis publier les fichiers à la racine d'un dépôt GitHub privé.
2. Créer un projet Cloudflare Pages avec intégration GitHub, sans framework ni commande de build, répertoire de sortie `public`.
3. Configurer les bindings D1 `SYSTEME_DB` et KV `SYSTEME_KV` selon `wrangler.toml`.
4. Appliquer la migration **sur une base vide ou après vérification et sauvegarde de la base existante** : `npx wrangler d1 execute systeme-d1 --remote --file=./migrations/0001_init.sql`.
5. Ajouter les secrets `SUPERADMIN_EMAIL`, `SUPERADMIN_INITIAL_PASSWORD`, `SESSION_PEPPER` dans les paramètres Cloudflare Pages (le mot de passe initial doit comporter au moins 12 caractères). Ne jamais les publier.
6. Après déploiement, effectuer une requête POST vers `/api/setup` pour initialiser une seule fois le Super Admin. La route ne doit pas rester publiquement accessible en production ; la désactiver après initialisation.
7. Vérifier le routage du Worker, les bindings et les logs avant toute utilisation.

## Avertissements
Le fichier `public/_worker.js` contient actuellement des fonctions expérimentales. Le endpoint de login utilise une limitation combinée IP/e-mail et non les deux limites indépendantes demandées. Les mouvements sont transactionnels, mais la protection d'idempotence n'est pas encore implémentée. Le contrôle d'accès par rôle doit être étendu à toutes les routes de lecture. L'inscription publique n'a pas encore de contrôle anti-abus. Les pages de l'interface ne couvrent pas toutes les fonctions du cahier des charges.

## Mise à jour 0002
Appliquer **dans l'ordre** `migrations/0001_init.sql` puis `migrations/0002_extended.sql` via Cloudflare D1 (une seule fois chacune). Ne pas réexécuter 0002 après application. Configurer `SYSTEME_DB`, `SYSTEME_KV`, `SUPERADMIN_EMAIL`, `SUPERADMIN_INITIAL_PASSWORD` (12 caractères minimum) et `SESSION_PEPPER`. Pour initialiser le Super Admin, configurer temporairement `ENABLE_INITIAL_SETUP=true`, appeler POST `/api/setup`, puis **retirer immédiatement** cette variable. Ne pas mettre ces secrets dans GitHub.

## Limitations connues — ne pas utiliser en production financière
Cette version enrichie est une **préversion de développement**. Le code n'a pas été déployé ni testé sur votre compte Cloudflare. Ne pas saisir de données réelles ou effectuer de mouvements réels avant audit indépendant. Modules restant à terminer : approbation par mot de passe des corrections, contre-écritures, clôtures journalières, vérification des soldes physiques, PDF professionnels, expiration Free 2 jours, demandes de fermeture, réinitialisation des mots de passe, vérification de paiement, mécanisme de protection contre la concurrence multi-écriture à éprouver, autorisation par entreprise pour chaque route, limitation de connexion IP et email séparément, migrations de credentials historiques, validation exhaustive des entrées et tests d'intégration. Les rapports actuels sont des impressions navigateur et non des PDF générés serveur. Les approvisionnements sont des crédits de fonds externes sans compte source interne et doivent être rapprochés manuellement.

## Modules complémentaires (migration 0003)

Appliquer **dans l'ordre** `migrations/0001_init.sql`, `0002_extended.sql`, puis `0003_controls.sql` à la base D1, après sauvegarde. Ne pas réappliquer `0002_extended.sql` sur une base où ses colonnes existent déjà (SQLite ALTER TABLE ADD COLUMN n'est pas idempotent).

### Fonctionnalités ajoutées
- Clôture journalière par PDV avec montants constatés, écarts par compte et blocage serveur de nouvelles écritures du jour.
- Demandes de correction, approbation/rejet avec vérification du mot de passe administrateur et contre-écriture financière atomique. Une contre-écriture qui rendrait un solde négatif est refusée.
- Changement de mot de passe personnel et réinitialisation des agents par l'admin ou des admins par le superadmin, avec vérification du mot de passe du responsable, révocation des sessions et journalisation.
- Rapport A4 paysage professionnel, impression navigateur vers PDF (aucune génération PDF binaire côté serveur).
- Tests SQL et vérifications statiques : `python -m unittest discover -s tests -v`.

### Initialisation Super Admin
Configurer `SUPERADMIN_EMAIL`, `SUPERADMIN_INITIAL_PASSWORD`, `SESSION_PEPPER`, `SETUP_TOKEN` comme secrets Cloudflare Pages. Mettre temporairement `ENABLE_INITIAL_SETUP=true` dans les variables d'environnement ; appeler `POST /api/setup` avec l'en-tête `x-setup-token` contenant le secret `SETUP_TOKEN`. Désactiver ensuite `ENABLE_INITIAL_SETUP` et retirer `SETUP_TOKEN`. Ne jamais publier ces secrets. Choisir un mot de passe initial d'au moins 12 caractères.

### Limites importantes avant production
Ce projet n'a pas été validé sur un déploiement Cloudflare réel. La fonction « mot de passe oublié » avec envoi d'un lien vérifié par e-mail n'est pas encore intégrée : seules les réinitialisations par un responsable authentifié et le changement personnel sont disponibles. Les exports PDF passent par le navigateur. Les abonnements et les fonctions historiques du projet nécessitent des tests de bout en bout. Les rapports sont plafonnés à 5 000 mouvements et ne constituent pas encore un état comptable rapproché complet. Les soldes d'ouverture injectés comme approvisionnements ne sont pas équilibrés par un compte source. La règle de clôture utilise la date UTC (Côte d'Ivoire). Ne pas exploiter ce logiciel avec des fonds réels sans audit de sécurité indépendant, tests d'intégration, restauration de sauvegarde et rapprochement financier.
