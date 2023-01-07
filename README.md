# CAA_encrypted_vault
Mini projet CAA

# Contraintes

- Pas de validation d’input
- En rust c’est bien
- L’attaquant ne peut pas modifier les données, mais il peut les lires
- Une authentification par entreprise
- Il n’y a pas d’autre mdp que ceux demandé pour l’authentification, donc pas de cookies ou autre
- On ne doit pas envoyé le mdp au serveur → on ne fait pas confiance au serveur
    - Tous les chiffrements se font côté client
    - Le serveur ne doit pas connaître le noms des fichiers. Ils peut éventuellement connaître le nombre
- Une clé diffrente par fichier ❗Mais un seul mdp
- Comment les clé sont dérivées ? où sont-elles stockées ?

# Lib util Rust pour la crypto

- sodium-oxyde
- dryoc

# A mentionner dans le rapport

- C’est okay de ne pas faire de revocation des users mais il faut expliquer que c’est possible de le faire dans le rapport. Si un user part de l’entreprise il faut retirer des shards pour tous le monde