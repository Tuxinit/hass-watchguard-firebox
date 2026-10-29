# hass-watchguard-firebox

<img src="custom_components/watchguard_firebox/brand/icon.png" width="96" align="right" alt="">

[![hacs_badge](https://img.shields.io/badge/HACS-Custom-41BDF5.svg)](https://github.com/hacs/integration)

Intégration Home Assistant pour les **WatchGuard Firebox** (Fireware 12.x), inspirée de [hass-pfsense](https://github.com/travisghansen/hass-pfsense).

pfSense expose une API XML-RPC locale ; Fireware n'a pas d'équivalent pour un Firebox géré localement. L'intégration utilise donc la **CLI Fireware en SSH (port 4118)**. Rien n'est à installer sur le Firebox.

Testée sur un Firebox T25, Fireware 12.12.3.

## Fonctionnalités (v0.1 — supervision seule)

| Entité | Source CLI | Activée par défaut |
|---|---|---|
| CPU 1 min / 5 min / 15 min | `show sysinfo` | 1 min seulement |
| Mémoire utilisée (%), libre, utilisée | `show sysinfo` | % seulement |
| Dernier démarrage (horodatage) | `show sysinfo` | oui |
| Version Fireware | `show sysinfo` | oui |
| État de chaque interface (binary_sensor connectivité) | `show interface` | oui, sauf les interfaces désactivées |
| Nombre d'entrées ARP | `show arp` | oui |
| Nombre de baux DHCP (+ détail par interface en attribut) | `show dhcp lease` | oui |
| Suivi de présence (`device_tracker`) par adresse MAC | `show arp` + `show dhcp lease` | appareils choisis dans les options |

L'intégration n'envoie aucune commande de configuration : elle ne fait que des `show`.

## Prérequis côté Firebox

1. **Compte dédié** : *System > Users and Roles*, créer un utilisateur `ha_monitor` (base Firebox-DB) avec le rôle **Device Monitor**. N'utilise pas `admin`.
2. **Accès restreint** : la policy *WatchGuard* (port 4118) doit autoriser `172.25.5.50` (IP de Home Assistant) vers *Firebox*, et rien de plus large depuis le VLAN domotique.

## Installation

1. HACS > menu ⋮ > *Dépôts personnalisés* > `https://github.com/Tuxinit/hass-watchguard-firebox`, catégorie **Intégration**.
2. Installer **WatchGuard Firebox**, puis redémarrer Home Assistant.
3. *Paramètres > Appareils et services > Ajouter une intégration > WatchGuard Firebox*.
4. Renseigner l'IP du Firebox, le port `4118` et le compte `ha_monitor`.

## Options

| Option | Défaut | Rôle |
|---|---|---|
| Intervalle de scrutation | 30 s | fréquence des `show` |
| Lire les baux DHCP | oui | désactive `show dhcp lease` si le Firebox ne fait pas le DHCP |
| Considérer présent pendant | 180 s | fenêtre glissante après la dernière vue ARP |
| Appareils à suivre | aucun | liste construite à partir des baux DHCP et de la table ARP |

## Sécurité

- **Clé d'hôte SSH (TOFU)** : l'empreinte SHA-256 de la clé du Firebox est mémorisée à l'ajout de l'intégration. Si elle change (reset usine, RMA… ou interception), la connexion est refusée et HA demande une ré-authentification, avec une case à cocher pour accepter explicitement la nouvelle clé.
- **Session persistante** : une seule session CLI est ouverte et réutilisée, pour éviter une connexion (et une ligne de log de management) toutes les 30 s. Elle est rouverte automatiquement en cas de coupure.
- **Diagnostics** : identifiants, numéro de série et MAC sont masqués dans l'export de diagnostic.

## Présence (device_tracker)

Même logique que hass-pfsense : un appareil est *home* si sa MAC apparaît avec une entrée ARP complète (pas `<incomplete>`) dans la fenêtre « considérer présent ». L'appareil doit donc parler au Firebox, ce qui est le cas de tout ce qui sort de son VLAN. Les entrées ARP du Firebox expirent après quelques minutes d'inactivité.

## Feuille de route

- [ ] Débits par interface (SNMPv3, compteurs IF-MIB 64 bits)
- [ ] État des tunnels VPN (`show vpn-status`)
- [ ] Utilisateurs authentifiés (`show users`)
- [ ] Services de sécurité : état et licences (`show features`)
- [ ] Actions optionnelles (compte admin) : redémarrage, activer/désactiver une policy, bloquer une IP

## Développement

```bash
pip install -r requirements_test.txt
pytest
```

Les tests rejouent des sorties CLI réelles (anonymisées) dans `tests/fixtures/` et testent le client SSH contre un faux serveur CLI Fireware.

## Licence

MIT
