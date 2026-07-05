# Backup, restore and reset

One backup file captures the whole appliance. Combined with the two reset levels, it covers the situations a touring box actually meets: save before a tour leg, hand a configured rig to another operator, recover a dead SD card, or clone the setup onto a spare Pi.

## What a backup contains

The backup is a single versioned file holding everything the appliance was told:

- administrator accounts (including password hashes)
- all saved profiles with their scopes and pool plans, and which one is active
- host reservations
- switch-port pin labels

It does not contain the leases currently in flight (devices simply re-lease after a restore) or the operating system itself.

> [!IMPORTANT]
> The file includes credential hashes. Treat it like a key to the appliance and store it somewhere safe - and store it off the box: a backup that only exists on the SD card it is meant to protect is not a backup.

## Taking a backup

Settings, Backup, download. Take one after every configuration change that took effort to get right; the file is small and the habit is cheap.

## Restoring

Restore is offered in three places, one per situation:

| Where | When you use it |
| --- | --- |
| Settings | A running appliance that should go back to a known state |
| Setup wizard | A fresh or reset box, mid-onboarding, that should skip manual setup |
| Factory screen | Bare-metal recovery, before any account exists - a replaced SD card, a spare Pi, or a box that self-healed its database |

All three accept the same file. You choose which sections to restore (administrators, profiles and scopes, port labels, reservations); the selected sections replace what is on the box, unselected ones are left untouched. The factory screen is the one exception: a box with no accounts can only be recovered by a backup that includes its administrator section, and you sign in with the restored credentials afterwards. The control-plane sections are applied as a single transaction; host reservations are written to the DHCP server's database in a separate step afterwards, and the UI says so plainly if that step does not complete. The appliance then re-applies the restored configuration - a full restore ends in the same state the backup was taken in, and restoring an active profile brings DHCP up serving it.

A backup made by a newer appliance version is refused with a clear message; upgrade the appliance first, then restore.

## Routine reset vs factory reset

Both live in the Settings danger zone, both behind a confirmation:

**Routine End-of-Job Reset** tears down the show: the active profile, its scopes, all leases, and the job's reservations and port pins are removed, and the appliance returns to onboarding. The administrator account, saved profiles and switch-port labels survive, so re-pinning a known port keeps its name. This is the "load-out" button; the next event starts at the setup wizard with your profiles still on file.

**Hard Factory Reset** wipes everything: configuration, accounts, saved profiles, port labels, the audit log. The appliance drops straight back to the factory state, exactly as after a fresh install, onboarding access point included - no reboot involved. It asks for your current password before acting; the extra step is deliberate.

> [!CAUTION]
> A factory reset is not undoable from the appliance itself. The only way back is a backup file - take one first.

## Moving to a replacement Pi

The full recovery path, end to end:

1. [Install](install.md) the appliance on the new Pi and reboot it.
2. Connect via the onboarding access point or eth0 as in [First boot](first-boot.md).
3. On the factory screen, choose restore and upload your backup.

The new box comes up with the accounts, profiles and reservations of the old one and applies the active profile. Total time is dominated by the OS install, not the appliance.
