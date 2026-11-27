# Jochens Ja per Telegram für Klasse A (Box; Selbstupdates auf VPS und Lab0)

Stand 26.11.2026, Karte t_1e9bc441; Selbstupdates seit 27.11.2026, Karte t_efc1d03e (Abschnitt
„Klasse A für Selbstupdates“). Code: `apps/api/src/telegram-approval.ts`, Klasse-A-Frage des
Türstehers in `apps/api/src/host-run.ts` (`HOST_RUN_CLASS_A`), gemeinsame Entscheidung mit der
Freigabe-Route in `apps/api/src/app.ts` (`decideChange`). Tests: `apps/api/test/telegram-approval.test.ts`.

## Entscheidung

Jochen (26.11.2026, Telegram): „Und das mit dem Ja von mir für Häkchen und Co machen wir auch.“
Für eine eng umrissene, harmlose Klasse genügt sein Ja aus Telegram als Freigabe; der Klick im
Cockpit entfällt. Alles andere bleibt beim Cockpit-Klick wie bisher. Die Klasse zu erweitern ist
Jochens Entscheidung.

**Klasse A** (Startumfang, nur auf der Box): Der Lauf legt eine Wegwerf-VM oder einen Wegwerf-Container
im Proxmox-Pool `werkstatt` an, ändert, startet, stoppt oder entfernt ihn, oder er richtet einen Port
bzw. Dienst nur innerhalb von `vmbr1` ein (Werkstatt-Netz, nur NAT). Alle Schnittstellen hängen an
`vmbr1`, und es entsteht kein Weg ins Heimnetz, ins WG-Netz, zum Box-Host, zu Lab0 oder zu
VPS-Diensten. Jeder geänderte Gast ist durch den Proxmox-Snapshot des Laufs gedeckt oder wird von ihm
neu angelegt, und der Plan nennt einen konkreten Rückweg. Der Lauf berührt nichts sonst: keinen
anderen Gast, den Box-Host nicht (keine Firewall-Regel, kein Paket, keine Unit, kein Nutzer, keine
Rechte, kein Speicher), keine Cockpit-Datei, kein Geheimnis und keinen Tresor-Wert, keine Backups
oder Snapshots (außer neuen) und keine Produktiv- oder Familiendaten.

Nicht Klasse A, also weiter Cockpit-Klick: alles auf VPS und Lab0 außer geprüften Selbstupdates
(Abschnitt unten), Änderungen am Box-Host (auch eine
DNAT- oder Firewall-Regel auf `wg0`), Backups löschen, prune oder compact, Rechte, Geheimnisse und
Netze außerhalb von `vmbr1`. Der Port auf `wg0` aus t_46caf5c5 (Job c3d239b5) fällt deshalb **nicht**
unter Klasse A: Er ist eine Host-Regel mit einem Weg ins WG-Netz.

## Abweichung vom Kartentext und warum

Der Kartentext sah vor, dass das Hermes-Gateway die Kanalmetadaten von Jochens Nachricht signiert und
das Cockpit diese Signatur prüft. Das hält Entscheidung 3 der Karte nicht: Ein Agent kann den Beleg
weder schreiben noch zitieren. Gateway und Agenten laufen im selben Container unter derselben uid
(1007). Den Schlüssel, mit dem das Gateway signieren würde, könnte also jeder Agent lesen und
nachmachen. Das ist dieselbe Grenze wie beim Zweitprüfungs-Marker
(`doc/setup/self-update.md`, Variante C) und beim Tresor-App-Passwort (Ehrliche Grenze in Skill `cockpit`).

Was ein Agent nicht nachmachen kann, ist Telegram selbst: Wer in einem Chat einen Knopf drückt,
bestätigt Telegram mit der Nutzer-ID des Kontos. Darum spricht das Cockpit **mit einem eigenen Bot**
direkt mit Jochen:

- Das Cockpit schickt das Angebot selbst und baut den Text aus seinem eigenen Job-Datensatz:
  Absicht, Plan, Urteil des Türstehers, Begründung für Klasse A, Prüfsumme und Frist. Vorgang,
  Absicht und Plantitel stammen von James bzw. dem Planer und sind im Text als „Angabe“
  gekennzeichnet; Urteil, Klasse und Prüfsumme setzt das Cockpit. Was freigegeben wird, ist
  immer der geprüfte Plan hinter der Prüfsumme, nicht der Text.
- Das Cockpit liest den Tipp selbst über `getUpdates`, nur ausgehend und ohne Webhook. Es gibt
  keinen Pfad über James und keine Agentenausgabe.
- Der Bot-Token liegt in `/etc/wireguard-ops-cockpit/telegram.env` (root 0600). Weder die
  Agent-Units des Cockpits noch der Hermes-Container sehen ihn. Die API nimmt ihn beim Start aus
  ihrer Prozessumgebung (`apps/api/src/index.ts`), damit Kindprozesse (Türsteher, tmux) ihn
  nicht erben.

Damit kehrt sich die Entscheidung aus `wartet-auf-dich.md` um, nach der das Cockpit keinen
Telegram-Token bekommt. Das gilt nur für diesen Zweck und nur auf der Instanz, auf der er eingeschaltet
ist. Für alles andere bleibt es dabei: James schickt den `operatorLink`.

Für Jochen ist der Ablauf derselbe Handgriff wie gewünscht, ein Ja in Telegram. Es ist aber ein
Knopf im Chat des Cockpit-Bots, nicht ein Text an James. Ein „ja“ als Nachricht wird nie gelesen,
die Abfrage holt nur Knopfdrücke (`allowed_updates: callback_query`). So gibt es kein
Ja-Erkennen per Muster.

## Ablauf

1. Ein Host-Lauf auf der Box endet in `blocked_user_approval` (Befund des Türstehers oder
   Risiko-Riegel). Der Türsteher hat auf der Box zusätzlich die Zeilen `CLASS_A: yes|no` und
   `CLASS_A_WHY:` geschrieben. Sein Urteil über VERDICT und Befunde ändert das nicht.
2. Alle 15 s prüft die API die wartenden Jobs. Ein Job wird angeboten, wenn **jede** dieser
   Bedingungen gilt (`classAEligibility`). Andernfalls passiert nichts, und der Cockpit-Klick bleibt
   der Weg.
   - Instanzrolle `box`. Job `hermes-change` in `blocked_user_approval`, Policy-Status ebenso.
   - Host-Tür: `hostRun` vorhanden, Capabilities genau `["host.run"]`. Kein Capability-Manifest,
     kein Paket, keine Dateien aus geprüften Repos, kein Breaker, kein Update-Review.
   - Der Türsteher hat vollständig geprüft. Er wurde nicht vom Sicherheitsfilter gestoppt
     (`safetyStops` 0), es gab keinen Fehler, und sein Urteil lautet `pass` oder `flag`.
   - Alle Befunde sind `X3`, auch solche, die mangels Beleg verworfen wurden.
   - Das erklärte Risiko ist nur `contained` oder `exposure`.
   - Der Türsteher hat genau einmal `CLASS_A: yes` geschrieben. Fehlt die Zeile, steht sie doppelt
     oder ist sie unklar, gilt „no“.
   - Der Envelope ist gültig: Signatur, Bindung an Job, Besitzer und Sitzung, keine Abweichung, nicht
     abgelaufen und noch nicht freigegeben.
3. Das Cockpit schickt Jochen (Chat = seine Nutzer-ID) eine Nachricht ohne Formatierung mit einem
   Knopf „✅ Freigeben“. Gespeichert werden in `telegram_offers`:
   - der Hash einer zufälligen Einmal-Nonce (18 Byte),
   - Chat und Nachrichten-ID,
   - der Hash des Nachrichtentexts, den Telegram zurückgab,
   - die Bindung über den geprüften Inhalt des Envelopes (Job, Besitzer, Sitzung, Intent, Belege,
     Plan, Prüfung, Policy, Capabilities, Manifest),
   - die Frist: 30 min, nie länger als die Frist des Envelopes.

   Audit `hermes.change.telegram_offered`. `GET /api/hermes/jobs/:id` zeigt `telegramOffer`, damit
   James den Link nicht doppelt schickt.
4. Jochen tippt. Das Cockpit gibt nur frei, wenn alles stimmt:
   - Der Knopf trägt eine bekannte Nonce.
   - Absender ist Jochens Nutzer-ID und kein Bot.
   - Chat und Nachrichten-ID sind die des Angebots.
   - Die Nachricht ist unbearbeitet (kein `edit_date`) und ihr Text-Hash ist gleich.
   - Das Angebot ist unbenutzt und das Fenster offen.
   - Der Job ist weiter Klasse A, der Envelope gültig und die Bindung unverändert.

   Danach wird das Angebot atomar als benutzt markiert. Die Entscheidung läuft durch **dieselbe**
   Funktion wie der Klick in der Oberfläche (`decideChange`) und kommt von Jochens
   Operator-Konto (`COCKPIT_ADMIN_USERNAME`). Neu signiert wird dabei nichts, auch nicht nach
   Fristablauf. Audit `hermes.change.approved` mit `via: {channel: "telegram", fromId, messageId,
   offerId, class: "A"}`, am Job `output.approval.via`.
5. Jede Abweisung schreibt `hermes.change.telegram_refused` mit Grund, Absender-ID und
   Nachrichten-ID. Jochen sieht einen Hinweis („Nicht freigegeben: … Im Cockpit entscheiden.“).
   Eine Abweisung verbraucht das Angebot nicht. Der echte Tipp und der Cockpit-Klick bleiben
   möglich.

Protokolle enthalten nie den Token. Fehler der Bot-API nennen nur Methode und HTTP-Status, nie die
URL, denn in ihr steckt der Token.

Ablehnen geht weiter im Cockpit (der Link steht in der Nachricht) oder durch Verfallenlassen.

## Klasse A für Selbstupdates (VPS und Lab0)

Entscheidung Jochen 26.11.2026 (auf die Frage, ob Klasse A auch für Selbstupdates auf VPS und Lab0
gelten soll: „Was glaubst du was ich will“, gelesen als Ja im engsten Umfang; „Ich will nur
freigegeben was ich wirklich muss“). Karte t_efc1d03e, Analyse t_c5858d13 Abschnitt 6c.

Anlass: Ein Selbstupdate, dessen PR die Opus-Zweitprüfung trägt, stoppt trotzdem für Jochen, wenn die
Prüfung vor der Installation einen belegten schweren Rechte-Befund (G1, G2, G4) meldet
(Schweregrad-Schnitt, `self-update.md`, „Second review“). Das ist meist genau die Änderung, zu der
Jochen schon Ja gesagt hat (PR #128: „neuer Freigabeweg“). Bisher hieß das ein Cockpit-Klick je
Instanz.

Auf VPS und Lab0 bietet das Cockpit einen solchen Job über seinen eigenen Bot an, wenn **jede** dieser
Bedingungen gilt (`selfUpdateEligibility`, alles gespeicherte Fakten, die das Cockpit selbst
geschrieben hat; fehlt eine, passiert nichts):

- Instanzrolle `vps` oder `lab0`. Auf der Box bleibt das Selbstupdate beim Klick (Box-Host).
- Job `hermes-change` in `blocked_user_approval`, Policy-Status ebenso; Capabilities genau
  `["self.update"]`, kein Host-Lauf, kein Capability-Manifest, kein Breaker. Envelope gültig, nicht
  abgelaufen, noch nicht freigegeben.
- Der Plan wäre ohne die Prüfung gelaufen (`updateReview.planAllowed`, gesetzt in `app.ts` vor
  `applyUpdateReviewPolicy`). Die Plan-Sicherheitsprüfung lautet `passed`, ohne Filter-Stopp. Damit
  bleiben Plan-Policy, nicht erlaubte Capability, `shell.exception` und Ähnliches beim Klick.
- Die Prüfung vor der Installation ist vollständig (keine Lücke, kein `UNVERIFIABLE`, kein
  Prüferfehler, alles gesehen) und endet mit Befund, nicht als Meldung.
- Für **jeden** installierten Commit hat das Cockpit selbst auf GitHub belegt (`verifySecondReview`,
  `secondReviewCovers`): Merge eines PR nach `main` des Repos mit der festen Repo-ID, Baum gleich dem
  geprüften Head, Marker `Cockpit-Zweitpruefung: FREIGABE <head-sha> opus` für genau diesen Head von
  einem Konto mit Schreibrecht. Ein anderer Head, ein fehlender Marker, ein Marker eines anderen
  Modells, ein Fremdkonto oder ein anderes Repo: kein Angebot.
- Jeder Befund nennt eine Garantie und sein zitierter Code steht im geprüften Diff
  (`quoteFound`). Keiner nennt G6 (Geheimnisse) oder G10 (Backups), keiner ist `INJECTION`.
- Jeder installierte Diff (Basis, Commit, Diff-Hash) ist an den signierten Envelope gebunden.

Text, Knopf, Prüfung des Tipps, Bindung, 30-min-Fenster, einmalige Verwendung, Abweisungen und
Protokoll sind dieselben wie oben. Das Angebot nennt Stand und PR der Zweitprüfung und jeden Befund
(Garantie, Schwere, Titel, Datei); Freitext aus dem Job geht geschwärzt hinaus (`redactSecrets`, G6).
Am Job steht `output.approval.via.scope: "self-update"`.

Bleibt beim Klick: Backups (G10), Geheimnisse (G6), `INJECTION`, unvollständige Prüfung, Befunde,
deren Zitat nicht im Diff steht, alles, was schon die Plan-Policy stoppt, Host-Läufe auf VPS und Lab0
(auch X2 außerhalb geprüfter Selbstupdates) und alles auf dem Box-Host. Ein Ja im Chat an James ist
nie eine Freigabe: Das Cockpit liest nur Knopfdrücke seines eigenen Bots.

**Ein Knopf je Instanz, nicht einer für alle drei.** Jede Instanz hat ihren eigenen Bot und gibt nur
ihre eigenen Jobs frei. Ein gemeinsamer Bot geht nicht: Telegram liefert jeden Knopfdruck nur an
einen Abholer (`getUpdates`), und eine Instanz, die für eine andere freigibt, bräuchte Vertrauen
zwischen den Instanzen, das es absichtlich nicht gibt (Lab0 vertraut dem VPS nicht, der borg-Schlüssel
des VPS ist dort nur append-only). Jochen tippt also bei einem Selbstupdate auf VPS und Lab0 je
einmal im Chat des jeweiligen Bots, statt sich je Instanz im Cockpit anzumelden und zu klicken.

Einführung: Das Selbstupdate, das diese Regel bringt, prüft noch die alte Fassung; es stoppt deshalb
für den Klick (eine neue Regel kann ihre eigene Einführung nicht freigeben).

## Einrichten (einmalig, nur Jochen)

Je Instanz ein eigener Bot (Box, VPS, Lab0), also die Schritte je Instanz, auf dem jeweiligen Host.


1. In Telegram bei @BotFather `/newbot` aufrufen, etwa „Cockpit Box“, und den Token notieren. Den
   Token nicht an James geben.
2. Den neuen Bot öffnen und `/start` senden. Erst dann darf er Jochen schreiben.
3. Auf der Box als root die Datei anlegen (0600, root:root; der nächste Deploy setzt die Rechte
   ohnehin):

   ```
   install -m 0600 -o root -g root /dev/stdin /etc/wireguard-ops-cockpit/telegram.env <<'EOF'
   COCKPIT_TELEGRAM_APPROVAL=on
   COCKPIT_TELEGRAM_BOT_TOKEN=<Token von BotFather>
   COCKPIT_TELEGRAM_OPERATOR_ID=8156515098
   EOF
   systemctl restart wireguard-ops-cockpit-api
   ```
4. Nachweis: `GET /api/health` → `security.telegramApproval: true`.

Fehlt eine Angabe oder hat sie eine falsche Form (Schalter nicht `on`, Token nicht im Format der
Bot-API, Nutzer-ID nicht numerisch), ist die Freigabe aus. Ebenso ohne bekannte Instanzrolle
(`instance-role.env`). Auf der Box gilt nur die Werkstatt-Klasse, auf VPS und Lab0 nur die
Selbstupdate-Klasse.

## Schalter und Rückweg

- Aus: in `telegram.env` `COCKPIT_TELEGRAM_APPROVAL=off` setzen oder die Datei entfernen, dann die
  API neu starten. Offene Angebote werden danach nicht mehr gelesen. Ein späterer Tipp bewirkt
  nichts, und der Cockpit-Klick bleibt.
- Sofort und ohne Host: Jochen sperrt den Bot in Telegram oder widerruft den Token bei @BotFather
  (`/revoke`). Dann scheitern Senden und Lesen, und es bleibt der Cockpit-Klick.
- Code: Revert des PR und Self-Update auf den Stand davor. Die Tabelle `telegram_offers` stört den
  alten Stand nicht.

## Ehrliche Grenzen

- Ob ein Lauf Klasse A ist, urteilt der Türsteher (Opus) nach der Definition oben. Ein Fehlurteil
  „yes“ bei einem harmlos wirkenden Lauf führt zu einem Angebot. Dagegen stehen die strukturellen
  Bedingungen: Jeder andere Befund als X3, jedes Risiko jenseits von `exposure`, Pakete, geprüfter
  Code und ein Filter-Stopp schließen ihn aus. Außerdem sieht Jochen das Urteil im Text, bevor er
  tippt.
- Wer root auf der Box hat, kann den Token lesen. Das ist dieselbe Grenze wie bei allen Dateien in
  `/etc/wireguard-ops-cockpit`. Ein Host-Lauf, der die Datei liest, ist ein X1-Befund des Türstehers.
- Telegram selbst ist Vertrauensanker. Wer Jochens Telegram-Konto übernimmt, kann Klasse-A-Läufe
  freigeben, aber nichts darüber hinaus.
- Selbstupdates (VPS, Lab0): Den Zweitprüfungs-Marker kann ein Agent mit dem Owner-Token selbst setzen
  (Variante C, `self-update.md`). Der Marker ist deshalb nur die Bindung an genau den geprüften Head,
  kein zweiter Prinzipal. Die Freigabe bleibt Jochens eigener Tipp, nachdem er Stand, PR und jeden
  Befund im Angebot gesehen hat. Was das Cockpit dabei nicht abnimmt, bleibt beim Klick (G6, G10,
  `INJECTION`, Lücken, Zitate außerhalb des Diffs).
