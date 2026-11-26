# Wartet auf dich — die Startseite des Cockpits

Stand 26.11.2026 (t_432807ea, verschlankt mit t_74f5f6e1, Entscheidungskarte t_b73103ef). Gilt für das VPS- und das
Lab0-Cockpit (gleicher Code).

Nach dem Login zeigt das Cockpit nur eine Liste: Jochens Aufgaben, also alles, was er entscheiden
muss — und sonst nichts. Terminals, Sitzungen, Runbooks, Zeitpläne, Borg-Zustand, Aufbewahrung und
Audits liegen hinter dem Knopf **Mehr** in der Kopfzeile; unter den Aufgaben steht nichts
Eingeklapptes mehr. Die Seite ist für das Handy gebaut: eine Spalte, Knöpfe über die volle Breite
und mindestens 52 px hoch.

## Was dort erscheint

| Karte | Quelle | Freigeben | Ablehnen |
|---|---|---|---|
| Änderung von James | `hermes-change`-Job in `blocked_user_approval` (Türsteher-Befund — auch Backups löschen oder eine Aufbewahrung unter der Untergrenze als X4 —, Risiko-Riegel, Update-Prüfer-Stopp, Plan-Policy) | `POST /api/hermes/jobs/:id/approval` | derselbe Weg mit `rejected` |
| Notfall-Durchlass | `hermes-change`-Job am offenen Circuit Breaker (`output.breaker`, noch ohne Plan): der Grund nennt die zählenden Jobs und wann der Breaker schließt; Frist = `breaker.approvalExpiresAt` | derselbe Weg: genau dieser Job wird geplant und geprüft wie jeder andere, nur der Breaker entfällt (Audit `hermes.change.breaker_override`) | derselbe Weg mit `rejected` |
| Freigabe | offener Eintrag in `approvals` (Runbook- und Agentenpläne) | `POST /api/approvals/:id/decision` | derselbe Weg mit `rejected` |
| Aufräum-Dienst | Lab0-Dienst `angehalten` nach einer Anomalie (Archive fehlen, die er nicht selbst entfernt hat), solange er für genau diese Anomalie keine Freigabe trägt (nach `freigeben` bleibt er bis zum Ende seines Laufs `angehalten`) | `POST /api/borg/retention/resume` (Grund ≥ 10 Zeichen, wie bisher) | `POST /api/inbox/retention/:anomalyId/keep`: der Dienst bleibt angehalten, die Karte verschwindet, ein Audit hält den Grund fest |

Eine Einstellung unter der Untergrenze, die Jochen selbst im Bereich „Backup retention" setzt,
fragt dort direkt nach seiner Freigabe — sie wartet auf niemanden und erscheint deshalb nicht als
Karte.

Auf der Startseite zeigt jede Karte nur **die Art** (Änderung von James, Freigabe,
Aufräum-Dienst), **die Frist** als Countdown, **die Absicht in einem Satz** und einen Knopf
**Details**. Erst „Details" öffnet einen Dialog (auf dem Handy bildschirmfüllend und selbst
scrollend, ab 40rem Breite ein Fenster in der Mitte; „✕", Escape oder ein Tipp daneben schließen
ihn). Der Dialog zeigt alles, was vorher direkt auf der Karte stand, und mehr:

- **die Absicht in einem Satz**, darunter **die ganze Absicht** (`intent`, bis 4000 Zeichen), wo
  der eine Satz sie nicht schon trägt (der erste Satz der vertrauenswürdigen Absicht des Jobs),
- **warum gestoppt wurde** (`policy.reason`),
- **die Befunde**: Titel, Garantie oder Klasse, Datei und Zeile (Update-Prüfer) bzw. Schritt und
  Zeile (Türsteher, `S3:L1`), Schwere; aufgeklappt die Begründung mit dem zitierten Code. Vom
  Türsteher nur die belegten Befunde — unbelegte verwirft er selbst, sie stoppen nichts.
- **die Zeiten**: angelegt, Frist als Uhrzeit und Countdown bis zum Ablauf des Envelopes
  (`envelope.expiresAt`, Vorgabe `COCKPIT_APPROVAL_TTL_MINUTES=30`) bzw. der Freigabe,
- **die Kennung** (Job-, Freigabe- oder Anomalie-Id),
- **Freigeben** und **Ablehnen**, beide erst mit einem Grund bedienbar.

**Der Grund ist Pflicht** — nicht nur in der Oberfläche: `POST /api/hermes/jobs/:id/approval` und
`POST /api/approvals/:id/decision` antworten ohne nicht-leeren `reason` mit 400.

Nichts offen: groß **„Nichts wartet auf dich"**, darunter eine Zeile mit dem letzten Lauf, dem Alter
des letzten Backups (aus `borg.status`, ohne neue Messung zu erzwingen) und dem freien Platz auf `/`.

## Entscheidungskarte (seit 26.11.2026, Karte t_b73103ef)

**Warum.** Jochen (26.11.2026): Die Jobbeschreibungen sind „sehr ausschweifend“, er kann sie kaum
bewerten. Ist-Zustand davor, gemessen an den echten Jobs 632345dd (VPS), b48b0e25 (Lab0), 30c82d1a
und c3d239b5 (box): Der Titel der Karte war der erste Satz der englischen Absicht des Auftraggebers
(„Switch the git origin of the cockpit checkout …“ bzw. „Zielzustand auf dem Box-Host (Proxmox), Karte
t_46caf5c5, Spec …“). Der Dialog zeigte die ganze Absicht samt JSON-Manifest (2676 bis 3136 Zeichen),
den Grund des Stopps auf Englisch mit Codes („S2:L3 …; S3:L5 …“) und die Befunde mit Klasse, Zeile und
englischer Begründung. Die Knöpfe standen unter all dem.

**Was jetzt oben steht.** Bei einem `hermes-change`-Job in `blocked_user_approval` steht oben im Dialog
die Entscheidungskarte auf Deutsch. Sie hat je Feld eine Zeile, die Schwere jedes Befunds kommt aus
den Daten des Prüfers, nicht vom Erklärer:

| Zeile | Inhalt | höchstens |
|---|---|---|
| Was · Wo | was passiert, ein Satz Alltagssprache · Host oder Netz | 120 · 60 Zeichen |
| Warum du gefragt wirst | **je belegtem Befund ein Satz**, in dessen Reihenfolge, dahinter die Schwere aus den Daten des Prüfers (schwer/mittel); ohne Befund (Risiko-Riegel, Plan-Policy) ein Satz aus dem Grund des Stopps | 120 je Satz |
| Schlimmstenfalls | der schlimmste realistische Effekt, wenn die Schritte laufen | 120 |
| Rückweg | ein Satz | 110 |
| Empfehlung | Freigeben, Ablehnen oder Einengen, mit Grund | 140 |

Direkt darunter stehen das Grund-Feld (eine Zeile) und die beiden Knöpfe nebeneinander, auch auf dem
Handy. Diese Leiste klebt am unteren Rand des Dialogs (`position: sticky`), so bleibt der Knopf auch bei
vielen Befunden ohne Scrollen sichtbar. Gemessen in Chromium (Headless-Shell 1148) mit den echten
Erklärer-Antworten zu den Jobs 632345dd (drei Befunde) und c3d239b5 (zwei Befunde): Bei 360 × 740 px
endet die Karte bei 560 bzw. 538 px, die Knöpfe bei 709 bzw. 687 px, ohne Scrollen und ohne seitlichen
Überlauf (Seitenbreite 360 px). Ein Stressfall mit sechs Befunden zu je 120 Zeichen hält die Knöpfe bei
724 px, die Karte scrollt darüber. Bei 1280 × 800 px steht der Dialog 768 px breit in der Mitte. Die
erste Messung mit 180 Zeichen je Zeile lag bei 902 px, deshalb sind die Grenzen jetzt kürzer. Ein Blick
auf dem echten Handy bleibt sinnvoll. Alles Weitere (Absicht im Wortlaut, ganze Absicht, Grund des Stopps, Befunde mit Codes und
zitierter Zeile, Zeiten, Kennung) steht eingeklappt unter „Alles Weitere“. Auf der Startseite trägt die
Karte den Satz „Was“ statt des ersten Satzes der Absicht.

**Wer sie schreibt.** Ein eigener Erklärer, keine Textbausteine: `apps/api/src/decision-card.ts`
(System-Prompt `DECISION_CARD_INSTRUCTIONS` mit drei Beispielen; die Schwere schreibt er nicht selbst, die Karte setzt sie aus den Daten) über dieselbe abgeschottete
Prüfrolle `safety` des Agent-Brokers (Claude Opus). Er liest den gespeicherten Job: Rolle der Instanz,
erklärte Wirkung und Risiko des Manifests, den Grund des Stopps, die belegten Befunde, die Absicht und
den geprüften Plan. Der Text des Auftraggebers geht nur als Daten hinein, jede Zeile hinter „| “ und
zwischen Markern mit Nonce. Er läuft im Hintergrund, sobald ein Job in `blocked_user_approval` endet,
und für Jobs, die schon ohne Karte warten, beim nächsten `GET /api/inbox`. Höchstens drei Versuche je
Job, zehn Minuten auseinander. Die Antwort des Jobs und `operatorLink` warten nicht auf ihn. Er kostet
einen Opus-Aufruf je Job, der auf Jochen wartet.

**Warum nicht der Türsteher selbst.** Der Türsteher (`host-run.ts`) und der Update-Prüfer bleiben
unverändert. Ein zusätzliches Antwortfeld in ihrem Prompt hätte ihre Prüfung ablenken können, und
ihre Antwortformate sind Teil der Tür (G-Garantien). Der Erklärer entscheidet nichts. Er ändert
weder Status noch Plan, Prüfung, Policy oder Envelope, sondern schreibt nur `output.decisionCard`.
Seinen Motor hält er auf der Karte (`decisionCard.engine`), nicht in `agentEngine`: Ein Rückfall bei
der Lesehilfe ist kein NOTBETRIEB des Jobs und darf im Verlauf, den der Türsteher liest, nicht als
einer erscheinen.

**Was der Code erzwingt (nicht der Prompt).**

- **Befunde werden nur umformuliert, nie gefiltert.** Die Antwort muss genau einen Satz W1..Wn je
  belegtem Befund tragen. Fehlt einer, kommt einer dazu oder steht einer doppelt, ist sie ungültig.
  Felder fehlen, Längen werden überschritten, ein Prüfcode (X1-X6, S2:L3, G1) steht oben, oder die
  Empfehlung beginnt nicht mit Freigeben/Ablehnen/Einengen samt Grund: auch dann ist sie ungültig
  (`parseDecisionCard`, Audit `hermes.decision_card.invalid`).
- **Gebunden an den Prüfstand.** `decisionCard.basis` ist der Hash über Befunde und Grund des Stopps.
  Beim Anzeigen prüft `validDecisionCard` Hash, Satzzahl und Schema erneut. Passt etwas nicht, fällt
  die Karte weg.
- **Fail closed zum Altverhalten.** Ohne gültige Karte (Erklärer läuft noch, scheiterte, Antwort
  ungültig, kein Agent-Broker) zeigt der Dialog genau die bisherige Ansicht. Die Befunde im Wortlaut
  bleiben in beiden Ansichten vollständig auf der Karte (`findings`).
- **Rückweg:** `COCKPIT_DECISION_CARD=off` in der Umgebung der API schaltet Erklärer und Karte ab.
  Nach einem Neustart der API zeigt die Startseite wieder die bisherige Ansicht, ohne neuen Build.

**Ehrliche Grenze.** Der Erklärer liest die Absicht des Auftraggebers mit. Eine manipulierte Absicht
kann Was oder Empfehlung färben. Sie kann aber keinen Befund verschwinden lassen und seine Schwere
nicht ändern (beides prüft der Code), und jeder Befund steht einen Tipp tiefer im Wortlaut. Die
Empfehlung ist Lesehilfe. Entscheiden tut Jochen, und das Schloss prüft wie vorher den Envelope.

**James' Seite:** `plugins/cockpit/warten.py` (Repo hermes-plugin-cockpit) gibt je Job eine Kurzzeile
aus. Bei `blocked_user_approval` nimmt sie den Grund aus `output.decisionCard`, die JSON-Zusammenfassung
kommt nur mit `--json`.

## Abgelaufene Frist: trotzdem freigeben (bis 72 h)

Seit 13.11.2026 (Karte t_36523a6a, Jochen: „Warum muss ich das immer freigeben?") bleibt ein Job,
dessen Envelope **nur** abgelaufen ist, freigebbar, solange er jünger als 72 h ist
(`REACTIVATION_MAX_AGE_HOURS`). Die Karte trägt dann `approvableAfterExpiry: true` und bietet
**Freigeben (Frist erneuern)** mit Pflichtgrund. `POST /api/hermes/jobs/:id/approval` (nur Jochens
Sitzung, Automation 403 wie immer) prüft den Envelope vollständig; ist der einzige Fehler
„execution envelope expired“ und war er nie freigegeben, signiert sie **denselben Inhalt** mit neuer
Frist neu (`renewExecutionEnvelope`) und gibt ihn in derselben Entscheidung frei — Audit
`hermes.change.approved_after_expiry` (alte Frist, `notAfter`) vor `hermes.change.approved`, im Job
`output.approval.afterExpiry`. Jede andere Abweichung (Signatur, Bindung, Plan, Prüfung, Policy,
Manifest) bleibt ein Stopp. Vorher hieß ein Ablauf „Neu bestellen lassen“: James bestellte neu, die
neue Prüfung stoppte am selben Befund, Jochen klickte zweimal für dieselbe Entscheidung (lab0-Job
dc8d47e3, 13.11.2026). Was der Host seit der Prüfung geändert hat, fangen die Prüfungen beim Lauf ab:
Self-Update vergleicht den geprüften Diff-Hash (65 bei Drift), der Tür-Helfer prüft Netz und
Snapshot beim Start.

## Abgelaufene Frist: „Neu bestellen lassen" (älter als 72 h)

Ist der Job älter als 72 h, ist der abgelaufene Envelope nicht mehr freigebbar (das prüft der
Server ohnehin). Die Karte sagt das deutlich und bietet statt Freigeben **Neu bestellen lassen**:

`POST /api/inbox/jobs/:id/reorder` (nur Jochens Sitzung, nie ein Automation-Token; nur wenn der
Envelope wirklich abgelaufen ist) schließt den alten Job endgültig (`blocked_policy`, mit
`output.reorder`), schreibt das Audit `hermes.change.reorder_requested` und listet den Wunsch
24 Stunden lang in `GET /api/inbox` unter `reorders` (Job-Id, Absicht, Notiz). James bestellt
dieselbe Absicht neu; die neue Bestellung wird frisch geplant, geprüft und signiert. Eine alte
Freigabe wird nie wiederverwendet. `reorders` zeigt einem Automation-Token nur Jobs seines eigenen
Kontos — die Absicht eines anderen Kontos wird nie zu James' Bestellung.

**Überziehende Tür-Läufe** (`attention`, seit 11.10.2026, `doc/setup/host-run.md` 3a): Ein
Schritt, der Zustand ändert (Pakete, GitLab, Migrationen, docker compose, Umschalten), wird am
Zeitlimit nie beendet. Überzieht er, listet `GET /api/inbox` den laufenden Job unter `attention`
(Job-Id, Absicht, `level`, Schritt, Meldung): `overrun` = läuft länger als geplant, `operator` =
harte Obergrenze (6 h) erreicht, jemand muss auf den Host sehen — beendet wird er trotzdem nicht.
Zu entscheiden gibt es nichts; James meldet es Jochen. Auch hier sieht ein Automation-Token nur
Jobs seines eigenen Kontos.

Kommt eine Freigabe knapp zu spät (letzte Sekunden des Countdowns, Handyuhr geht nach), schließt
die Freigabe-Route den Job wie bisher mit „execution envelope expired". Die Karte bleibt dann
stehen und bietet „Neu bestellen lassen"; die Route nimmt auch einen so geschlossenen Job an
(einmal).

Karte und Freigabe-Route lesen dieselbe Frist: `envelope.expiresAt`. „Abgelaufen" heißt nur ein
echter Ablauf: Die 409-Antwort trägt dann die Meldung „execution envelope expired", und nur darauf
schaltet die Karte auf „Abgelaufen". Jede andere Ablehnung (Signatur, Drift von Plan, Prüfung oder
Policy) kommt als „execution envelope validation failed" mit `envelopeErrors`; die Karte zeigt
diesen Grund und behält ihren Countdown — vorher stand dort auch bei Drift „Frist abgelaufen".

## Abgelaufene Frist: James reaktiviert (Frist neu, keine Freigabe)

Verpasst Jochen nur das Zeitfenster, muss der Plan nicht neu bestellt werden:
`POST /api/hermes/jobs/:id/reactivate` (James' Token mit genau diesem Scope, oder Jochens Sitzung)
gibt einem abgelaufenen Job eine neue Frist. **Reaktivieren ist kein Freigeben:**

- Es wirkt nur auf einen `hermes-change`-Job in `blocked_user_approval`, dessen Envelope
  abgelaufen ist, der nie entschieden (`approval`) und nie zur Neubestellung geschlossen
  (`reorder`) wurde. Läuft die Frist noch, ist er freigegeben, abgelehnt, gelaufen oder
  geschlossen: 409.
- Der Envelope wird vollständig gegen den Job geprüft (Signatur, Bindung, Intent, Plan,
  Türsteher-Urteil, Policy, Capabilities, Manifest) — nur die Frist nicht. Weicht etwas ab: 409
  mit `envelopeErrors`, Audit `hermes.change.reactivate_refused`, nichts ändert sich.
- Neu signiert wird **derselbe Inhalt** mit neuer Frist (`COCKPIT_APPROVAL_TTL_MINUTES`). Der
  neue Envelope trägt nie `operatorApproved` (`renewExecutionEnvelope` verweigert einen
  freigegebenen), `gatePassed` bleibt, wie er war (bei einem wartenden Job: nicht gesetzt). Der
  Job bleibt in `blocked_user_approval`; freigeben kann weiter nur Jochen über
  `POST /api/hermes/jobs/:id/approval`. Diese Route weist jedes Automation-Token mit 403 ab —
  auch eines, dem jemand ihren Scope gegeben hat.
- Türsteher und Risiko-Riegel laufen **nicht** erneut: Sie haben genau diesen Plan geprüft, und der
  Envelope bindet ihr Urteil per Hash. Was sie nicht sehen können, ist ein Host, der sich seit der
  Prüfung verändert hat. Deshalb die Grenze: höchstens **3** Reaktivierungen und nie über **72 h**
  seit Anlage des Jobs (die letzte Frist wird an dieser Grenze abgeschnitten). Mit der Live-Frist
  von 24 h reicht das über ein Wochenende; danach ist der geprüfte Stand zu alt — dann
  „Neu bestellen" bzw. James bestellt neu.
- Jede Reaktivierung steht im Job (`output.reactivations`: wann, wer, alte und neue Frist) und im
  Audit `hermes.change.reactivated` (`count`, `maxCount`, alte/neue Frist, `notAfter`) — im
  selben Audit-Pfad wie `hermes.change.approved`/`rejected`. Die Antwort enthält `operatorLink`,
  damit James Jochen den Link erneut schickt.

Eine Freigabe, die knapp zu spät kam, hat den Job schon geschlossen (`blocked_policy`); der lässt
sich nicht reaktivieren, nur neu bestellen.

Eine abgelaufene **Plan-Freigabe** aus `approvals` (Runbook- oder Agentenplan aus der
Oberfläche, nicht von James) lässt sich nicht neu bestellen: Die Karte sagt, den Lauf unter
„Mehr" neu zu planen, und erlaubt nur noch Ablehnen.

## Hinweis an Jochen über James (Telegram)

**Befunde über ohnehin gesperrten Plänen** (`reviewFindings`, seit 11.10.2026,
`doc/setup/host-run.md` „Freigabe-Matrix“): Meldet die Prüfung vor einem Selbstupdate oder
`dienste.update` einen echten Befund, ist der Plan aber schon `blocked_prerequisite` oder
`blocked_policy`, gibt es nichts freizugeben. Trotzdem listet `GET /api/inbox` den Job sieben Tage
lang unter `reviewFindings` (Job-Id, Status, Zeit, Absicht, Befunde mit Titel, Garantie, Datei).
James meldet ihn Jochen. Auch hier sieht ein Automation-Token nur Jobs seines eigenen Kontos.

**Gewählt: James holt, das Cockpit schickt nichts.** Das Cockpit bekommt keinen Telegram-Bot-Token
und keinen Webhook — es braucht damit kein neues Geheimnis und keine ausgehende Verbindung.

1. **James' eigene Jobs (der Hauptfall):** Endet ein Job in `blocked_user_approval`, liefert das
   Cockpit in der Job-Antwort (`GET /api/hermes/jobs/:id` und die fertige Antwort von
   `POST /api/hermes/runbook`) das Feld `operatorLink`, z. B.
   `https://<cockpit>/#karte-job-<id>`. James sieht diese Antwort ohnehin (`cockpit_auftrag`,
   `cockpit_einblick was=job`) und schickt den Link per Telegram an Jochen. Dafür ist **kein**
   neuer Scope und kein neuer Schlüssel nötig.
2. **Alles andere** (Freigaben aus `approvals`, Anomalie des Aufräum-Dienstes, `reorders`, `attention`, `reviewFindings`): James
   liest `GET /api/inbox` mit seinem bestehenden Automation-Token, sobald Jochen diesem Token den
   Scope `GET /api/inbox` gibt (bei der nächsten Rotation über `plugins/cockpit/schluessel.py`).
   Das ist eine Berechtigung, kein neues Geheimnis. Ein Automation-Token sieht dort nur die Jobs
   seines eigenen Kontos und kann weiterhin nichts freigeben.

Warum nicht das Cockpit selbst schicken lassen: Ein Bot-Token im Cockpit wäre ein neues Geheimnis
auf dem Host, und Telegram läuft bei James ohnehin schon. Home Assistant hätte dasselbe Problem
(Token). Der Weg über James nutzt nur, was schon da ist.

Die Basisadresse für den Link setzt `COCKPIT_WEB_URL` (kein Geheimnis, z. B.
`http://10.0.0.1:5173`). Ohne sie ist der Link relativ (`/#karte-job-<id>`).

Der Direktlink öffnet das Cockpit; nach dem Login springt die Seite zur Karte, hebt sie hervor und
öffnet gleich ihre Details.
Ist sie schon entschieden, steht dort „Die verlinkte Karte wartet nicht mehr".

**Noch offen auf James' Seite** (nicht Teil dieses Repos): im Skill `cockpit` den `operatorLink`
bei `blocked_user_approval` an Jochen weiterreichen; optional ein Cron, der `GET /api/inbox` liest
und für neue Karten bzw. `reorders` meldet.

## Korrektur am Freigabeweg

Bis zu diesem Stand suchte `POST /api/hermes/jobs/:id/approval` die Laufzeit-Sitzung mit der
Kennung des **freigebenden** Admins. James' Jobs liegen aber in Sitzungen seines
Automation-Kontos — eine Freigabe durch Jochen endete deshalb in `blocked_prerequisite`
(„executor runtime is unavailable"), ohne dass etwas lief. Jetzt sucht die Route die Sitzung des
Auftraggebers (`jobOwnerId`), an den auch der Envelope gebunden ist. Schloss, Türsteher und Risiko-Riegel
bleiben unverändert: Der Envelope wird genauso geprüft wie vorher.

## Eigene Bestellung zurückziehen (James, seit 18.10.2026)

Jochen (18.10.2026): „Wenn du den Job bestellt hast, fände ich das Abbrechen eigentlich ok.“
`POST /api/hermes/jobs/:id/withdraw` mit Body `{ "reason": "<warum>" }` (James' Token mit genau
diesem Scope). **Zurückziehen ist kein Ablehnen:** Der Besteller nimmt seine Bestellung zurück; über
einen Plan entscheidet weiter nur Jochen über die Freigabe-Route.

- Nur das Automation-Konto, nur der **eigene** Job (Besitzer = anfragende Token-Identität), nur
  `hermes-change`/`hermes-research`. Fremder Job: 403 (Audit `hermes.job.withdraw_refused`);
  Jochens Sitzung: 403 — er lehnt ab.
- Nur solange auf dem Host nichts lief: `pending`, `pending_approval`, `blocked_user_approval`,
  `blocked_policy`, `blocked_prerequisite` oder `running` in den Phasen `queued`/`planning`/
  `reviewing`. Nie mit einer Entscheidung (`approval`) und nie nach einem angestoßenen Tür-Lauf
  (`hostRunRequestedAt`/`hostRunStartedAt`). Alles andere (ausführend, fertig, abgelehnt,
  fehlgeschlagen, schon zurückgezogen): 403.
- Grund Pflicht (400 ohne). Ergebnis: Status `withdrawn` (endgültig), `output.withdrawal` (wann,
  wer, Grund, vorheriger Status/Phase), Audit `hermes.job.withdrawn`. Zählt nicht zum Circuit
  Breaker. Die Karte verschwindet aus „Wartet auf dich"; die Job-Zeitleiste zeigt
  „zurückgezogen von James: <Grund>".
- Ein Job, der beim Zurückziehen noch plant oder geprüft wird, läuft im Hintergrund zu Ende,
  schreibt aber nichts mehr in den Job und startet nichts: `updateHermesJob` lässt einen
  `withdrawn`-Job unverändert, und vor dem Start der Ausführung wird ohne `await` dazwischen
  geprüft. Eine späte Freigabe Jochens auf einen zurückgezogenen Job endet mit 409.

## API

| Route | Wer | Was |
|---|---|---|
| `GET /api/inbox` | Sitzung; Automation nur mit Scope | `cards` (je `hermes-change`-Karte mit gültiger Entscheidungskarte zusätzlich `decision`), `status` (`lastRuns`, `backup`, `disk`), `reorders`, `attention`, `reviewFindings`, `generatedAt` |
| `POST /api/hermes/jobs/:jobId/reactivate` | James' Token mit Scope, oder Sitzung | abgelaufenen, nie entschiedenen Job mit neuer Frist versehen (keine Freigabe; max. 3×, max. 72 h) |
| `POST /api/hermes/jobs/:jobId/withdraw` | James' Token mit Scope (nur Automation) | eigenen Job zurückziehen, solange auf dem Host nichts lief; Body `{ reason }` (Pflicht); Status `withdrawn` |
| `POST /api/inbox/jobs/:jobId/reorder` | Sitzung (nicht Automation) | abgelaufenen Job schließen, Neubestellung anmelden; Body `{ note? }` |
| `POST /api/inbox/retention/:anomalyId/keep` | Admin-Sitzung | Anomalie ablehnen = angehalten lassen; Body `{ reason }` |

## Tests

- `apps/api/test/inbox.test.ts` — Karten aus Job, Freigabe und Anomalie; Befunde (nur belegte);
  Frist und Sortierung; Sichtbarkeit je Rolle; `operatorLink`; Neubestellen nur abgelaufen und
  nicht per Token; Pflichtgrund.
- `apps/api/test/decision-card.test.ts` — Auftrag an den Erklärer mit jedem belegten Befund in
  Reihenfolge (unbelegte nicht), Text des Auftraggebers nur als Daten; Schema: fehlender, zusätzlicher
  oder doppelter Befund-Satz, fehlendes Feld, Überlänge, Prüfcode, Empfehlung ohne Grund → ungültig;
  veraltete Karte (Befunde geändert) oder falsche Satzzahl → bisherige Ansicht; Befunde bleiben auf der
  Karte; im App-Lauf: Karte im Hintergrund, Status/Prüfung/Envelope/`agentEngine` unberührt, ungültige
  Antwort → Audit und bisherige Ansicht, entschiedener Job bekommt keine Karte mehr, Schalter `off`
  ruft keinen Erklärer.
- `apps/api/test/reactivate.test.ts` — Reaktivieren nur abgelaufen und unentschieden, gleicher
  Envelope-Inhalt, nie `operatorApproved`, Obergrenzen (Anzahl, 72 h), Drift stoppt, keine
  Selbstfreigabe per Token.
- `apps/api/test/withdraw.test.ts` — Zurückziehen nur eigener, noch nicht laufender Jobs; fremd,
  laufend, entschieden, fertig: 403; Grund Pflicht; Freigabe-Route bleibt für Tokens 403; späte
  Freigabe auf einen zurückgezogenen Job: 409.
- `apps/api/test/host-run-flow.test.ts` — James bestellt mit seinem Token, Jochen gibt als Admin
  frei, der Lauf startet in James' Sitzung (vorher: `blocked_prerequisite`).
- `apps/web/src/Inbox.test.tsx` — Startseite nur mit Art, Frist, Absicht und „Details" (kein
  Grund, keine Befunde, kein Knopf zum Entscheiden), Dialog je Karte (öffnen, ganze Absicht,
  Kennung, schließen mit ✕ und Escape), Countdown, Zustandszeile, Knöpfe erst mit Grund, Befunde
  ausklappbar, „Neu bestellen lassen", Anomalie, Fehleranzeige, Direktlink; Handyansicht über die
  tragenden CSS-Regeln (eine Spalte zuerst, Knöpfe ≥ 44 px, nichts breiter als 360 px, Dialog
  bildschirmfüllend) und die Lesereihenfolge im Dialog. jsdom rechnet kein Layout; gemessen wurde
  zusätzlich in Chromium bei 360 × 740 px (kein Element breiter als der Bildschirm, Knöpfe 52 px,
  ✕ 45 px) und 1280 px (Dialog 768 px mittig). Ein Blick auf dem echten Handy bleibt sinnvoll.
- `apps/web/src/Inbox.test.tsx`, Block „Entscheidungskarte“: Startseite mit dem Satz „Was“, im Dialog
  Was/Wo, je Befund ein Satz mit Schwere, Schlimmstenfalls, Rückweg, Empfehlung, keine Codes oben,
  dann Grund-Feld und Knöpfe, „Alles Weitere“ eingeklappt mit allen Befunden im Wortlaut und der
  Kennung; ohne Karte die bisherige Ansicht; Entscheidungsleiste klebend, Knöpfe nebeneinander (CSS-Regeln).
- `apps/web/src/App.test.tsx` — Startseite zeigt „Wartet auf dich", der Rest ist hinter „Mehr"
  zu; Freigaben laufen über den Dialog der Karte mit Grund.
