#!/usr/bin/env python3
"""
Biblioteca Aeterna — backend Flask.
DB: PostgreSQL (psycopg 3)
Auth: bcrypt + cookie di sessione firmato (nessuna libreria esterna di auth)

Questo file SOSTITUISCE il vecchio app.py di "RBBC PWA / La biblioteca di
Babele". Non è una migrazione: il vecchio backend era quasi interamente
scraping delle reti bibliotecarie lombarde (OPAC DiscoveryNG) via curl+regex,
completamente estraneo alla nuova app — Biblioteca Aeterna cerca i libri
direttamente su Open Library dal browser (vedi index.html, funzione
searchAlexandria), quindi il backend non deve più fare da proxy di ricerca.

Cosa NON c'è più rispetto al vecchio app.py, e perché:
  - RETI / scraping OPAC / get_biblioteche / cerca_titolo → non pertinenti:
    niente più "biblioteca fisica di riferimento", niente più reti bibliotecarie.
  - tabelle "letti" + "salvati" separate → unificate in una sola tabella
    "libreria" con uno stato ('in_lettura' | 'letto' | 'desiderio'), perché
    così ragiona il nuovo frontend (vedi aeterna_libreria in index.html).
  - tabella "diario_note" (Memoriae, diario personale libero) → non esiste
    più una sezione "Memoriae" nella nuova app; al suo posto c'è "Agorà",
    che però è un forum PUBBLICO condiviso tra utenti, non un diario privato:
    richiede quindi tabelle nuove (discussioni/risposte), non un adattamento
    di diario_note.
  - tabella "badge" → i traguardi del Pantheon ora si calcolano interamente
    lato client dai dati reali della libreria (vedi ACHIEVEMENTS in
    index.html): nessuno stato "sbloccato" da persistere, quindi nessuna
    tabella dedicata.

Cosa è rimasto identico, di proposito, perché già testato e funzionante:
  - lo scheletro get_db()/close_db()/init_db() con ALTER TABLE IF NOT EXISTS
    per le migrazioni incrementali.
  - login_richiesto come decorator, utente_corrente() via sessione.
  - bcrypt per l'hash password, stesso schema di validazione.
  - il flusso di reset password via email (stessa logica, testi aggiornati).

IMPORTANTE — nessuna migrazione automatica dei dati: gli account e le
letture del vecchio "La Biblioteca di Babele" NON vengono trasferiti qui.
Gli schemi sono troppo diversi (biblioteca fisica + rete bibliotecaria da
un lato, stato di lettura libero dall'altro) perché un mapping automatico
abbia senso. Se serve conservare qualcosa del vecchio DB, va fatto a mano,
caso per caso.
"""

import os
import re
import secrets
import smtplib
from datetime import datetime, timedelta, timezone
from email.mime.text import MIMEText
from functools import wraps

import bcrypt
import psycopg
from flask import Flask, g, jsonify, request, session
from flask_cors import CORS
from psycopg.rows import dict_row

app = Flask(__name__, static_folder="static", static_url_path="")
app.secret_key = os.environ.get("SECRET_KEY", "cambia-questa-chiave-in-produzione")

# CORS con credenziali: necessario perché il frontend (index.html) può
# essere servito da un'origine diversa dal backend e usa fetch(...,
# {credentials:'include'}) implicito via cookie di sessione. flask-cors,
# quando supports_credentials=True, riflette automaticamente l'Origin della
# richiesta invece di mandare "*" (che i browser rifiuterebbero comunque
# insieme a un cookie) — stesso comportamento del vecchio app.py.
CORS(app, supports_credentials=True)

# In produzione dietro HTTPS il cookie di sessione deve avere SameSite=None
# + Secure per funzionare cross-site. In sviluppo locale su http:// questo
# combina male (i browser scartano i cookie Secure su http), quindi si può
# disattivare con FLASK_ENV=development.
IS_DEV = os.environ.get("FLASK_ENV") == "development"
app.config.update(
    SESSION_COOKIE_SAMESITE="Lax" if IS_DEV else "None",
    SESSION_COOKIE_SECURE=not IS_DEV,
)

# ── EMAIL (reset password) ──────────────────────────────────────────────
EMAIL_MITTENTE      = os.environ.get("EMAIL_MITTENTE", "biblioteca.aeterna@gmail.com")
SMTP_HOST           = os.environ.get("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT           = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER           = os.environ.get("SMTP_USER", EMAIL_MITTENTE)
SMTP_PASSWORD       = os.environ.get("SMTP_PASSWORD", "")  # App Password, non la password dell'account
FRONTEND_URL        = os.environ.get("FRONTEND_URL", "https://biblioteca-aeterna.example.com")
RESET_TOKEN_TTL_MIN = 30

def invia_email_reset(destinatario, nome, token):
    """Invia l'email col link di reset password. Se SMTP_PASSWORD non è
    configurata (es. in sviluppo locale), logga il link invece di fallire:
    utile per testare il flusso senza una vera casella email."""
    link = f"{FRONTEND_URL}/?reset={token}"
    corpo = (
        f"Ciao {nome},\n\n"
        f"Hai richiesto di reimpostare la password del tuo account su "
        f"Biblioteca Aeterna. Clicca sul link qui sotto per sceglierne una "
        f"nuova (valido per {RESET_TOKEN_TTL_MIN} minuti):\n\n"
        f"{link}\n\n"
        f"Se non hai richiesto tu il reset, ignora pure questa email: la tua "
        f"password attuale resta invariata.\n\n"
        f"— Biblioteca Aeterna\n"
        f"{EMAIL_MITTENTE}"
    )
    msg = MIMEText(corpo, "plain", "utf-8")
    msg["Subject"] = "Reimposta la tua password — Biblioteca Aeterna"
    msg["From"]    = EMAIL_MITTENTE
    msg["To"]      = destinatario

    if not SMTP_PASSWORD:
        app.logger.warning(
            "invia_email_reset: SMTP_PASSWORD non configurata, email NON inviata. "
            "Link di reset (solo per debug/sviluppo): %s", link
        )
        return False
    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.sendmail(EMAIL_MITTENTE, [destinatario], msg.as_string())
        return True
    except Exception:
        app.logger.exception("invia_email_reset: errore nell'invio a %s", destinatario)
        return False

# ── Database ─────────────────────────────────────────────────────────────

def get_db():
    if "db" not in g:
        g.db = psycopg.connect(os.environ["DATABASE_URL"], row_factory=dict_row)
    return g.db

@app.teardown_appcontext
def close_db(e=None):
    db = g.pop("db", None)
    if db:
        db.close()

def init_db():
    with psycopg.connect(os.environ["DATABASE_URL"]) as db:
        with db.cursor() as cur:

            cur.execute("""
                CREATE TABLE IF NOT EXISTS utenti (
                    id SERIAL PRIMARY KEY,
                    email VARCHAR(255) UNIQUE NOT NULL,
                    nome VARCHAR(255) NOT NULL,
                    password VARCHAR(255) NOT NULL,
                    obiettivo_annuale INTEGER NOT NULL DEFAULT 12,
                    creato_il TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                );
            """)

            # Libreria personale: un solo stato per libro per utente, come
            # nel frontend (aeterna_libreria). book_id è testo libero perché
            # può venire sia dal catalogo curato di Lapides Miliarii (es.
            # "hamlet") sia da una ricerca Open Library (es. "ol:/works/OL...").
            cur.execute("""
                CREATE TABLE IF NOT EXISTS libreria (
                    id SERIAL PRIMARY KEY,
                    utente_id INTEGER NOT NULL REFERENCES utenti(id) ON DELETE CASCADE,
                    book_id TEXT NOT NULL,
                    stato VARCHAR(16) NOT NULL CHECK (stato IN ('in_lettura','letto','desiderio')),
                    titolo TEXT NOT NULL,
                    autore TEXT NOT NULL DEFAULT '',
                    anno INTEGER,
                    cover TEXT,
                    aggiornato_il TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE (utente_id, book_id)
                );
            """)

            # Sfide di lettura accettate: solo l'id della sfida (i target e
            # le descrizioni restano lato frontend, in CHALLENGES — stesso
            # principio dei traguardi del Pantheon, calcolati sui dati reali
            # invece che persistiti come "sbloccati").
            cur.execute("""
                CREATE TABLE IF NOT EXISTS sfide_accettate (
                    id SERIAL PRIMARY KEY,
                    utente_id INTEGER NOT NULL REFERENCES utenti(id) ON DELETE CASCADE,
                    sfida_id VARCHAR(64) NOT NULL,
                    accettata_il TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE (utente_id, sfida_id)
                );
            """)

            # Agorà: forum pubblico, condiviso tra tutti gli utenti (a
            # differenza di libreria/sfide, che sono private). L'autore è
            # salvato sia come nome "congelato" al momento della pubblicazione
            # (autore_nome) sia come riferimento all'utente (utente_id), utile
            # se in futuro servirà collegare un profilo cliccabile.
            cur.execute("""
                CREATE TABLE IF NOT EXISTS discussioni (
                    id SERIAL PRIMARY KEY,
                    utente_id INTEGER NOT NULL REFERENCES utenti(id) ON DELETE CASCADE,
                    autore_nome TEXT NOT NULL,
                    titolo TEXT NOT NULL,
                    corpo TEXT NOT NULL,
                    creato_il TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                );
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS risposte (
                    id SERIAL PRIMARY KEY,
                    discussione_id INTEGER NOT NULL REFERENCES discussioni(id) ON DELETE CASCADE,
                    utente_id INTEGER NOT NULL REFERENCES utenti(id) ON DELETE CASCADE,
                    autore_nome TEXT NOT NULL,
                    testo TEXT NOT NULL,
                    creato_il TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                );
            """)

            # Motore economico (Aurei + XP/livello + streak) — trasversale a
            # tutte le feature di gamification future: oggi lo alimenta solo
            # Ephemeris, domani anche Tabellarium/Epistolarium/Atelier. Un
            # solo record per utente, niente storico delle transazioni: se
            # servirà davvero (es. un "estratto conto" in Scriptorium) si
            # aggiungerà una tabella a parte, per ora sarebbe complessità
            # senza una vista che la usi.
            cur.execute("""
                CREATE TABLE IF NOT EXISTS economia (
                    utente_id INTEGER PRIMARY KEY REFERENCES utenti(id) ON DELETE CASCADE,
                    aurei INTEGER NOT NULL DEFAULT 0,
                    xp INTEGER NOT NULL DEFAULT 0,
                    streak_giorni INTEGER NOT NULL DEFAULT 0,
                    ultimo_giorno TIMESTAMP
                );
            """)

            # Ephemeris: una riga per utente per giorno solare (UTC), così
            # "hai già risposto oggi?" è una semplice UNIQUE invece di dover
            # tenere uno stato a parte.
            cur.execute("""
                CREATE TABLE IF NOT EXISTS ephemeris_risposte (
                    id SERIAL PRIMARY KEY,
                    utente_id INTEGER NOT NULL REFERENCES utenti(id) ON DELETE CASCADE,
                    giorno DATE NOT NULL,
                    opzione_scelta INTEGER NOT NULL,
                    corretto BOOLEAN NOT NULL,
                    aurei_guadagnati INTEGER NOT NULL,
                    creato_il TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE (utente_id, giorno)
                );
            """)

            # Reset password: token monouso con scadenza (stessa logica del
            # vecchio app.py).
            cur.execute("""
                CREATE TABLE IF NOT EXISTS reset_password (
                    id SERIAL PRIMARY KEY,
                    utente_id INTEGER NOT NULL REFERENCES utenti(id) ON DELETE CASCADE,
                    token VARCHAR(64) UNIQUE NOT NULL,
                    creato_il TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    scade_il TIMESTAMP NOT NULL,
                    usato BOOLEAN NOT NULL DEFAULT FALSE
                );
            """)

init_db()

# ── Helpers auth ─────────────────────────────────────────────────────────

def utente_corrente():
    uid = session.get("uid")
    if not uid:
        return None
    return get_db().execute("SELECT * FROM utenti WHERE id=%s", (uid,)).fetchone()

def login_richiesto(fn):
    @wraps(fn)
    def wrapper(*a, **kw):
        if not utente_corrente():
            return jsonify({"error": "Non autenticato", "login_required": True}), 401
        return fn(*a, **kw)
    return wrapper

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

def _utcnow():
    """now() in UTC ma "naive" (senza tzinfo): datetime.utcnow() è deprecato
    da Python 3.12, ma le colonne TIMESTAMP di Postgres (non TIMESTAMPTZ)
    restituiscono comunque datetime naive — per confrontarle correttamente
    serve restare naive anche qui, non passare ad oggetti timezone-aware."""
    return datetime.now(timezone.utc).replace(tzinfo=None)

# ── Motore economico (Aurei / XP / Livelli / Streak) ────────────────────
# Scheletro pensato per essere "chiamato" da più feature senza che queste
# sappiano nulla di come i livelli sono calcolati: oggi solo Ephemeris usa
# accredita_economia(), domani lo faranno anche Tabellarium/Epistolarium.
# I nomi dei livelli sono provvisori (vedi documento "Sistema di Valuta ed
# Esperienza") — le soglie XP sono una prima stima da tarare quando ci
# saranno più fonti di XP oltre a Ephemeris.

LIVELLI = [
    (0,   "Discepolo"),
    (50,  "Scriba"),
    (200, "Philosophus"),
    (500, "Custode della Biblioteca"),
]

def livello_da_xp(xp):
    titolo = LIVELLI[0][1]
    for soglia, nome in LIVELLI:
        if xp >= soglia:
            titolo = nome
    return titolo

def get_o_crea_economia(db, utente_id):
    row = db.execute("SELECT * FROM economia WHERE utente_id=%s", (utente_id,)).fetchone()
    if row:
        return row
    db.execute("INSERT INTO economia (utente_id) VALUES (%s) ON CONFLICT DO NOTHING", (utente_id,))
    db.commit()
    return db.execute("SELECT * FROM economia WHERE utente_id=%s", (utente_id,)).fetchone()

def accredita_economia(db, utente_id, aurei=0, xp=0, nuovo_streak=None):
    """Accredita aurei/xp (sempre in aggiunta a quelli esistenti) ed
    eventualmente aggiorna lo streak (valore assoluto, se fornito — non
    incrementale, perché la logica di quando resettarlo/incrementarlo
    dipende dalla feature chiamante, non da questa funzione generica).
    Ritorna la riga aggiornata."""
    get_o_crea_economia(db, utente_id)
    if nuovo_streak is None:
        db.execute(
            "UPDATE economia SET aurei=aurei+%s, xp=xp+%s WHERE utente_id=%s",
            (aurei, xp, utente_id)
        )
    else:
        db.execute(
            "UPDATE economia SET aurei=aurei+%s, xp=xp+%s, streak_giorni=%s, "
            "ultimo_giorno=CURRENT_TIMESTAMP WHERE utente_id=%s",
            (aurei, xp, nuovo_streak, utente_id)
        )
    db.commit()
    return db.execute("SELECT * FROM economia WHERE utente_id=%s", (utente_id,)).fetchone()

def _serializza_economia(row):
    return {
        "aurei": row["aurei"],
        "xp": row["xp"],
        "livello": livello_da_xp(row["xp"]),
        "streak_giorni": row["streak_giorni"],
    }

# ── API Auth ─────────────────────────────────────────────────────────────

@app.route("/api/auth/registra", methods=["POST"])
def registra():
    d = request.get_json() or {}
    email    = (d.get("email") or "").strip().lower()
    nome     = (d.get("nome") or "").strip()
    password = d.get("password") or ""

    if not email or not nome or not password:
        return jsonify({"error": "Tutti i campi sono obbligatori"}), 400
    if not EMAIL_RE.match(email):
        return jsonify({"error": "Email non valida"}), 400
    if len(password) < 6:
        return jsonify({"error": "La password deve avere almeno 6 caratteri"}), 400

    pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    db = get_db()
    try:
        cur = db.execute(
            "INSERT INTO utenti (email, nome, password) VALUES (%s, %s, %s) RETURNING id",
            (email, nome, pw_hash)
        )
        uid = cur.fetchone()["id"]
        db.commit()
    except Exception as e:
        db.rollback()
        if "duplicate key" in str(e).lower():
            return jsonify({"error": "Email già registrata"}), 409
        app.logger.exception("registra: errore inatteso")
        return jsonify({"error": "Errore durante la registrazione"}), 500

    session["uid"] = uid
    session.permanent = True
    return jsonify({"ok": True, "nome": nome, "email": email, "obiettivo_annuale": 12})

@app.route("/api/auth/login", methods=["POST"])
def login():
    d = request.get_json() or {}
    email    = (d.get("email") or "").strip().lower()
    password = d.get("password") or ""
    u = get_db().execute("SELECT * FROM utenti WHERE email=%s", (email,)).fetchone()
    if not u or not bcrypt.checkpw(password.encode(), u["password"].encode()):
        return jsonify({"error": "Email o password errati"}), 401
    session["uid"] = u["id"]
    session.permanent = True
    return jsonify({
        "ok": True, "nome": u["nome"], "email": u["email"],
        "obiettivo_annuale": u["obiettivo_annuale"],
    })

@app.route("/api/auth/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify({"ok": True})

@app.route("/api/auth/me")
def me():
    u = utente_corrente()
    if not u:
        return jsonify({"autenticato": False})
    return jsonify({
        "autenticato": True,
        "nome": u["nome"],
        "email": u["email"],
        "obiettivo_annuale": u["obiettivo_annuale"],
    })

@app.route("/api/auth/password", methods=["POST"])
@login_richiesto
def cambia_password():
    u = utente_corrente()
    d = request.get_json() or {}
    password_attuale = d.get("password_attuale") or ""
    nuova_password   = d.get("nuova_password") or ""

    if not password_attuale or not nuova_password:
        return jsonify({"error": "Tutti i campi sono obbligatori"}), 400
    if not bcrypt.checkpw(password_attuale.encode(), u["password"].encode()):
        return jsonify({"error": "Password attuale non corretta"}), 401
    if len(nuova_password) < 6:
        return jsonify({"error": "La nuova password deve avere almeno 6 caratteri"}), 400

    pw_hash = bcrypt.hashpw(nuova_password.encode(), bcrypt.gensalt()).decode()
    db = get_db()
    db.execute("UPDATE utenti SET password=%s WHERE id=%s", (pw_hash, u["id"]))
    db.commit()
    return jsonify({"ok": True})

@app.route("/api/auth/password-dimenticata", methods=["POST"])
def password_dimenticata():
    """Risponde sempre allo stesso modo, anche se l'email non esiste:
    altrimenti l'endpoint diventerebbe un modo per scoprire quali email
    sono registrate (user enumeration)."""
    d = request.get_json() or {}
    email = (d.get("email") or "").strip().lower()
    msg_generico = {"ok": True, "message": "Se l'indirizzo è registrato, riceverai a breve un'email con le istruzioni."}
    if not email:
        return jsonify({"error": "Inserisci un'email"}), 400

    db = get_db()
    u = db.execute("SELECT * FROM utenti WHERE email=%s", (email,)).fetchone()
    if not u:
        return jsonify(msg_generico)

    token = secrets.token_urlsafe(32)
    scade_il = _utcnow() + timedelta(minutes=RESET_TOKEN_TTL_MIN)
    db.execute(
        "INSERT INTO reset_password (utente_id, token, scade_il) VALUES (%s, %s, %s)",
        (u["id"], token, scade_il)
    )
    db.commit()

    if not invia_email_reset(u["email"], u["nome"], token):
        app.logger.warning("password_dimenticata: invio email fallito per utente_id=%s", u["id"])
    return jsonify(msg_generico)

@app.route("/api/auth/reset-password", methods=["POST"])
def reset_password():
    d = request.get_json() or {}
    token          = (d.get("token") or "").strip()
    nuova_password = d.get("nuova_password") or ""

    if not token or not nuova_password:
        return jsonify({"error": "Dati mancanti"}), 400
    if len(nuova_password) < 6:
        return jsonify({"error": "La nuova password deve avere almeno 6 caratteri"}), 400

    db = get_db()
    row = db.execute("SELECT * FROM reset_password WHERE token=%s", (token,)).fetchone()
    if not row:
        return jsonify({"error": "Link non valido."}), 400
    if row["usato"]:
        return jsonify({"error": "Questo link è già stato utilizzato."}), 400
    if row["scade_il"] < _utcnow():
        return jsonify({"error": "Il link è scaduto. Richiedine uno nuovo."}), 400

    pw_hash = bcrypt.hashpw(nuova_password.encode(), bcrypt.gensalt()).decode()
    db.execute("UPDATE utenti SET password=%s WHERE id=%s", (pw_hash, row["utente_id"]))
    db.execute("UPDATE reset_password SET usato=TRUE WHERE id=%s", (row["id"],))
    db.commit()
    return jsonify({"ok": True})

# ── API Obiettivo di lettura ─────────────────────────────────────────────

@app.route("/api/obiettivo", methods=["POST"])
@login_richiesto
def imposta_obiettivo():
    u = utente_corrente()
    d = request.get_json() or {}
    try:
        obiettivo = int(d.get("obiettivo", 0))
    except (TypeError, ValueError):
        return jsonify({"error": "Valore non valido"}), 400
    if obiettivo < 1 or obiettivo > 9999:
        return jsonify({"error": "Valore non valido"}), 400
    db = get_db()
    db.execute("UPDATE utenti SET obiettivo_annuale=%s WHERE id=%s", (obiettivo, u["id"]))
    db.commit()
    return jsonify({"ok": True, "obiettivo_annuale": obiettivo})

# ── API Economia (Aurei / XP / Livello / Streak) ─────────────────────────

@app.route("/api/economia")
@login_richiesto
def get_economia():
    u = utente_corrente()
    row = get_o_crea_economia(get_db(), u["id"])
    return jsonify(_serializza_economia(row))

# ── Ephemeris (citazione del giorno + quiz) ──────────────────────────────
# Banco statico di domande, sul modello delle QUOTES già presenti nel
# frontend per la Citazione del Giorno: qui in più c'è una domanda a
# risposta multipla, la spiegazione da rivelare dopo, e un giro di Aurei.
# La selezione è deterministica per giorno solare (stesso seed usato da
# renderQuote() in index.html) così tutti vedono lo stesso enigma nello
# stesso giorno — nessuna tabella "domanda del giorno" da popolare a mano.
#
# NOTA: la "ricompensa doppia" del giorno 7 descritta nel documento di
# gamification è ambigua nel testo originale (doppia rispetto a cosa?).
# Qui è implementata come moltiplicatore x2 sulla base (quindi +20 invece
# di +10), applicato a ogni multiplo di 7 di streak consecutivo — è una
# scelta arbitraria per avere uno scheletro funzionante, da confermare o
# correggere quando si disegnerà per bene la ricompensa "Enigma Aureo".

EPHEMERIS_BANCO = [
    {
        "testo": "Tutte le famiglie felici si somigliano; ogni famiglia infelice è infelice a modo suo.",
        "domanda": "Da quale opera è tratto questo incipit?",
        "opzioni": ["Anna Karenina", "Guerra e pace", "Delitto e castigo", "I fratelli Karamazov"],
        "corretta": 0,
        "spiegazione": "È l'incipit di «Anna Karenina» di Lev Tolstoj (1877).",
    },
    {
        "testo": "È una verità universalmente riconosciuta che uno scapolo in possesso di una vistosa fortuna debba essere in cerca di moglie.",
        "domanda": "Chi ha scritto queste parole?",
        "opzioni": ["Charlotte Brontë", "Jane Austen", "George Eliot", "Elizabeth Gaskell"],
        "corretta": 1,
        "spiegazione": "È l'incipit di «Orgoglio e pregiudizio» (1813) di Jane Austen.",
    },
    {
        "testo": "Chiamatemi Ismaele.",
        "domanda": "Da quale romanzo è tratta questa celebre prima riga?",
        "opzioni": ["L'isola del tesoro", "Moby-Dick", "Robinson Crusoe", "Il vecchio e il mare"],
        "corretta": 1,
        "spiegazione": "È l'incipit di «Moby-Dick» (1851) di Herman Melville.",
    },
    {
        "testo": "Il paradiso, per me, ha sempre avuto la forma di una biblioteca.",
        "domanda": "Chi ha scritto questa celebre citazione?",
        "opzioni": ["Umberto Eco", "Italo Calvino", "Jorge Luis Borges", "Gabriel García Márquez"],
        "corretta": 2,
        "spiegazione": "È una citazione di Jorge Luis Borges, tratta da «Elogio dell'ombra».",
    },
    {
        "testo": "Molti anni dopo, davanti al plotone di esecuzione, il colonnello Aureliano Buendía si sarebbe ricordato di quel remoto pomeriggio in cui suo padre lo aveva condotto a conoscere il ghiaccio.",
        "domanda": "Da quale romanzo è tratto questo incipit?",
        "opzioni": ["L'amore ai tempi del colera", "Cent'anni di solitudine", "Cronaca di una morte annunciata", "Il generale nel suo labirinto"],
        "corretta": 1,
        "spiegazione": "È l'incipit di «Cent'anni di solitudine» (1967) di Gabriel García Márquez.",
    },
    {
        "testo": "Era la migliore e insieme la peggiore delle epoche.",
        "domanda": "Da quale romanzo è tratto questo celebre incipit?",
        "opzioni": ["Grandi speranze", "Oliver Twist", "Racconto di due città", "David Copperfield"],
        "corretta": 2,
        "spiegazione": "È l'incipit (nella traduzione italiana) di «Racconto di due città» (1859) di Charles Dickens.",
    },
    {
        "testo": "Qualcuno doveva aver calunniato Josef K., perché una mattina, senza che avesse fatto nulla di male, fu arrestato.",
        "domanda": "Da quale romanzo è tratto questo incipit?",
        "opzioni": ["La metamorfosi", "Il processo", "Il castello", "America"],
        "corretta": 1,
        "spiegazione": "È l'incipit de «Il processo» di Franz Kafka, pubblicato postumo nel 1925.",
    },
]

def ephemeris_di_oggi(giorno):
    seed = giorno.year * 10000 + giorno.month * 100 + giorno.day
    return EPHEMERIS_BANCO[seed % len(EPHEMERIS_BANCO)]

def _moltiplicatore_streak(streak):
    if streak >= 7:
        return 2.0
    if streak >= 3:
        return 1.5
    return 1.0

@app.route("/api/ephemeris/oggi")
def get_ephemeris_oggi():
    """Pubblico anche per gli ospiti: possono leggere la domanda, ma senza
    account non ha senso accreditare aurei/streak a nessuno, quindi il
    frontend mostra le opzioni come cliccabili solo se loggato. Se l'utente
    ha già risposto oggi, restituiamo anche l'esito, così il quiz non è
    "rifacibile" ricaricando la pagina."""
    oggi = _utcnow().date()
    domanda = ephemeris_di_oggi(oggi)
    out = {
        "testo": domanda["testo"],
        "domanda": domanda["domanda"],
        "opzioni": domanda["opzioni"],
        "gia_risposto": False,
    }
    u = utente_corrente()
    if not u:
        return jsonify(out)

    riga = get_db().execute(
        "SELECT * FROM ephemeris_risposte WHERE utente_id=%s AND giorno=%s",
        (u["id"], oggi)
    ).fetchone()
    if riga:
        out.update({
            "gia_risposto": True,
            "opzione_scelta": riga["opzione_scelta"],
            "corretto": riga["corretto"],
            "corretta": domanda["corretta"],
            "spiegazione": domanda["spiegazione"],
            "aurei_guadagnati": riga["aurei_guadagnati"],
        })
    return jsonify(out)

@app.route("/api/ephemeris/rispondi", methods=["POST"])
@login_richiesto
def rispondi_ephemeris():
    u = utente_corrente()
    d = request.get_json() or {}
    try:
        scelta = int(d.get("opzione"))
    except (TypeError, ValueError):
        return jsonify({"error": "Opzione non valida"}), 400

    oggi = _utcnow().date()
    domanda = ephemeris_di_oggi(oggi)
    if scelta < 0 or scelta >= len(domanda["opzioni"]):
        return jsonify({"error": "Opzione non valida"}), 400

    db = get_db()
    esiste = db.execute(
        "SELECT id FROM ephemeris_risposte WHERE utente_id=%s AND giorno=%s",
        (u["id"], oggi)
    ).fetchone()
    if esiste:
        return jsonify({"error": "Hai già risposto all'enigma di oggi."}), 409

    economia = get_o_crea_economia(db, u["id"])
    corretto = (scelta == domanda["corretta"])

    ieri = oggi - timedelta(days=1)
    streak_precedente = economia["streak_giorni"] or 0
    ultimo = economia["ultimo_giorno"].date() if economia["ultimo_giorno"] else None

    if corretto:
        nuovo_streak = streak_precedente + 1 if ultimo == ieri else 1
        mult = _moltiplicatore_streak(nuovo_streak)
        aurei = round(10 * mult)
        xp = aurei
    else:
        nuovo_streak = 0
        aurei = 2
        xp = 1

    db.execute(
        """
        INSERT INTO ephemeris_risposte (utente_id, giorno, opzione_scelta, corretto, aurei_guadagnati)
        VALUES (%s, %s, %s, %s, %s)
        """,
        (u["id"], oggi, scelta, corretto, aurei)
    )
    db.commit()

    riga_economia = accredita_economia(db, u["id"], aurei=aurei, xp=xp, nuovo_streak=nuovo_streak)

    return jsonify({
        "corretto": corretto,
        "corretta": domanda["corretta"],
        "spiegazione": domanda["spiegazione"],
        "aurei_guadagnati": aurei,
        "traguardo_speciale": corretto and nuovo_streak % 7 == 0,
        "economia": _serializza_economia(riga_economia),
    })

# ── API Libreria personale (Lapides Miliarii / Alexandria / Profilo) ─────
# Un solo stato per libro: 'in_lettura' | 'letto' | 'desiderio'. Il
# frontend decide se fare un PUT (imposta/cambia stato) o una DELETE
# (toglie del tutto) esattamente come faceva col vecchio togLetto/togSalvato:
# guarda lo stato attuale in cache e, se l'utente ha ricliccato lo stesso
# pulsante, manda una DELETE invece di un altro PUT.

@app.route("/api/libreria", methods=["GET"])
@login_richiesto
def get_libreria():
    u = utente_corrente()
    rows = get_db().execute(
        "SELECT book_id, stato, titolo, autore, anno, cover FROM libreria "
        "WHERE utente_id=%s ORDER BY aggiornato_il DESC",
        (u["id"],)
    ).fetchall()
    return jsonify([dict(r) for r in rows])

@app.route("/api/libreria", methods=["PUT", "POST"])
@login_richiesto
def imposta_libreria():
    u = utente_corrente()
    d = request.get_json() or {}
    book_id = (d.get("book_id") or "").strip()
    stato   = (d.get("stato") or "").strip()
    titolo  = (d.get("titolo") or "").strip()

    if not book_id or not titolo:
        return jsonify({"error": "book_id e titolo sono obbligatori"}), 400
    if stato not in ("in_lettura", "letto", "desiderio"):
        return jsonify({"error": "Stato non valido"}), 400

    autore = (d.get("autore") or "").strip()
    anno   = d.get("anno")
    try:
        anno = int(anno) if anno is not None else None
    except (TypeError, ValueError):
        anno = None
    cover = (d.get("cover") or "").strip() or None

    db = get_db()
    try:
        db.execute(
            """
            INSERT INTO libreria (utente_id, book_id, stato, titolo, autore, anno, cover)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (utente_id, book_id) DO UPDATE SET
                stato=EXCLUDED.stato, titolo=EXCLUDED.titolo, autore=EXCLUDED.autore,
                anno=EXCLUDED.anno, cover=EXCLUDED.cover, aggiornato_il=CURRENT_TIMESTAMP
            """,
            (u["id"], book_id, stato, titolo, autore, anno, cover)
        )
        db.commit()
        return jsonify({"ok": True})
    except Exception as e:
        db.rollback()
        app.logger.exception("imposta_libreria: errore inatteso")
        return jsonify({"error": "Errore nel salvataggio"}), 400

@app.route("/api/libreria/<path:book_id>", methods=["DELETE"])
@login_richiesto
def rimuovi_libreria(book_id):
    u = utente_corrente()
    db = get_db()
    db.execute("DELETE FROM libreria WHERE book_id=%s AND utente_id=%s", (book_id, u["id"]))
    db.commit()
    return jsonify({"ok": True})

# ── API Sfide di lettura ───────────────────────────────────────────────
# Idem: solo gli id delle sfide accettate. Target e descrizioni restano
# nel CHALLENGES del frontend.

@app.route("/api/sfide", methods=["GET"])
@login_richiesto
def get_sfide():
    u = utente_corrente()
    rows = get_db().execute(
        "SELECT sfida_id FROM sfide_accettate WHERE utente_id=%s", (u["id"],)
    ).fetchall()
    return jsonify([r["sfida_id"] for r in rows])

@app.route("/api/sfide", methods=["POST"])
@login_richiesto
def accetta_sfida():
    u = utente_corrente()
    d = request.get_json() or {}
    sfida_id = (d.get("sfida_id") or "").strip()
    if not sfida_id:
        return jsonify({"error": "sfida_id mancante"}), 400
    db = get_db()
    db.execute(
        "INSERT INTO sfide_accettate (utente_id, sfida_id) VALUES (%s, %s) ON CONFLICT DO NOTHING",
        (u["id"], sfida_id)
    )
    db.commit()
    return jsonify({"ok": True})

@app.route("/api/sfide/<sfida_id>", methods=["DELETE"])
@login_richiesto
def abbandona_sfida(sfida_id):
    u = utente_corrente()
    db = get_db()
    db.execute("DELETE FROM sfide_accettate WHERE sfida_id=%s AND utente_id=%s", (sfida_id, u["id"]))
    db.commit()
    return jsonify({"ok": True})

# ── API Agorà (forum pubblico) ───────────────────────────────────────────
# Lettura libera per tutti (anche senza login, come nel frontend attuale);
# scrivere un post o una risposta richiede invece un account, così ogni
# messaggio ha un autore reale e non "Ospite" per chiunque.

def _valida_testo(s, campo, max_len):
    s = (s or "").strip()
    if not s:
        return None, f"{campo} non può essere vuoto"
    if len(s) > max_len:
        return None, f"{campo} troppo lungo (massimo {max_len} caratteri)"
    return s, None

@app.route("/api/agora", methods=["GET"])
def get_discussioni():
    rows = get_db().execute("""
        SELECT d.id, d.titolo, d.corpo, d.autore_nome, d.creato_il,
               COUNT(r.id) AS n_risposte
        FROM discussioni d
        LEFT JOIN risposte r ON r.discussione_id = d.id
        GROUP BY d.id
        ORDER BY d.creato_il DESC
    """).fetchall()
    return jsonify([dict(r) for r in rows])

@app.route("/api/agora/<int:did>", methods=["GET"])
def get_discussione(did):
    db = get_db()
    d = db.execute("SELECT * FROM discussioni WHERE id=%s", (did,)).fetchone()
    if not d:
        return jsonify({"error": "Discussione non trovata"}), 404
    risposte = db.execute(
        "SELECT * FROM risposte WHERE discussione_id=%s ORDER BY creato_il ASC", (did,)
    ).fetchall()
    out = dict(d)
    out["risposte"] = [dict(r) for r in risposte]
    return jsonify(out)

@app.route("/api/agora", methods=["POST"])
@login_richiesto
def crea_discussione():
    u = utente_corrente()
    d = request.get_json() or {}
    titolo, err = _valida_testo(d.get("titolo"), "Il titolo", 200)
    if err:
        return jsonify({"error": err}), 400
    corpo, err = _valida_testo(d.get("corpo"), "Il messaggio", 5000)
    if err:
        return jsonify({"error": err}), 400

    db = get_db()
    cur = db.execute(
        "INSERT INTO discussioni (utente_id, autore_nome, titolo, corpo) VALUES (%s,%s,%s,%s) RETURNING *",
        (u["id"], u["nome"], titolo, corpo)
    )
    row = dict(cur.fetchone())
    db.commit()
    row["n_risposte"] = 0
    return jsonify(row)

@app.route("/api/agora/<int:did>/risposte", methods=["POST"])
@login_richiesto
def rispondi_discussione(did):
    u = utente_corrente()
    d = request.get_json() or {}
    testo, err = _valida_testo(d.get("testo"), "La risposta", 3000)
    if err:
        return jsonify({"error": err}), 400

    db = get_db()
    esiste = db.execute("SELECT id FROM discussioni WHERE id=%s", (did,)).fetchone()
    if not esiste:
        return jsonify({"error": "Discussione non trovata"}), 404

    cur = db.execute(
        "INSERT INTO risposte (discussione_id, utente_id, autore_nome, testo) VALUES (%s,%s,%s,%s) RETURNING *",
        (did, u["id"], u["nome"], testo)
    )
    row = cur.fetchone()
    db.commit()
    return jsonify(dict(row))

# ── Static / avvio ────────────────────────────────────────────────────────

@app.route("/")
def index():
    return app.send_static_file("index.html")

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, threaded=True)
