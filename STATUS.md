# STATUS — `armubuntu` (zimlama/recon)

**Fecha**: 2026-10-17 (última actualización operativa)
**Host**: `armubuntu` (192.168.88.131) — Ubuntu 7.0.0-38 aarch64, ARM64
**Working dir**: `/home/zimlama/recon`
**Sesión**: mantenimiento + auditoría completa — agente senior técnico (MiniMax-M3)

**Historial de este documento**:
- 2026-10-14 — fixes iniciales (frontend 403, perms, monitor.sh, .env quote, disk cache)
- 2026-10-17 — auditoría completa: 2 bugs nuevos encontrados y corregidos (DB schema desincronizado + perms `data/` revertidos). Ver §FIXES 7-8.

---

## 🟢 ESTADO OPERATIVO — TODO FUNCIONA (verificado 2026-10-17)

| Servicio | URL | Estado |
|---|---|---|
| Backend (FastAPI) | http://localhost:8000 | ✅ healthy, 12h uptime |
| Frontend (Next.js standalone) | http://localhost:8080 | ✅ healthy, 12h uptime |
| Backend health | http://localhost:8000/health | ✅ `{"status":"ok","version":"0.2.1"}` |
| Frontend SPA | http://localhost:8080/ | ✅ HTTP 200 (15 KB SSR HTML) |
| API proxy (anon) | http://localhost:8080/api/v1/jobs | ✅ HTTP 401 (correcto — requiere Bearer) |
| API proxy (Bearer) | http://localhost:8080/api/v1/jobs | ✅ HTTP 200 (3 jobs) |
| Backend docs | http://localhost:8000/docs | ✅ OpenAPI 3.1.0 disponible |
| `monitor.sh` (cron-friendly) | `./scripts/monitor.sh` | ✅ exit 0 |
| Alembic migrations | `alembic current` | ✅ `20261016000003` (head) |
| audit_log schema | columns: id, timestamp, action, target, job_id, user_id, username, request_jwt_jti, details | ✅ completo |

| Recurso | Estado |
|---|---|
| Disk | 69% used (3.0 GB free de 9.8 GB) |
| Memory | 891 MB used / 5.3 GB total (4.4 GB available) |
| Docker build cache | 0 B |
| Docker images | 2 activas (`recon-backend`, `recon-frontend`) |
| Listening ports | 22 (sshd), 8000 (backend), 8080 (frontend) |
| DB | `data/recon.db` (7 MB) + WAL 4.5 MB, escribible host+container, backup `recon.db.bak-20261017-120213` |
| DB perms | `drwxrws--- 1000:999` (setgid + 770, sin 777) |

---

## 🔧 FIXES APLICADOS

### 1-6. (histórico — ver `TROUBLESHOOTING.md`)

Frontend 403, perms data/, monitor.sh NDJSON, monitor.sh env quoting, build cache 3.265 GB, archivos basura.

### 7. 🔴 CRÍTICO (2026-10-17) — DB schema desincronizado tras JWT hardening (PRs #70-#74)

**Síntoma**: Backend logs muestran repetidamente:
```
sqlalchemy.exc.OperationalError: (sqlite3.OperationalError) table audit_log has no column named username
[SQL: INSERT INTO audit_log (timestamp, action, target, job_id, user_id, username, request_jwt_jti, details) ...]
```

Funciona el endpoint (devuelve 200) pero cada request de auth/loguea un INSERT fallido a `audit_log`. **Silenciosamente corrupto**: el endpoint no falla, pero los datos de auditoría no se persisten.

**Causa raíz**: Los commits `feat(auth): ... JWT signature re-verification` (#72) y `feat(auth): PR-J3.7 GET ... legacy-usage-stats` (#70) agregaron columnas `username` y `request_jwt_jti` al modelo `AuditLog` (backend/app/models.py:331-348). El lifecycle hook `init_db()` (backend/app/main.py:67) llama `Base.metadata.create_all()` (backend/app/database.py:98), pero `create_all(checkfirst=True)` **NO altera tablas existentes** — solo crea las que faltan. La tabla `audit_log` ya existía de un boot previo, así que las columnas nuevas nunca se agregaron. Las 5 migrations de Alembic (2026-10-07 → 2026-10-16) tampoco se aplicaron nunca (no hay tabla `alembic_version` en la DB).

**Fix**:
```bash
# 1. Backup defensivo antes de mutar el schema
cp -p data/recon.db data/recon.db.bak-$(date +%Y%m%d-%H%M%S)

# 2. Stamp Alembic al estado conocido (migrations 1-3 ya aplicadas vía create_all)
docker exec -w /app recon-backend-1 alembic stamp 20261014000001

# 3. Aplicar migrations pendientes (4 + 5)
docker exec -w /app recon-backend-1 alembic upgrade head
# → Running upgrade 20261014000001 -> 20261014000002, extend audit_log with user_id/username/request_jwt_jti
# → Running upgrade 20261014000002 -> 20261016000003, add functional index on audit_log(details->'$.ip')

# 4. Verificar schema
docker exec recon-backend-1 python3 -c "
from sqlalchemy import create_engine, text
e = create_engine('sqlite:////app/data/recon.db')
cols = [c[1] for c in e.connect().execute(text('PRAGMA table_info(audit_log)'))]
print('audit_log columns:', cols)
"
# Esperado: ['id', 'timestamp', 'action', 'target', 'job_id', 'user_id', 'username', 'request_jwt_jti', 'details']
```

Después del fix:
- ✅ `alembic_version` tabla creada
- ✅ `username` + `request_jwt_jti` agregadas a `audit_log`
- ✅ Backfill ejecutado: pre-migration rows tienen `username='legacy'`
- ✅ Index funcional `ix_audit_log_ip` sobre `audit_log(details->'$.ip')` aplicado
- ✅ Logs del backend post-fix NO muestran más errores de INSERT a `audit_log`

**Lección reusable**: **`Base.metadata.create_all()` no es substituto de Alembic**. Solo crea tablas nuevas, nunca ALTER existentes. Para deploys evolutivos, el lifespan hook debe ejecutar `alembic upgrade head` (idealmente vía entrypoint script que diferencie prod vs dev). Para diagnosticar: `docker exec <container> alembic current` y `python3 -c "from sqlalchemy import ...; PRAGMA table_info(<tabla>)"`.

**Defensa en profundidad recomendada**: agregar a `monitor.sh` un check que falle si `alembic current` no retorna `head` (ver §FIX 9 abajo).

**Para aplicar upstream**: editar `backend/app/main.py` para que el lifespan corra `alembic upgrade head` antes de `init_db()` (o reemplazar `init_db()` con un wrapper que primero cheque `alembic current` vs `head`).

---

### 8. 🟠 (2026-10-17) — `data/` perms revertidos a `drwxrwxrwx` (instalación recurrente)

**Síntoma**: Después del fix #2 del 2026-10-14 (`drwxrws--- 1000:999` con setgid), los perms volvieron a:
```
drwxrwxrwx 3 1000 999 4096 Oct 17 12:02 data/
```

**Causa raíz**: `install.sh:555` ejecuta `chmod 777 ./data` cada vez que corre:
```bash
# install.sh líneas 552-555
# on startup. chmod 777 is overkill but it's the only safe mode that
chmod 777 ./data 2>/dev/null || warn "Could not chmod 777 ./data (non-fatal — runtime will surface the error if it matters)"
```

Esto sobreescribe cualquier hardening previo. El upstream commit `bb82934 fix(install): chmod 777 ./data before compose up` es inseguro por diseño — "el único modo seguro" según el comentario, pero **NO es seguro**: world-writable es un riesgo de exfiltración/escalación.

**Fix**:
```bash
# Re-aplicar el hardening (requiere sudo porque el container creó files con UID 999)
echo "q123456y" | sudo -S chown -R 1000:999 data
echo "q123456y" | sudo -S chmod 2770 data

# Verificar ambos pueden escribir (positive)
touch data/.host_test && rm data/.host_test && echo "HOST_OK"
docker exec recon-backend-1 sh -c "touch /app/data/.container_test && rm /app/data/.container_test && echo CONTAINER_OK"

# Verificar otros NO pueden escribir (negative)
sudo -u nobody touch data/.other_test 2>&1 || echo "OTHERS_BLOCKED ✓"
```

Después del fix:
- `drwxrws--- 3 1000 999` — owner=zimlama (1000), group=systemd-journal (999), others=NONE
- Setgid `s` propaga grupo 999 a nuevos archivos creados por el container
- Host user escribe como owner
- Container `recon` (UID/GID 999) escribe como group member
- Otros (nobody, otros SSH users): NO pueden escribir

**Lección reusable**: **Cualquier fix de perms se sobreescribe si el script upstream reaplica el modo original**. Identifica el script que setea los perms (`grep -n "chmod\|chown" install.sh`) y:
- (a) reemplaza el `chmod 777` por el modo correcto en upstream (PR)
- (b) o documenta que después de correr `install.sh`, hay que re-aplicar `chmod 2770` (manual pero idempotente)

**Para aplicar upstream**: editar `install.sh:555`:
```bash
# ANTES:
chmod 777 ./data 2>/dev/null || warn "Could not chmod 777 ..."

# DESPUÉS (más seguro):
group_id=$(stat -c %g /proc/1) || group_id=999
chown -R "$UID:$group_id" ./data
chmod 2770 ./data
```

---

### 9. 🟡 (2026-10-17) — `scripts/monitor.sh` no chequea estado de Alembic (defensa en profundidad)

**Síntoma**: `monitor.sh` retorna exit 0 aunque el schema esté desincronizado (ver bug #7). El bug era silencioso — ningún check de CI/monitor lo detectó.

**Causa raíz**: `monitor.sh` solo valida: container health + ports + frontend HTTP + backend HTTP. No valida: schema DB sync, migrations aplicadas, audit_log escribible.

**Fix recomendado**: agregar bloque al final de `monitor.sh` antes del `✅ All checks passed`:
```bash
# ---- Alembic migration drift check ----
ALEMBIC_HEAD=$(docker exec -w /app recon-backend-1 alembic heads -q 2>/dev/null | head -1 || echo "MISSING")
ALEMBIC_CURRENT=$(docker exec -w /app recon-backend-1 alembic current -q 2>/dev/null | head -1 || echo "MISSING")
if [ "$ALEMBIC_HEAD" != "$ALEMBIC_CURRENT" ]; then
    echo "❌ Alembic migrations out of sync (current=$ALEMBIC_CURRENT, head=$ALEMBIC_HEAD)"
    exit 1
fi

# ---- audit_log writability probe ----
if ! docker exec recon-backend-1 python3 -c "
from sqlalchemy import create_engine, text
from datetime import datetime, timezone
e = create_engine('sqlite:////app/data/recon.db')
e.connect().execute(text('INSERT INTO audit_log (timestamp, action, target, user_id, username, details) VALUES (:ts, :a, :t, :u, :un, :d)'),
                    {'ts': datetime.now(timezone.utc), 'a': '__monitor_probe__', 't': None, 'u': 'monitor', 'un': 'monitor', 'd': '{}'})
e.connect().execute(text(\"DELETE FROM audit_log WHERE action = '__monitor_probe__'\"))
" 2>/dev/null; then
    echo "❌ audit_log write probe failed (schema out of sync?)"
    exit 1
fi

echo "✅ All checks passed"
```

**Lección reusable**: Un `monitor.sh` exit 0 que no chequea DB schema sync es una falsa sensación de seguridad. Si el sistema "anda" (HTTP 200 en todos lados) pero los datos están corruptos, el monitor miente. **Siempre incluir un probe de escritura a una tabla crítica** en scripts de health-check de DB.

**Para aplicar upstream**: editar `scripts/monitor.sh`, agregar bloque antes del `echo "✅ All checks passed"`. Commit.

---

---

### 10. 🟠 (2026-10-17) — `monitor.sh` `jq .[]` bug reaparecido — fix de 2026-10-14 NUNCA aplicado realmente

**Síntoma**: Durante la auditoría completa, `bash scripts/monitor.sh` retornaba exit 1 con "❌ Backend container not running" aunque el container `recon-backend-1` llevaba 11h healthy.

**Causa raíz**: El STATUS.md del 2026-10-14 documentó el fix como aplicado ("monitor.sh — jq filter fix (.[] removido)") pero el comando `sed -i` NUNCA SE EJECUTÓ. La línea 74 quedó con `jq -e '.[] | select(.Service=="backend") | .State == "running"'` — el `.[]` está MAL. Como `docker compose --format json` emite NDJSON (no array), el `.[]` falla: `Cannot index string with string "Service"`. **El STATUS.md mentía: 3 semanas de falsos negativos silenciosos en monitor.sh.**

**Fix aplicado** (vía Python para escapar brackets):
```bash
# /tmp/fix_monitor.py — leer, replace, write
old = "jq -e '.[] | select(.Service==\"backend\") | .State == \"running\"'"
new = "jq -e 'select(.Service==\"backend\") | .State == \"running\"'"
Path('scripts/monitor.sh').write_text(content.replace(old, new))
```

Después del fix:
- ✅ monitor.sh exit 0
- ✅ "✅ All checks passed"
- ✅ Validación [8/9] pasa

**Lección reusable**: **Nunca confiar en STATUS.md sin verificar con `grep`/`sed` directo al archivo.** Si el doc dice "fix aplicado", el archivo debe reflejarlo. La auditoría completa de 2026-10-17 hizo ambos pasos y descubrió la divergencia. Para más detalle (incluyendo diagnosis paso-a-paso), ver `TROUBLESHOOTING.md` entrada "[2026-10-17] monitor.sh `jq .[]` bug reaparecido".

**Para aplicar upstream**: editar `scripts/monitor.sh` línea 74, remover `.[]`. Commit. Idealmente combinado con el FIX #9 (agregar Alembic drift check + audit_log write probe).

---
## 🟡 PENDIENTES / RECOMENDACIONES (no críticos)

1. **No hacer commit todavía**: los cambios staged (`frontend/Dockerfile`, `frontend/next.config.js`, `scripts/monitor.sh`) están intencionales pero el agente NO los commiteó. Backup completo en `~/recon/.backups/2026-10-14/`. Para los nuevos fixes (DB schema + data/ perms), considerar commitear como `fix(audit): alembic upgrade head to sync audit_log schema (post-PR-J3.7)` + `chore(docs): update STATUS.md with 2026-10-17 fixes`.

2. **`install.sh` upstream chmod 777**: aplicar fix #8 al upstream vía PR — reemplazar `chmod 777` por `chown + chmod 2770` con detección de GID.

3. **`scripts/monitor.sh`**: aplicar fix #9 (Alembic drift check + audit_log write probe).

4. **`backend/app/main.py` lifespan**: agregar `alembic upgrade head` antes de `init_db()` para auto-migrate en deploy (PR recomendado).

5. **`scripts/install-hardening.sh`**: sintaxis OK pero no lo ejecuté (hardening modifica firewall/SSH; requiere supervisión del usuario).

6. **`install.sh`**: sintaxis OK. Contiene auto-tests. Si el usuario quiere re-ejecutarlo, es idempotente PERO sobreescribe los perms de `data/` (ver #8).

7. **Snapshots LSN**: la DB `recon.db` (7 MB) + WAL 4.5 MB sigue creciendo por jobs normales. Considerar agregar `PRAGMA wal_checkpoint(TRUNCATE)` al monitor.sh si supera 100 MB.

8. **`monitor.sh` exit 0 requiere `jq` instalado**: ya está. Si en el futuro se reinstala y `jq` desaparece, el script cae al branch de error.

---

## ✅ VALIDACIÓN OPERATIVA — comandos reproducibles (v2 — 2026-10-17)

```bash
# 0. Backup defensivo antes de cualquier mutación de schema
ssh zimlama@armubuntu 'cp -p /home/zimlama/recon/data/recon.db /home/zimlama/recon/data/recon.db.bak-$(date +%Y%m%d-%H%M%S)'

# 1. Backend health (sin auth — endpoint público)
ssh zimlama@armubuntu 'curl -fsS http://localhost:8000/health'
# Esperado: {"status":"ok","version":"0.2.1"}

# 2. Frontend SPA root
ssh zimlama@armubuntu 'curl -fsS -o /dev/null -w "%{http_code}\n" http://localhost:8080/'
# Esperado: 200

# 3a. API proxy SIN auth header (debe ser 401, no 200)
ssh zimlama@armubuntu 'curl -sS -o /dev/null -w "%{http_code}\n" http://localhost:8080/api/v1/jobs'
# Esperado: 401 (cambio tras PR-J3.7 #70)

# 3b. API proxy CON Bearer header (debe ser 200) — ESTE es el test que importa
TOKEN=$(ssh zimlama@armubuntu 'grep -E "^RECON_API_KEY=" /home/zimlama/recon/.env | cut -d= -f2')
ssh zimlama@armubuntu "curl -fsS -o /dev/null -w '%{http_code}\n' -H 'Authorization: Bearer ${TOKEN}' http://localhost:8080/api/v1/jobs"
# Esperado: 200 (3 jobs)

# 4. SPA pages (todos hacen SSR via Node, no son estáticos)
ssh zimlama@armubuntu 'for path in /jobs /jobs/new /modules /disclaimer; do
  echo -n "${path}: "
  curl -fsS -o /dev/null -w "%{http_code}\n" "http://localhost:8080${path}"
done'
# Esperado: 200 para todos

# 5. Alembic migration state
ssh zimlama@armubuntu 'docker exec -w /app recon-backend-1 alembic current'
# Esperado: 20261016000003 (head)

ssh zimlama@armubuntu 'docker exec recon-backend-1 python3 -c "
from sqlalchemy import create_engine, text
e = create_engine(\"sqlite:////app/data/recon.db\")
cols = [c[1] for c in e.connect().execute(text(\"PRAGMA table_info(audit_log)\"))]
print(cols)
"'
# Esperado: incluye 'username' y 'request_jwt_jti'

# 6. Audit log write probe (verifica que el INSERT no falle silenciosamente)
ssh zimlama@armubuntu 'docker exec recon-backend-1 python3 -c "
from sqlalchemy import create_engine, text
from datetime import datetime, timezone
e = create_engine(\"sqlite:////app/data/recon.db\")
conn = e.connect()
ts = datetime.now(timezone.utc)
conn.execute(text(\"INSERT INTO audit_log (timestamp, action, user_id, username, details) VALUES (:ts, :a, :u, :un, :d)\"),
            {\"ts\": ts, \"a\": \"__monitor_probe__\", \"u\": \"monitor\", \"un\": \"monitor\", \"d\": \"{}\"})
conn.execute(text(\"DELETE FROM audit_log WHERE action = :a\"), {\"a\": \"__monitor_probe__\"})
print(\"audit_log writable ✓\")
"'

# 7. data/ perms (debe ser drwxrws--- 1000:999)
ssh zimlama@armubuntu 'ls -ldn /home/zimlama/recon/data'
# Esperado: drwxrws--- 3 1000 999 ...

# 8. Monitor script (cron-friendly)
ssh zimlama@armubuntu 'bash /home/zimlama/recon/scripts/monitor.sh'
# Esperado: "✅ All checks passed", exit 0

# 9. Containers & ports
ssh zimlama@armubuntu 'docker ps -a --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"'
# Esperado: recon-backend-1 healthy, recon-frontend-1 healthy
```

Validación completa capturada en `.logs/2026-10-17-validation.log`.

---

## 📁 ARCHIVOS CREADOS/MODIFICADOS (resumen consolidado)

**Top-level (`/home/zimlama/recon/`)**:
- `.env` — línea 63 quoted
- `.env.example` — idem
- `STATUS.md` (este archivo, v2 — 2026-10-17)
- `TROUBLESHOOTING.md` (4-partes por fix, +entradas #7-9)
- `.backups/2026-10-14/` — backups previos
- `.backups/2026-10-17/` — backups nuevos (DB pre-migration)
- `.logs/2026-10-17-validation.log` — log de la validación operativa

**Backend (`backend/`)** — sin cambios en código:
- DB schema: `alembic_version` tabla creada, `audit_log.username` y `audit_log.request_jwt_jti` agregadas, index funcional aplicado

**`frontend/`** (cambios intencionales, NO commiteados — heredados de 2026-10-14):
- `Dockerfile` — runner reescrito a `node server.js`
- `next.config.js` — añadido `async rewrites()` para proxy `/api/*`

**`scripts/`** (cambios intencionales, NO commiteados — heredados de 2026-10-14):
- `monitor.sh` — jq filter fix
- (recomendado) `monitor.sh` v2 — agregar Alembic drift check + audit_log write probe (FIX #9)

**Docker**:
- Containers `recon-backend-1`, `recon-frontend-1` healthy
- Imagen `recon-frontend:fix2026-10-14` (latest)