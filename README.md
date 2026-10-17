# Auditor

CLI defensiva en Python para auditar sitios web propios o con autorización escrita. Inventaría endpoints públicos, formularios, scripts, headers, cookies, CORS, TLS y exposiciones accidentales comunes. Para quien debe revisar la superficie pública de un sitio que está autorizado a auditar.

## Qué hace

- `validate-scope` confirma si una URL está autorizada en `authorized_targets.yaml`. Sin autorización, no se ejecuta ninguna auditoría.
- `inventory` rastrea el sitio (profundidad y número de páginas limitados) y genera un inventario sin checks activos adicionales.
- `run` ejecuta inventario y checks defensivos, y genera `audit.json` e `index.html` en la carpeta de salida.
- Compara respuestas con distintos User-Agent (`--ua-profile auditor|desktop|mobile|googlebot`, `--cloak-check`) para detectar cloaking y gates JS/cookie con recarga.
- Límites: no hace fuerza bruta, no explota vulnerabilidades, no intenta saltar autenticación, no sigue dominios externos por defecto y limita profundidad, páginas, timeouts y frecuencia.

## Stack

- Python 3.11 o superior (`requires-python`).
- Solo librería estándar (`dependencies = []`).
- Build con setuptools >=68.
- Tests con `unittest` en `tests/`.

## Cómo correrlo en local

Autorización: crear el archivo de dominios permitidos a partir del ejemplo y editarlo con el dominio autorizado:

```bash
cp authorized_targets.example.yaml authorized_targets.yaml
```

Comandos (el ejemplo usa `example.com`):

```bash
python3 -m auditor validate-scope https://example.com
python3 -m auditor inventory https://example.com --out reports/example
python3 -m auditor run https://example.com --out reports/example
```

Instalación como comando:

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e .
auditor run https://example.com --out reports/example
```

Tests:

```bash
python3 -m unittest discover -s tests -v
```

La carpeta `reports/` no se versiona: contiene resultados de auditorías. `authorized_targets.yaml` tampoco se versiona porque es local a cada uso.

## Estructura

```text
auditor/                Paquete: cli, crawler, checks, extractors, http_client, scope, reporting, models
tests/                  Pruebas de alcance, extractores y checks
authorized_targets.example.yaml   Ejemplo de dominios autorizados (example.com)
reports/                Salidas de auditoría (no versionadas; solo .gitkeep)
```

## Estado

MVP en desarrollo. El inventario y los checks defensivos están implementados; la detección de cloaking por User-Agent es la función más reciente.

## Licencia

MIT — ver LICENSE.

---
Hecho por Matías Moreno · github.com/MatiasJMB
