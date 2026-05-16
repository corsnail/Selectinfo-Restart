# PROJECT KNOWLEDGE BASE

**Generated:** 2026-04-25
**Commit:** f441a86
**Branch:** development

## OVERVIEW

**selectinf** - Automated asset collection and vulnerability scanning framework integrating OneForAll, amass, massdns, ksubdomain, subfinder, and JSFinder into a unified pipeline for subdomain enumeration and security testing.

## STRUCTURE

```
.
├── run.py                       # Main orchestration entry point
├── selectinf/                   # Core Python package
│   ├── __init__.py
│   ├── __main__.py              # python -m selectinf
│   ├── collect/                 # Data collection layer
│   │   ├── extract_domains.py   # Parse results from tools
│   │   └── dnsgrep.py           # DNS record processing
│   ├── process/                 # Data processing layer
│   │   ├── deduplicate.py       # Domain/URL deduplication
│   │   ├── filter_wildcard.py   # Filter wildcard DNS
│   │   └── url_converter.py     # Domain-to-URL conversion
│   └── output/                  # Data output layer
│       ├── arl_exporter.py      # ARL platform integration
│       └── mysql_exporter.py    # CSV to MySQL import
├── config/                      # Configuration files
│   └── database.conf            # MySQL connection settings
├── output/                      # Runtime output directory
│   └── xlsx/                    # ARL export files
├── engines/                     # Large frameworks
│   └── OneForAll/               # Integrated subdomain collection framework
├── tools/                       # External binaries and scripts
│   ├── amass/                   # amass binary + configs
│   ├── massdns/                 # massdns scripts + binaries
│   ├── ksubdomain/              # ksubdomain executable
│   ├── subfinder/               # subfinder executable
│   ├── subDomainsBrute/         # Alternative brute-force tool
│   └── jsfinder/                # JS-based URL/domain extraction
└── application/                 # Task configs (add.json, task.json)
```

## WHERE TO LOOK

| Task | Location | Notes |
|------|----------|-------|
| Start asset collection | `run.py` | Main entry, coordinates all tools |
| Core Python modules | `selectinf/` | All utility scripts packaged here |
| Data collection layer | `selectinf/collect/` | Domain extraction, DNS discovery |
| Data processing layer | `selectinf/process/` | Dedup, filter, URL conversion |
| Data output layer | `selectinf/output/` | ARL export, MySQL storage |
| OneForAll framework | `engines/OneForAll/` | Complex subdomain enumeration tool |
| External binaries | `tools/` | amass, subfinder, massdns, ksubdomain, jsfinder |
| Database config | `config/database.conf` | MySQL connection settings |
| Configs | `application/` | Task and asset configurations |

## CONVENTIONS

- **Entry point**: `python run.py` or `python -m selectinf`
- **Tool calls**: Use `os.system()` and `subprocess` for external binaries
- **Threading**: Parallel execution via `threading.Thread` (see scan_thread1/2)
- **Output format**: Text files (.txt) for intermediate, CSV for final results
- **Naming**: `<target>.txt` for URLs, `domain_<target>.txt` for domains
- **Database**: SQLite3 via `database.conf` connection settings
- **Package**: Core modules in `selectinf/`, external tools at root level

## ANTI-PATTERNS

- **DO NOT** run tools directly; always use `run.py` orchestration
- **DO NOT** modify `OneForAll/config/api.py` without backing up API keys
- **NEVER** commit API keys to version control
- **AVOID** running without proper authorization (legal compliance required)

## COMMANDS

```bash
# Main asset collection (interactive)
python run.py

# OneForAll standalone
python OneForAll/oneforall.py --target example.com run

# Database setup (if needed)
pip install -r OneForAll/requirements.txt
```

## NOTES

- Windows-focused: Paths use backslashes, includes `.exe` binaries
- OneForAll requires Python 3.8+ and dependencies from `requirements.txt`
- External binaries must exist: `subfinder.exe`, `amass.exe`, `ksubdomain.exe`, `massdns`
- Results accumulate in root directory as `.txt` and `.csv` files
- Do not modify the internal code of third-party modules.（/tools、/engines）