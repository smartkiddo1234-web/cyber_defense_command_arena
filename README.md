# AI Tactical Command And Deployment Simulator (CYBER ARENA)

## Project Purpose

CYBER ARENA is a **synthetic cybersecurity digital twin** and defensive command decision platform built for an academic cybersecurity competition.

The application simulates a fictional national digital environment where a simulated adversary moves through the infrastructure, and a cyber defense command detects, analyzes, deceives, contains, and responds to the simulated threat.

### Safety Notice

> **This is ONLY a synthetic cybersecurity simulation.**
>
> The application does **NOT**:
> - Attack real systems
> - Scan real networks
> - Exploit real vulnerabilities
> - Connect to real attacker machines
> - Interfere with real computers
> - Collect real attacker information
> - Execute real offensive cybersecurity actions
> - Affect real infrastructure of any kind
>
> All infrastructure, attackers, events, telemetry, credentials, vulnerabilities, network activity, and outcomes are fictional and generated locally by the application.

---

## Technology Stack

| Layer      | Technology                     |
|------------|--------------------------------|
| Backend    | Python, Flask                  |
| Frontend   | HTML5, CSS3, JavaScript        |
| Database   | SQLite                         |

The application runs locally on Windows.

---

## Current Development Phase

**Phase 1 — Foundation**

The project is being built incrementally. Each phase adds a specific set of capabilities.

### Planned Future Modules

| Phase   | Module                          |
|---------|---------------------------------|
| Phase 2 | Simulated adversary & attack paths (MITRE ATT&CK) |
| Phase 3 | Threat detection, temporal confidence, evidence engine |
| Phase 4 | Deception engine & adaptive containment |
| Phase 5 | AI commander & human decision layer |
| Phase 6 | Defense units & national impact engine |
| Phase 7 | Recovery system & full simulation loop |
| Phase 8 | Reporting, analytics, and final polish |

---

## Installation

### Prerequisites

- Python 3.10 or later
- pip (Python package manager)

### Install Dependencies

```bash
cd cyber_defense_command_arena
pip install -r requirements.txt
```

---

## Running the Application

```bash
cd cyber_defense_command_arena
python app.py
```

The application will start on:

```
http://127.0.0.1:5000
```

Open that URL in a web browser to see the command-center dashboard.

---

## Running Tests

```bash
cd cyber_defense_command_arena
python -m unittest tests/test_app.py -v
```

---

## Project Structure

```
cyber_defense_command_arena/
├── app.py                  # Flask application entry point
├── config.py               # Application configuration
├── requirements.txt        # Python dependencies
├── README.md               # This file
│
├── database/
│   ├── __init__.py         # Database package
│   └── database.py         # SQLite connection & initialization
│
├── simulation/             # Adversary simulation (Phase 2+)
├── detection/              # Threat detection (Phase 3+)
├── deception/              # Deception engine (Phase 4+)
├── command/                # AI/human commander (Phase 5+)
├── defense/                # Defense units (Phase 5+)
├── intelligence/           # Evidence & intelligence (Phase 3+)
├── reports/                # Reporting & analytics (Phase 6+)
│
├── templates/
│   ├── base.html           # Shared layout template
│   └── dashboard.html      # Command-center dashboard
│
├── static/
│   ├── css/
│   │   └── style.css       # Dashboard styling
│   ├── js/
│   │   └── app.js          # Client-side logic
│   └── images/             # Static images
│
└── tests/
    ├── __init__.py
    └── test_app.py         # Basic tests
```

---

## License

Academic competition project. All rights reserved.
