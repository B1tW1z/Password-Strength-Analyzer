
# Password Strength Analyzer

[![Python](https://img.shields.io/badge/Python-3.x-blue.svg)]()
[![Flask](https://img.shields.io/badge/Flask-3.0-lightgrey.svg)]()


A lightweight web application to evaluate password strength and simulate basic password cracking techniques. Built with Flask, it helps demonstrate how secure a password is and how long it may take to crack.

## Features
- Strength rating (Weak / Medium / Strong)
- Dictionary attack using wordlists
- Limited brute-force attack simulation
- Time tracking for attacks
- Graph generation (password length vs cracking time)

## Requirements
```
Flask>=3.0
zxcvbn>=4.5.0
passwordmeter
````

## Installation
```bash
git clone https://github.com/B1tW1z/Password-Strength-Analyzer.git
cd Password-Strength-Analyzer
pip install -r requirements.txt
````

## Usage

```bash
python app.py
```

Open in browser:

```
http://127.0.0.1:5000/
```

## Project Structure

```
.
├── run.py
├── requirements.txt
├── attacks/
│   ├── brute_force.py
│   └── dictionary.py
├── data/
│   ├── default_wordlist.txt
│   └── results.json
├── metrics/
│   ├── graph.py
│   └── tracker.py
├── strength/
│   ├── aggregator.py
│   ├── entropy.py
│   ├── rule_based.py
│   └── zxcvbn_adapter.py
├── web/
│   ├── app.py
│   ├── static/
│   │   ├── css/app.css
│   │   └── graphs/
│   └── templates/
│       ├── base.html
│       ├── home.html
│       ├── strength.html
│       ├── bruteforce.html
│       ├── history.html
│       ├── faq.html
│       └── not_found.html
```

## Output

* Strength rating (Weak / Medium / Strong)
* Estimated cracking time
* Visualization of password length vs cracking time

## Notes
- Dictionary attacks use default_wordlist.txt (can be replaced with larger lists like rockyou.txt)
- Brute-force simulation is intentionally limited for performance reasons
- Results and metrics are stored in data/results.json