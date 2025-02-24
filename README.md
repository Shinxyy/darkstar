# Darkstar - Advanced Vulnerability Management  
<img src="logo.png" alt="Darkstar Logo" width="300" height="300">

### The ultimate **Red Team** and **Blue Team** tool for attack surface mapping and vulnerability management!  

## Features  
- Dashboard insight into vulnerabilities 
- Vulnerability Scanning  
- Attack Surface mapping 
- Easy deployment via Docker  

---

## Requirements  
Before installing, ensure you have the following tools:  

- [Docker](https://docs.docker.com/get-docker/)  
- [Docker Compose](https://docs.docker.com/compose/install/)  


## Quick Setup with Docker  

1. Grant execution permission:  
   ```bash
   chmod +x run.sh
   ```
2. Start the tool:
    ```bash
    ./run.sh
    ```


## Inside the container
- The database name must be `test`. If you need a custom name, update the database in [`init.sql`](sql/init.sql).
- To run a scan, use the following command:
```bash
python3 main.py -t testphp.vulnweb.com -m 2 -d test -env .env
```

## Datasets
Darkstar leverages high quality threat intelligence sources:
- [Epss Scores](https://www.first.org/epss/data_stats) – Probabilistic vulnerability prioritization
- [CISA Kev](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) – Known exploited vulnerabilities

## Security Tip
Please change the database password and the openvas password if running in production environment

## Lead Developers
- [![LinkedIn](https://i.sstatic.net/gVE0j.png) Joost Grunwald](https://www.linkedin.com/in/joost-grunwald-1a48a31b2)
- [![LinkedIn](https://i.sstatic.net/gVE0j.png) Patrick Kuin](https://www.linkedin.com/in/patrick-kuin-8a08a81b7)

### License
This project is licensed under [GNU GPLv3](LICENSE)