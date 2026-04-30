\# CTI Gateway



Threat Intelligence ingestion, enrichment and correlation engine designed to extend OpenCTI capabilities.



\## Overview



CTI Gateway transforms raw threat feeds into contextualized intelligence by applying:



\- Deduplication

\- Contextual scoring

\- MITRE ATT\&CK mapping

\- Threat-type tagging

\- Correlation logic



\## Why



Most SOCs consume IoCs.



CTI Gateway focuses on:



> Turning indicators into intelligence.



\## ⚙️ Features



\- OTX ingestion engine

\- Persistent deduplication (stateful)

\- MITRE ATT\&CK enrichment

\- Contextual confidence scoring

\- Automatic threat tagging

\- OpenCTI integration



\## Architecture



Feeds → Connector → Processing Engine → OpenCTI







\## Stack



\- Python

\- OpenCTI

\- Docker

\- OTX (AlienVault)



\## Project Structure



connectors/ # ingestion layer

core/ # enrichment \& correlation

config/ # behavior configuration

state/ # deduplication state

docker/ # runtime





\## Roadmap



\- \[ ] Advanced correlation engine

\- \[ ] Sector-based threat targeting

\- \[ ] Sigma rules generation

\- \[ ] Multi-feed support (MISP, etc)

\- \[ ] Intelligence scoring engine v2



\## Version



See `VERSION` file



\## Contributing



WIP



\## License



TBD



