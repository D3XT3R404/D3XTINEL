# D3XTINEL (UNDER MAINTENANCE)

D3XTINEL is a web-based URL analysis and threat detection platform designed to identify potentially malicious, phishing, or suspicious URLs using Machine Learning and threat intelligence integration.

## Live Demo

🌐 Website:

https://d3xt3r404.github.io/D3XTINEL/

---

## Features

* URL threat analysis
* Machine Learning-based classification
* Phishing URL detection
* Suspicious URL identification
* VirusTotal integration (Maintenance)
* Modern web interface
* Real-time analysis results
* Public dataset support

---

## How It Works

1. User submits a URL.
2. Feature extraction is performed.
3. Machine Learning model analyzes the URL.
4. Threat intelligence checks are executed.
5. Results are displayed through the web interface.

---

## Dataset

The project uses publicly available URL datasets for research, educational purposes, and model training.

Dataset may include:

* Benign URLs
* Suspicious URLs
* Phishing URLs
* Malicious URLs

---

## Disclaimer

This project is intended for:

* Educational purposes
* Cybersecurity research
* Threat analysis learning
* Machine Learning experimentation

Users are responsible for how they use this project.

---

## Author

GitHub:

https://github.com/D3XT3R404

---

## License

This project is provided for educational and research purposes.


## Local run note

Frontend can use the backend in the browser by setting `window.API_BASE` to your backend URL,
or it will default to `http://127.0.0.1:8000` on localhost.

VirusTotal is optional now. If the API key is missing or expired, the app still returns ML-based results.
