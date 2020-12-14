# Trust-Seeding
This repository implements a Proof of Concept (PoC) to create a trust store bundle based on CT-Log Monitoring.

# Idea behind this project
This approach detects the current **trend** which Root CA Certificates are used more frequently then others for currently issued End-Entity/Subscriber certificates.

# Alternative approaches by other researchers
- Trust Store Minimization based on the browser history.
- Trust Store Minimization based on policy metrics of CA Organizations.

# Used Services
- CA Trust Bundle: https://curl.haxx.se/ca/cacert.pem
- CT-Log Monitor Stream: wss://certstream.calidog.io/
- top list: https://s3.amazonaws.com/alexa-static/top-1m.csv.zip
