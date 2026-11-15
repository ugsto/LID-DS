# Worker image for the LID-DS evaluation: the stock PentAGI Kali worker plus the
# tools the scenarios need OFFLINE (the lab network has no internet route).
# Build from pentagi-lab/:  docker build -t lab-kali worker/
FROM vxcontrol/kali-linux

# Java for ysoserial deserialization chains (target10), mysql client for the
# auth-bypass loop (target02). Everything else ships with Kali.
RUN apt-get update \
    && apt-get install -y --no-install-recommends default-jre-headless default-mysql-client \
    && rm -rf /var/lib/apt/lists/*

# ysoserial is not packaged: vendor the release jar so target10 stays solvable offline
ADD https://github.com/frohoff/ysoserial/releases/latest/download/ysoserial-all.jar /opt/tools/ysoserial.jar
