STANDARD RF DETECTOR
--------------------
Install ../requirements.txt and ../requirements-ml.txt in an isolated virtual
environment. Models are stored as validated inert JSON, not executable pickle.

Run tests: python3 -m unittest discover -v
Integration test: ./shadow6_detector.py --test


NEO SEQUENCE DETECTOR

DEPENDENCIES REQUIRED
---------------------
pip install -r ../requirements.txt -r ../requirements-ml.txt

TO RUN UNIT TESTS
-----------------
./shadow6_detector_neo.py --test

TO EXTRACT PCAP TO CSV (INCLUDING INTER-ARRIVAL TIME)
-----------------------------------------------------
./shadow6_detector_neo.py --extract-pcap normal.pcap probes.pcap extracted_features.csv

TO TRAIN RANDOM FOREST MODEL
----------------------------
./shadow6_detector_neo.py --train extracted_features.csv rf_model.json --model-type rf

TO TRAIN PYTORCH LSTM MODEL (ADVANCED SEQUENTIAL DETECTION)
-----------------------------------------------------------
./shadow6_detector_neo.py --train extracted_features.csv lstm_model.pth --model-type lstm

TO RUN REAL-TIME DETECTION (REQUIRES ROOT)
------------------------------------------
./shadow6_detector_neo.py --detect --model-path lstm_model.pth --model-type lstm --interface any

TO ENABLE ACTIVE TARPIT DECOY
-----------------------------
./shadow6_detector.py --decoy --decoy-port 8080



How to use watch.py:

# Standard usage (Recommended)
python3 Detector/watch.py --topo Auto-Orchestrator/shadow-net.yaml

# Using the sequence-aware LSTM detector
python3 Detector/watch.py --neo --model Detector/lstm_model.pth --topo Auto-Orchestrator/shadow-net.yaml
