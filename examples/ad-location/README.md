# ad-location

GPS route anomaly detection tool that compares test GPS tracks against reference tracks to identify position deviations.

## Description

This tool analyzes GPS position data to detect anomalies by comparing test tracks with reference tracks. It calculates the distance between GPS points and flags deviations exceeding a configurable threshold.

## Features

- GPS distance calculation using Haversine formula
- Configurable position deviation threshold
- JSONL format support for GPS data
- Anomaly detection with detailed deviation reporting

## Installation

```bash
pip install pyyaml
```

## Usage

```python
from routeAnalyser import RouteAnalyzer

analyzer = RouteAnalyzer(
    referenceFile="positions_normal.jsonl",
    testFile="position_hack.jsonl",
    configFile="config.yaml"
)
result = analyzer.analyze()
```

Run the example:
```bash
python exemple.py
```

## Configuration

Edit `config.yaml` to set the position threshold in meters:

```yaml
positionThresholdMeters: 20
```

## Data Format

GPS data should be in JSONL format with `latitude` and `longitude` fields:

```json
{"latitude": 48.8566, "longitude": 2.3522}
```

## Output

The tool generates a `position.json` file with:
- `events`: The GPS event being analyzed
- `deviation`: Distance in meters from the reference track
- `anomalies`: Status (`confirmed_anomalies` or `no_anomalies`)
