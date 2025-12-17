# main.py

import json
from routeAnalyser import RouteAnalyzer

if __name__ == "__main__":
    analyzer = RouteAnalyzer(
        referenceFile="positions_normal.jsonl",
        testFile="position_hack.jsonl",
        configFile="config.yaml"
    )
    result = analyzer.analyze()
    print(json.dumps(result, indent=4))
