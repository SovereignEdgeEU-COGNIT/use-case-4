import json
import re
from math import radians, cos, sin, asin, sqrt
import os
import yaml
from collections import OrderedDict

class GpsPoint:
    def __init__(self, latitude, longitude):
        self.latitude = latitude
        self.longitude = longitude

    def distanceTo(self, other):
        R = 6371000  # Rayon de la Terre en mètres
        dLat = radians(other.latitude - self.latitude)
        dLon = radians(other.longitude - self.longitude)
        a = sin(dLat / 2)**2 + cos(radians(self.latitude)) * cos(radians(other.latitude)) * sin(dLon / 2)**2
        c = 2 * asin(sqrt(a))
        return R * c

class ReferenceTrack:
    def __init__(self, filePath):
        self.points = self._loadPoints(filePath)

    def _loadPoints(self, path):
        points = []
        with open(path, 'r') as file:
            for line in file:
                line = self._fixJson(line)
                if line:
                    try:
                        obj = json.loads(line)
                        point = GpsPoint(obj['latitude'], obj['longitude'])
                        points.append(point)
                    except (json.JSONDecodeError, KeyError):
                        continue
        return points

    def _fixJson(self, line):
        if not line.strip():
            return None
        line = re.sub(r"([{,]\s*)(\w+)(\s*:)", r'\1"\2"\3', line)
        return line.replace("'", '"')

    def findClosestPoint(self, testPoint):
        closest = None
        minDistance = float('inf')
        for refPoint in self.points:
            distance = testPoint.distanceTo(refPoint)
            if distance < minDistance:
                minDistance = distance
                closest = refPoint
        return closest, minDistance

class TestTrack:
    def __init__(self, filePath):
        self.point = None
        self.rawEvent = None
        self._loadFirstPoint(filePath)

    def _loadFirstPoint(self, path):
        with open(path, 'r') as file:
            for line in file:
                lineFixed = self._fixJson(line)
                if lineFixed:
                    try:
                        obj = json.loads(lineFixed)
                        self.rawEvent = obj
                        self.point = GpsPoint(obj['latitude'], obj['longitude'])
                        break
                    except (json.JSONDecodeError, KeyError):
                        continue

    def _fixJson(self, line):
        if not line.strip():
            return None
        line = re.sub(r"([{,]\s*)(\w+)(\s*:)", r'\1"\2"\3', line)
        return line.replace("'", '"')

class RouteAnalyzer:
    def __init__(self, referenceFile, testFile, configFile="config.yaml"):
        self.referenceTrack = ReferenceTrack(referenceFile)
        self.testTrack = TestTrack(testFile)
        self.config = self._loadConfig(configFile)

        if "positionThresholdMeters" not in self.config:
            raise ValueError("Le fichier de configuration doit contenir la clé 'positionThresholdMeters'.")

        self.positionThreshold = self.config["positionThresholdMeters"]

    def _loadConfig(self, configPath):
        if os.path.exists(configPath):
            try:
                with open(configPath, 'r') as f:
                    return yaml.safe_load(f)
            except Exception as e:
                raise RuntimeError(f"Erreur lors du chargement du fichier de configuration : {e}")
        else:
            raise FileNotFoundError(f"Fichier de configuration introuvable : {configPath}")

    def analyze(self):
        result = OrderedDict()

        if not self.testTrack.point or not self.referenceTrack.points:
            #result["positionAnomaly"] = False
            #result["DeviationPositionMeters"] = None
            #result["event"] = None
            result["events"] = None
            result["deviation"] = None
            result["anomalies"] = "no_anomalies"
            return result

        closestRef, distance = self.referenceTrack.findClosestPoint(self.testTrack.point)
        deviation = int(round(distance))
        positionAnomaly = deviation > self.positionThreshold

        if positionAnomaly:
            result["events"] = self.testTrack.rawEvent
            result["deviation"] = deviation
            result["anomalies"] = "confirmed_anomalies"

        else:
            result["events"] = self.testTrack.rawEvent
            result["deviation"] = 0
            result["anomalies"] = "no_anomalies"

        json_output = json.dumps(result, indent=4)

        #print(json_output)
        with open("position.json", "w") as file:
            file.write(json_output)

        return result


