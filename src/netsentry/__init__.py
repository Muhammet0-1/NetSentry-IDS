"""NetSentry IDS package."""

from netsentry.config import DetectionConfig
from netsentry.detector import SynDetector
from netsentry.models import Alert, PacketMetadata

__all__ = ["Alert", "DetectionConfig", "PacketMetadata", "SynDetector"]
__version__ = "0.2.0"
