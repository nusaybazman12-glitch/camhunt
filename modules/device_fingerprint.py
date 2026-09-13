"""Device fingerprint - MAC OUI to vendor mapping"""


class DeviceFingerprint:
    CAMERA_PREFIXES = {
        "44:19:B6": "Hikvision Camera", "C0:56:E3": "Hikvision Camera",
        "BC:AD:28": "Hikvision Camera", "3C:EF:8C": "Dahua Camera",
        "90:02:A9": "Dahua Camera", "4C:11:BF": "Dahua Camera",
        "00:40:8C": "Axis Camera", "AC:CC:8E": "Axis Camera",
        "2C:AA:8E": "Wyze Camera", "7C:78:B2": "Wyze Camera",
        "EC:71:DB": "Reolink Camera", "00:62:6E": "Foscam Camera",
        "9C:8E:CD": "Amcrest Camera", "C4:2F:90": "EZVIZ Camera",
        "BC:7E:8B": "EZVIZ Camera", "F0:9F:C2": "Xiaomi Camera",
        "64:B4:73": "Xiaomi Camera", "78:11:DC": "Xiaomi Camera",
    }
    ROUTER_PREFIXES = {
        "A4:2B:B0": "TP-Link Router", "50:C7:BF": "TP-Link Router",
        "B0:4E:26": "TP-Link Router", "00:1A:2B": "Cisco Router",
        "00:1E:BD": "Cisco Router",
    }
    PHONE_PREFIXES = {
        "00:1A:11": "Google Device", "3C:5A:B4": "Google Device",
        "84:38:38": "Apple Device", "F0:18:98": "Apple Device",
    }

    @classmethod
    def identify(cls, mac):
        if not mac or mac == "N/A":
            return "Unknown"
        p = mac[:8].upper()
        if p in cls.CAMERA_PREFIXES:
            return cls.CAMERA_PREFIXES[p]
        if p in cls.ROUTER_PREFIXES:
            return cls.ROUTER_PREFIXES[p]
        if p in cls.PHONE_PREFIXES:
            return cls.PHONE_PREFIXES[p]
        return "Generic Device"

    @classmethod
    def is_camera(cls, mac):
        if not mac or mac == "N/A":
            return False
        return mac[:8].upper() in cls.CAMERA_PREFIXES
