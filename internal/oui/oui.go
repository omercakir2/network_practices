// Package oui provides a small offline MAC OUI → vendor lookup.
//
// This is intentionally a curated subset of common consumer and network
// equipment OUIs — enough to be useful on a home/office LAN without shipping
// the full IEEE database.
package oui

import (
	"fmt"
	"net"
)

// Lookup returns a vendor name for the given MAC, or "Unknown".
// Matches on the first 3 octets (standard 24-bit OUI).
// Locally administered addresses (common on phones with MAC randomization)
// are reported as "Randomized MAC".
func Lookup(mac net.HardwareAddr) string {
	if len(mac) < 3 {
		return "Unknown"
	}
	// IEEE: U/L bit is the second least-significant bit of the first octet.
	if mac[0]&0x02 != 0 {
		return "Randomized MAC"
	}
	key := fmt.Sprintf("%02X:%02X:%02X", mac[0], mac[1], mac[2])
	if v, ok := vendors[key]; ok {
		return v
	}
	return "Unknown"
}

// Curated OUI prefixes (AA:BB:CC → vendor). Not exhaustive.
var vendors = map[string]string{
	// --- Network infrastructure ---
	"00:00:0C": "Cisco", "00:01:42": "Cisco", "00:01:43": "Cisco",
	"00:0A:41": "Cisco", "00:0A:B8": "Cisco", "00:0F:23": "Cisco",
	"00:1A:A1": "Cisco", "00:1B:D4": "Cisco", "00:1C:0E": "Cisco",
	"00:1E:13": "Cisco", "00:1E:14": "Cisco", "00:21:1B": "Cisco",
	"00:22:90": "Cisco", "00:23:04": "Cisco", "00:23:5E": "Cisco",
	"00:24:14": "Cisco", "00:25:45": "Cisco", "00:26:0B": "Cisco",
	"00:26:CA": "Cisco", "00:30:94": "Cisco", "00:30:F2": "Cisco",
	"00:40:96": "Cisco", "00:50:0F": "Cisco", "00:50:14": "Cisco",
	"00:60:09": "Cisco", "00:60:2F": "Cisco", "00:90:21": "Cisco",
	"00:D0:BC": "Cisco", "00:E0:1E": "Cisco", "04:C5:A4": "Cisco",
	"08:1F:F3": "Cisco", "0C:68:03": "Cisco", "18:80:F5": "Cisco",
	"1C:1D:86": "Cisco", "28:94:0F": "Cisco", "2C:3E:CF": "Cisco",
	"2C:54:2D": "Cisco", "3C:08:F6": "Cisco", "40:55:39": "Cisco",
	"44:03:A7": "Cisco", "50:1C:BF": "Cisco", "54:75:D0": "Cisco",
	"58:AC:78": "Cisco", "64:00:F1": "Cisco", "68:BC:0C": "Cisco",
	"70:10:5C": "Cisco", "70:CA:9B": "Cisco", "78:DA:6E": "Cisco",
	"84:78:AC": "Cisco", "88:1D:FC": "Cisco", "A0:E0:AF": "Cisco",
	"B0:00:B4": "Cisco", "C4:71:FE": "Cisco", "D0:C2:82": "Cisco",
	"E0:5F:B9": "Cisco", "E8:04:62": "Cisco", "F4:0F:1B": "Cisco",
	"F8:0B:CB": "Cisco", "FC:5B:39": "Cisco",

	"00:15:6D": "Ubiquiti", "00:27:22": "Ubiquiti", "04:18:D6": "Ubiquiti",
	"18:E8:29": "Ubiquiti", "24:5A:4C": "Ubiquiti", "24:A4:3C": "Ubiquiti",
	"44:D9:E7": "Ubiquiti", "60:22:32": "Ubiquiti", "68:72:51": "Ubiquiti",
	"74:83:C2": "Ubiquiti", "78:8A:20": "Ubiquiti", "80:2A:A8": "Ubiquiti",
	"B4:FB:E4": "Ubiquiti", "DC:9F:DB": "Ubiquiti", "E0:63:DA": "Ubiquiti",
	"F0:9F:C2": "Ubiquiti", "FC:EC:DA": "Ubiquiti",

	"00:27:19": "TP-Link", "14:CC:20": "TP-Link", "14:CF:92": "TP-Link",
	"18:A6:F7": "TP-Link", "1C:3B:F3": "TP-Link", "30:B5:C2": "TP-Link",
	"50:C7:BF": "TP-Link", "54:C8:0F": "TP-Link", "5C:63:BF": "TP-Link",
	"60:32:B1": "TP-Link", "64:70:02": "TP-Link", "6C:5A:B0": "TP-Link",
	"74:DA:88": "TP-Link", "98:DA:C4": "TP-Link", "A0:F3:C1": "TP-Link",
	"B0:4E:26": "TP-Link", "C0:25:E9": "TP-Link", "C0:4A:00": "TP-Link",
	"D8:0D:17": "TP-Link", "E8:DE:27": "TP-Link", "F4:EC:38": "TP-Link",
	"F4:F2:6D": "TP-Link", "F8:1A:67": "TP-Link",

	"00:09:5B": "Netgear", "00:0F:B5": "Netgear", "00:14:6C": "Netgear",
	"00:1B:2F": "Netgear", "00:1E:2A": "Netgear", "00:1F:33": "Netgear",
	"00:22:3F": "Netgear", "00:24:B2": "Netgear", "00:26:F2": "Netgear",
	"04:A1:51": "Netgear", "08:BD:43": "Netgear", "10:0D:7F": "Netgear",
	"20:0C:C8": "Netgear", "20:4E:7F": "Netgear", "28:C6:8E": "Netgear",
	"30:46:9A": "Netgear", "3C:37:86": "Netgear", "44:94:FC": "Netgear",
	"6C:B0:CE": "Netgear", "A0:04:60": "Netgear", "A0:21:B7": "Netgear",
	"B0:39:56": "Netgear", "C0:3F:0E": "Netgear", "E0:46:9A": "Netgear",

	"00:0C:6E": "ASUS", "00:0E:A6": "ASUS", "00:11:2F": "ASUS",
	"00:13:D4": "ASUS", "00:15:F2": "ASUS", "00:17:31": "ASUS",
	"00:1A:92": "ASUS", "00:1B:FC": "ASUS", "00:1D:60": "ASUS",
	"00:1E:8C": "ASUS", "00:1F:C6": "ASUS", "00:22:15": "ASUS",
	"00:23:54": "ASUS", "00:24:8C": "ASUS", "00:26:18": "ASUS",
	"04:92:26": "ASUS", "08:60:6E": "ASUS", "10:7B:44": "ASUS",
	"14:DD:A9": "ASUS", "2C:4D:54": "ASUS", "2C:56:DC": "ASUS",
	"30:85:A9": "ASUS", "38:D5:47": "ASUS", "40:16:7E": "ASUS",
	"50:46:5D": "ASUS", "54:A0:50": "ASUS", "60:45:CB": "ASUS",
	"70:4D:7B": "ASUS", "88:D7:F6": "ASUS", "AC:22:0B": "ASUS",
	"B0:6E:BF": "ASUS", "BC:EE:7B": "ASUS", "D4:5D:64": "ASUS",
	"E0:3F:49": "ASUS", "F0:79:59": "ASUS", "FC:34:97": "ASUS",

	"00:0C:42": "MikroTik", "08:55:31": "MikroTik", "2C:C8:1B": "MikroTik",
	"4C:5E:0C": "MikroTik", "64:D1:54": "MikroTik", "6C:3B:6B": "MikroTik",
	"74:4D:28": "MikroTik", "B8:69:F4": "MikroTik", "C4:AD:34": "MikroTik",
	"CC:2D:E0": "MikroTik", "D4:CA:6D": "MikroTik", "E4:8D:8C": "MikroTik",

	"00:0B:86": "Aruba", "00:1A:1E": "Aruba", "04:BD:88": "Aruba",
	"18:64:72": "Aruba", "24:DE:C6": "Aruba", "40:E3:D6": "Aruba",
	"6C:F3:7F": "Aruba", "84:D4:7E": "Aruba", "9C:1C:12": "Aruba",
	"D8:C7:C8": "Aruba", "F0:5C:19": "Aruba",

	"00:05:85": "Juniper", "00:10:DB": "Juniper", "00:12:1E": "Juniper",
	"00:17:CB": "Juniper", "00:19:E2": "Juniper", "00:1F:12": "Juniper",
	"00:21:59": "Juniper", "00:23:9C": "Juniper", "00:26:88": "Juniper",
	"28:8A:1C": "Juniper", "2C:21:31": "Juniper", "3C:61:04": "Juniper",
	"54:4B:8C": "Juniper", "78:19:F7": "Juniper", "84:18:88": "Juniper",
	"88:E0:F3": "Juniper", "F0:1C:2D": "Juniper",

	"00:01:E6": "HP", "00:01:E7": "HP", "00:08:02": "HP",
	"00:0B:CD": "HP", "00:0F:20": "HP", "00:11:0A": "HP",
	"00:14:C2": "HP", "00:17:A4": "HP", "00:1A:4B": "HP",
	"00:1E:0B": "HP", "00:21:5A": "HP", "00:23:7D": "HP",
	"00:25:B3": "HP", "00:30:6E": "HP", "08:00:09": "HP",
	"10:60:4B": "HP", "18:A9:05": "HP", "2C:41:38": "HP",
	"3C:D9:2B": "HP", "64:31:50": "HP", "78:E3:B5": "HP",
	"9C:8E:99": "HP", "A0:1D:48": "HP", "B0:5A:DA": "HP",
	"C8:CB:B8": "HP", "D0:7E:28": "HP", "F4:CE:46": "HP",

	// --- End-user / compute ---
	"00:03:93": "Apple", "00:0A:27": "Apple", "00:0A:95": "Apple",
	"00:0D:93": "Apple", "00:11:24": "Apple", "00:14:51": "Apple",
	"00:16:CB": "Apple", "00:17:F2": "Apple", "00:19:E3": "Apple",
	"00:1B:63": "Apple", "00:1E:52": "Apple", "00:1E:C2": "Apple",
	"00:1F:5B": "Apple", "00:1F:F3": "Apple", "00:21:E9": "Apple",
	"00:22:41": "Apple", "00:23:12": "Apple", "00:23:32": "Apple",
	"00:23:6C": "Apple", "00:23:DF": "Apple", "00:24:36": "Apple",
	"00:25:00": "Apple", "00:25:4B": "Apple", "00:25:BC": "Apple",
	"00:26:08": "Apple", "00:26:4A": "Apple", "00:26:B0": "Apple",
	"00:26:BB": "Apple", "00:61:71": "Apple", "00:C6:10": "Apple",
	"04:0C:CE": "Apple", "04:15:52": "Apple", "08:00:07": "Apple",
	"08:66:98": "Apple", "08:74:02": "Apple", "0C:74:C2": "Apple",
	"10:40:F3": "Apple", "10:93:E9": "Apple", "14:10:9F": "Apple",
	"14:7D:DA": "Apple", "18:65:90": "Apple", "18:AF:61": "Apple",
	"1C:1A:C0": "Apple", "1C:36:BB": "Apple", "1C:AB:A7": "Apple",
	"20:78:F0": "Apple", "20:A2:E4": "Apple", "24:A0:74": "Apple",
	"28:37:37": "Apple", "28:CF:E9": "Apple", "28:E0:2C": "Apple",
	"2C:1F:23": "Apple", "2C:BE:08": "Apple", "30:90:AB": "Apple",
	"34:15:9E": "Apple", "34:36:3B": "Apple", "34:A3:95": "Apple",
	"38:C9:86": "Apple", "3C:07:54": "Apple", "3C:15:C2": "Apple",
	"40:33:1A": "Apple", "40:A6:D9": "Apple", "44:00:10": "Apple",
	"44:2A:60": "Apple", "48:43:7C": "Apple", "48:A1:95": "Apple",
	"4C:74:BF": "Apple", "4C:8D:79": "Apple", "50:EA:D6": "Apple",
	"54:26:96": "Apple", "54:72:4F": "Apple", "58:55:CA": "Apple",
	"58:B0:35": "Apple", "5C:95:AE": "Apple", "5C:F7:E6": "Apple",
	"60:03:08": "Apple", "60:33:4B": "Apple", "60:69:44": "Apple",
	"60:F8:1D": "Apple", "64:A3:CB": "Apple", "64:B0:A6": "Apple",
	"68:09:27": "Apple", "68:5B:35": "Apple", "68:96:7B": "Apple",
	"68:A8:6D": "Apple", "6C:40:08": "Apple", "6C:72:E7": "Apple",
	"6C:8D:C1": "Apple", "70:11:24": "Apple", "70:48:0F": "Apple",
	"70:56:81": "Apple", "70:A2:B3": "Apple", "70:DE:E2": "Apple",
	"74:1B:B2": "Apple", "78:31:C1": "Apple", "78:4F:43": "Apple",
	"78:7E:61": "Apple", "78:A3:E4": "Apple", "7C:04:D0": "Apple",
	"7C:6D:62": "Apple", "7C:C3:A1": "Apple", "7C:D1:C3": "Apple",
	"80:00:6E": "Apple", "80:49:71": "Apple", "80:E6:50": "Apple",
	"80:EA:96": "Apple", "84:38:35": "Apple", "84:85:06": "Apple",
	"84:A1:34": "Apple", "84:FC:FE": "Apple", "88:63:DF": "Apple",
	"88:66:A5": "Apple", "88:C6:63": "Apple", "8C:2D:AA": "Apple",
	"8C:58:77": "Apple", "8C:7C:92": "Apple", "8C:85:90": "Apple",
	"90:27:E4": "Apple", "90:72:40": "Apple", "90:84:0D": "Apple",
	"90:B0:ED": "Apple", "90:FD:61": "Apple", "94:E9:6A": "Apple",
	"98:01:A7": "Apple", "98:03:D8": "Apple", "98:10:E8": "Apple",
	"98:5A:EB": "Apple", "98:B8:E3": "Apple", "98:D6:BB": "Apple",
	"98:E0:D9": "Apple", "98:F0:AB": "Apple", "9C:04:EB": "Apple",
	"9C:20:7B": "Apple", "9C:84:BF": "Apple", "9C:F3:87": "Apple",
	"A0:99:9B": "Apple", "A0:D7:95": "Apple", "A4:5E:60": "Apple",
	"A4:83:E7": "Apple", "A4:B1:97": "Apple", "A4:C3:61": "Apple",
	"A4:D1:8C": "Apple", "A8:20:66": "Apple", "A8:5B:78": "Apple",
	"A8:60:B6": "Apple", "A8:66:7F": "Apple", "A8:96:8A": "Apple",
	"A8:BB:CF": "Apple", "AC:1F:74": "Apple", "AC:29:3A": "Apple",
	"AC:87:A3": "Apple", "AC:BC:32": "Apple", "AC:DE:48": "Apple",
	"B0:65:BD": "Apple", "B4:18:D1": "Apple", "B4:F0:AB": "Apple",
	"B8:09:8A": "Apple", "B8:17:C2": "Apple", "B8:53:AC": "Apple",
	"B8:63:4D": "Apple", "B8:C7:5D": "Apple", "B8:E8:56": "Apple",
	"B8:F6:B1": "Apple", "BC:3B:AF": "Apple", "BC:52:B7": "Apple",
	"BC:67:78": "Apple", "BC:6C:21": "Apple", "BC:92:6B": "Apple",
	"C0:1A:DA": "Apple", "C0:63:94": "Apple", "C0:A5:3E": "Apple",
	"C0:CC:F8": "Apple", "C4:B3:01": "Apple", "C8:1E:E7": "Apple",
	"C8:2A:14": "Apple", "C8:33:4B": "Apple", "C8:69:CD": "Apple",
	"C8:B5:B7": "Apple", "C8:BC:C8": "Apple", "C8:E0:EB": "Apple",
	"CC:08:E0": "Apple", "CC:25:EF": "Apple", "CC:29:F5": "Apple",
	"CC:44:63": "Apple", "D0:03:4B": "Apple", "D0:23:DB": "Apple",
	"D0:25:98": "Apple", "D0:4F:7E": "Apple", "D0:A6:37": "Apple",
	"D4:61:9D": "Apple", "D4:9A:20": "Apple", "D8:1C:79": "Apple",
	"D8:30:62": "Apple", "D8:96:95": "Apple", "D8:A2:5E": "Apple",
	"D8:BB:2C": "Apple", "D8:CF:9C": "Apple", "DC:2B:2A": "Apple",
	"DC:2B:61": "Apple", "DC:37:14": "Apple", "DC:41:5F": "Apple",
	"DC:56:E7": "Apple", "DC:86:D8": "Apple", "DC:A9:04": "Apple",
	"E0:AC:CB": "Apple", "E0:B5:2D": "Apple", "E0:C9:7A": "Apple",
	"E0:F5:C6": "Apple", "E4:25:E7": "Apple", "E4:8B:7F": "Apple",
	"E4:9A:DC": "Apple", "E4:C6:3D": "Apple", "E4:CE:8F": "Apple",
	"E8:04:0B": "Apple", "E8:06:88": "Apple", "E8:80:2E": "Apple",
	"E8:8D:28": "Apple", "EC:35:86": "Apple", "F0:18:98": "Apple",
	"F0:24:75": "Apple", "F0:B4:79": "Apple", "F0:C1:F1": "Apple",
	"F0:DB:E2": "Apple", "F0:DB:F8": "Apple", "F4:0F:24": "Apple",
	"F4:1B:A1": "Apple", "F4:F1:5A": "Apple", "F8:1E:DF": "Apple",
	"F8:27:93": "Apple", "F8:62:14": "Apple", "FC:25:3F": "Apple",
	"FC:E9:98": "Apple", "FC:FC:48": "Apple",

	"00:07:AB": "Samsung", "00:12:47": "Samsung", "00:12:FB": "Samsung",
	"00:13:77": "Samsung", "00:15:99": "Samsung", "00:16:32": "Samsung",
	"00:16:6B": "Samsung", "00:17:C9": "Samsung", "00:18:AF": "Samsung",
	"00:1A:8A": "Samsung", "00:1B:98": "Samsung", "00:1C:43": "Samsung",
	"00:1D:25": "Samsung", "00:1E:7D": "Samsung", "00:1F:CC": "Samsung",
	"00:21:19": "Samsung", "00:21:4C": "Samsung", "00:23:39": "Samsung",
	"00:23:99": "Samsung", "00:24:54": "Samsung", "00:24:90": "Samsung",
	"00:25:66": "Samsung", "00:26:37": "Samsung", "00:26:5D": "Samsung",
	"04:FE:31": "Samsung", "08:37:3D": "Samsung", "08:D4:2B": "Samsung",
	"10:1D:C0": "Samsung", "14:49:E0": "Samsung", "14:A3:64": "Samsung",
	"18:3A:2D": "Samsung", "1C:62:B8": "Samsung", "20:55:31": "Samsung",
	"24:18:1D": "Samsung", "28:39:5E": "Samsung", "2C:44:01": "Samsung",
	"30:19:66": "Samsung", "34:23:BA": "Samsung", "38:01:95": "Samsung",
	"3C:5A:37": "Samsung", "40:0E:85": "Samsung", "44:78:3E": "Samsung",
	"50:01:BB": "Samsung", "50:32:75": "Samsung", "5C:0A:5B": "Samsung",
	"60:6B:BD": "Samsung", "68:27:37": "Samsung", "70:F9:27": "Samsung",
	"78:1F:DB": "Samsung", "78:25:AD": "Samsung", "7C:1C:68": "Samsung",
	"80:57:19": "Samsung", "84:25:DB": "Samsung", "88:32:9B": "Samsung",
	"8C:71:F8": "Samsung", "90:00:DB": "Samsung", "94:35:0A": "Samsung",
	"A0:07:98": "Samsung", "A0:21:95": "Samsung", "A8:7C:01": "Samsung",
	"AC:5F:3E": "Samsung", "B0:C5:59": "Samsung", "B4:79:A7": "Samsung",
	"BC:14:85": "Samsung", "BC:20:A4": "Samsung", "BC:72:B1": "Samsung",
	"C0:65:99": "Samsung", "C8:14:79": "Samsung", "CC:07:AB": "Samsung",
	"D0:17:6A": "Samsung", "D0:22:BE": "Samsung", "D8:57:EF": "Samsung",
	"E4:40:E2": "Samsung", "E8:50:8B": "Samsung", "EC:1F:72": "Samsung",
	"F0:25:B7": "Samsung", "F4:09:D8": "Samsung", "F8:04:2E": "Samsung",
	"FC:A1:3E": "Samsung",

	"00:1A:11": "Google", "3C:5A:B4": "Google", "54:60:09": "Google",
	"94:EB:2C": "Google", "F4:F5:D8": "Google", "F4:F5:E8": "Google",
	"DA:A1:19": "Google", "18:B4:30": "Nest", "64:16:66": "Nest",

	"00:03:FF": "Microsoft", "00:0D:3A": "Microsoft", "00:12:5A": "Microsoft",
	"00:15:5D": "Microsoft", "00:17:FA": "Microsoft", "00:1D:D8": "Microsoft",
	"00:22:48": "Microsoft", "00:25:AE": "Microsoft", "00:50:F2": "Microsoft",
	"28:18:78": "Microsoft", "7C:1E:52": "Microsoft",

	"00:02:B3": "Intel", "00:03:47": "Intel", "00:04:23": "Intel",
	"00:07:E9": "Intel", "00:0E:0C": "Intel", "00:12:F0": "Intel",
	"00:13:02": "Intel", "00:13:20": "Intel", "00:13:CE": "Intel",
	"00:15:00": "Intel", "00:16:6F": "Intel", "00:16:EA": "Intel",
	"00:18:DE": "Intel", "00:19:D1": "Intel", "00:1B:21": "Intel",
	"00:1C:BF": "Intel", "00:1E:64": "Intel", "00:1E:67": "Intel",
	"00:1F:3B": "Intel", "00:21:5C": "Intel", "00:21:6A": "Intel",
	"00:22:FA": "Intel", "00:24:D6": "Intel", "00:26:C6": "Intel",
	"00:27:10": "Intel", "3C:F8:62": "Intel", "48:51:B7": "Intel",
	"68:05:CA": "Intel", "8C:A9:82": "Intel", "A0:36:9F": "Intel",
	"A4:34:D9": "Intel", "B8:08:CF": "Intel", "D8:F2:CA": "Intel",
	"F8:34:41": "Intel", "F8:63:3F": "Intel",

	"00:06:5B": "Dell", "00:08:74": "Dell", "00:0B:DB": "Dell",
	"00:0D:56": "Dell", "00:0F:1F": "Dell", "00:11:43": "Dell",
	"00:12:3F": "Dell", "00:13:72": "Dell", "00:14:22": "Dell",
	"00:15:C5": "Dell", "00:18:8B": "Dell", "00:1A:A0": "Dell",
	"00:1C:23": "Dell", "00:1D:09": "Dell", "00:1E:4F": "Dell",
	"00:21:70": "Dell", "00:21:9B": "Dell", "00:22:19": "Dell",
	"00:23:AE": "Dell", "00:24:E8": "Dell", "00:25:64": "Dell",
	"00:26:B9": "Dell", "14:18:77": "Dell", "18:03:73": "Dell",
	"18:A9:9B": "Dell", "24:6E:96": "Dell", "28:F1:0E": "Dell",
	"34:17:EB": "Dell", "44:A8:42": "Dell", "4C:76:25": "Dell",
	"74:86:7A": "Dell", "74:E6:E2": "Dell", "84:2B:2B": "Dell",
	"A4:BA:DB": "Dell", "B0:83:FE": "Dell", "B8:AC:6F": "Dell",
	"D0:67:E5": "Dell", "D4:BE:D9": "Dell", "F8:B1:56": "Dell",
	"F8:BC:12": "Dell",

	// Additional common consumer / CPE vendors
	"3C:94:FD": "Cisco/Linksys", "C8:4F:86": "Sony", "A4:D7:3C": "TP-Link",
	"48:4D:7E": "HP",

	// --- IoT / media / embedded ---
	"B8:27:EB": "Raspberry Pi", "DC:A6:32": "Raspberry Pi",
	"E4:5F:01": "Raspberry Pi", "28:CD:C1": "Raspberry Pi",
	"2C:CF:67": "Raspberry Pi", "D8:3A:DD": "Raspberry Pi",

	"18:FE:34": "Espressif", "24:0A:C4": "Espressif", "24:6F:28": "Espressif",
	"24:B2:DE": "Espressif", "2C:3A:E8": "Espressif", "30:AE:A4": "Espressif",
	"3C:71:BF": "Espressif", "40:F5:20": "Espressif", "48:3F:DA": "Espressif",
	"4C:11:AE": "Espressif", "5C:CF:7F": "Espressif", "60:01:94": "Espressif",
	"68:C6:3A": "Espressif", "84:0D:8E": "Espressif", "84:CC:A8": "Espressif",
	"84:F3:EB": "Espressif", "90:97:D5": "Espressif", "A0:20:A6": "Espressif",
	"A4:CF:12": "Espressif", "AC:67:B2": "Espressif", "B4:E6:2D": "Espressif",
	"BC:DD:C2": "Espressif", "C4:4F:33": "Espressif", "C8:2B:96": "Espressif",
	"CC:50:E3": "Espressif", "D8:A0:1D": "Espressif", "DC:4F:22": "Espressif",
	"E0:98:06": "Espressif", "EC:FA:BC": "Espressif", "FC:F5:C4": "Espressif",

	"0C:47:C9": "Amazon", "10:CE:A9": "Amazon", "34:D2:70": "Amazon",
	"40:B4:CD": "Amazon", "44:65:0D": "Amazon", "4C:EF:C0": "Amazon",
	"50:DC:E7": "Amazon", "68:37:E9": "Amazon", "68:54:FD": "Amazon",
	"74:75:48": "Amazon", "84:D6:D0": "Amazon", "A0:02:DC": "Amazon",
	"AC:63:BE": "Amazon", "B4:7C:9C": "Amazon", "CC:9E:A2": "Amazon",
	"F0:27:2D": "Amazon", "F0:4F:7C": "Amazon", "FC:65:DE": "Amazon",

	"00:0E:58": "Sonos", "34:7E:5C": "Sonos", "48:A6:B8": "Sonos",
	"5C:AA:FD": "Sonos", "78:28:CA": "Sonos", "94:9F:3E": "Sonos",
	"B8:E9:37": "Sonos",

	"00:0D:4B": "Roku", "08:05:81": "Roku", "B0:A7:37": "Roku",
	"B8:3E:59": "Roku", "C8:3A:6B": "Roku", "D0:4D:2C": "Roku",
	"D8:31:34": "Roku", "DC:3A:5E": "Roku",

	"00:17:88": "Philips Hue", "EC:B5:FA": "Philips Hue",

	"00:9E:C8": "Xiaomi", "0C:1D:AF": "Xiaomi", "14:F6:5A": "Xiaomi",
	"28:6C:07": "Xiaomi", "34:80:B3": "Xiaomi", "50:8F:4C": "Xiaomi",
	"64:09:80": "Xiaomi", "64:B4:73": "Xiaomi", "68:DF:DD": "Xiaomi",
	"78:02:F8": "Xiaomi", "7C:1D:D9": "Xiaomi", "8C:BE:BE": "Xiaomi",
	"AC:F7:F3": "Xiaomi", "F0:B4:29": "Xiaomi", "F8:A4:5F": "Xiaomi",

	// --- Virtualization ---
	"00:05:69": "VMware", "00:0C:29": "VMware", "00:1C:14": "VMware",
	"00:50:56": "VMware",
	"08:00:27": "VirtualBox", "0A:00:27": "VirtualBox",
	"52:54:00": "QEMU/KVM",
	"00:1C:42": "Parallels",

	// --- Common NIC chipsets ---
	"00:E0:4C": "Realtek",
	"00:05:B5": "Broadcom", "00:0A:F7": "Broadcom", "00:10:18": "Broadcom",
}
