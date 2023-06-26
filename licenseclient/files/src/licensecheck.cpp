#include <iostream>
#include <unordered_map>
#include <licensecc/licensecc.h>
#include <string.h>
using namespace std;

#include <string>
#include <cstdio>

#include <unistd.h>

bool is_root() {
    return getuid() == 0;
}

// Function to extract integer from a string
int extractNumber(const char* str) {
    std::string strFeature(str);

    // Find the position of the first numeric character
    std::size_t pos = strFeature.find_first_of("0123456789");

    // If a numeric character was found
    if (pos != std::string::npos) {
        // Get the substring from that position onward
        std::string num_str = strFeature.substr(pos);

        // Convert the numeric part of the string to an int and return it
        return std::stoi(num_str);
    }
    
    // If no numeric character was found, return a default value
    return -1;
}

LCC_EVENT_TYPE extracted_cpu(LicenseInfo &licenseInfo) {
  auto dummy = extractNumber(licenseInfo.feature_name);
  int cpuNum = dummy;
  if (cpuNum != -1) {
    cout << "CPU number licensed : " << cpuNum << endl;
    int cpuCores = detect_CPUcores();
    cout << "CPU number detected : " << cpuCores << endl;
    if (cpuNum < cpuCores) {
      cout << "CPU number mismatch" << endl;
      return FEATURE_MISMATCH;
    } else {
      cout << "CPU number OK" << endl;
      return LICENSE_OK;
    }
  } else {
	cout << "CPU number not licensed" << endl;
 	return FEATURE_MISMATCH;
  }
}

int get_wg_vpn_service_count(const char* command) {
    FILE* pipe = popen(command, "r");
    if (!pipe) {
        std::cerr << "popen() failed!" << std::endl;
        return -1;
    }
    char buffer[128];
    int interface_count = 0;
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        if (strncmp(buffer, "interface:", 10) == 0) {
            ++interface_count;
        }
    }
    pclose(pipe);
    return interface_count;
}

int get_ipsec_vpn_service_count(const char* command) {
    FILE* pipe = popen(command, "r");
    if (!pipe) {
        std::cerr << "popen() failed!" << std::endl;
        return -1;
    }
    char buffer[128];
    int connection_count = 0;
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        if (strstr(buffer, "ESTABLISHED") != nullptr) {
            ++connection_count;
        }
    }
    pclose(pipe);
    return connection_count;
}

LCC_EVENT_TYPE extracted_vpnwg(LicenseInfo &licenseInfo) {
  auto dummy = extractNumber(licenseInfo.feature_name);
  int wgNum = dummy;
  if (wgNum != -1) {
    cout << "Wireguard VPN service count licensed : " << wgNum << endl;
    std::string command = is_root() ? "wg show" : "sudo wg show";
    int wireguard_count = get_wg_vpn_service_count(command.c_str());
    if (wireguard_count != -1) {
      cout << "Wireguard VPN service count detected : " << wireguard_count << endl;
      if(wireguard_count <= wgNum) {
        cout << "Wireguard VPN service license OK."  << endl;
        return LICENSE_OK;
      } else {
        cout << "Wireguard VPN service license mismatch." << endl;
        return FEATURE_MISMATCH;
      }
    }
  } 
  
  cout << "Wireguard VPN number not licensed" << endl;
  return FEATURE_MISMATCH;
}

LCC_EVENT_TYPE extracted_vpnipsec(LicenseInfo &licenseInfo) {
  auto dummy = extractNumber(licenseInfo.feature_name);
  int ipsecNum = dummy;
  if (ipsecNum != -1) {
    cout << "IPSec VPN service count licensed : " << ipsecNum << endl;
    int ipsec_count = get_ipsec_vpn_service_count("ipsec status");
    if (ipsec_count != -1) {
      cout << "IPSec VPN service count detected : " << ipsec_count << endl;
      if(ipsec_count <= ipsecNum) {
        cout << "IPSec VPN service license OK."  << endl;
        return LICENSE_OK;
      } else {
        cout << "IPSec VPN service license mismatch." << endl;
        return FEATURE_MISMATCH;
      }
    }
  } 
  
  cout << "IPSec VPN number not licensed" << endl;
  return FEATURE_MISMATCH;
}

LCC_EVENT_TYPE check_license(const std::string& feature_name, std::unordered_map<LCC_EVENT_TYPE, std::string>& stringByEventType) {
    CallerInformations callerInfo = {"\0", "\0"};
    LicenseInfo licenseInfo;

    memset(callerInfo.feature_name, 0, sizeof(callerInfo.feature_name)); // This line is optional, for clearing the buffer
    strncpy(callerInfo.feature_name, feature_name.c_str(), sizeof(callerInfo.feature_name) - 1); // Copy the string

    LCC_EVENT_TYPE result = acquire_license(&callerInfo, nullptr, &licenseInfo);
    
    if (result == LICENSE_OK) {
        cout << licenseInfo.feature_name << " is licensed" << endl;
        if (feature_name == "CPUNUM") {
            result = extracted_cpu(licenseInfo);
        } else if (feature_name == "WGVPN") {
            result = extracted_vpnwg(licenseInfo);
        } else if (feature_name == "IPSECVPN") {
            result = extracted_vpnipsec(licenseInfo);
        }

        if (result != LICENSE_OK) {
            cout << "license ERROR :" << endl;
            cout << "    " << stringByEventType[result].c_str() << endl;
        }
    } else {
        cout << callerInfo.feature_name << " is NOT licensed" << endl;
    }
    return result;
}

int main(int argc, char *argv[]) {
  unordered_map<LCC_EVENT_TYPE, string> stringByEventType = {
      {LICENSE_OK, "OK "},
      {LICENSE_FILE_NOT_FOUND, "license file not found "},
      {LICENSE_SERVER_NOT_FOUND, "license server can't be contacted "},
      {ENVIRONMENT_VARIABLE_NOT_DEFINED, "environment variable not defined "},
      {FILE_FORMAT_NOT_RECOGNIZED,
       "license file has invalid format (not .ini file) "},
      {LICENSE_MALFORMED,
       "some mandatory field are missing, or data can't be fully read. "},
      {PRODUCT_NOT_LICENSED, "this product was not licensed "},
      {PRODUCT_EXPIRED, "license expired "},
      {LICENSE_CORRUPTED,
       "license signature didn't match with current license "},
      {IDENTIFIERS_MISMATCH,
       "Calculated identifier and the one provided in license didn't match"},
	  {FEATURE_MISMATCH,
	   "Detected features and the one in license didn't match"}};

  LicenseInfo licenseInfo;

  LCC_EVENT_TYPE result = acquire_license(nullptr, nullptr, &licenseInfo);

  if (result == LICENSE_OK) {
    cout << "license for main software OK" << endl;
    if (!licenseInfo.linked_to_pc) {
      cout << "No hardware signature in license file. This is a 'demo' license "
              "that works on every pc."
           << endl
           << "To generate a 'single pc' license call 'issue license' with "
              "option -s "
           << endl
           << "and the hardware identifier obtained before." << endl;
    }
  }
  if (result != LICENSE_OK) {
    size_t pc_id_sz = LCC_API_PC_IDENTIFIER_SIZE;
    char pc_identifier[LCC_API_PC_IDENTIFIER_SIZE + 1];
    cout << "license ERROR :" << endl;
    cout << "    " << stringByEventType[result].c_str() << endl;
    if (identify_pc(STRATEGY_DEFAULT, pc_identifier, &pc_id_sz, nullptr)) {
      cout << "pc signature is :" << endl;
      cout << "    " << pc_identifier << endl;
    } else {
      cerr << "errors in identify_pc" << endl;
    }
    return -1;
  }
  // Check the license for "CPUNUM", "WGVPN" and "IPSECVPN"
  result = check_license("CPUNUM", stringByEventType);
  result = check_license("WGVPN", stringByEventType);
  result = check_license("IPSECVPN", stringByEventType);

  return result;
}
