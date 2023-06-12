#include <iostream>
#include <unordered_map>
#include <licensecc/licensecc.h>
#include <string.h>
using namespace std;

#include <string>

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

LCC_EVENT_TYPE extracted(LicenseInfo &licenseInfo) {
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
  // Call the software
  CallerInformations callerInfo = {"\0", "CPUNUM"};
  result = acquire_license(&callerInfo, nullptr, &licenseInfo);

  if (result == LICENSE_OK) {
    cout << licenseInfo.feature_name << " is licensed" << endl;
    result = extracted(licenseInfo);
	if (result != LICENSE_OK) {
		cout << "license ERROR :" << endl;
    	cout << "    " << stringByEventType[result].c_str() << endl;
	}
  } else {
    cout << callerInfo.feature_name << " is NOT licensed" << endl;
  }

  return result;
}
