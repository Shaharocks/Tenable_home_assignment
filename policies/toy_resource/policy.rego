package example

import future.keywords.in

# Task 1:
analyze[risk_path] {
    some i
    resource := input.resources[i]
    vmSize := resource.properties.hardwareProfile.vmSize
    not startswith(vmSize, "Standard_B")
    risk_path := sprintf("resources.%d.properties.hardwareProfile.vmSize", [i])
}

# Task 2:
# Case 1: securityProfile exists, securityType exists but wrong value
analyze[risk_path] {
    some i
    resource := input.resources[i]
    
    # properties exists
    properties := object.get(resource, "properties", null)
    properties != null
    
    # securityProfile exists
    securityProfile := object.get(properties, "securityProfile", null)
    securityProfile != null
    
    # securityType exists
    securityType := object.get(securityProfile, "securityType", null)
    securityType != null
    
    # But it's not TrustedLaunch
    securityType != "TrustedLaunch"
    
    # Return path to the securityType field
    risk_path := sprintf("resources.%d.properties.securityProfile.securityType", [i])
}

# Case 2: securityProfile exists but securityType is missing or null
analyze[risk_path] {
    some i
    resource := input.resources[i]
    
    # properties exists
    properties := object.get(resource, "properties", null)
    properties != null
    
    # securityProfile exists
    securityProfile := object.get(properties, "securityProfile", null)
    securityProfile != null
    
    # But securityType doesn't exist or is null (defaults to "standard" which is a risk)
    securityType := object.get(securityProfile, "securityType", null)
    securityType == null
    
    # Return path to securityProfile (parent of missing field)
    risk_path := sprintf("resources.%d.properties.securityProfile", [i])
}

# Case 3: properties exists but securityProfile doesn't exist at all
analyze[risk_path] {
    some i
    resource := input.resources[i]
    
    # properties exists
    properties := object.get(resource, "properties", null)
    properties != null
    
    # But securityProfile is completely missing
    securityProfile := object.get(properties, "securityProfile", null)
    securityProfile == null
    
    # Return path to properties (parent)
    risk_path := sprintf("resources.%d.properties", [i])
}

# Case 4: properties doesn't exist at all
analyze[risk_path] {
    some i
    resource := input.resources[i]
    
    # properties is completely missing
    properties := object.get(resource, "properties", null)
    properties == null
    
    # Return path to the resource itself
    risk_path := sprintf("resources.%d", [i])
}