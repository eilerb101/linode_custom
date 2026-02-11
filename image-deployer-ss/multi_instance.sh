#!/bin/bash

# Linode API Build Script
# Usage: ./build_linode.sh

set -e
#set -x
# Function to log failures
log_failure() {
    local message="$1"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] FAILURE: $message" | tee "failed-${FAIL_COUNTER}.log"
    exit 1
}

# Function to log info messages
log_info() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] INFO: $1"
}
# Configuration file path
CONFIG_FILE="instance.config"
# Function to get config value from file or environment variable
get_config() {
    local var_name="$1"
    local value=""
    # Try to read from config file if it exists
    if [[ -f "$CONFIG_FILE" ]]; then
        value=$(grep -E "^[[:space:]]*${var_name}=" "$CONFIG_FILE" \
            | grep -vE "^[[:space:]]*#" \
            | head -n 1 \
            | cut -d'=' -f2- \
            | sed 's/^["'\'']\(.*\)["'\'']$/\1/')
    fi
    # If not found in config file, use environment variable
    if [[ -z "$value" ]]; then
        value="${!var_name}"
    fi
    echo "$value"
}
# Load configuration
token=$(get_config "token")
label=$(get_config "label")
tag=$(get_config "tag")
root_pass=$(get_config "root_pass")
region=$(get_config "region")
linode_type=$(get_config "linode_type")
memory=$(( $(get_config "memory") * 1024))
StackScriptID=$(get_config "StackScriptID")
network=$(get_config "network")
network_id=$(get_config "network_id")
subnet_CIDR=$(get_config "subnet_CIDR")
bucket_name=$(get_config "bucket_name")
image_name=$(get_config "image_name")
bucket_region=$(get_config "bucket_region")
bucket_key=$(get_config "bucket_key")
bucket_secret=$(get_config "bucket_secret")
cpu=$(get_config "cpu")
virtualdisk=$(( $(get_config "virtual_disk") * 1024 + 520 ))
API_BASE="https://api.linode.com/v4"
HEADERS=(-H "Authorization: Bearer $token" -H "Content-Type: application/json")
# Retry settings
MAX_RETRIES=${MAX_RETRIES:-50}
RETRY_DELAY=${RETRY_DELAY:-7}
LOG_FILE=${LOG_FILE:-workspot.log}
touch "$LOG_FILE" 2>/dev/null || LOG_FILE="workspot.log"
echo "Logging to $LOG_FILE"
#Validate required variables exist
required_vars=("token" "region" "linode_type" "memory" "network" "virtualdisk" "StackScriptID")
for var in "${required_vars[@]}"; do
    if [[ -z "${!var}" ]]; then
        echo "Error: Required variable '$var' is not set in $CONFIG_FILE or environment" >&2
        exit 1
    fi
done
# Convert all to lowercase
region=$(echo "$region" | tr '[:upper:]' '[:lower:]')
linode_type=$(echo "$linode_type" | tr '[:upper:]' '[:lower:]')
network=$(echo "$network" | tr '[:upper:]' '[:lower:]')
bucket_name=$(echo "$bucket_name" | tr '[:upper:]' '[:lower:]')
bucket_region=$(echo "$bucket_region" | tr '[:upper:]' '[:lower:]')

# Validation function
validate_field() {
    local field_name="$1"
    local field_value="$2"

    if [ -z "$field_value" ]; then
        echo "ERROR: $field_name cannot be empty."
        exit 1
    fi

    if ! [[ "$field_value" =~ ^[a-z0-9-]+$ ]]; then
        echo "ERROR: $field_name must contain only lowercase letters, numbers, and dashes."
        echo "Invalid value: $field_value"
        exit 1
    fi
}

# Validate each field
validate_field "region" "$region"
validate_field "linode_type" "$linode_type"
validate_field "network" "$network"
validate_field "bucket_name" "$bucket_name"
validate_field "bucket_region" "$bucket_region"
##API CALL FUNCTION WITH BACKOFFS
api_call() {
    local method="$1"
    local url="$2"
    local data="$3"
    local attempt=0
    local response
    local http_code

    while (( attempt < MAX_RETRIES )); do
        ((attempt++))

        if [[ -z "$data" ]]; then
            response=$(curl -sS -w "\n%{http_code}" -X "$method" \
                -H "Authorization: Bearer $token" \
                -H "Content-Type: application/json" \
                "$url" 2>>"$LOG_FILE")
        else
            response=$(curl -sS -w "\n%{http_code}" -X "$method" \
                -H "Authorization: Bearer $token" \
                -H "Content-Type: application/json" \
                -d "$data" \
                "$url" 2>>"$LOG_FILE")
        fi

        # Separate body and HTTP code
        http_code=$(echo "$response" | tail -n1)
        response=$(echo "$response" | sed '$d')

        # --- Handle HTTP-level retry conditions ---
        if [[ "$http_code" == "429" ]]; then
            echo "Rate limit hit (attempt $attempt/$MAX_RETRIES). Sleeping ${RETRY_DELAY}s..."  >&2
            sleep "$RETRY_DELAY"
            continue
        elif [[ "$http_code" =~ ^5[0-9]{2}$ ]]; then
            echo "Server error ($http_code) on attempt $attempt/$MAX_RETRIES. Sleeping ${RETRY_DELAY}s..."  >&2
            sleep "$RETRY_DELAY"
            continue
        fi

        # --- Handle Linode busy or application-level errors ---
        if echo "$response" | grep -qiE "busy|rate limit"; then
            #echo "Linode busy or rate limited (attempt $attempt/$MAX_RETRIES). Sleeping ${RETRY_DELAY}s..."
            echo "Linode busy or rate limited (attempt $attempt/$MAX_RETRIES). Sleeping ${RETRY_DELAY}s..." >&2
	    sleep "$RETRY_DELAY"
            continue
        fi

        # --- Handle API 'errors' key in JSON body ---
        if echo "$response" | grep -q "\"errors\""; then
            if (( attempt < MAX_RETRIES )); then
                echo "API error (attempt $attempt/$MAX_RETRIES). Retrying in ${RETRY_DELAY}s..."  >&2
                echo "Response: $response"
                sleep "$RETRY_DELAY"
                continue
            else
                echo "ERROR: Max retries reached. Last response: $response"
                echo "$response"
                return 1
            fi
        fi

        # --- Success ---
        echo "$response"
        return 0
    done

    echo "ERROR: Max retries ($MAX_RETRIES) reached without success"
    return 1
}
###END API CALL FUNCTION
##Wrapper for api_call to handle pagination
get_all_pages() {
    local url="$1"
    local all_data="[]"
    local page=1
    local total_pages=1

    # First request
    local response
    response=$(api_call "GET" "${url}?page=${page}" "") || return 1
    total_pages=$(echo "$response" | jq -r '.pages // 1')

    all_data=$(echo "$response" | jq '.data')

    # Loop through additional pages, if any
    while (( page < total_pages )); do
        ((page++))
        response=$(api_call "GET" "${url}?page=${page}" "") || return 1
        all_data=$(jq -s '[.[0][] , .[1][]]' <(echo "$all_data") <(echo "$response" | jq '.data'))
    done

    echo "$all_data"
}
#End api_call wrapper
echo "Validating token and grants..."
response=$(api_call "GET" "${API_BASE}/profile/tokens")
echo "API call exit code: $?"
echo "Raw response content: '$response'"
echo "$response"
if [[ -z "$response" ]]; then
    echo "ERROR: Failed to fetch token info."
    exit 1
fi
# Get the first 16 characters of the token
token_prefix="${token:0:16}"
# Find the token object that matches the prefix
matched=$(echo "$response" | jq -r --arg prefix "$token_prefix" '.data[] | select(.token | startswith($prefix))')
if [[ -z "$matched" ]]; then
    echo "ERROR: No matching token found."
    exit 1
fi
# Exact scopes required
exact_scopes=(firewall:read_write ips:read_write linodes:read_write object_storage:read_write vpc:read_write)

# Flexible stackscripts scope: either read_only or read_write
flexible_stackscripts=("stackscripts:read_write" "stackscripts:read_only")

# Extract scopes from the matched token (string or array)
scopes=$(echo "$matched" | jq -r '
  if type=="object" then
    if (.scopes | type=="array") then
      .scopes | join(" ")
    else
      .scopes
    end
  else
    ""
  end
')

# Full access check
if [[ "$scopes" == "*" ]]; then
    echo "Token is valid with full access."
else
    # Check exact scopes
    missing=false
    for s in "${exact_scopes[@]}"; do
        if ! grep -qw "$s" <<<"$scopes"; then
            missing=true
            echo "Missing required scope: $s"
        fi
    done

    # Check at least one flexible stackscripts scope
    has_stack=false
    for f in "${flexible_stackscripts[@]}"; do
        if grep -qw "$f" <<<"$scopes"; then
            has_stack=true
            break
        fi
    done
    if [[ "$has_stack" != true ]]; then
        echo "Missing required stackscripts scope (need read_only or read_write)"
        missing=true
    fi

    if [[ "$missing" == true ]]; then
        echo "ERROR: Token does not have all required scopes."
        exit 1
    fi

    echo "Token is valid with all required scopes."
fi

echo "Token validation passed!"
# Validate CIDR format
validate_cidr() {
    local cidr="$1"
    # Matches A.B.C.D/N where N is 0-32
    if [[ "$cidr" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/([0-9]|[1-2][0-9]|3[0-2])$ ]]; then
        # Optional: check each octet <= 255
        IFS=. read -r o1 o2 o3 o4 <<<"${cidr%/*}"
        for octet in $o1 $o2 $o3 $o4; do
            if ((octet < 0 || octet > 255)); then
                return 1
            fi
        done
        return 0
    else
        return 1
    fi
}
# Network validation
if [ "$(echo "$network" | tr '[:upper:]' '[:lower:]')" != "public" ]; then
    # Validate network_id: must be 1-40 alphanumeric or dash
    if ! [[ "$network_id" =~ ^[a-zA-Z0-9-]{1,40}$ ]]; then
        log_failure "network_id must be 1–40 alphanumeric characters or dashes."
    fi

    # If network is VPC, perform extra validation
    if [ "$(echo "$network" | tr '[:upper:]' '[:lower:]')" = "vpc" ]; then
        if ! validate_cidr "$subnet_CIDR"; then
            log_failure "subnet_CIDR is not a valid CIDR notation."
        fi

        log_info "Checking for existing VPC with label '$network_id'..."

        # Normalize comparison strings
        search_label="$(echo "$network_id" | tr '[:upper:]' '[:lower:]')"
        search_region="$(echo "$region" | tr '[:upper:]' '[:lower:]')"

        # 1. Try single-shot large page to minimize calls
        vpc_response=$(api_call "GET" "${API_BASE}/vpcs?page_size=500")
        if [[ $? -ne 0 || -z "$vpc_response" ]]; then
            log_failure "Failed to retrieve VPC list from Linode API."
        fi

        total_pages=$(echo "$vpc_response" | jq -r '.pages // 1')

        # Function to check response for matching label
        check_vpc_match() {
            local json="$1"
            local match
            match=$(echo "$json" | jq -r --arg label "$search_label" '
                .data[]? | select((.label // "" | ascii_downcase) == $label) | [.label, .region] | @tsv' 2>/dev/null)
            if [[ -n "$match" ]]; then
                while IFS=$'\t' read -r vpc_label vpc_region; do
                    if [[ -n "$vpc_label" ]]; then
                        vpc_label_lc=$(echo "$vpc_label" | tr '[:upper:]' '[:lower:]')
                        vpc_region_lc=$(echo "$vpc_region" | tr '[:upper:]' '[:lower:]')
                        if [[ "$vpc_label_lc" == "$search_label" ]]; then
                            if [[ "$vpc_region_lc" != "$search_region" ]]; then
                                log_failure "VPC '$vpc_label' already exists in region '$vpc_region'. VPC labels must be unique per account and cannot be reused in a different region."
                            else
                                log_info "VPC '$vpc_label' already exists in region '$vpc_region' (matches requested region). Proceeding..."
                                return 0
                            fi
                        fi
                    fi
                done <<< "$match"
            fi
            return 1
        }

        # 2. Evaluate first page or full single-shot response
        if check_vpc_match "$vpc_response"; then
            found=true
        else
            found=false
        fi

        # 3. If there are multiple pages, iterate until we find or finish
        if [[ "$found" == false && "$total_pages" -gt 1 ]]; then
            page=2
            while (( page <= total_pages )); do
                vpc_response=$(api_call "GET" "${API_BASE}/vpcs?page=$page")
                if [[ $? -ne 0 || -z "$vpc_response" ]]; then
                    log_failure "Failed to retrieve VPC list (page $page)."
                fi
                if check_vpc_match "$vpc_response"; then
                    found=true
                    break
                fi
                ((page++))
            done
        fi

        # 4. If not found at all
        if [[ "$found" == false ]]; then
            log_info "No existing VPC with label '$network_id' found. Proceeding to create new one."
        fi
    fi
fi
#END NEW NET VAL
echo "Instance variable inputs validated... Checking Object Storage..."

# Counter for failed attempts
FAIL_COUNTER=1
while [[ -f "failed-${FAIL_COUNTER}.log" ]]; do
    ((FAIL_COUNTER++))
done

# Function to update or add variable in config file
update_config_var() {
    local var_name="$1"
    local var_value="$2"
    local config_file="$3"
    
    if grep -q "^${var_name}=" "$config_file" 2>/dev/null; then
        # Variable exists, update it
        sed -i.bak "s|^${var_name}=.*|${var_name}=\"${var_value}\"|" "$config_file"
    else
        # Variable doesn't exist, append it
        echo "${var_name}=\"${var_value}\"" >> "$config_file"
    fi
}

# Check if bucket-related variables are set
bucket_vars=("bucket_region" "image_name" "bucket_name")
bucket_vars_set=true
for var in "${bucket_vars[@]}"; do
    if [[ -z "${!var}" ]]; then
        bucket_vars_set=false
        break
    fi
done
# If bucket variables are set, validate them
if [[ "$bucket_vars_set" == true ]]; then
    log_info "Validating bucket configuration..."

    # Validate bucket and region
    log_info "Checking bucket '$bucket_name' in region '$bucket_region'..."
    bucket_response=$(api_call "GET" "${API_BASE}/object-storage/buckets/${bucket_region}/${bucket_name}")
    # Extract hostname
    bucket_endpoint=$(echo "$bucket_response" | jq -r '.s3_endpoint // empty')

    if [[ -z "$bucket_endpoint" ]]; then
        log_failure "bucket_name '$bucket_name' or bucket_region '$bucket_region' is incorrect value"
    fi

    log_info "Bucket endpoint verified: $bucket_endpoint"

    # Validate image_name exists in bucket
    log_info "Checking if image '$image_name' exists in bucket..."
    #Get objects from bucket
    object_list=$(get_all_pages "${API_BASE}/object-storage/buckets/${bucket_region}/${bucket_name}/object-list")
    if [[ $? -ne 0 || -z "$object_list" ]]; then
        log_failure "Failed to retrieve object list from bucket '$bucket_name'."
    fi
    #Check if image exists...
    if echo "$object_list" | jq -e --arg img "$image_name" '.[]? | select(.name == $img)' > /dev/null 2>&1; then
        log_info "Image '$image_name' verified in bucket."
        image_verified=true
    else
        log_failure "image_name '$image_name' provided is not valid (not found in bucket)."
    fi
#NEW BUCKET KEY CREATE FUNCTION
	create_bucket_keys() {
    log_info "Creating new bucket access keys..."

    # Generate random 8-digit suffix
    random_suffix=$(shuf -i 10000000-99999999 -n 1)
    deployment_label="${deployment:-linode-deployment}-${random_suffix}"

    # API endpoint and payload
    url="https://api.linode.com/v4/object-storage/keys"
    data=$(jq -nc \
        --arg bucket "$bucket_name" \
        --arg region "$bucket_region" \
        --arg label "$deployment_label" \
        '{bucket_access: [{bucket_name: $bucket, permissions: "read_only", region: $region}], label: $label}'
    )
  # Use centralized API call function with retries and rate-limit handling
    key_response=$(api_call "POST" "$url" "$data")
    if [[ $? -ne 0 ]]; then
        log_failure "Failed to create bucket access keys after ${MAX_RETRIES:-5} attempts"
        return 1
    fi

    # Parse access and secret keys
    bucket_key=$(echo "$key_response" | jq -r '.access_key // empty')
    bucket_secret=$(echo "$key_response" | jq -r '.secret_key // empty')

    if [[ -z "$bucket_key" || -z "$bucket_secret" ]]; then
        error_msg=$(echo "$key_response" | jq -r '.errors[]?.reason // "Unknown error"' | head -1)
        log_failure "Bucket key creation failed: $error_msg"
        return 1
    fi

    log_info "Bucket access keys created successfully"
    log_info "Access Key: $bucket_key"
    log_info "Secret Key: [REDACTED]"

    # --- Save credentials to config file ---
    if [[ -f "$CONFIG_FILE" ]]; then
        log_info "Writing bucket credentials to $CONFIG_FILE..."
        if grep -q '^bucket_key=' "$CONFIG_FILE"; then
            sed -i "s|^bucket_key=.*|bucket_key=\"$bucket_key\"|" "$CONFIG_FILE"
        else
            echo "bucket_key=\"$bucket_key\"" >> "$CONFIG_FILE"
        fi
        if grep -q '^bucket_secret=' "$CONFIG_FILE"; then
            sed -i "s|^bucket_secret=.*|bucket_secret=\"$bucket_secret\"|" "$CONFIG_FILE"
        else
            echo "bucket_secret=\"$bucket_secret\"" >> "$CONFIG_FILE"
        fi
    else
        log_info "Creating $CONFIG_FILE with bucket credentials..."
        {
            echo "bucket_key=\"$bucket_key\""
            echo "bucket_secret=\"$bucket_secret\""
        } > "$CONFIG_FILE"
    fi
    log_info "Credentials saved to $CONFIG_FILE"

    # Export for later script use
    export bucket_key bucket_secret
    } 
###END Bucket Ket Create
# Check bucket access credentials (separate from bucket configuration vars)
    if [[ -n "$bucket_key" ]] && [[ -n "$bucket_secret" ]]; then
        log_info "Validating existing access key..."
	response=$(api_call "GET" "${API_BASE}/object-storage/keys")

        # Try to find a matching key object
        matched=$(echo "$response" | jq -r --arg key "$bucket_key" '.data[]? | select(.access_key == $key)')
        
        if [[ -z "$matched" || "$matched" == "null" ]]; then
            log_info "Access key $bucket_key not found in object storage keys"
            create_bucket_keys
        else
            # Validate bucket_name and region
            bucket_match=$(echo "$matched" | jq -r --arg bucket "$bucket_name" --arg region "$bucket_region" \
                '.bucket_access[]? | select(.bucket_name==$bucket and .region==$region)')
            
            if [[ -z "$bucket_match" || "$bucket_match" == "null" ]]; then
                log_info "Access key does not have access to bucket '$bucket_name' in region '$bucket_region'"
                create_bucket_keys
            else
                log_info "Access key, bucket, and region validated successfully"
            fi
        fi
    else
        # Either both are missing or only one is provided - create new keys
        if [[ -n "$bucket_key" ]] || [[ -n "$bucket_secret" ]]; then
            log_info "Incomplete credentials provided (only one of key/secret), creating new pair..."
        else
            log_info "No bucket credentials provided, creating new access keys..."
        fi
        create_bucket_keys
    fi

    log_info "All bucket configurations validated successfully"
else
    log_info "Bucket variables not fully configured, skipping bucket validation"
fi
# Get regions and check availability
log_info "Checking if instance type '$linode_type' is available in region '$region'..."
regions_response=$(api_call "GET" "${API_BASE}/regions")
# Determine capability string based on linode_type
case "$linode_type" in
    shared|standard)
        capability="Linodes"
        type_class="standard"
        ;;
    dedicated)
        capability="Linodes"
        type_class="dedicated"
        ;;
    premium)
        capability="Premium Plans"
        type_class="premium"
        ;;
    gpu)
        capability="GPU Linodes"
        type_class="gpu"
        ;;
    vpu)
        capability="NETINT Quadra T1U"
        type_class="accelerated"
        ;;
    *)
        log_failure "Invalid linode_type: $linode_type"
        ;;
esac

# Check if region supports the required capability
region_id=$(echo "$regions_response" | jq -r --arg region "$region" --arg cap "$capability" \
    '.data[] | select(.id == $region and (.capabilities[] | contains($cap))) | .id')

if [[ -z "$region_id" ]]; then
    log_failure "Region '$region' does not support capability '$capability' (linode_type: $linode_type)"
fi

log_info "Region '$region' supports '$capability'"

# Get instance types filtered by class
log_info "Fetching instance types for class '$type_class'..."
types_response=$(curl -s -H "Authorization: Bearer $token" \
    -H "X-Filter: {\"class\":\"$type_class\"}" \
    "${API_BASE}/linode/types")

# Find smallest instance type that meets ALL minimum requirements
log_info "Searching for instance type matching minimum requirements:"
log_info "  - Class: $type_class"
log_info "  - Memory: >= ${memory}MB"
log_info "  - vCPU: >= ${cpu}"
log_info "  - Disk: >= ${virtualdisk}MB"

# Filter instances meeting ALL minimums, sort by memory (as proxy for size), take smallest
selected_type=$(echo "$types_response" | jq -r \
    --argjson mem "$memory" \
    --argjson vcpu "$cpu" \
    --argjson disk "$virtualdisk" \
    '.data[] | 
    select(
        .memory >= $mem and
        .vcpus >= $vcpu and
        .disk >= $disk
    ) | {id: .id, memory: .memory, vcpus: .vcpus, disk: .disk} | 
    [.memory, .id]' | \
    jq -s 'sort_by(.[0]) | .[0][1]' | tr -d '"')

if [[ -z "$selected_type" ]]; then
    log_failure "No instance type found matching ALL minimum requirements:
  - Class: $type_class
  - Memory: >= ${memory}MB
  - vCPU: >= ${cpu}
  - Disk: >= ${virtualdisk}MB"
fi

log_info "Selected instance type: $selected_type"

# Display selected instance details
selected_details=$(echo "$types_response" | jq -r --arg type "$selected_type" \
    '.data[] | select(.id == $type) | 
    "  Memory: \(.memory)MB\n  vCPUs: \(.vcpus)\n  Disk: \(.disk)MB\n  Transfer: \(.transfer)MB"')
log_info "Instance specifications:\n$selected_details"

# Get full type details for logging
type_details=$(echo "$types_response" | jq -r --arg id "$selected_type" '.data[] | select(.id == $id)')
type_memory=$(echo "$type_details" | jq -r '.memory')
type_disk=$(echo "$type_details" | jq -r '.disk')

echo "Instance will have ${type_memory}MB memory and ${type_disk}MB disk"

# Handle VPC/VLAN networking
interface_config=""
if [[ "$network" == "vpc" ]]; then
    echo "Checking for VPC: $network_id in region $region..."
    vpc_response=$(api_call "GET" "${API_BASE}/vpcs")
    vpc_id=$(echo "$vpc_response" | jq -r --arg label "$network_id" --arg region "$region" \
        '.data[] | select(.label == $label and .region == $region) | .id')
    
    if [[ -z "$vpc_id" || "$vpc_id" == "null" ]]; then
        echo "VPC not found, creating: $network_id"
	vpc_data="{\"label\":\"$network_id\",\"region\":\"$region\"}"
	vpc_create=$(api_call "POST" "${API_BASE}/vpcs" "${vpc_data}") 
	vpc_id=$(echo "$vpc_create" | jq -r '.id')
        if [[ -z "$vpc_id" || "$vpc_id" == "null" ]]; then
            log_failure "Failed to create VPC"
        fi
        echo "Created VPC with ID: $vpc_id"
    else
        echo "Found existing VPC with ID: $vpc_id"
    fi
    
    # Check for subnet
    echo "Checking for subnet: $subnet_CIDR"
    subnet_response=$(api_call "GET" "${API_BASE}/vpcs/${vpc_id}/subnets")
    log_info "DEBUG: $subnet_response"
    subnet_id=$(echo "$subnet_response" | jq -r --arg cidr "$subnet_CIDR" \
        '.data[] | select(.ipv4 == $cidr) | .id')
    
    if [[ -z "$subnet_id" || "$subnet_id" == "null" ]]; then
        echo "Subnet not found, creating: $subnet_CIDR"
	###Subnet label create
	base_label="subnet-${network_id}"
        new_label="$base_label"
	# Build a set of existing labels for this VPC
        existing_labels=$(echo "$subnet_response" | jq -r '.data[].label')

        # Increment label if collision exists
        while echo "$existing_labels" | grep -qx "$new_label"; do
            if [[ "$new_label" =~ -([0-9]+)$ ]]; then
            # Ends with a number, increment it
                num="${BASH_REMATCH[1]}"
                ((num++))
                new_label="${base_label}-${num}"
            else
            # Ends with letters, append -1
                new_label="${base_label}-1"
            fi
            base_label="$base_label"  # keep original base for next increment
        done
        echo "DEBUG: Using subnet label: $new_label"
	###End subnet label create
	
	subnet_data="{\"label\":\"${new_label}\",\"ipv4\":\"$subnet_CIDR\"}"
	log_info "DEBUG: $subnet_data"
	subnet_create=$(api_call "POST" "${API_BASE}/vpcs/${vpc_id}/subnets" "${subnet_data}")
        subnet_id=$(echo "$subnet_create" | jq -r '.id')
        if [[ -z "$subnet_id" || "$subnet_id" == "null" ]]; then
            log_failure "Failed to create subnet"
        fi
        echo "Created subnet with ID: $subnet_id"
    else
        echo "Found existing subnet with ID: $subnet_id"
    fi
   
    interface_config="{\"purpose\":\"public\",\"primary\":true}"
    vpc_init_config="{\"purpose\":\"vpc\",\"primary\":true,\"subnet_id\":${subnet_id},\"ipv4\":{\"nat_1_1\":\"any\"}}"
    alpine_interface_config="{\"purpose\":\"vlan\",\"label\":\"null\"}"
    net_init="{\"interfaces\": [$vpc_init_config]}"
    escaped_payload=$(printf '%s' "$net_init" | sed 's/"/\\"/g')
elif [[ "$network" == "vlan" ]]; then
    echo "Using VLAN: $network_id"
    interface_config="{\"purpose\":\"public\",\"primary\":true}"
    win_interface_config="{\"purpose\":\"vlan\",\"label\":\"$network_id\"}"
    escaped_payload="NULL"
elif [[ "$network" == "public" ]]; then
    echo "Using public network"
    interface_config="{\"purpose\":\"public\",\"primary\":true}"
    win_interface_config="{\"purpose\":\"public\",\"primary\":true}"
    escaped_payload="NULL"
else
    log_failure "Invalid network type: $network"
fi

# Calculate disk sizes
alpine_disk_size=520  # in MB
raw_disk_size=$((type_disk - alpine_disk_size))
#raw_disk_size=81920

if [[ $raw_disk_size -le 0 ]]; then
    log_failure "Insufficient disk space for configuration"
fi
##NEW LOOP
qty=$(get_config "quantity")
qty=${qty:-1}

# Validate qty is a positive integer
if ! [[ "$qty" =~ ^[1-9][0-9]*$ ]]; then
    log_failure "qty must be a positive integer, got: $qty"
fi

log_info "Creating $qty instance(s)..."
wait_for_disk_ready() {
    local instance_id="$1"
    local disk_id="$2"
    local label="$3"
    local max_wait=180  # seconds
    local interval=5
    local elapsed=0

    echo "Waiting for disk '$label' (ID: $disk_id) to become ready..."

    while (( elapsed < max_wait )); do
        response=$(api_call "GET" "${API_BASE}/linode/instances/${instance_id}/disks/${disk_id}")
        if [[ $? -ne 0 || -z "$response" ]]; then
            echo "Failed to query disk status for $label. Retrying in $interval seconds..." >&2
            sleep "$interval"
            ((elapsed+=interval))
            continue
        fi

        status=$(echo "$response" | jq -r '.status // empty')
        if [[ "$status" == "ready" ]]; then
            echo "Disk '$label' is ready."
            return 0
        fi

        echo "Disk '$label' status: $status (waiting...)"
        sleep "$interval"
        ((elapsed+=interval))
    done

    echo "ERROR: Timed out waiting for disk '$label' to become ready after ${max_wait}s" >&2
    return 1
}
###NEW LOOP
declare -a created_instances=()
for instance_num in $(seq 1 "$qty"); do
    log_info "=== Creating instance $instance_num of $qty ==="
echo "Creating disks: Alpine=${alpine_disk_size}MB, Raw=${raw_disk_size}MB"

# Create Linode instance
echo "Creating Linode instance..."

create_payload=$(cat <<EOF
{
  "type": "$selected_type",
  "region": "$region",
  "label": "$label-$(date +%s)-${instance_num}",
  "tags": ["$tag"],
  "booted": false
}
EOF
)

instance_response=$(api_call "POST" "${API_BASE}/linode/instances" "${create_payload}")

instance_id=$(echo "$instance_response" | jq -r '.id')
if [[ -z "$instance_id" || "$instance_id" == "null" ]]; then
    error_msg=$(echo "$instance_response" | jq -r '.errors[]?.reason' | tr '\n' ' ')
    log_failure "Failed to create instance: $error_msg"
fi

echo "Created instance with ID: $instance_id"
sleep 2
#Create Disks in instance
create_disk1=$(cat <<EOF
{
  "filesystem": "ext4",
  "image": "linode/alpine3.22",
  "label": "alpine",
  "root_pass": "$root_pass",
  "size": $alpine_disk_size,
  "stackscript_id": $StackScriptID,
  "stackscript_data": {
    "token": "$token",
    "region":"$region",
    "instance_id":"$instance_id",
    "network":"$network",
    "bucket_name":"$bucket_name",
    "image_name":"$image_name",
    "bucket_region":"$bucket_region",
    "ss_passthrough_payload":"$escaped_payload",
    "bucket_key":"$bucket_key",
    "bucket_endpoint":"$bucket_endpoint",
    "bucket_secret":"$bucket_secret"
  }
}
EOF
)
echo "This is the disk1 config: $create_disk1"
create_disk2=$(cat <<EOF
{
  "filesystem": "raw",
  "label": "raw",
  "size": $raw_disk_size
}
EOF
)
sleep 2
disk2_response=$(api_call "POST" "${API_BASE}/linode/instances/${instance_id}/disks" "${create_disk2}")
echo "This is the api response for Disk2: $disk2_response"
sleep 2
disk1_response=$(api_call "POST" "${API_BASE}/linode/instances/${instance_id}/disks" "${create_disk1}")
echo "This is the api response for Disk1: $disk1_response"
sleep 2
# Get disk IDs
raw_disk_id=$(echo "$disk2_response" | jq -r '.id')
alpine_disk_id=$(echo "$disk1_response" | jq -r '.id')
raw_disk_size_actual=$(echo "$disk2_response" | jq -r '.size')
raw_disk_fs=$(echo "$disk2_response" | jq -r '.filesystem')
alpine_disk_size_actual=$(echo "$disk1_response" | jq -r '.size')
alpine_disk_fs=$(echo "$disk1_response" | jq -r '.filesystem')

echo "Alpine Disk ID: $alpine_disk_id"
echo "Raw Disk ID: $raw_disk_id"
##WAIT FOR DISK READY

wait_for_disk_ready "$instance_id" "$alpine_disk_id" "Alpine Disk" || log_failure "Alpine disk not ready"
wait_for_disk_ready "$instance_id" "$raw_disk_id" "Raw Disk" || log_failure "Raw disk not ready"
log_info "Disks are ready"
echo "Creating Initial Alpine configuration..."
alpine_initial_payload=$(cat <<EOF
{
  "label": "Alpine",
  "interfaces": [$interface_config],
  "virt_mode": "paravirt",
  "kernel": "linode/grub2",
  "devices": {
    "sda": {"disk_id": $alpine_disk_id},
    "sdb": {"disk_id": $raw_disk_id}
  },
  "root_device": "/dev/sda"
}
EOF
)
alpine_config_response=$(api_call "POST" "${API_BASE}/linode/instances/${instance_id}/configs" "${alpine_initial_payload}")
echo "API response for first config: $alpine_config_response"
alpine_id=$(echo "$alpine_config_response" | jq -r '.id')
if [[ -z "$alpine_id" || "$alpine_id" == "null" ]]; then
    log_failure "Failed to create Alpine configuration"
fi

echo "Created Alpine config with ID: $alpine_id"
sleep 2
alpine_config=$(echo "$alpine_config_response" | jq -r '.id')

# Create Windows configuration (direct disk)
echo "Creating Windows configuration..."
if [[ "$network" == "vpc" ]]; then
    windows_int_payload=$(cat <<EOF
{
  "label": "System",
  "interfaces": [$alpine_interface_config],
  "virt_mode": "paravirt",
  "kernel": "linode/direct-disk",
  "devices": {
    "sda": {"disk_id": $raw_disk_id}
  },
  "root_device": "/dev/sda"
}
EOF
)
else
    windows_int_payload=$(cat <<EOF
{
  "label": "System",
  "interfaces": [$win_interface_config],
  "virt_mode": "paravirt",
  "kernel": "linode/direct-disk",
  "devices": {
    "sda": {"disk_id": $raw_disk_id}
  },
  "root_device": "/dev/sda"
}
EOF
)
fi
windows_int_response=$(api_call "POST" "${API_BASE}/linode/instances/${instance_id}/configs" "${windows_int_payload}")
echo "This is Windows Config response: $windows_int_response"
windows_int=$(echo "$windows_int_response" | jq -r '.id')
if [[ -z "$windows_int" || "$windows_int" == "null" ]]; then
    log_failure "Failed to create Windows configuration"
fi

echo "Created Interstitial Windows config with ID: $windows_int"
sleep 2
# Boot with Alpine configuration
echo "Booting instance with Alpine configuration..."
boot_config="{\"config_id\": $alpine_id}"
boot_response=$(api_call "POST" "${API_BASE}/linode/instances/${instance_id}/boot" "${boot_config}")

boot_status=$(echo "$boot_response" | jq -r '.status' 2>/dev/null || echo "unknown")

# Create log file
log_file="${instance_id}.log"
cat > "$log_file" <<EOF
=== Linode Instance Build Log ===
Timestamp: $(date '+%Y-%m-%d %H:%M:%S')

REQUEST PARAMETERS:
- Instance Type Requested: $linode_type
- Memory Requested: ${memory}MB
- Region: $region
- Network Type Requested: $network
- Network ID: $network_id
- Subnet CIDR: $subnet_CIDR

CREATED INSTANCE:
- Instance ID: $instance_id
- Instance Type Created: $selected_type
- Actual Memory: ${type_memory}MB
- Total Disk: ${type_disk}MB

DISKS:
- Alpine Disk ID: $alpine_disk_id
  Format: $alpine_disk_fs
  Size: ${alpine_disk_size_actual}MB
  
- Raw Disk ID: $raw_disk_id
  Format: $raw_disk_fs
  Size: ${raw_disk_size_actual}MB

CONFIGURATIONS:
- Alpine Config ID: $alpine_id
  Virt Mode: paravirt
  Kernel: grub2
  Root Device: /dev/sda
  
- Windows Config ID: $windows_int
  Virt Mode: paravirt
  Kernel: direct-disk
  Root Device: /dev/sda

NETWORK:
- Network Type Created: $network
EOF

if [[ "$network" == "vpc" ]]; then
    echo "- VPC ID: $vpc_id" >> "$log_file"
    echo "- Subnet ID: $subnet_id" >> "$log_file"
    echo "- Subnet CIDR: $subnet_CIDR" >> "$log_file"
elif [[ "$network" == "vlan" ]]; then
    echo "- VLAN Label: $network_id" >> "$log_file"
fi

cat >> "$log_file" <<EOF

BOOT STATUS:
- Booted with Config: $alpine_id (Alpine)
- Boot Status: $boot_status

STACKSCRIPT:
- StackScript ID: $StackScriptID
- Bucket: $bucket_name
- Image: $image_name
- Bucket Region: $bucket_region
EOF

echo ""
echo "=== Build Complete ==="
echo "Instance ID: $instance_id"
echo "Log file: $log_file"
echo "Alpine Config: $alpine_id"
echo "Windows Config: $windows_int"
####END LOOP STUFF
# Store the instance ID
    created_instances+=("$instance_id")
    
    log_info "=== Instance $instance_num of $qty completed ==="
    echo ""

done  # End of main loop

# Summary
echo ""
echo "=== All Builds Complete ==="
echo "Total instances created: ${#created_instances[@]}"
echo "Instance IDs:"
for id in "${created_instances[@]}"; do
    echo "  - $id (log: ${id}.log)"
done
