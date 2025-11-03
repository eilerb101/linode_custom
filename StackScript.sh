#!/bin/sh

# Linode StackScript for Image Conversion
# This script runs on the Alpine Linux instance to convert a QCOW2 image to raw format

set -e

# UDF Variables (these are passed from the API call)
# <UDF name="token" label="Linode API Token" />
# <UDF name="region" label="Region" />
# <UDF name="instance_id" label="Linode ID" />
# <UDF name="network" label="Network Type" />
# <UDF name="ss_passthrough_payload" label="vpc config" default="null" />
# <UDF name="bucket_name" label="Object Storage Bucket Name" />
# <UDF name="image_name" label="Image File Name (QCOW2)" />
# <UDF name="bucket_region" label="Bucket Region" />
# <UDF name="bucket_key" label="read-only obj key" />
# <UDF name="bucket_secret" label="read-only obj secret" />
# <UDF name="bucket_endpoint" label="full bucket-cluster-region endpoint url" />

# Normalize all UDF variable names to uppercase (preserve values as-is)
TOKEN="${TOKEN:-$token}"
REGION="${REGION:-$region}"
INSTANCE_ID="${INSTANCE_ID:-$instance_id}"
NETWORK="${NETWORK:-$network}"
SS_PASSTHROUGH_PAYLOAD="${SS_PASSTHROUGH_PAYLOAD:-$ss_passthrough_payload}"
BUCKET_NAME="${BUCKET_NAME:-$bucket_name}"
IMAGE_NAME="${IMAGE_NAME:-$image_name}"
BUCKET_REGION="${BUCKET_REGION:-$bucket_region}"
BUCKET_KEY="${BUCKET_KEY:-$bucket_key}"
BUCKET_SECRET="${BUCKET_SECRET:-$bucket_secret}"
BUCKET_ENDPOINT="${BUCKET_ENDPOINT:-$bucket_endpoint}"

LOG_FILE="/var/log/image-conversion.log"
API_BASE="https://api.linode.com/v4"
MAX_RETRIES=150
RETRY_DELAY=5

# Logging function
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

# API retry function
# Usage: api_call "METHOD" "URL" "DATA"
api_call() {
    local method="$1"
    local url="$2"
    local data="$3"
    local attempt=0
    local response
    local http_code
    
    while [ $attempt -lt $MAX_RETRIES ]; do
        attempt=$((attempt + 1))
        
        if [ -z "$data" ]; then
            response=$(curl -s -w "\n%{http_code}" -X "$method" \
                -H "Authorization: Bearer $TOKEN" \
                -H "Content-Type: application/json" \
                "$url")
        else
            response=$(curl -s -w "\n%{http_code}" -X "$method" \
                -H "Authorization: Bearer $TOKEN" \
                -H "Content-Type: application/json" \
                -d "$data" \
                "$url")
        fi
        
        http_code=$(echo "$response" | tail -n1)
        response=$(echo "$response" | sed '$d')
        
        # Check for rate limit (429) or busy errors
        if [ "$http_code" = "429" ]; then
            log "Rate limit hit (attempt $attempt/$MAX_RETRIES). Waiting ${RETRY_DELAY}s before retry..."
            sleep $RETRY_DELAY
            continue
        fi
        
        # Check for "linode busy" or other busy-related errors
        if echo "$response" | grep -iq "busy\|rate limit"; then
            log "Linode busy or rate limited (attempt $attempt/$MAX_RETRIES). Waiting ${RETRY_DELAY}s before retry..."
            sleep $RETRY_DELAY
            continue
        fi
        
        # Check for general errors
        if echo "$response" | grep -q "\"errors\""; then
            if [ $attempt -lt $MAX_RETRIES ]; then
                log "API error on attempt $attempt/$MAX_RETRIES. Waiting ${RETRY_DELAY}s before retry..."
                log "Response: $response"
                sleep $RETRY_DELAY
                continue
            else
                log "ERROR: Max retries reached. Last response: $response"
                echo "$response"
                return 1
            fi
        fi
        
        # Success
        echo "$response"
        return 0
    done
    
    log "ERROR: Max retries ($MAX_RETRIES) reached"
    return 1
}

log "=== Starting Image Conversion Process ==="
log "Bucket: $BUCKET_NAME"
log "Image: $IMAGE_NAME"
log "Region: $REGION"
log "Token: $TOKEN"
log "Instance ID: $INSTANCE_ID"
log "Network: $NETWORK" 
log "SS Passthrough Payload: $SS_PASSTHROUGH_PAYLOAD"
log "Bucket Region: $BUCKET_REGION"
log "Bucket Key: $BUCKET_KEY" 
log "Bucket Secret: $BUCKET_SECRET" 
log "Bucket Endpoint: $BUCKET_ENDPOINT"

# Install required packages
log "Installing qemu-utils and s3fs..."
apk update
apk add qemu-img s3fs-fuse curl jq lsblk
INSTALL_DISK=$(lsblk -b -dn -o NAME,SIZE | sort -k2 -nr | head -n1 | awk '{print "/dev/" $1}')
log "Install target disk: $INSTALL_DISK"
# --- Discover Config IDs dynamically ---
log "Fetching Linode configuration list..."
configs=$(api_call "GET" "${API_BASE}/linode/instances/${INSTANCE_ID}/configs")
log "$configs"
if [ $? -ne 0 ] || echo "$configs" | grep -q "\"errors\""; then
    log "ERROR: Failed to fetch Linode configs"
    log "Response: $configs"
    exit 1
fi

# Extract Alpine and Windows config IDs based on label matches
ALPINE_CONFIG=$(echo "$configs" | jq -r '.data[] | select(.label | test("Alpine"; "i")) | .id' | head -n1)
log "Alpine Config: $ALPINE_CONFIG"
WINDOWS_CONFIG=$(echo "$configs" | jq -r '.data[] | select(.label | test("System"; "i")) | .id' | head -n1)
log "Windows Config: $WINDOWS_CONFIG"
if [ -z "$ALPINE_CONFIG" ] || [ "$ALPINE_CONFIG" = "null" ]; then
    log "ERROR: Could not find config labeled 'Alpine'"
    log "Configs available: $(echo "$configs" | jq -r '.data[].label')"
    exit 1
fi

if [ -z "$WINDOWS_CONFIG" ] || [ "$WINDOWS_CONFIG" = "null" ]; then
    log "ERROR: Could not find config labeled containing 'System'"
    log "Configs available: $(echo "$configs" | jq -r '.data[].label')"
    exit 1
fi

log "Discovered Alpine Config ID: $ALPINE_CONFIG"
log "Discovered Windows Config ID: $WINDOWS_CONFIG"

# Enable s3fs mount
modprobe fuse

# Create s3fs password file
log "Creating S3FS credentials file..."
echo "${BUCKET_KEY}:${BUCKET_SECRET}" > /etc/.s3fs-passwd
chmod 400 /etc/.s3fs-passwd

# Create mount point
log "Creating mount point /s3..."
mkdir -p /s3

# Mount object storage bucket
log "Mounting bucket ${BUCKET_NAME} from ${BUCKET_REGION}..."

s3fs "$BUCKET_NAME" /s3 \
    -o passwd_file=/etc/.s3fs-passwd \
    -o url=https://${BUCKET_ENDPOINT} \
    -o use_path_request_style \
    -o ro

if [ $? -ne 0 ]; then
    log "ERROR: Failed to mount S3 bucket"
    exit 1
fi

log "Successfully mounted bucket"

# Verify image exists
log "Checking for image file: $IMAGE_NAME"
if [ ! -f "/s3/$IMAGE_NAME" ]; then
    log "ERROR: Image file /s3/$IMAGE_NAME not found"
    log "Contents of /s3:"
    ls -lh /s3 | tee -a "$LOG_FILE"
    exit 1
fi

log "Image file found: /s3/$IMAGE_NAME"
IMAGE_SIZE=$(stat -c %s "/s3/$IMAGE_NAME")
IMAGE_SIZE_GB=$((IMAGE_SIZE / 1024 / 1024 / 1024))
log "Image size: ${IMAGE_SIZE} bytes (${IMAGE_SIZE_GB} GB)"

# Get target disk size
if [ ! -b "$INSTALL_DISK" ]; then
    log "ERROR: Target disk $INSTALL_DISK not found"
    exit 1
fi

DISK_SIZE=$(blockdev --getsize64 "$INSTALL_DISK")
DISK_SIZE_GB=$((DISK_SIZE / 1024 / 1024 / 1024))
log "Target disk $INSTALL_DISK size: ${DISK_SIZE} bytes (${DISK_SIZE_GB} GB)"

# Check if image will fit (with qemu-img info for actual virtual size)
log "Checking actual image virtual size..."
VIRTUAL_SIZE=$(qemu-img info "/s3/$IMAGE_NAME" | grep "virtual size" | awk '{print $3}')
VIRTUAL_SIZE_BYTES=$(qemu-img info --output=json "/s3/$IMAGE_NAME" | jq -r '.["virtual-size"]')
log "Image virtual size: ${VIRTUAL_SIZE_BYTES} bytes"
if [ "$VIRTUAL_SIZE_BYTES" -gt "$DISK_SIZE" ]; then
    log "ERROR: Image virtual size (${VIRTUAL_SIZE_BYTES} bytes) exceeds target disk size (${DISK_SIZE} bytes)"
    exit 1
fi
log "Image will fit on target disk"

# Detect image format
log "Detecting image format..."
IMAGE_FORMAT=$(qemu-img info --output=json "/s3/$IMAGE_NAME" | jq -r '.format')
log "Detected image format: $IMAGE_FORMAT"

# Convert or copy image based on format
if [ "$IMAGE_FORMAT" = "raw" ]; then
    log "Image is already in RAW format, using dd for direct copy..."
    log "Source: /s3/$IMAGE_NAME"
    log "Destination: $INSTALL_DISK"
    log "This may take a while..."
    dd if="/s3/$IMAGE_NAME" of="$INSTALL_DISK" bs=4M
    if [ $? -ne 0 ]; then
        log "ERROR: dd copy failed"
        exit 1
    fi
    log "Image copy completed successfully"

elif echo "$IMAGE_FORMAT" | grep -Eq '^(qcow|qcow2|vmdk|vdi|vhd|vhdx)$'; then
    log "Starting image conversion from $IMAGE_FORMAT to RAW..."
    log "Source: /s3/$IMAGE_NAME"
    log "Destination: $INSTALL_DISK"
    log "This may take a while..."
    qemu-img convert -p -f "$IMAGE_FORMAT" -O raw -W "/s3/$IMAGE_NAME" "$INSTALL_DISK"
    if [ $? -ne 0 ]; then
        log "ERROR: Image conversion failed"
        exit 1
    fi
    log "Image conversion completed successfully"

else
    log "ERROR: Unsupported image format: $IMAGE_FORMAT"
    log "Supported formats: raw, qcow, qcow2, vmdk, vdi, vhd, vhdx"
    exit 1
fi

# Sync to ensure all data is written
sync
log "Data synced to disk"

# Unmount S3
log "Unmounting S3 bucket..."
umount /s3

# Delete Alpine configuration with retry
log "Deleting Alpine configuration (ID: $ALPINE_CONFIG)..."
delete_response=$(api_call "DELETE" "${API_BASE}/linode/instances/${INSTANCE_ID}/configs/${ALPINE_CONFIG}")

if [ $? -ne 0 ] || echo "$delete_response" | grep -q "error"; then
    log "WARNING: Failed to delete Alpine configuration"
    log "Response: $delete_response"
else
    log "Alpine configuration deleted successfully"
fi

# Handle VPC configuration if needed
NET_VAL=$(echo "$NETWORK" | tr '[:upper:]' '[:lower:]')
if [ "$NET_VAL" = "vpc" ]; then 
    sleep 5
    log "Input from script: $SS_PASSTHROUGH_PAYLOAD"
    echo "Input from script: $SS_PASSTHROUGH_PAYLOAD"
    
    log "=== Updating Windows VPC Config ==="
    windows_config_response=$(api_call "PUT" "${API_BASE}/linode/instances/${INSTANCE_ID}/configs/${WINDOWS_CONFIG}" "$SS_PASSTHROUGH_PAYLOAD")
    
    if [ $? -ne 0 ]; then
        log "ERROR: Failed to update Windows configuration"
        log "Response: $windows_config_response"
        exit 1
    fi
    
    log "Response from API: $windows_config_response"
    echo "Response from API: $windows_config_response"
    
    windows_config=$(echo "$windows_config_response" | jq -r '.id')
    if [ -z "$windows_config" ] || [ "$windows_config" = "null" ]; then
        log "ERROR: Failed to create Windows configuration"
        exit 1
    fi
    log "Windows configuration updated successfully"
else 
    log "Network type is: $NET_VAL (not VPC, skipping VPC config update)"
fi

# Boot Windows configuration with retry
log "Booting Windows configuration (ID: $WINDOWS_CONFIG)..."
boot_response=$(api_call "POST" "${API_BASE}/linode/instances/${INSTANCE_ID}/reboot")

if [ $? -ne 0 ] || echo "$boot_response" | grep -q "error"; then
    log "ERROR: Failed to boot Windows configuration"
    log "Response: $boot_response"
    exit 1
fi

log "Windows configuration boot initiated"
log "=== Image Conversion Process Complete ==="
log "The system will now reboot into the Windows configuration"

# The instance will reboot automatically as initiated by the API call
exit 0
