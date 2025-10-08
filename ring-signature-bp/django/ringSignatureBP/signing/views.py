# Django Framework Imports
from django.shortcuts import render
from django.contrib import messages
from django.http import HttpResponse, JsonResponse
from django.views.decorators.csrf import csrf_exempt

# Standard Library Imports
import os
import re
import json
import base64
import datetime
import hashlib
import requests
import textwrap
from typing import List, Optional, Union, Tuple, Any
from urllib.parse import quote

# Cryptography Library Imports
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey, RSAPrivateKey

# Type alias for RSA keys (public and private)
RSAKey = Union[RSAPublicKey, RSAPrivateKey]

MAX_128_BIT_VALUE = (1 << 128) - 1 

def truncate_to_128_bits(value: int) -> int:
    return value & MAX_128_BIT_VALUE


def format_pem_key(key_str: str, key_type_hint: str = "public") -> str:
 
    #Convert a key string into properly formatted PEM format.
    
    # First, check if the key is already in valid PEM format
    if key_type_hint == "private":
        if (re.search(r"-----BEGIN (RSA )?PRIVATE KEY-----", key_str) and 
            re.search(r"-----END (RSA )?PRIVATE KEY-----", key_str)):
            return re.sub(r'\r\n?', '\n', key_str.strip())
    elif key_type_hint == "public":
        if (re.search(r"-----BEGIN PUBLIC KEY-----", key_str) and 
            re.search(r"-----END PUBLIC KEY-----", key_str)):
            return re.sub(r'\r\n?', '\n', key_str.strip())
    
    # Clean up the key string
    key_str = re.sub(r'\s+', '', key_str)  # Remove whitespace
    key_str = re.sub(r'-*BEGIN ?[A-Z ]*KEY-*(?:\r?\n)?', '', key_str, flags=re.IGNORECASE)
    key_str = re.sub(r'-*END ?[A-Z ]*KEY-*(?:\r?\n)?', '', key_str, flags=re.IGNORECASE)
    key_str = re.sub(r'[^A-Za-z0-9+/=]', '', key_str)  # Keep only valid base64 characters
    
    # Add PEM headers and footers
    if key_type_hint == "private":
        header = "-----BEGIN PRIVATE KEY-----"
        footer = "-----END PRIVATE KEY-----"
    else:
        header = "-----BEGIN PUBLIC KEY-----"
        footer = "-----END PUBLIC KEY-----"
    
    # 64 character lines
    base64_lines = textwrap.wrap(key_str, 64)
    
    # Combine 
    return f"{header}\n" + '\n'.join(base64_lines) + f"\n{footer}"

def load_key(key_data: Union[str, bytes], expected_type: str = "any") -> Any:

    # Convert string input to bytes for cryptographic library compatibility
    if isinstance(key_data, str):
        key_data = key_data.encode('utf-8')
    
    try:
        # Try loading as private key first (if requested)
        if expected_type in ["private", "any"]:
            try:
                # First try standard PEM format
                key = serialization.load_pem_private_key(key_data, password=None)
                return key
            except Exception as e1:
                # Try to fix common PEM formatting issues
                try:
                    # Clean up the PEM data
                    key_str = key_data.decode('utf-8') if isinstance(key_data, bytes) else key_data
                    
                    # Remove any extra whitespace and ensure proper line endings
                    lines = key_str.strip().split('\n')
                    cleaned_lines = []
                    in_key = False
                    
                    for line in lines:
                        line = line.strip()
                        if line.startswith('-----BEGIN'):
                            in_key = True
                            cleaned_lines.append(line)
                        elif line.startswith('-----END'):
                            cleaned_lines.append(line)
                            in_key = False
                        elif in_key and line:
                            cleaned_lines.append(line)
                    
                    if cleaned_lines:
                        cleaned_key = '\n'.join(cleaned_lines) + '\n'
                        key = serialization.load_pem_private_key(cleaned_key.encode('utf-8'), password=None)
                        return key
                    else:
                        raise ValueError("No valid key data found")
                        
                except Exception as e2:
                    # Only raise error if private key was specifically requested
                    if expected_type == "private":
                        error_msg = f"Could not load private key. Tried PEM and cleaned PEM formats. "
                        error_msg += f"PEM error: {str(e1)}. "
                        error_msg += f"Cleaned PEM error: {str(e2)}"
                        raise ValueError(error_msg)
        
        # Try loading as public key (if requested or as fallback)
        if expected_type in ["public", "any"]:
            try:
                return serialization.load_pem_public_key(key_data)
            except Exception as e:
                # Only raise error if public key was specifically requested
                if expected_type == "public":
                    raise ValueError(f"Could not load public key: {str(e)}")
        
        # If we reach here, neither loading method worked
        raise ValueError("Could not load key as either private or public")
        
    except Exception as e:
        # Re-raise with more context if it's not already a ValueError
        if isinstance(e, ValueError):
            raise
        else:
            raise ValueError(f"Error loading key: {str(e)}")

def get_key_size(key: RSAKey) -> Optional[int]:
    
    #Extract the bit size of an RSA key.
        
    try:
        # Method 1: Try direct key_size attribute (most reliable)
        if hasattr(key, 'key_size') and key.key_size is not None:
            return key.key_size
        
        # Method 2: Calculate from public key modulus
        if hasattr(key, 'public_numbers'):
            return key.public_numbers().n.bit_length()
        
        # Method 3: Calculate from private key modulus (for private keys)
        elif hasattr(key, 'private_numbers'):
            return key.private_numbers().public_numbers.n.bit_length()
        
        return None
        
    except Exception:
        return None


def validate_rsa_key(key: RSAKey, expected_type: str = "any", expected_size: Optional[int] = None) -> Tuple[bool, str]:
    #Validate an RSA key for type and size compliance.
    
    
    # Step 1: Validate key type
    is_private = isinstance(key, RSAPrivateKey)
    is_public = isinstance(key, RSAPublicKey)
    
    if expected_type == "public" and not is_public:
        return False, "Expected public key, but found different key type"
    elif expected_type == "private" and not is_private:
        return False, "Expected private key, but found different key type"
    
    # Step 2: Validate key size (if specified)
    if expected_size is not None:
        key_size = get_key_size(key)
        if key_size is not None:
            # Calculate size difference with tolerance for compatibility
            size_difference = abs(key_size - expected_size)
            
            # Allow up to 1024 bits difference for compatibility
            if size_difference > 1024:
                return False, f"Expected key size around {expected_size} bits, found {key_size} bits"
    
    # If all validations pass, return success
    return True, ""

def get_expected_key_size(key_type: str) -> Optional[int]:
    # Mapping of key type strings to bit sizes
    size_map = {
        "RSA 1024": 1024,
        "RSA 2048": 2048,
        "RSA 4096": 4096,
    }
    return size_map.get(key_type)


def symmetric_encrypt(k: int, data: int) -> int:
   # E_k(x) = (x + k) mod 2^128
    return (data + k) & MAX_128_BIT_VALUE

def combining_function(k: int, v: int, y_values: List[int]) -> int:

    result = v  # v = glue value
    
    # Apply the nested encryption: E_k(y_n ⊕ E_k(y_{n-1} ⊕ E_k(... ⊕ E_k(y_1 ⊕ v)...)))
    for y in y_values: # y_values = list of y-values from ring members
        # XOR with current result
        result = result ^ y
        # Encrypt with symmetric key derived from message hash
        result = symmetric_encrypt(k, result)
 
    return truncate_to_128_bits(result)


class RingSignature:

    def __init__(self, keys: List[RSAKey]):
    
        self.keys = keys
        self.n = len(keys)
        
        # Validate that we have at least one key
        if self.n == 0:
            raise ValueError("Ring signature requires at least one key")
        
        # Check that all keys have compatible sizes
        first_key_size = get_key_size(keys[0])
        if first_key_size is None:
            # Fallback: try to get size from modulus if direct method fails
            first_key_size = keys[0].public_numbers().n.bit_length()
        
        # Validate each subsequent key against the first key's size
        for i, key in enumerate(keys[1:], 1):
            key_size = get_key_size(key)
            if key_size is None:
                # Fallback: try to get size from modulus if direct method fails
                key_size = key.public_numbers().n.bit_length()
            
            # Allow small variations in key size for compatibility
            # This handles cases like 3072-bit keys being used as 2048-bit
            size_difference = abs(key_size - first_key_size)
            if size_difference > 1024:  # Allow up to 1024 bits difference
                raise ValueError(
                    f"All keys must have compatible sizes. "
                    f"Key {i} has {key_size} bits, first key has {first_key_size} bits"
                )
    
    def sign(self, message: str, signer_index: int) -> Tuple[int, List[int]]:
        # Validate signer index
        if signer_index < 0 or signer_index >= self.n:
            raise ValueError(f"Invalid signer index: {signer_index}")
        
        # Get the signer's private key and validate it
        signer_key = self.keys[signer_index]
        
        if not isinstance(signer_key, RSAPrivateKey):
            raise ValueError("Signer key must be a private key")
        # 1: Pick a random glue value v
        v = int.from_bytes(os.urandom(16), byteorder='big')  # 128-bit random value

        # 2: Calculate the key k = H(m) using cryptographic hash function
        k = int(hashlib.sha256(message.encode()).hexdigest(), 16)
        k = truncate_to_128_bits(k)  # Truncate to 128 bits for consistency
        
       
        
        # Step 3: Pick random x_i for all ring members except the signer and calculate y_i = g_i(x_i)
        
        # Extract public keys for the combining function
        public_keys = [key.public_key() if isinstance(key, RSAPrivateKey) else key for key in self.keys]
        
        # Compute temporary x_signer to determine target length
        #why this step? if we do not do this step, all X-values have the same lentgth except the signers one 
        temp_y_signer = int.from_bytes(os.urandom(16), byteorder='big')
        temp_y_signer = truncate_to_128_bits(temp_y_signer)
        temp_x_signer = pow(temp_y_signer, signer_key.private_numbers().d, 
                           signer_key.private_numbers().public_numbers.n)
        target_length = temp_x_signer.bit_length()
        
        x_values = []
        y_values = []
        
        for i in range(self.n):
            if i != signer_index:
                # Generate random x_i for non-signers with target length for anonymity
                # Ensure x_i has similar bit length to the final x_signer
                while True:
                    x_i = int.from_bytes(os.urandom((target_length + 7) // 8), byteorder='big')
                    # Ensure x_i is within reasonable range of target_length
                    if abs(x_i.bit_length() - target_length) <= 8:  # Allow small variation
                        break
                
                x_values.append(x_i)
                
                # Calculate y_i = g_i(x_i) = x_i^e_i mod n_i using public key
                y_i = pow(x_i, public_keys[i].public_numbers().e, public_keys[i].public_numbers().n)
                y_i = truncate_to_128_bits(y_i)  # Truncate to 128 bits for consistency
                y_values.append(y_i)
            else:
                # Placeholder for signer - will be computed later
                x_values.append(0)
                y_values.append(0)
        
        
        partial_result = v
        
        # Process all y-values before the signer
        for i in range(signer_index):
            if y_values[i] != 0:
                partial_result = partial_result ^ y_values[i]
                partial_result = symmetric_encrypt(k, partial_result)
                partial_result = truncate_to_128_bits(partial_result)
        
        
        
        # Work backwards from the desired final result (v) through remaining y-values
        target_before_signer = v
        for i in range(len(y_values) - 1, signer_index, -1):
            if y_values[i] != 0:
                # Work backwards: if E_k(y_i ⊕ prev) = target, then prev = y_i ⊕ E_k^-1(target)
                # For E_k(x) = (x + k), E_k^-1(x) = (x - k)
                target_before_signer = y_values[i] ^ ((target_before_signer - k) & MAX_128_BIT_VALUE)
                target_before_signer = truncate_to_128_bits(target_before_signer)
        
        # Now solve for y_signer: E_k(y_signer ⊕ partial_result) = target_before_signer
        # So: y_signer ⊕ partial_result = E_k^-1(target_before_signer) = (target_before_signer - k)
        # Therefore: y_signer = partial_result ⊕ (target_before_signer - k)
        y_signer = partial_result ^ ((target_before_signer - k) & MAX_128_BIT_VALUE)
        y_signer = truncate_to_128_bits(y_signer)
        y_values[signer_index] = y_signer
        
        # Step 5: Calculate x_signer using the signer's private key: x_signer = g_signer^-1(y_signer)
        # For RSA: g_signer^-1(y_signer) = y_signer^d_signer mod n_signer
        x_signer = pow(y_signer, signer_key.private_numbers().d, 
                      signer_key.private_numbers().public_numbers.n)
        x_values[signer_index] = x_signer
        
        return v, x_values
    
    def verify(self, message: str, v: int, x_values: List[int]) -> bool:
        """
        Verify a ring signature using the correct algorithm:
        
        1. Apply the public key trap door on all x_i: y_i = g_i(x_i)
        2. Calculate the symmetric key k = H(m)
        3. Verify that the ring equation holds C_k,v(y_1, y_2, ..., y_n) = v
        
        Returns:
            True if the signature is valid, False otherwise
        """
        # Step 1: Validate input lengths
        if len(x_values) != self.n:
            return False
        
        # Step 2:  key k = H(m)
        k = int(hashlib.sha256(message.encode()).hexdigest(), 16)
        k = truncate_to_128_bits(k)  # Truncate to 128 bits for consistency
        
        # Step 3: Apply the public key trap door on all x_i: y_i = g_i(x_i)
        y_values = []
        
        # Extract public keys (reuse the same logic as in signing)
        public_keys = [key.public_key() if isinstance(key, RSAPrivateKey) else key for key in self.keys]
        
        for x_i, pub_key in zip(x_values, public_keys):
            # Compute y_i = g_i(x_i) = x_i^e_i mod n_i using RSA public key
            y_i = pow(x_i, pub_key.public_numbers().e, pub_key.public_numbers().n)
            
            # Ensure y_i fits in 128 bits for the combining function
            y_i = truncate_to_128_bits(y_i)
            y_values.append(y_i)
        
        # Step 4: Verify that the ring equation holds C_k,v(y_1, y_2, ..., y_n) = v
        # Use the signing combining function with the provided v
        # The result should equal v if the signature is valid
        computed_result = combining_function(k, v, y_values)
        
        # The signature is valid if the ring equation holds: C_k,v(...) = v
        return computed_result == v


def load_ring_keys_from_manual_members(member_data: List[dict], signer_index: int, private_key_str: str) -> Tuple[List[RSAKey], List[str], List[str]]:
   
    
    #This function processes member data submitted through the web form, validates
    #all public keys, loads the signer's private key, and prepares them for ring
    #signature operations. It ensures all keys are compatible and properly formatted.
    
    # Validate input parameters
    if not member_data:
        raise ValueError("No member data provided")
    
    if signer_index < 0 or signer_index >= len(member_data):
        raise ValueError(f"Invalid signer index: {signer_index}")
    
    # Initialize result lists
    ring_keys = []
    member_names = []
    member_orgs = []
    
    # Step 1: Process each member's public key
    for i, member in enumerate(member_data):
        try:
            # Format the public key into proper PEM format
            formatted_public_key = format_pem_key(member['public_key'])
            public_key_obj = load_key(formatted_public_key, "public")
            
            # Validate the key size matches the expected type
            expected_size = get_expected_key_size(member['key_type'])
            valid, error_msg = validate_rsa_key(public_key_obj, "public", expected_size)
            
            if not valid:
                raise ValueError(f"Key validation failed for {member['name']}: {error_msg}")
            
            # Add to result lists
            ring_keys.append(public_key_obj)
            member_names.append(member['name'])
            member_orgs.append(member.get('organization', ''))
            
        except Exception as e:
            raise ValueError(f"Error loading key for {member['name']}: {str(e)}")
    
    # Step 2: Load and validate the signer's private key
    try:
        # Format the private key into proper PEM format
        formatted_private_key = format_pem_key(private_key_str, key_type_hint='private')
        private_key_obj = load_key(formatted_private_key, "private")
        
        # Validate the signer's key size matches their public key type
        signer_member = member_data[signer_index]
        expected_size = get_expected_key_size(signer_member['key_type'])
        valid, error_msg = validate_rsa_key(private_key_obj, "private", expected_size)
        
        if not valid:
            raise ValueError(f"Signer key validation failed for {signer_member['name']}: {error_msg}")
        
        # Replace the signer's public key with their private key in the ring
        # This enables signature generation
        ring_keys[signer_index] = private_key_obj
        
    except Exception as e:
        raise ValueError(f"Error loading signer's private key: {str(e)}")
    
    return ring_keys, member_names, member_orgs


def sign(request):
   
    #This view handles both GET and POST requests for the ring signature  process. It provides a comprehensive interface for users to create ring
    
    if request.method == "POST":
        try:
            
            # Extract form data from POST request
            message = request.POST.get("message", "").strip()
            private_key = request.POST.get("private_key", "").strip()
            member_data_json = request.POST.get("member_data", "")
            signer_index_str = request.POST.get("signer_index", "")
            
            # Handle PDF file upload if provided
            pdf_file = request.FILES.get("pdf_file")
            if pdf_file:
                # Read PDF file content and use its hash as the message
                pdf_content = pdf_file.read()
                
                message = hashlib.sha256(pdf_content).hexdigest()
                
            elif not message:
                raise ValueError("Message is required (either text message or PDF file)")
            if not private_key:
                raise ValueError("Private key is required")
            if not member_data_json:
                raise ValueError("At least one ring member is required")
            if not signer_index_str:
                raise ValueError("Please select a signer")
            
            # Parse JSON member data and convert signer index to integer
            try:
                member_data = json.loads(member_data_json)
                signer_index = int(signer_index_str)
            except (json.JSONDecodeError, ValueError) as e:
                raise ValueError(f"Invalid member data format: {str(e)}")
            
            # Validate member data structure and requirements
            if not isinstance(member_data, list) or len(member_data) < 2:
                raise ValueError("At least 2 ring members are required")
            
            # Ensure each member has all required fields
            for member in member_data:
                required_fields = ['name', 'public_key', 'key_type']
                for field in required_fields:
                    if field not in member or not member[field].strip():
                        raise ValueError(f"All members must have a {field}")
            
            # Validate that the signer index is within valid range
            if signer_index < 0 or signer_index >= len(member_data):
                raise ValueError("Invalid signer selection")
            
            # Load and validate all ring member keys (public keys + signer's private key)
            ring_keys, member_names, member_orgs = load_ring_keys_from_manual_members(
                member_data, signer_index, private_key
            )
            
            ring = RingSignature(ring_keys)
            
            glue_value, x_values = ring.sign(message, signer_index)
            
            # Convert large integers to base64 for safe database storage
            glue_value_b64 = int_to_base64(glue_value)
            x_values_b64 = [int_to_base64(x) for x in x_values]
            
            # Convert all keys to PEM format for storage and verification
            public_keys_pem = []
            for key in ring_keys:
                if isinstance(key, RSAPrivateKey):
                    
                    key = key.public_key()
                
                # Convert key to PEM format for storage
                key_pem = key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ).decode('utf-8')
                public_keys_pem.append(key_pem)
            
            #
            
            # Generate verification URL with all signature data pre-filled
            # This allows immediate verification without database storage
            # Get the current domain and protocol (localhost or .onion)
            current_domain = request.get_host()
            protocol = 'https' if request.is_secure() else 'http'
            verification_url = (
                f'{protocol}://{current_domain}/signing/verifier/?message={quote(message)}'
                f'&glue_value={quote(glue_value_b64)}'
                f'&x_values={quote(json.dumps(x_values_b64))}'
                f'&public_keys={quote(json.dumps(public_keys_pem))}'
            )
            
            # Prepare context for result page
            context = {
                "signature_details": {
                    "message": message,
                    "message_type": "PDF file hash" if pdf_file else "Text message",
                    "original_message": request.POST.get("message", "").strip() if not pdf_file else f"PDF file: {pdf_file.name}",
                    "glue_value": glue_value_b64,
                    "x_values": x_values_b64,
                    "public_keys": public_keys_pem,
                    "message_hash": base64.b64encode(hashlib.sha256(message.encode()).digest()).decode(),
                    "ring_signature_tuple": {
                        "public_keys": public_keys_pem,
                        "glue_value": glue_value_b64,
                        "x_values": x_values_b64
                    },
                    "ring_members": []
                },
                "member_names": member_names,
                "member_orgs": member_orgs,
                "signer_name": member_names[signer_index],
                "total_members": len(member_data),
                "verification_url": verification_url
            }
            
            # Add ring members to signature_details
            for i, member in enumerate(member_data):
                member_info = {
                    "name": member['name'],
                    "public_key": member['public_key'],
                    "x_value": x_values_b64[i] if i < len(x_values_b64) else "0",
                    "member_index": i + 1
                }
                context["signature_details"]["ring_members"].append(member_info)
            
            return render(request, "signing/signature_result.html", context)
            
        except Exception as e:
            # Handle errors gracefully
            error_message = f"Error creating signature: {str(e)}"
            messages.error(request, error_message)
            
            # Return to form with error
            context = {
                "error": error_message,
                "prefilled": {
                    "message": request.POST.get("message", ""),
                    "private_key": request.POST.get("private_key", ""),
                    "member_data": request.POST.get("member_data", ""),
                    "signer_index": request.POST.get("signer_index", "")
                }
            }
            return render(request, "signing/index.html", context)
    
    # GET request - show the form
    context = {
        "prefilled": {
            "message": request.GET.get("message", ""),
            "private_key": request.GET.get("private_key", ""),
            "member_data": request.GET.get("member_data", ""),
            "signer_index": request.GET.get("signer_index", "")
        }
    }
    
    return render(request, "signing/index.html", context)

def verifier(request):
    
    context = {
        "prefilled": {
            "message": request.GET.get("message", ""),
            "glue_value": request.GET.get("glue_value", ""),
            "x_values": request.GET.get("x_values", ""),
            "public_keys": request.GET.get("public_keys", ""),
        }
    }
    
    # If this is a POST request, preserve the form data for error cases
    if request.method == "POST":
        context["prefilled"] = {
            "message": request.POST.get("message", ""),
            "glue_value": request.POST.get("glue_value", ""),
            "x_values": request.POST.get("x_values", ""),
            "public_keys": request.POST.get("public_keys", ""),
        }
    
    if request.method == "POST":
        # ================================================================
        # STEP 1: EXTRACT AND VALIDATE FORM DATA
        # ================================================================
        
        # Extract form data from POST request
        message = request.POST.get("message", "").strip()
        glue_value = request.POST.get("glue_value", "").strip()
        x_values = request.POST.get("x_values", "").strip()
        public_keys = request.POST.get("public_keys", "").strip()
        
        # Handle PDF file upload if provided
        pdf_file = request.FILES.get("pdf_file")
        if pdf_file:
            # Read PDF file content and use its hash as the message
            pdf_content = pdf_file.read()
            pdf_hash = hashlib.sha256(pdf_content).hexdigest()
            
            # If both message and PDF are provided, they should match
            if message and message != pdf_hash:
                context["error"] = "Message text and PDF file hash don't match. Use either message text OR PDF file, not both."
                context["prefilled"] = {
                    "message": message,
                    "glue_value": glue_value,
                    "x_values": x_values,
                    "public_keys": public_keys,
                }
                return render(request, "signing/verifier.html", context)
            
            # Use PDF hash as the message
            message = pdf_hash
        
        # Validate that all required fields are present
        if not all([message, glue_value, x_values, public_keys]):
            context["error"] = "Message (or PDF file) and all signature fields are required."
            # Update context with current form data
            context["prefilled"] = {
                "message": message,
                "glue_value": glue_value,
                "x_values": x_values,
                "public_keys": public_keys,
            }
            return render(request, "signing/verifier.html", context)
        
        try:
            
            try:
                if public_keys.startswith("["):
                    # JSON format: ["key1", "key2", ...]
                    public_keys_list = json.loads(public_keys)
                else:
                    # Newline-separated format
                    public_keys_list = [pk.strip() for pk in public_keys.split("\n") if pk.strip()]
            except Exception as e:
                # Fallback to newline-separated parsing
                public_keys_list = [pk.strip() for pk in public_keys.split("\n") if pk.strip()]
            
            # Parse glue value (challenge value) from base64
            try:
                # Always use base64_to_int for glue value since we store it as base64 during signing
                c = base64_to_int(glue_value)
            except Exception as e:
                context["error"] = f"Invalid glue value (s/c): {str(e)}"
                # Update context with current form data
                context["prefilled"] = {
                    "message": message,
                    "glue_value": glue_value,
                    "x_values": x_values,
                    "public_keys": public_keys,
                }
                return render(request, "signing/verifier.html", context)
            
            # Parse x_values (signature components) from base64
            try:
                if x_values.startswith("["):
                    # JSON format: ["value1", "value2", ...]
                    x_list = json.loads(x_values)
                    # Convert base64 encoded values to integers
                    x_list = [base64_to_int(x) if isinstance(x, str) else x for x in x_list]
                else:
                    # Comma or newline-separated format
                    x_list = [base64_to_int(x.strip()) for x in x_values.replace(",", "\n").split("\n") if x.strip()]
            
            except Exception as e:
                context["error"] = f"Invalid x values: {str(e)}"
                # Update context with current form data
                context["prefilled"] = {
                    "message": message,
                    "glue_value": glue_value,
                    "x_values": x_values,
                    "public_keys": public_keys,
                }
                return render(request, "signing/verifier.html", context)
            
            
            # Load all public keys from the parsed list
            ring_keys = []
            
            
            for i, pk_pem in enumerate(public_keys_list):
                try:
                    # Load the PEM string directly (no base64 decoding needed)
                    key = load_key(pk_pem, "public")
                    ring_keys.append(key)
                   
                except Exception as e:
                    context["error"] = f"Error loading public key {i+1}: {str(e)}"
                    # Update context with current form data
                    context["prefilled"] = {
                        "message": message,
                        "glue_value": glue_value,
                        "x_values": x_values,
                        "public_keys": public_keys,
                    }
                    return render(request, "signing/verifier.html", context)
            
    
            
            # Validate that we have matching numbers of keys and x_values
            if len(ring_keys) == len(x_list):
                # Create ring signature instance and perform verification
                ring = RingSignature(ring_keys)
                is_valid = ring.verify(message, c, x_list)
                # Display verification result
                if is_valid:
                    context["success"] = True
                    context["message"] = "✅ Ring signature is VALID!"
                    context["details"] = {
                        "message": message,
                        "ring_size": len(ring_keys),
                        "verification_time": datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')
                    }
                else:
                    context["success"] = False
                    context["error"] = "❌ Ring signature is INVALID!"
            else:
                context["error"] = f"Mismatch between number of public keys ({len(ring_keys)}) and x values ({len(x_list)})."
                # Update context with current form data
                context["prefilled"] = {
                    "message": message,
                    "glue_value": glue_value,
                    "x_values": x_values,
                    "public_keys": public_keys,
                }
                
        except Exception as e:
            context["error"] = f"Verification error: {str(e)}"
            # Update context with current form data
            context["prefilled"] = {
                "message": message,
                "glue_value": glue_value,
                "x_values": x_values,
                "public_keys": public_keys,
            }
        
        return render(request, "signing/verifier.html", context)
    
    return render(request, "signing/verifier.html", context)


def fetch_github_keys(username: str) -> dict:

   # Fetch public keys from GitHub API for a given username.
    
    try:
        # Fetch user data from GitHub API
        user_url = f"https://api.github.com/users/{username}"
        user_response = requests.get(user_url, timeout=10)
        user_response.raise_for_status()
        user_data = user_response.json()
        
        # Fetch public keys from GitHub API
        keys_url = f"https://api.github.com/users/{username}/keys"
        keys_response = requests.get(keys_url, timeout=10)
        keys_response.raise_for_status()
        keys_data = keys_response.json()
        
        # Process RSA keys
        rsa_keys = []
        for key in keys_data:
            if key['key'].startswith('ssh-rsa'):
                try:
                    # Convert SSH key to PEM format
                    pem_key = ssh_to_pem(key['key'])
                    
                    # Get key size from the modulus directly (more accurate)
                    parts = key['key'].strip().split()
                    key_data_b64 = base64.b64decode(parts[1])
                    
                    # Parse SSH key structure to get modulus
                    offset = 0
                    type_len = int.from_bytes(key_data_b64[offset:offset+4], byteorder='big')
                    offset += 4 + type_len
                    e_len = int.from_bytes(key_data_b64[offset:offset+4], byteorder='big')
                    offset += 4 + e_len
                    n_len = int.from_bytes(key_data_b64[offset:offset+4], byteorder='big')
                    offset += 4
                    n_bytes = key_data_b64[offset:offset+n_len]
                    n = int.from_bytes(n_bytes, byteorder='big')
                    key_size = n.bit_length()
                    
                    # Determine key type based on size
                    key_type = determine_key_type(key_size)
                    
                    rsa_keys.append({
                        'id': key['id'],
                        'key': pem_key,
                        'ssh_key': key['key'],
                        'title': key.get('title', 'GitHub SSH Key'),
                        'created_at': key.get('created_at'),
                        'key_type': key_type,
                        'key_size': key_size
                    })
                except Exception as e:
                    # Skip keys that can't be converted
                    continue
        
        return {
            'success': True,
            'name': user_data.get('name', username),
            'organization': user_data.get('company', ''),
            'keys': rsa_keys
        }
        
    except requests.exceptions.RequestException as e:
        raise Exception(f"GitHub API request failed: {str(e)}")
    except Exception as e:
        raise Exception(f"Error fetching GitHub data: {str(e)}")

@csrf_exempt
def github_lookup(request):
   
    if request.method == "POST":
        try:
            # Parse JSON request body
            data = json.loads(request.body)
            username = data.get('username', '').strip()
            
            if not username:
                return JsonResponse({
                    'success': False,
                    'error': 'Username is required'
                })
            
            # Fetch GitHub data
            result = fetch_github_keys(username)
            return JsonResponse(result)
            
        except json.JSONDecodeError as e:
            return JsonResponse({
                'success': False,
                'error': 'Invalid JSON data'
            })
        except Exception as e:
            return JsonResponse({
                'success': False,
                'error': f'Server error: {str(e)}'
            })
    
    return JsonResponse({
        'success': False,
        'error': 'Only POST requests are allowed'
    })

def landing_page(request):
    
    return render(request, "signing/landing.html")

def ssh_to_pem(ssh_key: str) -> str:
    
    #Convert SSH public key to PEM format.
    try:
        # Parse SSH key format
        parts = ssh_key.strip().split()
        if len(parts) < 2:
            raise ValueError("Invalid SSH key format")
        
        key_type = parts[0]
        key_data = parts[1]
        
        if key_type != "ssh-rsa":
            raise ValueError(f"Unsupported key type: {key_type}. Only RSA keys are supported.")
        
        # Decode base64 key data
        key_bytes = base64.b64decode(key_data)
        
        # Parse SSH key structure
        # SSH RSA key format: type_len + type + e_len + e + n_len + n
        offset = 0
        
        # Read type length and type
        type_len = int.from_bytes(key_bytes[offset:offset+4], byteorder='big')
        offset += 4
        key_type_str = key_bytes[offset:offset+type_len].decode('ascii')
        offset += type_len
        
        if key_type_str != "ssh-rsa":
            raise ValueError("Key type mismatch")
        
        # Read exponent length and exponent
        e_len = int.from_bytes(key_bytes[offset:offset+4], byteorder='big')
        offset += 4
        e_bytes = key_bytes[offset:offset+e_len]
        offset += e_len
        
        # Read modulus length and modulus
        n_len = int.from_bytes(key_bytes[offset:offset+4], byteorder='big')
        offset += 4
        n_bytes = key_bytes[offset:offset+n_len]
        
        # Convert to integers
        e = int.from_bytes(e_bytes, byteorder='big')
        n = int.from_bytes(n_bytes, byteorder='big')
        
        # Create RSA public key
        from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
        public_numbers = RSAPublicNumbers(e, n)
        public_key = public_numbers.public_key()
        
        # Export to PEM format
        pem_key = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
        
        return pem_key
        
    except Exception as e:
        raise ValueError(f"Failed to convert SSH key to PEM: {str(e)}")


def determine_key_type(key_size: int) -> str:
    if key_size <= 1024:
        return "RSA 1024"
    elif key_size <= 2048:
        return "RSA 2048"
    elif key_size <= 3072:
        return "RSA 2048"  # Treat 3072 as 2048 for compatibility
    elif key_size <= 4096:
        return "RSA 4096"
    else:
        return "RSA 4096"  # Default for larger keys

def int_to_base64(value: int) -> str:
    try:
        # Try direct conversion first (works for smaller integers)
        return base64.b64encode(str(value).encode()).decode()
    except (OverflowError, ValueError):
        # For very large integers, convert to hex first, then to bytes
        hex_str = hex(value)[2:]  # Remove '0x' prefix
        if len(hex_str) % 2 != 0:
            hex_str = '0' + hex_str  # Ensure even length
        
        # Convert hex to bytes
        try:
            bytes_data = bytes.fromhex(hex_str)
            return base64.b64encode(bytes_data).decode()
        except Exception:
            # Final fallback: convert to string and handle encoding
            value_str = str(value)
            # Split into chunks if too long
            chunk_size = 1000
            chunks = [value_str[i:i+chunk_size] for i in range(0, len(value_str), chunk_size)]
            encoded_chunks = []
            for chunk in chunks:
                encoded_chunks.append(base64.b64encode(chunk.encode()).decode())
            return '|'.join(encoded_chunks)

def base64_to_int(encoded: str) -> int:

    try:
        # Try direct conversion first
        decoded_bytes = base64.b64decode(encoded.encode())
        return int(decoded_bytes.decode())
    except (UnicodeDecodeError, ValueError):
        # Check if it's a chunked encoding
        if '|' in encoded:
            chunks = encoded.split('|')
            decoded_chunks = []
            for chunk in chunks:
                decoded_bytes = base64.b64decode(chunk.encode())
                decoded_chunks.append(decoded_bytes.decode())
            return int(''.join(decoded_chunks))
        else:
            # Try hex conversion
            try:
                decoded_bytes = base64.b64decode(encoded.encode())
                hex_str = decoded_bytes.hex()
                return int(hex_str, 16)
            except Exception:
                # Final fallback: try direct string conversion
                decoded_bytes = base64.b64decode(encoded.encode())
                return int(decoded_bytes.decode())


