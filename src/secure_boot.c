/**
 * @file secure_boot.c
 * @brief Secure Boot Implementation - Mitigating Top 10 Verification Mistakes
 * 
 * This code demonstrates secure boot practices for embedded systems
 * Based on "Top 10 Secure Boot Mistakes" by Jasper Van Woudenberg (Riscure)
 */

#include <stdint.h>
#include <stdbool.h>
#include <string.h>

/*============================================================================
 * CONFIGURATION & CONSTANTS
 *============================================================================*/

#define FIRMWARE_MAX_SIZE       (256 * 1024)  // 256KB max
#define SIGNATURE_SIZE          256           // RSA-2048 signature
#define HASH_SIZE               32            // SHA-256
#define VERSION_COUNTER_ADDR    0x08000000    // OTP/eFuse address
#define PUBLIC_KEY_SIZE         256

/* State machine states for secure boot */
typedef enum {
    STATE_INIT              = 0x5A5A5A5A,
    STATE_HEADER_VERIFIED   = 0xA5A5A5A5,
    STATE_SIGNATURE_VALID   = 0x12345678,
    STATE_VERSION_OK        = 0x87654321,
    STATE_READY_TO_EXECUTE  = 0xDEADBEEF,
    STATE_ERROR             = 0x00000000
} SecureBootState;

/* Firmware header - ALL fields must be signed */
typedef struct __attribute__((packed)) {
    uint32_t magic;              // Magic number
    uint32_t version;            // Firmware version (anti-rollback)
    uint32_t firmware_size;      // Size of firmware
    uint32_t load_address;       // Fixed load address
    uint32_t entry_point;        // Entry point offset
    uint8_t  hash[HASH_SIZE];    // SHA-256 of firmware
    uint8_t  signature[SIGNATURE_SIZE]; // Signature of header
} FirmwareHeader;

/*============================================================================
 * MITIGATION #1: SIGN EVERYTHING
 * - All data must be verified BEFORE use
 * - Never trust any field until signature is validated
 *============================================================================*/

/* Public key stored in ROM/OTP - cannot be modified */
static const uint8_t PUBLIC_KEY[PUBLIC_KEY_SIZE] __attribute__((section(".rodata.key"))) = {
    /* Your RSA/ECDSA public key here */
    0x00 /* ... */
};

/*============================================================================
 * MITIGATION #5: TIMING ATTACKS
 * Use constant-time comparison to prevent timing side-channels
 *============================================================================*/

/**
 * @brief Constant-time memory comparison (prevents timing attacks)
 * @note Uses XOR accumulation instead of early-exit if comparison
 */
static bool secure_compare(const uint8_t *a, const uint8_t *b, size_t len)
{
    volatile uint8_t result = 0;
    volatile size_t i;
    
    /* XOR all bytes - timing is constant regardless of where mismatch occurs */
    for (i = 0; i < len; i++) {
        result |= a[i] ^ b[i];
    }
    
    /* Additional check to prevent compiler optimization */
    volatile bool is_equal = (result == 0);
    return is_equal;
}

/*============================================================================
 * MITIGATION #6: FAULT INJECTION - DEFENSIVE CODING
 * - Double/triple checks for critical decisions
 * - Redundant variables
 * - Check for impossible states
 *============================================================================*/

/**
 * @brief Verify signature with fault injection protection
 */
static bool verify_signature_defensive(const uint8_t *data, size_t data_len,
                                       const uint8_t *signature)
{
    volatile bool result1 = false;
    volatile bool result2 = false;
    volatile bool result3 = false;
    
    /* Perform verification three times */
    result1 = crypto_verify_signature(data, data_len, signature, PUBLIC_KEY);
    result2 = crypto_verify_signature(data, data_len, signature, PUBLIC_KEY);
    result3 = crypto_verify_signature(data, data_len, signature, PUBLIC_KEY);
    
    /* All three must agree - detects single fault injection */
    if (result1 && result2 && result3) {
        /* Additional sanity check */
        if (result1 == result2 && result2 == result3) {
            return true;
        }
    }
    
    /* Any disagreement = attack detected */
    return false;
}

/**
 * @brief Compute hash with fault protection
 */
static bool compute_hash_defensive(const uint8_t *data, size_t len, uint8_t *hash_out)
{
    uint8_t hash1[HASH_SIZE];
    uint8_t hash2[HASH_SIZE];
    
    /* Compute hash twice */
    crypto_sha256(data, len, hash1);
    crypto_sha256(data, len, hash2);
    
    /* Verify both computations match */
    if (!secure_compare(hash1, hash2, HASH_SIZE)) {
        /* Fault detected! */
        memset(hash_out, 0, HASH_SIZE);
        return false;
    }
    
    memcpy(hash_out, hash1, HASH_SIZE);
    return true;
}

/*============================================================================
 * MITIGATION #2: FIRMWARE UPGRADE - ANTI-ROLLBACK
 * Prevent downgrade attacks using monotonic counter in OTP/eFuse
 *============================================================================*/

/**
 * @brief Read anti-rollback counter from OTP
 */
static uint32_t read_version_counter(void)
{
    volatile uint32_t *otp = (volatile uint32_t *)VERSION_COUNTER_ADDR;
    volatile uint32_t counter1 = *otp;
    volatile uint32_t counter2 = *otp;
    
    /* Read twice to detect glitching */
    if (counter1 != counter2) {
        /* Fault detected */
        return 0xFFFFFFFF;
    }
    
    return counter1;
}

/**
 * @brief Check firmware version against anti-rollback counter
 */
static bool check_anti_rollback(uint32_t firmware_version)
{
    uint32_t min_version = read_version_counter();
    
    /* Firmware must be >= minimum allowed version */
    volatile bool check1 = (firmware_version >= min_version);
    volatile bool check2 = (firmware_version >= min_version);
    
    return (check1 && check2);
}

/*============================================================================
 * MITIGATION #4: TOCTOU (Time-of-Check to Time-of-Use)
 * - Copy data to secure RAM before verification
 * - Verify and use from the SAME location
 * - Disable interrupts during critical sections
 *============================================================================*/

/* Secure RAM that cannot be modified by DMA or external masters */
static uint8_t secure_ram[FIRMWARE_MAX_SIZE] __attribute__((section(".secure_ram")));

/**
 * @brief Copy firmware to secure memory (prevents TOCTOU)
 */
static bool copy_to_secure_ram(const void *src, size_t size)
{
    if (size > FIRMWARE_MAX_SIZE) {
        return false;
    }
    
    /* Disable interrupts during copy */
    __disable_irq();
    
    /* Copy to secure RAM */
    memcpy(secure_ram, src, size);
    
    /* Verify copy integrity */
    if (memcmp(secure_ram, src, size) != 0) {
        __enable_irq();
        return false;
    }
    
    __enable_irq();
    return true;
}

/*============================================================================
 * MITIGATION #7: STATE ERRORS
 * Use explicit state machine with magic values
 *============================================================================*/

static volatile SecureBootState g_boot_state = STATE_INIT;
static volatile SecureBootState g_boot_state_shadow = STATE_INIT;  /* Redundant */

/**
 * @brief Set state with redundancy check
 */
static void set_state(SecureBootState new_state)
{
    g_boot_state = new_state;
    g_boot_state_shadow = new_state;
}

/**
 * @brief Verify current state matches expected
 */
static bool verify_state(SecureBootState expected)
{
    volatile bool check1 = (g_boot_state == expected);
    volatile bool check2 = (g_boot_state_shadow == expected);
    volatile bool check3 = (g_boot_state == g_boot_state_shadow);
    
    return (check1 && check2 && check3);
}

/*============================================================================
 * MITIGATION #8: DEBUG/JTAG PORTS
 * Disable debug interfaces in production
 *============================================================================*/

/**
 * @brief Lock down debug interfaces
 */
static void disable_debug_interfaces(void)
{
    /* Example for ARM Cortex-M */
    #ifdef PRODUCTION_BUILD
    /* Disable JTAG/SWD */
    // DBGMCU->CR = 0;
    
    /* Lock flash readout protection */
    // FLASH->OPTCR |= FLASH_OPTCR_RDP;
    
    /* Disable debug in low-power modes */
    // DBGMCU->CR &= ~(DBGMCU_CR_DBG_SLEEP | DBGMCU_CR_DBG_STOP);
    #endif
}

/*============================================================================
 * MITIGATION #9: KEY MANAGEMENT
 * Clear sensitive data after use
 *============================================================================*/

/**
 * @brief Secure memory wipe (prevents compiler optimization)
 */
static void secure_wipe(void *ptr, size_t len)
{
    volatile uint8_t *p = (volatile uint8_t *)ptr;
    while (len--) {
        *p++ = 0;
    }
    
    /* Memory barrier to ensure wipe completes */
    __DSB();
    __ISB();
}

/**
 * @brief Clear crypto engine registers
 */
static void clear_crypto_state(void)
{
    /* Clear any keys in hardware crypto accelerator */
    // AES->KEYR0 = 0;
    // AES->KEYR1 = 0;
    // ... etc
    
    /* Clear any intermediate values */
    // HASH->HR[0] = 0;
    // ... etc
}

/*============================================================================
 * MAIN SECURE BOOT VERIFICATION
 * Combines all mitigations
 *============================================================================*/

typedef enum {
    BOOT_SUCCESS = 0,
    BOOT_ERR_SIZE,
    BOOT_ERR_COPY,
    BOOT_ERR_SIGNATURE,
    BOOT_ERR_VERSION,
    BOOT_ERR_HASH,
    BOOT_ERR_STATE,
    BOOT_ERR_ADDRESS
} BootResult;

/**
 * @brief Main secure boot verification function
 * @param firmware_addr Address where firmware is loaded (flash/RAM)
 * @return Boot result code
 */
BootResult secure_boot_verify(const void *firmware_addr)
{
    FirmwareHeader *header;
    uint8_t computed_hash[HASH_SIZE];
    BootResult result = BOOT_ERR_STATE;
    
    /* MITIGATION #8: Disable debug ports first */
    disable_debug_interfaces();
    
    /* Initialize state machine */
    set_state(STATE_INIT);
    
    /*----------------------------------------------------------------------
     * STEP 1: Copy header to secure RAM (TOCTOU protection)
     *----------------------------------------------------------------------*/
    if (!copy_to_secure_ram(firmware_addr, sizeof(FirmwareHeader))) {
        result = BOOT_ERR_COPY;
        goto cleanup;
    }
    
    header = (FirmwareHeader *)secure_ram;
    
    /*----------------------------------------------------------------------
     * STEP 2: Validate header fields BEFORE trusting them
     * MITIGATION #1: Don't use any data before signature verification
     * But we need basic sanity checks on fixed expected values
     *----------------------------------------------------------------------*/
    
    /* Check magic (this is a known constant, safe to check) */
    if (header->magic != 0x46574152) {  /* "FWAR" */
        result = BOOT_ERR_SIGNATURE;
        goto cleanup;
    }
    
    /*----------------------------------------------------------------------
     * STEP 3: Verify header signature FIRST
     * MITIGATION #1 & #6: Sign everything + defensive coding
     *----------------------------------------------------------------------*/
    
    if (!verify_state(STATE_INIT)) {
        result = BOOT_ERR_STATE;
        goto cleanup;
    }
    
    /* Verify signature over header (excluding signature field itself) */
    size_t header_data_size = sizeof(FirmwareHeader) - SIGNATURE_SIZE;
    
    if (!verify_signature_defensive((uint8_t *)header, header_data_size,
                                    header->signature)) {
        result = BOOT_ERR_SIGNATURE;
        goto cleanup;
    }
    
    set_state(STATE_SIGNATURE_VALID);
    
    /*----------------------------------------------------------------------
     * STEP 4: NOW we can trust header fields - validate them
     *----------------------------------------------------------------------*/
    
    if (!verify_state(STATE_SIGNATURE_VALID)) {
        result = BOOT_ERR_STATE;
        goto cleanup;
    }
    
    /* Validate size (MITIGATION #3: Logical bugs) */
    if (header->firmware_size == 0 || 
        header->firmware_size > FIRMWARE_MAX_SIZE - sizeof(FirmwareHeader)) {
        result = BOOT_ERR_SIZE;
        goto cleanup;
    }
    
    /* Validate load address is in allowed range */
    if (header->load_address < 0x20000000 || 
        header->load_address > 0x20040000) {
        result = BOOT_ERR_ADDRESS;
        goto cleanup;
    }
    
    set_state(STATE_HEADER_VERIFIED);
    
    /*----------------------------------------------------------------------
     * STEP 5: Check anti-rollback version
     * MITIGATION #2: Firmware upgrade protection
     *----------------------------------------------------------------------*/
    
    if (!verify_state(STATE_HEADER_VERIFIED)) {
        result = BOOT_ERR_STATE;
        goto cleanup;
    }
    
    if (!check_anti_rollback(header->version)) {
        result = BOOT_ERR_VERSION;
        goto cleanup;
    }
    
    set_state(STATE_VERSION_OK);
    
    /*----------------------------------------------------------------------
     * STEP 6: Copy firmware body to secure RAM and verify hash
     * MITIGATION #4: TOCTOU protection
     *----------------------------------------------------------------------*/
    
    if (!verify_state(STATE_VERSION_OK)) {
        result = BOOT_ERR_STATE;
        goto cleanup;
    }
    
    /* Copy firmware body after header */
    const uint8_t *fw_body = (const uint8_t *)firmware_addr + sizeof(FirmwareHeader);
    uint8_t *secure_fw = secure_ram + sizeof(FirmwareHeader);
    
    if (!copy_to_secure_ram(fw_body, header->firmware_size)) {
        result = BOOT_ERR_COPY;
        goto cleanup;
    }
    
    /* Compute and verify firmware hash */
    if (!compute_hash_defensive(secure_fw, header->firmware_size, computed_hash)) {
        result = BOOT_ERR_HASH;
        goto cleanup;
    }
    
    /* MITIGATION #5: Constant-time comparison */
    if (!secure_compare(computed_hash, header->hash, HASH_SIZE)) {
        result = BOOT_ERR_HASH;
        goto cleanup;
    }
    
    set_state(STATE_READY_TO_EXECUTE);
    
    /*----------------------------------------------------------------------
     * STEP 7: Final state verification before execution
     * MITIGATION #7: State errors
     *----------------------------------------------------------------------*/
    
    if (!verify_state(STATE_READY_TO_EXECUTE)) {
        result = BOOT_ERR_STATE;
        goto cleanup;
    }
    
    /* All checks passed! */
    result = BOOT_SUCCESS;
    
cleanup:
    /* MITIGATION #9: Clear sensitive data */
    secure_wipe(computed_hash, sizeof(computed_hash));
    clear_crypto_state();
    
    if (result != BOOT_SUCCESS) {
        /* Clear secure RAM on failure */
        secure_wipe(secure_ram, sizeof(secure_ram));
        set_state(STATE_ERROR);
    }
    
    return result;
}

/**
 * @brief Jump to verified firmware
 * Only call after secure_boot_verify() returns BOOT_SUCCESS
 */
void boot_firmware(void)
{
    /* Final state check */
    if (!verify_state(STATE_READY_TO_EXECUTE)) {
        /* Halt on error */
        while(1) { __WFI(); }
    }
    
    FirmwareHeader *header = (FirmwareHeader *)secure_ram;
    
    /* Get entry point from verified header */
    void (*entry)(void) = (void (*)(void))(header->load_address + header->entry_point);
    
    /* Disable interrupts */
    __disable_irq();
    
    /* Set stack pointer and jump */
    // __set_MSP(*(uint32_t *)header->load_address);
    entry();
    
    /* Should never reach here */
    while(1);
}

/*============================================================================
 * STUB FUNCTIONS (implement with actual crypto library)
 *============================================================================*/

/* These would be implemented using your crypto library (mbedTLS, wolfSSL, etc.) */

bool crypto_verify_signature(const uint8_t *data, size_t len,
                            const uint8_t *sig, const uint8_t *pubkey)
{
    /* Implement RSA-PSS or ECDSA verification */
    (void)data; (void)len; (void)sig; (void)pubkey;
    return false;  /* Replace with actual implementation */
}

void crypto_sha256(const uint8_t *data, size_t len, uint8_t *hash)
{
    /* Implement SHA-256 */
    (void)data; (void)len; (void)hash;
}

/* ARM intrinsics stubs */
void __disable_irq(void) {}
void __enable_irq(void) {}
void __DSB(void) {}
void __ISB(void) {}
void __WFI(void) {}
