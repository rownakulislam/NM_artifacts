// vault-helper.swift
// Compile: swiftc vault-helper.swift -o vault-helper
//
// Stores a generic password in the macOS Login Keychain with an explicit ACL
// that trusts ONLY this binary (vault-helper).  Any other process attempting
// to read the item is hard-rejected — no dialog, non-zero exit.
//
// Trust is based on the binary's path + hash at compile time.  Recompiling
// without re-seeding (install.sh) will break access — the new binary has a
// different hash and is no longer trusted.
//
// On read, an explicit LAContext.evaluatePolicy call fires Touch ID (or
// password fallback) before the Keychain is queried.
//
// Usage:
//   vault-helper write <secret>   — store secret silently, exits 0 on success
//   vault-helper read             — Touch ID / password prompt, then prints secret

import Foundation
import Security
import LocalAuthentication

let SERVICE = "com.demo.securevault"
let ACCOUNT  = "demo"

// ── Build ACL: only this binary is trusted ────────────────────────────────────

func buildAccess() -> SecAccess? {
    let binaryPath = CommandLine.arguments[0]

    var trustedApp: SecTrustedApplication?
    let taStatus = SecTrustedApplicationCreateFromPath(binaryPath, &trustedApp)
    guard taStatus == errSecSuccess, let app = trustedApp else {
        fputs("ERROR: SecTrustedApplicationCreateFromPath failed (\(taStatus))\n", stderr)
        return nil
    }

    var access: SecAccess?
    let acStatus = SecAccessCreate(
        "SecureVault Demo Secret" as CFString,
        [app] as CFArray,
        &access
    )
    guard acStatus == errSecSuccess else {
        fputs("ERROR: SecAccessCreate failed (\(acStatus))\n", stderr)
        return nil
    }
    return access
}

// ── write ─────────────────────────────────────────────────────────────────────

func cmdWrite(secret: String) {
    guard let access = buildAccess() else { exit(1) }

    // Remove stale item — ignore error if it does not exist
    SecItemDelete([
        kSecClass:       kSecClassGenericPassword,
        kSecAttrService: SERVICE,
        kSecAttrAccount: ACCOUNT,
    ] as CFDictionary)

    let status = SecItemAdd([
        kSecClass:          kSecClassGenericPassword,
        kSecAttrService:    SERVICE,
        kSecAttrAccount:    ACCOUNT,
        kSecValueData:      Data(secret.utf8),
        kSecAttrAccessible: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        kSecAttrAccess:     access,
    ] as CFDictionary, nil)

    guard status == errSecSuccess else {
        fputs("ERROR: SecItemAdd failed (\(status))\n", stderr)
        exit(1)
    }
    print("OK — secret stored, ACL trusts only '\(CommandLine.arguments[0])'")
}

// ── read ──────────────────────────────────────────────────────────────────────

func cmdRead() {
    let ctx = LAContext()
    var biometryError: NSError?
    let hasBiometry = ctx.canEvaluatePolicy(
        .deviceOwnerAuthenticationWithBiometrics, error: &biometryError
    )

    let policy: LAPolicy = hasBiometry
        ? .deviceOwnerAuthenticationWithBiometrics
        : .deviceOwnerAuthentication

    let reason = "SecureVault needs to read your stored secret"

    let sema = DispatchSemaphore(value: 0)
    var authOK  = false
    var authErr: Error?

    ctx.evaluatePolicy(policy, localizedReason: reason) { success, error in
        authOK  = success
        authErr = error
        sema.signal()
    }
    sema.wait()

    guard authOK else {
        let msg = authErr.map { "\($0)" } ?? "cancelled"
        fputs("ERROR: authentication failed — \(msg)\n", stderr)
        exit(1)
    }

    var ref: AnyObject?
    let status = SecItemCopyMatching([
        kSecClass:       kSecClassGenericPassword,
        kSecAttrService: SERVICE,
        kSecAttrAccount: ACCOUNT,
        kSecReturnData:  true,
    ] as CFDictionary, &ref)

    guard status == errSecSuccess,
          let data   = ref as? Data,
          let secret = String(data: data, encoding: .utf8)
    else {
        fputs("ERROR: SecItemCopyMatching failed (\(status))\n", stderr)
        exit(1)
    }

    print(secret, terminator: "")
}

// ── entry point ───────────────────────────────────────────────────────────────

let args = CommandLine.arguments
guard args.count >= 2 else {
    fputs("usage: vault-helper write <secret>\n       vault-helper read\n", stderr)
    exit(1)
}

switch args[1] {
case "write":
    guard args.count >= 3 else {
        fputs("write requires <secret> argument\n", stderr)
        exit(1)
    }
    cmdWrite(secret: args[2])
case "read":
    cmdRead()
default:
    fputs("unknown command: \(args[1])\n", stderr)
    exit(1)
}
